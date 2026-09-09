import { create } from "@bufbuild/protobuf";
import { blake3 } from "@noble/hashes/blake3.js";
import { SignedRecordSchema, type RevisionRef, type SignedRecord } from "./common_pb.js";
import { EndpointKind } from "./stream_pb.js";
import { SharedFacet, ThreadLifecycle, ThreadProperty, ThreadPropertyFrontierSchema, ReviewDecision_Kind, type ThreadIntent, type ThreadOverview, type ThreadPropertyFrontier, type ThreadSharingPolicy, type ReviewDecision } from "./thread_pb.js";
import type { CollaborationActor, CollaborationSigner } from "./collaboration.js";
import { encode, equal, type Value } from "./_collaboration-msgpack.js";

const OPERATION_FORMAT = "heddle-thread-operation-v1";
const AUTHORITY_FORMAT = "heddle-thread-control-authority-v1";
const PROPERTY_FORMAT = "heddle-thread-property-v1";
const utf8 = new TextEncoder();

export type ThreadControlValue =
  | { kind: "name"; value: string }
  | { kind: "intent"; value: ThreadIntent }
  | { kind: "lifecycle"; value: ThreadLifecycle }
  | { kind: "sharing"; value: ThreadSharingPolicy }
  | { kind: "review"; value: ReviewDecision };
export interface ThreadControlCommand {
  clientOperationId: string;
  occurredAtMs: bigint;
  control: ThreadControlValue;
}
export interface ThreadControlAuthor {
  actor: CollaborationActor;
  /** Original portable authority, independently validated by every receiver. */
  authorityEnvelope: Uint8Array;
  signer: CollaborationSigner;
}

/** Sign from the page's exact per-property frontier. Every concurrent candidate
 * is retained as a parent. No read round trip or timestamp winner is needed.
 * This proves authorship; it never substitutes for receiving-host admission. */
export async function signThreadControl(
  overview: ThreadOverview,
  command: ThreadControlCommand,
  author: ThreadControlAuthor,
  frontier?: ThreadPropertyFrontier,
): Promise<{ operation: SignedRecord; expectedVersion: Uint8Array }> {
  overview = structuredClone(overview);
  command = structuredClone(command);
  const actor = structuredClone(author.actor);
  const envelope = Uint8Array.from(author.authorityEnvelope);
  const thread = fixed(overview.ref?.id?.value, 32);
  const spool = overview.ref?.spool?.id ?? "";
  uuid(spool);
  uuid(actor.principalId);
  if (actor.agentId !== undefined) text(actor.agentId, 256);
  if (envelope.length === 0 || envelope.length > 64 * 1024) throw new Error("Thread authority envelope exceeds bounds");
  timestamp(command.occurredAtMs);
  const property = propertyOf(command.control);
  const recordId = command.control.kind === "review" ? command.control.value.ref?.id ?? "" : "";
  const matches = overview.metadataFrontiers.filter(item => item.property === property && item.recordId === recordId);
  if (!frontier && matches.length === 0 && property === ThreadProperty.REVIEW) {
    frontier = create(ThreadPropertyFrontierSchema, { property, recordId, operationIds: [],
      version: threadPropertyVersion(thread, property, recordId, []) });
  }
  if (!frontier && matches.length !== 1) throw new Error("Exact Thread property frontier is required");
  frontier = structuredClone(frontier ?? matches[0]!);
  if (frontier.property !== property || frontier.recordId !== recordId) throw new Error("Thread property frontier belongs to another field");
  const parents = canonicalParents(frontier.operationIds);
  const version = threadPropertyVersion(thread, property, recordId, parents);
  if (!equal(frontier.version, version)) throw new Error("Thread property version does not bind this scope and frontier");
  const inner = encode({
    version: 1,
    spool: uuid(spool),
    actor: { principal_id: uuid(actor.principalId), agent_id: actor.agentId ?? null },
    authority_digest: Array.from(typedHash(AUTHORITY_FORMAT, envelope)),
    authority_envelope: Array.from(envelope),
    client_operation_id: uuid(command.clientOperationId),
    occurred_at_ms: command.occurredAtMs,
    control: controlValue(command.control, spool, thread, actor, command.occurredAtMs),
  });
  if (inner.length > 128 * 1024) throw new Error("Thread control exceeds record budget");
  const publisher = fixed(author.signer.publicKey, 32);
  const canonicalRecord = encode({ version: 1, thread: Array.from(thread), parents: parents.map(id => Array.from(id)),
    publisher: Array.from(publisher), body: { kind: "metadata", canonical: Array.from(inner) } });
  if (canonicalRecord.length > 256 * 1024) throw new Error("Thread operation exceeds record budget");
  const signingBytes = concat(utf8.encode(OPERATION_FORMAT), Uint8Array.of(0), canonicalRecord);
  const signature = fixed(await author.signer.sign(Uint8Array.from(signingBytes)), 64);
  const key = await crypto.subtle.importKey("raw", publisher, { name: "Ed25519" }, false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", key, signature, signingBytes)) throw new Error("Thread control signer does not match publisher");
  return { operation: create(SignedRecordSchema, { format: OPERATION_FORMAT, canonicalRecord,
    signatures: [{ publicKey: publisher, signature }] }), expectedVersion: version };
}

/** Deterministic empty/frontier version, including a fresh caller-generated
 * review UUID. Missing an observed existing frontier is never an empty view. */
export function threadPropertyVersion(thread: Uint8Array, property: ThreadProperty, recordId: string, operationIds: readonly Uint8Array[]): Uint8Array {
  const names: Partial<Record<ThreadProperty, string>> = {
    [ThreadProperty.NAME]: "name", [ThreadProperty.INTENT]: "intent", [ThreadProperty.LIFECYCLE]: "lifecycle", [ThreadProperty.SHARING]: "sharing",
  };
  let key: Value;
  if (property === ThreadProperty.REVIEW) key = { review: uuid(recordId) };
  else {
    if (recordId || !names[property]) throw new Error("Invalid Thread property identity");
    key = names[property]!;
  }
  return typedHash(PROPERTY_FORMAT, encode([Array.from(fixed(thread, 32)), key, canonicalParents(operationIds).map(id => Array.from(id))]));
}

function propertyOf(control: ThreadControlValue): ThreadProperty {
  switch (control.kind) {
    case "name": return ThreadProperty.NAME;
    case "intent": return ThreadProperty.INTENT;
    case "lifecycle": return ThreadProperty.LIFECYCLE;
    case "sharing": return ThreadProperty.SHARING;
    case "review": return ThreadProperty.REVIEW;
  }
}
function controlValue(control: ThreadControlValue, spool: string, thread: Uint8Array, actor: CollaborationActor, at: bigint): Value {
  let value: Value;
  switch (control.kind) {
    case "name": text(control.value, 1024); value = control.value; break;
    case "intent": {
      const intent = control.value;
      text(intent.outcome, 32768);
      if (intent.acceptanceCriteria.length > 64 || intent.originUrls.length > 64) throw new Error("Thread intent exceeds bounds");
      if (intent.principalId && intent.principalId !== actor.principalId || intent.agentId && intent.agentId !== actor.agentId)
        throw new Error("Thread intent author differs from signer authority");
      if (intent.principalApproved && actor.agentId) throw new Error("Agent-authored intent cannot fabricate human approval");
      intent.acceptanceCriteria.forEach(item => text(item, 4096)); intent.originUrls.forEach(item => text(item, 4096));
      value = { outcome: intent.outcome, acceptance_criteria: intent.acceptanceCriteria, origin_urls: intent.originUrls, principal_approved: intent.principalApproved };
      break;
    }
    case "lifecycle": {
      const names: Partial<Record<ThreadLifecycle, string>> = { [ThreadLifecycle.DRAFT]: "draft", [ThreadLifecycle.ACTIVE]: "active", [ThreadLifecycle.READY]: "ready", [ThreadLifecycle.ABANDONED]: "abandoned" };
      if (!names[control.value]) throw new Error("Landing requires an integration receipt");
      value = names[control.value]!; break;
    }
    case "sharing": {
      const policy = control.value;
      if (!policy.thread?.id || !equal(policy.thread.id.value, thread) || policy.thread.spool?.id !== spool)
        throw new Error("Sharing policy belongs to another Thread");
      if (policy.destinations.length > 64) throw new Error("Too many sharing destinations");
      const seen = new Set<string>();
      const facetNames: Partial<Record<SharedFacet, string>> = {
        [SharedFacet.SOURCE]: "source", [SharedFacet.COLLABORATION]: "collaboration", [SharedFacet.EVIDENCE]: "evidence", [SharedFacet.SCRUBBED_TIMELINE]: "scrubbed_timeline", [SharedFacet.METADATA]: "metadata",
      };
      value = { ongoing: policy.ongoing, destinations: policy.destinations.map(destination => {
        const endpoint = fixed(destination.endpoint?.publicKey, 32);
        const target = destination.spool?.id ?? "";
        const key = `${Array.from(endpoint).join(",")}:${target}`;
        if (endpoint.every(byte => byte === 0) || seen.has(key)) throw new Error("Invalid or duplicate sharing destination");
        seen.add(key);
        const facets = [...new Set(destination.facets)].sort((a, b) => a - b);
        if (!facets.length || facets.some(facet => !facetNames[facet])) throw new Error("Invalid sharing facets");
        const kind = destination.endpoint?.kind;
        if (kind !== EndpointKind.DEVICE && kind !== EndpointKind.WEFT) throw new Error("Invalid sharing endpoint kind");
        return { endpoint: Array.from(endpoint), kind: kind === EndpointKind.DEVICE ? "device" : "weft", spool: uuid(target), facets: facets.map(facet => facetNames[facet]!) };
      }) }; break;
    }
    case "review": {
      const review = control.value;
      const id = review.ref?.id ?? "";
      if (review.ref?.spool?.id !== spool || review.thread?.spool?.id !== spool || !review.thread.id || !equal(review.thread.id.value, thread)) throw new Error("Review belongs to another Thread");
      if (review.principalId !== actor.principalId || review.agentId !== (actor.agentId ?? "")) throw new Error("Review actor differs from original authority");
      const names: Partial<Record<ReviewDecision_Kind, string>> = { [ReviewDecision_Kind.OPINION]: "opinion", [ReviewDecision_Kind.APPROVAL]: "approval", [ReviewDecision_Kind.REJECTION]: "rejection", [ReviewDecision_Kind.REVOCATION]: "revocation" };
      if (!names[review.kind]) throw new Error("Invalid review kind");
      const revokes = review.revokes;
      if ((review.kind === ReviewDecision_Kind.REVOCATION) !== Boolean(revokes) || revokes && (revokes.spool?.id !== spool || revokes.id === id)) throw new Error("Invalid review revocation");
      text(review.explanation, 32768, true);
      const expires = review.expiresAt;
      if (expires && (expires.nanos !== 0 || expires.seconds <= at / 1000n || expires.seconds > 9223372036854775807n)) throw new Error("Review expiry must be a future whole second");
      value = { id: uuid(id), source: Array.from(stateRevision(review.source, spool)), target: Array.from(stateRevision(review.target, spool)), policy_version: Array.from(fixed(review.policyVersion, 32)), kind: names[review.kind]!, explanation: review.explanation,
        revokes: revokes ? uuid(revokes.id) : null, expires_at_unix_seconds: expires?.seconds ?? null }; break;
    }
  }
  return { kind: control.kind, value };
}
function stateRevision(revision: RevisionRef | undefined, spool: string): Uint8Array {
  if (revision?.spool?.id !== spool || revision.revision.case !== "state") throw new Error("Review requires an exact native State in its Spool");
  return fixed(revision.revision.value.value, 32);
}
function canonicalParents(ids: readonly Uint8Array[]): Uint8Array[] {
  if (ids.length > 128) throw new Error("Thread property frontier exceeds bounds");
  const copied = ids.map(id => fixed(id, 32));
  for (let i = 1; i < copied.length; i++) if (compare(copied[i - 1]!, copied[i]!) >= 0) throw new Error("Thread property frontier must be sorted and unique");
  return copied;
}
function text(value: string, max: number, empty = false): void {
  if ((!empty && !value.trim()) || value.includes("\0") || utf8.encode(value).length > max) throw new Error("Invalid or unbounded Thread control text");
}
function timestamp(value: bigint): void { if (value < 0n || value > 9223372036854775807n) throw new Error("Invalid Thread control timestamp"); }
function uuid(value: string): Uint8Array {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) || value === "00000000-0000-0000-0000-000000000000") throw new Error("Expected canonical non-nil UUID");
  return Uint8Array.from(value.replaceAll("-", "").match(/../g)!, byte => Number.parseInt(byte, 16));
}
function fixed(value: Uint8Array | undefined, size: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== size) throw new Error(`Expected ${size} bytes`);
  return Uint8Array.from(value);
}
function compare(left: Uint8Array, right: Uint8Array): number { for (let i = 0; i < left.length; i++) if (left[i] !== right[i]) return left[i]! - right[i]!; return 0; }
function concat(...parts: Uint8Array[]): Uint8Array { const value = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0)); let offset = 0; for (const part of parts) { value.set(part, offset); offset += part.length; } return value; }
function typedHash(domain: string, bytes: Uint8Array): Uint8Array { const length = new Uint8Array(8); new DataView(length.buffer).setBigUint64(0, BigInt(bytes.length), true); return blake3(concat(utf8.encode(domain), length, Uint8Array.of(0), bytes)); }

import { create } from "@bufbuild/protobuf";
import { blake3 } from "@noble/hashes/blake3.js";
import { SignedRecordSchema, type SignedRecord } from "./common_pb.js";
import { AnnotationSourceReferenceSchema, SourceTargetReferenceSchema, AnnotationTagSchema, type AnnotationTag, type AnnotationSourceReference, type AnnotationValue, type SourceTargetReference, type SourceAnchor } from "./collaboration_pb.js";
import type { EntityRef } from "./common_pb.js";
import { Audience } from "./administration_pb.js";
import { encode, decode, equal, type Value } from "./_collaboration-msgpack.js";

const FORMAT = "heddle-thread-operation-v1";
const utf8 = new TextEncoder();
type MapValue = { [key: string]: Value };
export interface CollaborationSigner {
  publicKey: Uint8Array;
  sign(bytes: Uint8Array): Promise<Uint8Array>;
}
export interface CollaborationScope { spoolId: string; threadId: Uint8Array }
export interface CollaborationActor { principalId: string; agentId?: string }
export type CollaborationMention =
  | { kind: "spool"; spoolId: string }
  | { kind: "thread"; spoolId: string; id: Uint8Array }
  | { kind: "state"; spoolId: string; id: Uint8Array }
  | { kind: "git_commit"; spoolId: string; oid: string }
  | { kind: "checkout"; spoolId: string; device: Uint8Array; id: string }
  | { kind: "record"; spoolId?: string; recordKind: string; id: string }
  | { kind: "device"; key: Uint8Array };
export type PortableCollaborationAnchor =
  | { kind: "repository" }
  | { kind: "source"; revision: { kind: "state"; stateId: Uint8Array } | { kind: "git_commit"; oid: string };
      path: string; symbolId?: string; startLine?: number; endLine?: number; target?: SourceTargetReference };
export type CollaborationVisibility = "public" | "internal"
  | { kind: "private"; label: string };
/** Typed native audiences map losslessly to canonical visibility. Labels are
 * private-scope identifiers, not a way to broaden the containing spool ACL. */
export function collaborationVisibility(audience: Audience, label = ""): CollaborationVisibility {
  if (audience === Audience.PRIVATE) {
    text(label, 512);
    if (!label.trim()) throw new Error("Private discussion audience requires a label");
    return { kind: "private", label };
  }
  if (label) throw new Error("Only a private discussion audience may carry a label");
  if (audience === Audience.PUBLIC) return "public";
  if (audience === Audience.MEMBERS) return "internal";
  throw new Error("Discussion audience must be explicit");
}
export type DiscussionAction =
  | { kind: "open"; blocking: boolean; title: string; anchor: PortableCollaborationAnchor; visibility: CollaborationVisibility; body: string }
  | { kind: "append"; body: string }
  | { kind: "resolve"; resolution: { kind: "dismissed"; reason: string } | { kind: "addressed_by_state"; stateId: Uint8Array }
      | { kind: "annotation"; annotationId: string } }
  | { kind: "reopen"; reason: string };
interface SharedCommand {
  scope: CollaborationScope;
  actor: CollaborationActor;
  mentions?: CollaborationMention[];
  occurredAtMs: bigint;
}
export interface DiscussionCommand extends SharedCommand {
  discussionId: string;
  clientOperationId: string;
  /** Display attribution only. Stable authority comes from actor and signature. */
  author: { name: string; email?: string; agent?: { provider: string; model: string } };
  action: DiscussionAction;
}
export interface ContextCommand extends SharedCommand {
  contextId: string;
  anchor: PortableCollaborationAnchor;
  content: string;
  tags: AnnotationTag[];
  supersedes?: string;
  extractedFrom?: string;
}

/** Sign immutable collaboration from the original observed frontier records.
 * A version token or causal ID alone is deliberately insufficient. Receiving
 * hosts still authorize the actor and admit the causal graph independently. */
export async function signDiscussion(command: DiscussionCommand, parents: readonly SignedRecord[], signer: CollaborationSigner): Promise<SignedRecord> {
  command = structuredClone(command);
  const metadata = metadataValue(command);
  discussionId(command.discussionId);
  text(command.clientOperationId, 512);
  const body = actionValue(command.action);
  if ((command.action.kind === "open") !== (parents.length === 0)) throw new Error("Only discussion root operations use an empty causal frontier");
  const frontier = await verifyParents(command.scope, parents, "discussion", command.discussionId);
  const agent = command.author.agent;
  const author = {
    principal: { name: utf8.encode(command.author.name), email: utf8.encode(command.author.email ?? "") },
    agent: agent ? { provider: agent.provider, model: agent.model, session_id: null, segment_id: null, policy_id: null } : null,
  };
  const inner = encode({ schema_version: 2, metadata, discussion_id: command.discussionId,
    parents: frontier.inner, idempotency_key: command.clientOperationId, author,
    occurred_at_ms: timestamp(command.occurredAtMs), body });
  return signOperation(command.scope.threadId, frontier.outer, "discussion", inner, signer);
}

export async function signContext(command: ContextCommand, parents: readonly SignedRecord[], signer: CollaborationSigner): Promise<SignedRecord> {
  command = structuredClone(command);
  const metadata = metadataValue(command);
  const id = uuid(command.contextId);
  if (command.supersedes === command.contextId) throw new Error("Context cannot supersede itself");
  if (command.tags.length > 128) throw new Error("Too many context tags");
  const tags = annotationTagsValue(command.tags);
  text(command.content, 256 * 1024);
  if (command.extractedFrom) {
    discussionId(command.extractedFrom);
    if (parents.length === 0) throw new Error("Context extraction requires a signed discussion resolution");
  }
  const frontier = await verifyParents(command.scope, parents, "context", command.contextId);
  const inner = encode({ version: 2, id, parents: frontier.outer, metadata,
    anchor: anchorValue(command.anchor), content: command.content, tags,
    supersedes: command.supersedes ? uuid(command.supersedes) : null,
    extracted_from: command.extractedFrom ?? null, occurred_at_ms: timestamp(command.occurredAtMs) });
  return signOperation(command.scope.threadId, frontier.outer, "context", inner, signer);
}

export interface VerifiedCollaboration {
  operationId: Uint8Array;
  threadId: Uint8Array;
  spoolId: string;
  kind: "discussion" | "context";
  recordId: string;
  canonicalContent: Uint8Array;
}
/** Verify the publisher and bounded canonical bytes. This does not establish
 * server authorization, causal admission, or truth of display attribution. */
export async function verifyCollaboration(record: SignedRecord): Promise<VerifiedCollaboration> {
  record = structuredClone(record);
  if (record.format !== FORMAT || record.signatures.length !== 1) throw new Error("Unsupported collaboration signature record");
  const canonical = record.canonicalRecord;
  const operation = map(decode(canonical));
  keys(operation, ["version", "thread", "parents", "publisher", "body"]);
  if (operation.version !== 1) throw new Error("Unsupported Thread operation version");
  const publisher = byteArray(operation.publisher, 32);
  const signature = record.signatures[0]!;
  if (!equal(publisher, signature.publicKey) || signature.signature.length !== 64) throw new Error("Collaboration publisher does not match signature key");
  const key = await crypto.subtle.importKey("raw", publisher, { name: "Ed25519" }, false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", key, signature.signature, signingBytes(canonical))) throw new Error("Invalid collaboration author signature");
  const body = map(operation.body);
  keys(body, ["kind", "canonical"]);
  if (body.kind !== "discussion" && body.kind !== "context") throw new Error("Expected collaboration operation");
  const content = byteArray(body.canonical);
  const inner = map(decode(content));
  keys(inner, body.kind === "discussion"
    ? ["schema_version", "metadata", "discussion_id", "parents", "idempotency_key", "author", "occurred_at_ms", "body"]
    : ["version", "id", "parents", "metadata", "anchor", "content", "tags", "supersedes", "extracted_from", "occurred_at_ms"]);
  if ((body.kind === "discussion" ? inner.schema_version : inner.version) !== 2) throw new Error("Unsupported collaboration schema");
  const metadata = map(inner.metadata);
  keys(metadata, ["scope", "actor", "mentions"]);
  const scope = map(metadata.scope);
  keys(scope, ["spool", "thread"]);
  const thread = byteArray(operation.thread, 32);
  if (!equal(thread, byteArray(scope.thread, 32))) throw new Error("Collaboration scope differs from Thread");
  const spoolId = uuidString(scope.spool);
  const actor = map(metadata.actor);
  keys(actor, ["principal_id", "agent_id"]);
  uuidString(actor.principal_id);
  if (actor.agent_id !== null) text(string(actor.agent_id), 512, true);
  if (!Array.isArray(metadata.mentions) || metadata.mentions.length > 128) throw new Error("Invalid collaboration mentions");
  validateInner(inner, body.kind);
  const recordId = body.kind === "discussion" ? discussionId(string(inner.discussion_id)) : uuidString(inner.id);
  const outerParents = hashes(operation.parents);
  if (body.kind === "context" && !equal(encode(outerParents), encode(hashes(inner.parents)))) throw new Error("Context causal frontier differs from Thread operation");
  if (body.kind === "discussion" && (!Array.isArray(inner.parents) || inner.parents.length > 128 || inner.parents.some(id => typeof id !== "string" || !/^co-[0-9a-hjkmnp-tv-z]{52}$/.test(id)))) throw new Error("Invalid discussion causal frontier");
  if (body.kind === "discussion") {
    const action = map(inner.body);
    if (action.kind === "resolve") {
      const resolution = map(action.resolution);
      if (resolution.kind === "into_context" && !equal(encode(outerParents), encode(hashes(map(resolution.context).parents)))) throw new Error("Extracted context frontier differs from Thread operation");
    }
  }
  return { operationId: typedHash(FORMAT, canonical), threadId: thread, spoolId, kind: body.kind, recordId, canonicalContent: content };
}

async function verifyParents(scope: CollaborationScope, records: readonly SignedRecord[], kind: "discussion" | "context", recordId: string) {
  records = structuredClone(records);
  if (records.length > 128) throw new Error("Too many causal parents");
  const outer: Uint8Array[] = [];
  const inner: Uint8Array[] = [];
  for (const record of records) {
    const parent = await verifyCollaboration(record);
    if (!equal(parent.threadId, scope.threadId) || parent.spoolId !== scope.spoolId || parent.kind !== kind || parent.recordId !== recordId) throw new Error("Causal parent belongs to another record or scope");
    if (outer.some(id => equal(id, parent.operationId))) throw new Error("Duplicate causal parent");
    outer.push(parent.operationId);
    if (kind === "discussion") {
      const id = typedHash("collaboration-operation", parent.canonicalContent);
      if (!inner.some(existing => equal(existing, id))) inner.push(id);
    }
  }
  return { outer: outer.sort(compare).map(id => Array.from(id)), inner: inner.sort(compare).map(id => "co-" + base32(id)) };
}
async function signOperation(thread: Uint8Array, parents: number[][], kind: string, inner: Uint8Array, signer: CollaborationSigner) {
  const publisher = fixed(signer.publicKey, 32);
  const canonicalRecord = encode({ version: 1, thread: Array.from(fixed(thread, 32)), parents,
    publisher: Array.from(publisher), body: { kind, canonical: Array.from(inner) } });
  const signature = await signer.sign(signingBytes(canonicalRecord));
  const record = create(SignedRecordSchema, { format: FORMAT, canonicalRecord,
    signatures: [{ publicKey: publisher, signature }] });
  await verifyCollaboration(record);
  return record;
}
function metadataValue(command: SharedCommand): MapValue {
  const mentions = command.mentions ?? [];
  if (mentions.length > 128) throw new Error("Too many collaboration mentions");
  if (command.actor.agentId !== undefined) text(command.actor.agentId, 512, true);
  return { scope: { spool: uuid(command.scope.spoolId), thread: Array.from(fixed(command.scope.threadId, 32)) },
    actor: { principal_id: uuid(command.actor.principalId), agent_id: command.actor.agentId ?? null },
    mentions: mentions.map(mentionValue) };
}
function mentionValue(mention: CollaborationMention): MapValue {
  const kind = mention.kind;
  if (kind === "device") return { kind, key: Array.from(fixed(mention.key, 32)) };
  if (kind === "record") {
    if (!RECORD_KINDS.has(mention.recordKind)) throw new Error("Unknown collaboration record kind");
    text(mention.id, 1024, true);
    return { kind, spool: mention.spoolId ? uuid(mention.spoolId) : null, record_kind: mention.recordKind, id: mention.id };
  }
  const spool = uuid(mention.spoolId);
  if (kind === "spool") return { kind, spool };
  if (kind === "thread" || kind === "state") return { kind, spool, [kind]: Array.from(fixed(mention.id, 32)) };
  if (kind === "git_commit") return { kind, spool, oid: gitOid(mention.oid) };
  text(mention.id, 1024, true);
  return { kind, spool, device: Array.from(fixed(mention.device, 32)), id: mention.id };
}
const RECORD_KINDS = new Set(["discussion", "context", "operation", "run", "policy", "analysis", "invitation", "grant", "discussion_turn", "review", "notification", "attention_item", "member", "approval_group", "session", "signup_invitation", "timeline_event", "artifact", "mount", "support_access", "device_record", "delegation", "recovery", "owner_transition", "billing", "evidence", "check_acknowledgement", "provider_connection", "remote_link"]);
/** Intern original source evidence once; materialized locations preserve the existing
 * identity. The binding chooses a resolver, never grants access to that scope. */
export function sourceTargetReference(source: SourceAnchor, binding: SourceTargetReference["binding"]): SourceTargetReference {
  const evidence = annotationSourceValue(create(AnnotationSourceReferenceSchema, { source }));
  const anchor = map(evidence.source);
  if (source.symbolId && !source.symbolId.trim()) throw new Error("Invalid source symbol address");
  let targetId = source.target?.targetId;
  if (!targetId) {
    const file = typedHash("heddle-source-file-v1", encode({ scope: evidence.scope, revision: anchor.revision, path: anchor.path }));
    const selector: MapValue = source.symbolId ? { kind: "symbol", address: source.symbolId }
      : source.startLine !== undefined ? { kind: "lines", range: { start: source.startLine - 1, end: source.endLine!, start_affinity: "after", end_affinity: "before" } }
      : { kind: "file" };
    targetId = typedHash("heddle-source-target-v1", encode({ file: Array.from(file), revision: anchor.revision, selector }));
  }
  const target = create(SourceTargetReferenceSchema, { targetId: Uint8Array.from(targetId), binding });
  sourceTargetValue(target);
  return target;
}
function sourceTargetValue(target: SourceTargetReference): MapValue {
  const id = Array.from(fixed(target.targetId, 32));
  const binding = target.binding;
  if (binding.case === "viewedThread") {
    if (!binding.value) throw new Error("Viewed Thread binding must be true");
    return { target: id, binding: { kind: "viewed_thread" } };
  }
  if (binding.case === "namedThread") {
    const thread = binding.value;
    if (!thread.spool || !thread.id) throw new Error("Named target requires scoped Thread");
    return { target: id, binding: { kind: "named_thread", scope: {
      spool: uuid(thread.spool.id), thread: Array.from(fixed(thread.id.value, 32)) } } };
  }
  if (binding.case === "pinnedRevision") {
    const pinned = binding.value, ref = pinned.revision;
    if (!ref?.spool) throw new Error("Pinned target requires scoped exact revision");
    const thread = pinned.thread;
    if (thread && (!thread.id || thread.spool?.id !== ref.spool.id)) throw new Error("Pinned target Thread belongs to another spool");
    const r = ref.revision;
    const revision: MapValue = r.case === "state" ? { kind: "state", state_id: Array.from(fixed(r.value.value, 32)) }
      : r.case === "gitCommitOid" ? { kind: "git_commit", oid: gitOid(r.value) }
      : (() => { throw new Error("Pinned target requires exact revision"); })();
    return { target: id, binding: { kind: "pinned_revision", scope: {
      spool: uuid(ref.spool.id), thread: thread ? Array.from(fixed(thread.id!.value, 32)) : null }, revision } };
  }
  throw new Error("Explicit source target binding required");
}
function validateSourceTarget(value: Value | undefined) {
  const target = map(value); keys(target, ["target", "binding"]); byteArray(target.target, 32);
  const binding = map(target.binding);
  if (binding.kind === "viewed_thread") { keys(binding, ["kind"]); return; }
  if (binding.kind !== "named_thread" && binding.kind !== "pinned_revision") throw new Error("Unknown source target binding");
  keys(binding, ["kind", "scope", ...(binding.kind === "pinned_revision" ? ["revision"] : [])]);
  const scope = map(binding.scope); keys(scope, ["spool", "thread"]); uuidString(scope.spool);
  if (binding.kind === "named_thread" || scope.thread !== null) byteArray(scope.thread, 32);
  if (binding.kind === "pinned_revision") {
    const revision = map(binding.revision);
    if (revision.kind === "state") { keys(revision, ["kind", "state_id"]); byteArray(revision.state_id, 32); }
    else if (revision.kind === "git_commit") { keys(revision, ["kind", "oid"]); gitOid(string(revision.oid)); }
    else throw new Error("Pinned target requires exact revision");
  }
}
function anchorValue(anchor: PortableCollaborationAnchor): MapValue {
  if (anchor.kind === "repository") return { kind: "repository" };
  text(anchor.path, 4096, true, true);
  text(anchor.symbolId ?? "", 4096, true, true);
  for (const line of [anchor.startLine, anchor.endLine]) if (line !== undefined && (!Number.isInteger(line) || line < 1 || line > 4294967295)) throw new Error("Invalid source line");
  if ((!anchor.path && (anchor.symbolId || anchor.startLine !== undefined || anchor.endLine !== undefined))
    || (anchor.endLine !== undefined && (anchor.startLine === undefined || anchor.endLine < anchor.startLine))) throw new Error("Invalid source span");
  const revision: MapValue = anchor.revision.kind === "state" ? { kind: "state", state_id: Array.from(fixed(anchor.revision.stateId, 32)) }
    : { kind: "git_commit", oid: gitOid(anchor.revision.oid) };
  return { kind: "source", source: { revision, path: anchor.path, symbol_id: anchor.symbolId ?? "", start_line: anchor.startLine ?? null, end_line: anchor.endLine ?? null, ...(anchor.target ? { target: sourceTargetValue(anchor.target) } : {}) } };
}
function actionValue(action: DiscussionAction): MapValue {
  const turn = (body: string) => { text(body, 256 * 1024); return { body, content_hash: Array.from(typedHash("collaboration-turn", utf8.encode(body))) }; };
  if (action.kind === "open") {
    text(action.title, 256 * 1024);
    let visibility: Value;
    if (action.visibility === "public") visibility = "Public";
    else if (action.visibility === "internal") visibility = "Internal";
    else if (typeof action.visibility === "object" && action.visibility.kind === "private") {
      text(action.visibility.label, 512);
      if (!action.visibility.label.trim()) throw new Error("Private discussion audience requires a label");
      visibility = { Private: { scope_label: action.visibility.label } };
    } else throw new Error("Visibility has no native discussion audience representation");
    return { kind: "open", blocking: action.blocking, title: action.title, anchor: anchorValue(action.anchor), visibility, turn: turn(action.body) };
  }
  if (action.kind === "append") return { kind: "append_turn", turn: turn(action.body) };
  if (action.kind === "reopen") { text(action.reason, 256 * 1024); return { kind: "reopen", reason: action.reason }; }
  const resolution = action.resolution;
  if (resolution.kind === "addressed_by_state") return { kind: "resolve", resolution: { kind: resolution.kind, state_id: Array.from(fixed(resolution.stateId, 32)) } };
  if (resolution.kind === "annotation") { text(resolution.annotationId, 1024); return { kind: "resolve", resolution: { kind: resolution.kind, annotation_id: resolution.annotationId } }; }
  text(resolution.reason, 256 * 1024);
  return { kind: "resolve", resolution: { kind: resolution.kind, reason: resolution.reason } };
}
function timestamp(value: bigint): bigint {
  if (value < -9223372036854775808n || value > 9223372036854775807n) throw new Error("Timestamp exceeds int64");
  return value;
}
function typedHash(domain: string, bytes: Uint8Array): Uint8Array {
  const length = new Uint8Array(8); new DataView(length.buffer).setBigUint64(0, BigInt(bytes.length), true);
  return blake3(concat(utf8.encode(domain), length, Uint8Array.of(0), bytes));
}
function signingBytes(bytes: Uint8Array) { return concat(utf8.encode(FORMAT), Uint8Array.of(0), bytes); }
function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0)); let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; } return result;
}
function fixed(bytes: Uint8Array, size: number) { if (!(bytes instanceof Uint8Array) || bytes.length !== size) throw new Error(`Expected ${size} bytes`); return Uint8Array.from(bytes); }
function text(value: string, max: number, noControls = false, empty = false) {
  if (typeof value !== "string" || (!empty && !value.trim()) || utf8.encode(value).length > max || (noControls && /[\p{Cc}]/u.test(value))) throw new Error("Invalid or unbounded collaboration text");
}
function string(value: Value | undefined): string { if (typeof value !== "string") throw new Error("Expected collaboration string"); return value; }
function map(value: Value | undefined): MapValue {
  if (!value || typeof value !== "object" || Array.isArray(value) || value instanceof Uint8Array) throw new Error("Expected collaboration record"); return value;
}
function keys(value: MapValue, expected: string[]) { if (Object.keys(value).join("\0") !== expected.join("\0")) throw new Error("Noncanonical collaboration field order or schema"); }
function byteArray(value: Value | undefined, size?: number): Uint8Array {
  if (!Array.isArray(value) || value.some(b => typeof b !== "number" || !Number.isInteger(b) || b < 0 || b > 255) || (size !== undefined && value.length !== size)) throw new Error("Invalid collaboration byte array");
  return Uint8Array.from(value as number[]);
}
function hashes(value: Value | undefined): number[][] {
  if (!Array.isArray(value) || value.length > 128) throw new Error("Invalid causal parent list");
  const result = value.map(id => byteArray(id, 32));
  if (result.some((id, i) => i > 0 && compare(result[i - 1]!, id) >= 0)) throw new Error("Causal parents must be unique and sorted");
  return result.map(id => Array.from(id));
}
function uuid(value: string): Uint8Array {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) || value === "00000000-0000-0000-0000-000000000000") throw new Error("Expected canonical non-nil UUID");
  return Uint8Array.from(value.replaceAll("-", "").match(/../g)!, pair => Number.parseInt(pair, 16));
}
function uuidString(value: Value | undefined): string {
  if (!(value instanceof Uint8Array) || value.length !== 16) throw new Error("Expected binary UUID");
  const hex = Array.from(value, b => b.toString(16).padStart(2, "0")).join("");
  const id = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  uuid(id); return id;
}
function discussionId(value: string): string { if (!/^disc-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)) throw new Error("Expected discussion UUIDv7"); return value; }
function gitOid(value: string): string { if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(value)) throw new Error("Expected exact Git object identity"); return value; }
function compare(a: Uint8Array, b: Uint8Array): number { for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i]! - b[i]!; return a.length - b.length; }
function base32(bytes: Uint8Array): string {
  const alphabet = "0123456789abcdefghjkmnpqrstvwxyz"; let bits = 0, buffer = 0, result = "";
  for (const byte of bytes) { buffer = (buffer << 8) | byte; bits += 8; while (bits >= 5) { bits -= 5; result += alphabet[(buffer >> bits) & 31]; } }
  if (bits) result += alphabet[(buffer << (5 - bits)) & 31]; return result;
}

/** Validate every named nested structure, not merely its MessagePack spelling. */
function validateInner(inner: MapValue, kind: "discussion" | "context") {
  const occurred = inner.occurred_at_ms;
  if (typeof occurred !== "number" && typeof occurred !== "bigint") throw new Error("Invalid collaboration timestamp");
  timestamp(BigInt(occurred));
  const metadata = map(inner.metadata);
  for (const item of metadata.mentions as Value[]) {
    validateMention(item);
  }
  if (kind === "context") {
    validateAnchor(inner.anchor);
    text(string(inner.content), 256 * 1024);
    if (!Array.isArray(inner.tags) || inner.tags.length > 128) throw new Error("Invalid context tags");
    validateAnnotationTags(inner.tags);
    if (inner.supersedes !== null && uuidString(inner.supersedes) === uuidString(inner.id)) throw new Error("Context cannot supersede itself");
    if (inner.extracted_from !== null) discussionId(string(inner.extracted_from));
    return;
  }
  text(string(inner.idempotency_key), 512);
  const author = map(inner.author); keys(author, ["principal", "agent"]);
  const principal = map(author.principal); keys(principal, ["name", "email"]);
  if (!(principal.name instanceof Uint8Array) || !(principal.email instanceof Uint8Array)) throw new Error("Invalid binary display attribution");
  if (author.agent !== null) {
    const agent = map(author.agent);
    const expected = ["provider", "model", "session_id", "segment_id", "policy_id"];
    for (const optional of ["thought_level", "parent"]) if (Object.hasOwn(agent, optional)) expected.push(optional);
    keys(agent, expected);
    string(agent.provider); string(agent.model);
    for (const field of expected.slice(2)) if (agent[field] !== null) string(agent[field]);
  }
  const body = map(inner.body);
  const parents = inner.parents;
  if (!Array.isArray(parents) || parents.some((id, i) => typeof id !== "string" || (i > 0 && string(parents[i - 1]) >= id))) throw new Error("Discussion parents must be unique and sorted");
  if ((body.kind === "open") !== (parents.length === 0)) throw new Error("Only discussion roots use an empty causal frontier");
  switch (body.kind) {
    case "open": {
      keys(body, ["kind", "blocking", "title", "anchor", "visibility", "turn", ...(Object.hasOwn(body, "thread_ref") ? ["thread_ref"] : [])]);
      if (typeof body.blocking !== "boolean") throw new Error("Invalid discussion blocking flag");
      text(string(body.title), 256 * 1024); validateAnchor(body.anchor);
      if (body.thread_ref !== undefined) text(string(body.thread_ref), 256 * 1024);
      if (body.visibility !== "Public" && body.visibility !== "Internal") {
        const visibility = map(body.visibility); const label = Object.keys(visibility)[0];
        if (!label || !["TeamScoped", "Restricted", "Private"].includes(label)) throw new Error("Unknown visibility tier");
        keys(visibility, [label]); const scope = map(visibility[label]); const field = label === "TeamScoped" ? "team_id" : "scope_label";
        keys(scope, [field]); text(string(scope[field]), 512);
      }
      validateTurn(body.turn); break;
    }
    case "append_turn": keys(body, ["kind", "turn"]); validateTurn(body.turn); break;
    case "reopen": keys(body, ["kind", "reason"]); text(string(body.reason), 256 * 1024); break;
    case "resolve": {
      keys(body, ["kind", "resolution"]); const resolution = map(body.resolution);
      if (resolution.kind === "dismissed") { keys(resolution, ["kind", "reason"]); text(string(resolution.reason), 256 * 1024); }
      else if (resolution.kind === "addressed_by_state") { keys(resolution, ["kind", "state_id"]); byteArray(resolution.state_id, 32); }
      else if (resolution.kind === "annotation") { keys(resolution, ["kind", "annotation_id"]); text(string(resolution.annotation_id), 1024); }
      else if (resolution.kind === "into_context") {
        keys(resolution, ["kind", "context"]);
        const context = map(resolution.context);
        keys(context, ["version", "id", "parents", "metadata", "anchor", "content", "tags", "supersedes", "extracted_from", "occurred_at_ms"]);
        if (context.version !== 2) throw new Error("Unsupported extracted context schema");
        uuidString(context.id); hashes(context.parents);
        const metadata = map(context.metadata), parentMetadata = map(inner.metadata);
        keys(metadata, ["scope", "actor", "mentions"]);
        if (!equal(encode(metadata.scope!), encode(parentMetadata.scope!)) || !equal(encode(metadata.actor!), encode(parentMetadata.actor!)) || context.extracted_from !== inner.discussion_id) throw new Error("Extracted context differs from original discussion scope or actor");
        if (!Array.isArray(metadata.mentions) || metadata.mentions.length > 128) throw new Error("Invalid context mentions");
        validateInner(context, "context");
      }
      else throw new Error("Unsupported collaboration resolution");
      break;
    }
    default: throw new Error("Unsupported collaboration action");
  }
}
function validateTurn(value: Value | undefined) {
  const turn = map(value); keys(turn, ["body", "content_hash"]);
  text(string(turn.body), 256 * 1024);
  if (!equal(typedHash("collaboration-turn", utf8.encode(string(turn.body))), byteArray(turn.content_hash, 32))) throw new Error("Turn content hash differs from body");
}
function validateAnchor(value: Value | undefined) {
  const anchor = map(value);
  if (anchor.kind === "repository") { keys(anchor, ["kind"]); return; }
  if (anchor.kind !== "source") throw new Error("Unsupported collaboration anchor");
  keys(anchor, ["kind", "source"]);
  const source = map(anchor.source); keys(source, ["revision", "path", "symbol_id", "start_line", "end_line", ...(Object.hasOwn(source, "target") ? ["target"] : [])]);
  if (Object.hasOwn(source, "target")) validateSourceTarget(source.target);
  const revision = map(source.revision);
  let typedRevision: Extract<PortableCollaborationAnchor, { kind: "source" }>["revision"];
  if (revision.kind === "state") { keys(revision, ["kind", "state_id"]); typedRevision = { kind: "state", stateId: byteArray(revision.state_id, 32) }; }
  else if (revision.kind === "git_commit") { keys(revision, ["kind", "oid"]); typedRevision = { kind: "git_commit", oid: gitOid(string(revision.oid)) }; }
  else throw new Error("Unsupported source revision");
  const line = (value: Value | undefined) => {
    if (value === null) return undefined;
    if (typeof value !== "number") throw new Error("Invalid source line");
    return value;
  };
  anchorValue({ kind: "source", revision: typedRevision, path: string(source.path), symbolId: string(source.symbol_id), startLine: line(source.start_line), endLine: line(source.end_line) });
}

function validateMention(item: Value) {
    const mention = map(item);
    const kind = string(mention.kind);
    const fields: Record<string, string[]> = {
      spool: ["kind", "spool"], thread: ["kind", "spool", "thread"], state: ["kind", "spool", "state"],
      git_commit: ["kind", "spool", "oid"], checkout: ["kind", "spool", "device", "id"],
      record: ["kind", "spool", "record_kind", "id"], device: ["kind", "key"],
    };
    if (!fields[kind]) throw new Error("Unknown collaboration mention kind");
    keys(mention, fields[kind]);
    if (kind !== "device" && !(kind === "record" && mention.spool === null)) uuidString(mention.spool);
    if (kind === "thread" || kind === "state") byteArray(mention[kind], 32);
    if (kind === "checkout" || kind === "device") byteArray(mention[kind === "checkout" ? "device" : "key"], 32);
    if (kind === "checkout" || kind === "record") text(string(mention.id), 1024, true);
    if (kind === "record" && !RECORD_KINDS.has(string(mention.record_kind))) throw new Error("Unknown collaboration record kind");
    if (kind === "git_commit") gitOid(string(mention.oid));
}

/** Freeform remains explicit text; strings are never parsed as typed metadata. */
export function textAnnotationTag(value: string): AnnotationTag {
  text(value, 512, true);
  return create(AnnotationTagSchema, { tag: { case: "text", value } });
}
function annotationPath(value: string) {
  text(value, 4096, true);
  if (/[\\:]/.test(value) || value.split("/").some(part => part === "" || part === "." || part === "..")) throw new Error("Expected canonical relative annotation path");
}
function annotationSourceValue(reference: AnnotationSourceReference): MapValue {
  const source = reference.source;
  if (!source?.revision?.spool) throw new Error("Annotation source requires scoped revision");
  const spool = uuid(source.revision.spool.id);
  const thread = source.thread;
  if (thread && (thread.spool?.id !== source.revision.spool.id || !thread.id)) throw new Error("Annotation source Thread belongs to another spool");
  const revision = source.revision.revision;
  const anchor: PortableCollaborationAnchor = { kind: "source", revision: revision.case === "state"
    ? { kind: "state", stateId: revision.value.value } : revision.case === "gitCommitOid"
      ? { kind: "git_commit", oid: revision.value } : (() => { throw new Error("Exact annotation revision required"); })(),
    path: source.path, symbolId: source.symbolId, startLine: source.startLine, endLine: source.endLine, target: source.target };
  annotationPath(source.path);
  if ((source.startLine === undefined) !== (source.endLine === undefined)) throw new Error("Annotation lines require both endpoints");
  return { scope: { spool, thread: thread ? Array.from(fixed(thread.id!.value, 32)) : null }, source: map(anchorValue(anchor).source) };
}
function annotationEntityValue(ref: EntityRef): MapValue {
  const entity = ref.entity;
  switch (entity.case) {
    case "spool": return mentionValue({ kind: "spool", spoolId: entity.value.id });
    case "thread": {
      if (!entity.value.spool || !entity.value.id) throw new Error("Thread reference requires scope and ID");
      return mentionValue({ kind: "thread", spoolId: entity.value.spool.id, id: entity.value.id.value });
    }
    case "revision": {
      const r = entity.value; if (!r.spool) throw new Error("Revision reference requires spool");
      if (r.revision.case === "state") return mentionValue({ kind: "state", spoolId: r.spool.id, id: r.revision.value.value });
      if (r.revision.case === "gitCommitOid") return mentionValue({ kind: "git_commit", spoolId: r.spool.id, oid: r.revision.value });
      throw new Error("Exact entity revision required");
    }
    case "device":
      if (entity.value.kind !== 2) throw new Error("Entity must name a device endpoint");
      return mentionValue({ kind: "device", key: entity.value.publicKey });
    case "checkout": {
      const r = entity.value; if (!r.spool || !r.device || r.device.kind !== 2) throw new Error("Checkout requires spool and device");
      return mentionValue({ kind: "checkout", spoolId: r.spool.id, device: r.device.publicKey, id: r.id });
    }
    case undefined: case "bookmark": throw new Error("Unsupported annotation entity reference");
    default: {
      const kind = entity.case.replace(/[A-Z]/g, c => "_" + c.toLowerCase());
      if (!RECORD_KINDS.has(kind)) throw new Error("Unsupported annotation record reference");
      return mentionValue({ kind: "record", recordKind: kind, spoolId: entity.value.spool?.id, id: entity.value.id });
    }
  }
}
function annotationScalarValue(value: AnnotationValue): MapValue {
  const field = value.value;
  switch (field.case) {
    case "text": return { kind: "text", value: field.value };
    case "boolean": return { kind: "boolean", value: field.value };
    case "integer": return { kind: "integer", value: field.value };
    case "decimal": return { kind: "decimal", value: { coefficient: field.value.coefficient, scale: field.value.scale } };
    default: throw new Error("Annotation property requires a typed value");
  }
}
function annotationTagsValue(tags: readonly AnnotationTag[]): Value[] {
  const values = tags.map(({ tag }): Value => {
    switch (tag.case) {
      case "text": return { kind: "text", text: tag.value };
      case "symbol": return { kind: "symbol", name: tag.value.name, target: tag.value.target ? annotationSourceValue(tag.value.target) : null };
      case "source": return { kind: "source", target: annotationSourceValue(tag.value) };
      case "entity": return { kind: "entity", target: annotationEntityValue(tag.value) };
      case "property": {
        if (!tag.value.value) throw new Error("Annotation property requires a value");
        return { kind: "property", key: tag.value.key, value: annotationScalarValue(tag.value.value) };
      }
      default: throw new Error("Annotation tag requires a known variant");
    }
  });
  validateAnnotationTags(values);
  return values;
}
function validateAnnotationSource(value: Value | undefined) {
  const ref = map(value); keys(ref, ["scope", "source"]);
  const scope = map(ref.scope); keys(scope, ["spool", "thread"]);
  uuidString(scope.spool); if (scope.thread !== null) byteArray(scope.thread, 32);
  validateAnchor({ kind: "source", source: ref.source! });
  const source = map(ref.source); annotationPath(string(source.path));
  if ((source.start_line === null) !== (source.end_line === null)) throw new Error("Annotation lines require both endpoints");
}
function annotationInteger(value: Value | undefined): bigint {
  if (typeof value !== "bigint" && (typeof value !== "number" || !Number.isSafeInteger(value))) throw new Error("Annotation integer must be exact");
  return timestamp(BigInt(value));
}
function validateAnnotationTags(values: Value[]) {
  if (values.length > 128) throw new Error("Too many annotation tags");
  const propertyKeys = new Set<string>();
  for (const item of values) {
    const tag = map(item);
    switch (tag.kind) {
      case "text": keys(tag, ["kind", "text"]); text(string(tag.text), 512, true); break;
      case "symbol":
        keys(tag, ["kind", "name", "target"]); text(string(tag.name), 512, true);
        if (tag.target !== null) validateAnnotationSource(tag.target);
        break;
      case "source": keys(tag, ["kind", "target"]); validateAnnotationSource(tag.target); break;
      case "entity": keys(tag, ["kind", "target"]); validateMention(tag.target!); break;
      case "property": {
        keys(tag, ["kind", "key", "value"]);
        const key = string(tag.key);
        if (!/^[A-Za-z0-9_.\/-]{1,128}$/.test(key) || propertyKeys.has(key)) throw new Error("Invalid or duplicate annotation property key");
        propertyKeys.add(key);
        const value = map(tag.value); keys(value, ["kind", "value"]);
        switch (value.kind) {
          case "text": text(string(value.value), 512, false, true); break;
          case "boolean": if (typeof value.value !== "boolean") throw new Error("Expected annotation boolean"); break;
          case "integer": annotationInteger(value.value); break;
          case "decimal": {
            const decimal = map(value.value); keys(decimal, ["coefficient", "scale"]);
            const coefficient = annotationInteger(decimal.coefficient), scale = decimal.scale;
            if (typeof scale !== "number" || !Number.isInteger(scale) || scale < 0 || scale > 9 || (scale > 0 && coefficient % 10n === 0n)) throw new Error("Annotation decimal must be normalized with scale at most nine");
            break;
          }
          default: throw new Error("Unknown annotation property value type");
        }
        break;
      }
      default: throw new Error("Unknown annotation tag type");
    }
  }
}

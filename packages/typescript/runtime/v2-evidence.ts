import { create, toBinary } from "@bufbuild/protobuf";
import { blake3 } from "@noble/hashes/blake3.js";
import { SignedRecordSchema, Coverage, type SignedRecord } from "./common_pb.js";
import { EvidenceRecordSchema, AcknowledgeCheckRequestSchema, CheckEvidenceSummary_Outcome, type EvidenceRecord, type AcknowledgeCheckRequest } from "./activity_pb.js";
import type { ThreadControlAuthor } from "./thread-control.js";
import { encode, decode, equal, type Value } from "./_collaboration-msgpack.js";

const EVIDENCE = "heddle-check-evidence-v2", ACK = "heddle-check-acknowledgement-v1";
const utf8 = new TextEncoder();
type MapValue = { [key: string]: Value };
export interface CheckResult {
  id: string;
  spoolId: string;
  /** Original audience scope; matching source in another Thread is no grant. */
  threadId: Uint8Array;
  revision: Uint8Array;
  check: string;
  outcome: CheckEvidenceSummary_Outcome;
  detail: string;
  artifacts: string[];
  /** Exact own prior results to replace. Concurrent results remain independent. */
  supersedes: string[];
  completedAtMs: bigint;
}

/** Prepare once and retain the complete signed request across retries. Neither
 * signing nor projection establishes the receiver's current authority decision. */
export async function signCheckEvidence(input: CheckResult, author: ThreadControlAuthor): Promise<EvidenceRecord> {
  input = structuredClone(input);
  const canonical = encode(evidenceValue(input, authorValue(author)));
  return projectCheckEvidence(await signed(EVIDENCE, canonical, author));
}

/** Signature-verified typed projection. Reported success is still a producer's
 * claim; the host independently admits authority and evaluates current policy. */
export async function projectCheckEvidence(record: SignedRecord): Promise<EvidenceRecord> {
  record = structuredClone(record);
  if (record.format !== EVIDENCE || !record.canonicalRecord.length || record.canonicalRecord.length > 128 * 1024) throw new Error("Invalid check evidence framing");
  const raw = map(decode(record.canonicalRecord)), author = map(raw.author), actor = map(author.actor);
  const outcomes: Record<string, CheckEvidenceSummary_Outcome> = { passed: CheckEvidenceSummary_Outcome.PASSED, failed: CheckEvidenceSummary_Outcome.FAILED, error: CheckEvidenceSummary_Outcome.ERROR, skipped: CheckEvidenceSummary_Outcome.SKIPPED };
  const input: CheckResult = {
    id: uuidString(raw.id), spoolId: uuidString(raw.spool), threadId: byteArray(raw.thread, 32), revision: byteArray(raw.revision, 32),
    check: string(raw.check), outcome: outcomes[string(raw.outcome)] ?? CheckEvidenceSummary_Outcome.UNSPECIFIED,
    detail: string(raw.detail), artifacts: list(raw.artifacts).map(uuidString), supersedes: list(raw.supersedes).map(uuidString), completedAtMs: integer(raw.completed_at_ms),
  };
  const publisher = byteArray(author.publisher, 32), envelope = byteArray(author.authority_envelope);
  const canonicalAuthor = authorValue({ actor: { principalId: uuidString(actor.principal_id), ...(actor.agent_id === null ? {} : { agentId: string(actor.agent_id) }) }, authorityEnvelope: envelope,
    signer: { publicKey: publisher, sign: async () => { throw new Error("Projection cannot sign"); } } });
  // Re-encoding the defined shape rejects unknown/reordered/noncanonical fields,
  // including a mismatched authority digest and unsupported record version.
  if (!equal(encode(evidenceValue(input, canonicalAuthor)), record.canonicalRecord)) throw new Error("Noncanonical signed evidence");
  await verify(record, publisher);
  const spool = { id: input.spoolId }, ref = (id: string) => ({ spool, id });
  return create(EvidenceRecordSchema, { ref: ref(input.id), thread: { spool, id: { value: input.threadId } }, version: signedCheckVersion(record),
    revision: { spool, revision: { case: "state", value: { value: input.revision } } }, check: input.check, evidence: record, coverage: Coverage.COMPLETE,
    summary: { outcome: input.outcome, detail: input.detail, author: { id: uuidString(actor.principal_id) }, agentId: actor.agent_id === null ? "" : string(actor.agent_id),
      artifacts: input.artifacts.map(ref), supersedes: input.supersedes.map(ref), completedAt: { seconds: input.completedAtMs / 1000n, nanos: Number(input.completedAtMs % 1000n) * 1_000_000 } } });
}

/** Acknowledge the verified original under the currently observed exact policy.
 * Progress never changes a failed outcome or supplies a landing approval. */
export async function prepareCheckAcknowledgement(evidence: EvidenceRecord, policyVersion: Uint8Array, clientOperationId: string, occurredAtMs: bigint, author: ThreadControlAuthor): Promise<AcknowledgeCheckRequest> {
  evidence = structuredClone(evidence);
  if (!evidence.evidence) throw new Error("Original signed evidence required");
  const verified = await projectCheckEvidence(evidence.evidence);
  if (!equal(toBinary(EvidenceRecordSchema, verified), toBinary(EvidenceRecordSchema, evidence))) throw new Error("Evidence presentation differs from original");
  const policy = fixed(policyVersion, 32), at = timestamp(occurredAtMs);
  const original = verified.evidence!, revision = verified.revision!;
  if (revision.revision.case !== "state") throw new Error("Native evidence revision required");
  const canonical = encode({ version: 1, spool: uuid(verified.ref!.spool!.id), evidence: uuid(verified.ref!.id),
    evidence_digest: Array.from(typedHash(EVIDENCE, original.canonicalRecord)), revision: Array.from(revision.revision.value.value), policy_version: Array.from(policy),
    author: authorValue(author), client_operation_id: uuid(clientOperationId), occurred_at_ms: at });
  const acknowledgement = await signed(ACK, canonical, author);
  return create(AcknowledgeCheckRequestSchema, { clientOperationId, evidence: verified.ref, revision, policyVersion: policy, acknowledgement });
}
export function signedCheckVersion(record: SignedRecord): Uint8Array {
  return typedHash("heddle-signed-check-receipt-v1", toBinary(SignedRecordSchema, record));
}
function evidenceValue(input: CheckResult, author: MapValue): MapValue {
  const outcomes: Partial<Record<CheckEvidenceSummary_Outcome, string>> = { [CheckEvidenceSummary_Outcome.PASSED]: "passed", [CheckEvidenceSummary_Outcome.FAILED]: "failed", [CheckEvidenceSummary_Outcome.ERROR]: "error", [CheckEvidenceSummary_Outcome.SKIPPED]: "skipped" };
  const outcome = outcomes[input.outcome];
  if (!outcome) throw new Error("Explicit check outcome required");
  text(input.check, 512); text(input.detail, 32768, true);
  const artifacts = ids(input.artifacts, 64), supersedes = ids(input.supersedes, 32);
  if (input.supersedes.includes(input.id)) throw new Error("Check cannot supersede itself");
  return { version: 2, id: uuid(input.id), spool: uuid(input.spoolId), thread: Array.from(fixed(input.threadId, 32)), revision: Array.from(fixed(input.revision, 32)), check: input.check, outcome, detail: input.detail,
    artifacts, supersedes, author, completed_at_ms: timestamp(input.completedAtMs) };
}
function authorValue(author: ThreadControlAuthor): MapValue {
  const envelope = Uint8Array.from(author.authorityEnvelope), publisher = fixed(author.signer.publicKey, 32);
  if (!envelope.length || envelope.length > 65536 || publisher.every(byte => byte === 0)) throw new Error("Invalid original check authority");
  if (author.actor.agentId !== undefined) text(author.actor.agentId, 256);
  return { actor: { principal_id: uuid(author.actor.principalId), agent_id: author.actor.agentId ?? null }, publisher: Array.from(publisher),
    authority_digest: Array.from(typedHash("heddle-thread-control-authority-v1", envelope)), authority_envelope: Array.from(envelope) };
}
async function signed(format: string, canonicalRecord: Uint8Array, author: ThreadControlAuthor): Promise<SignedRecord> {
  if (!canonicalRecord.length || canonicalRecord.length > 128 * 1024) throw new Error("Check exceeds record bound");
  const publisher = fixed(author.signer.publicKey, 32), bytes = concat(utf8.encode(format), Uint8Array.of(0), canonicalRecord);
  const signature = fixed(await author.signer.sign(bytes.slice()), 64);
  const record = create(SignedRecordSchema, { format, canonicalRecord, signatures: [{ publicKey: publisher, signature }] });
  await verify(record, publisher); return record;
}
async function verify(record: SignedRecord, publisher: Uint8Array): Promise<void> {
  const signature = record.signatures[0];
  if (record.signatures.length !== 1 || !signature || !equal(signature.publicKey, publisher)) throw new Error("Exactly one original publisher required");
  const key = await crypto.subtle.importKey("raw", fixed(publisher, 32), "Ed25519", false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", key, fixed(signature.signature, 64), concat(utf8.encode(record.format), Uint8Array.of(0), record.canonicalRecord))) throw new Error("Invalid original check signature");
}
function map(value: Value | undefined): MapValue { if (!value || typeof value !== "object" || Array.isArray(value) || ArrayBuffer.isView(value)) throw new Error("Expected check record"); return value; }
function list(value: Value | undefined): Value[] { if (!Array.isArray(value)) throw new Error("Expected check array"); return value; }
function string(value: Value | undefined): string { if (typeof value !== "string") throw new Error("Expected check text"); return value; }
function integer(value: Value | undefined): bigint { if (typeof value !== "bigint" && !(typeof value === "number" && Number.isSafeInteger(value))) throw new Error("Expected exact check timestamp"); return BigInt(value); }
function byteArray(value: Value | undefined, size?: number): Uint8Array { const values = list(value); if (values.some(byte => typeof byte !== "number" || !Number.isInteger(byte) || byte < 0 || byte > 255)) throw new Error("Invalid check bytes"); const bytes = Uint8Array.from(values as number[]); return size === undefined ? bytes : fixed(bytes, size); }
function fixed(value: Uint8Array, size: number): Uint8Array { if (!ArrayBuffer.isView(value) || Object.prototype.toString.call(value) !== "[object Uint8Array]" || value.length !== size) throw new Error(`Expected ${size} bytes`); return Uint8Array.from(value); }
function uuid(value: string): Uint8Array { if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) || value === "00000000-0000-0000-0000-000000000000") throw new Error("Expected canonical non-nil UUID"); return Uint8Array.from(value.replaceAll("-", "").match(/../g)!, byte => parseInt(byte, 16)); }
function uuidString(value: Value | undefined): string { if (!(value instanceof Uint8Array) || value.length !== 16) throw new Error("Invalid check UUID"); const hex = Array.from(value, byte => byte.toString(16).padStart(2, "0")).join(""); const result = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`; uuid(result); return result; }
function ids(values: string[], max: number): Uint8Array[] { if (values.length > max || values.some((value, index) => index > 0 && values[index - 1]! >= value)) throw new Error("Check references must be bounded, sorted and unique"); return values.map(uuid); }
function timestamp(value: bigint): bigint { if (value < 0n || value > 9223372036854775807n) throw new Error("Invalid check timestamp"); return value; }
function text(value: string, max: number, empty = false): void { if ((!empty && !value.trim()) || value.includes("\0") || utf8.encode(value).length > max) throw new Error("Invalid check text"); }
function concat(...parts: Uint8Array[]): Uint8Array { const value = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0)); let offset = 0; for (const part of parts) { value.set(part, offset); offset += part.length; } return value; }
function typedHash(domain: string, bytes: Uint8Array): Uint8Array { const length = new Uint8Array(8); new DataView(length.buffer).setBigUint64(0, BigInt(bytes.length), true); return blake3(concat(utf8.encode(domain), length, Uint8Array.of(0), bytes)); }

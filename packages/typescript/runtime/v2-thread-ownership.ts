import { create } from "@bufbuild/protobuf";
import { blake3 } from "@noble/hashes/blake3.js";
import { SignedRecordSchema, type SignedRecord } from "./common_pb.js";
import type { ThreadOverview } from "./thread_pb.js";
import type { ThreadControlAuthor } from "./thread-control.js";
import { encode } from "./_collaboration-msgpack.js";

const FORMAT = "heddle-thread-ownership-claim-v1";
const AUTHORITY = "heddle-thread-control-authority-v1";
const utf8 = new TextEncoder();

/** Explicit account consent for one local Thread and exact source cutoff.
 * The owned-device ClaimThreadOwnership command adds its retained local-owner
 * signature after independently admitting the account authority. Enrollment
 * and uploading do not call this helper or change Thread ownership. */
export async function signThreadOwnershipAcceptance(
  overview: ThreadOverview, author: ThreadControlAuthor,
): Promise<SignedRecord> {
  overview = structuredClone(overview);
  const actor = structuredClone(author.actor);
  const envelope = Uint8Array.from(author.authorityEnvelope);
  const publisher = fixed(author.signer.publicKey, 32);
  const thread = fixed(overview.ref?.id?.value, 32);
  if (overview.ownership?.owner.case !== "localKey") throw new Error("Ownership claim requires an observed local-key owner");
  const local = fixed(overview.ownership.owner.value, 32);
  if (local.every(byte => byte === 0) || publisher.every(byte => byte === 0)) throw new Error("Ownership keys must be nonzero");
  if (!overview.sourceFrontier?.complete) throw new Error("Ownership claim requires a complete source frontier");
  const frontier = overview.sourceFrontier.operationIds.map(id => fixed(id, 32));
  if (frontier.length > 128) throw new Error("Ownership source frontier exceeds bounds");
  for (let index = 1; index < frontier.length; index++) if (compare(frontier[index - 1]!, frontier[index]!) >= 0) throw new Error("Ownership source frontier must be sorted and unique");
  if (envelope.length === 0 || envelope.length > 65536) throw new Error("Ownership authority envelope exceeds bounds");
  if (actor.agentId !== undefined && (!actor.agentId.length || utf8.encode(actor.agentId).length > 256 || /\p{Cc}/u.test(actor.agentId))) throw new Error("Invalid accepting agent");
  const canonicalRecord = encode({ version: 1, thread: Array.from(thread), prior_local_key: Array.from(local),
    accepting_publisher: Array.from(publisher), acceptance: { kind: "account", spool: uuid(overview.ref?.spool?.id ?? ""),
      actor: { principal_id: uuid(actor.principalId), agent_id: actor.agentId ?? null },
      authority_digest: Array.from(typedHash(AUTHORITY, envelope)), authority: envelope },
    source_frontier: frontier.map(id => Array.from(id)) });
  const signingBytes = concat(utf8.encode(FORMAT), Uint8Array.of(0), canonicalRecord);
  const signature = fixed(await author.signer.sign(Uint8Array.from(signingBytes)), 64);
  const key = await crypto.subtle.importKey("raw", publisher, { name: "Ed25519" }, false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", key, signature, signingBytes)) throw new Error("Ownership acceptor does not match signer");
  return create(SignedRecordSchema, { format: FORMAT, canonicalRecord, signatures: [{ publicKey: publisher, signature }] });
}

function uuid(value: string): Uint8Array {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) || value === "00000000-0000-0000-0000-000000000000") throw new Error("Expected canonical non-nil UUID");
  return Uint8Array.from(value.replaceAll("-", "").match(/../g)!, byte => Number.parseInt(byte, 16));
}
function fixed(value: Uint8Array | undefined, size: number): Uint8Array {
  if (!ArrayBuffer.isView(value) || Object.prototype.toString.call(value) !== "[object Uint8Array]" || value.length !== size) throw new Error(`Expected ${size} bytes`);
  return Uint8Array.from(value);
}
function compare(left: Uint8Array, right: Uint8Array): number { for (let i = 0; i < left.length; i++) if (left[i] !== right[i]) return left[i]! - right[i]!; return 0; }
function concat(...parts: Uint8Array[]): Uint8Array { const value = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0)); let offset = 0; for (const part of parts) { value.set(part, offset); offset += part.length; } return value; }
function typedHash(domain: string, bytes: Uint8Array): Uint8Array { const length = new Uint8Array(8); new DataView(length.buffer).setBigUint64(0, BigInt(bytes.length), true); return blake3(concat(utf8.encode(domain), length, Uint8Array.of(0), bytes)); }

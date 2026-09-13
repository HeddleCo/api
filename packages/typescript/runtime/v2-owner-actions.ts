import { create } from "@bufbuild/protobuf";
import { SignedRecordSchema, type RecordRef, type SignedRecord } from "./common_pb.js";

const utf8 = new TextEncoder();
export const OWNER_TRANSITION_POSSESSION = "heddle.owner-transition-possession.v2";
export const OWNER_RECOVERY_POSSESSION = "heddle.owner-recovery-possession.v2";

function joined(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
function number(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) throw new Error("Invalid owner action length");
  const out = new Uint8Array(4); new DataView(out.buffer).setUint32(0, value); return out;
}
function sized(value: Uint8Array): Uint8Array { return joined(number(value.length), value); }

/** Rust identity_management::recovery_action version 1, including the
 * unscoped transition/recovery reference. Protobuf is only its envelope. */
export function canonicalOwnerAction(accountId: string, clientOperationId: string, reference: RecordRef,
  expectedVersion: Uint8Array, proposedKey: Uint8Array): Uint8Array {
  if (!reference?.id || reference.id.length > 256 || reference.spool || proposedKey.length !== 32
    || !accountId || !clientOperationId || expectedVersion.length === 0)
    throw new Error("Invalid owner action binding");
  return joined(number(1), sized(utf8.encode(accountId)), sized(utf8.encode(clientOperationId)),
    sized(utf8.encode(reference.id)), sized(expectedVersion), sized(proposedKey));
}

export interface OwnerActionSigner {
  publicKey: Uint8Array;
  sign(bytes: Uint8Array): Promise<Uint8Array>;
}

/** Sign the exact CAS and proposed key after the veto window. The signer must
 * be the proposed owner key for rotation/recovery, or current owner for policy. */
export async function signOwnerActionPossession(format: typeof OWNER_TRANSITION_POSSESSION | typeof OWNER_RECOVERY_POSSESSION,
  accountId: string, clientOperationId: string, reference: RecordRef, expectedVersion: Uint8Array,
  proposedKey: Uint8Array, signer: OwnerActionSigner): Promise<SignedRecord> {
  const canonicalRecord = canonicalOwnerAction(accountId, clientOperationId, reference,
    expectedVersion.slice(), proposedKey.slice());
  const publicKey = signer.publicKey.slice();
  if (publicKey.length !== 32 || !publicKey.every((byte, index) => byte === proposedKey[index]))
    throw new Error("Owner action signer must be the proposed key");
  const signingBytes = joined(utf8.encode(format), Uint8Array.of(0), canonicalRecord);
  const signature = (await signer.sign(signingBytes.slice())).slice();
  if (signature.length !== 64) throw new Error("Invalid owner action signature length");
  const verifier = await crypto.subtle.importKey("raw", publicKey as BufferSource, "Ed25519", false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", verifier, signature as BufferSource, signingBytes as BufferSource))
    throw new Error("Owner action signature does not match the proposed key");
  return create(SignedRecordSchema, { format, canonicalRecord, signatures: [{ publicKey, signature }] });
}

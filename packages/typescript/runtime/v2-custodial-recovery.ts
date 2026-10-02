// Intent encoding and preliminary gates only. Hosts additionally authenticate
// the email secret/current state and use the shared portable capability verifier.
import { toBinary } from "@bufbuild/protobuf";
import { sha256 } from "@noble/hashes/sha2.js";
import type { CustodialEmailBinding, CustodialEmailProof, RecoveryAttempt,
  CustodialRecoverProposal, SubmitCustodialRecoverRequest } from "./identity_pb.js";
import { RecoveryAttemptSchema } from "./identity_pb.js";
import { OwnerKeyTransitionSchema, AuthorizationSignatureSchema,
  type AuthorizationSignature, type AuthorizationVerificationKey, type OwnerKeyTransition } from "./owner_records_pb.js";

export const CUSTODIAL_VETO = "heddle.custodial-recovery-veto.v1";
const utf8 = new TextEncoder();
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
function joined(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0; for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
function u32(value: number): Uint8Array {
  const out = new Uint8Array(4); new DataView(out.buffer).setUint32(0, value); return out;
}
function i64(value: bigint): Uint8Array {
  if (value < 0n || value > 0x7fffffffffffffffn) throw new Error("Binding");
  const out = new Uint8Array(8); new DataView(out.buffer).setBigInt64(0, value); return out;
}
export function canonicalCustodialEmailBinding(binding: CustodialEmailBinding): Uint8Array {
  if (binding.formatVersion !== 1 || binding.accountUuid.length !== 16
    || binding.attemptUuid.length !== 16 || binding.proposedRootPublicKey.length !== 32
    || binding.challenge.length !== 32 || binding.expiresAtUnixSeconds <= 0n) throw new Error("Binding");
  return joined(u32(1), binding.accountUuid, binding.attemptUuid,
    binding.proposedRootPublicKey, binding.challenge, i64(binding.expiresAtUnixSeconds));
}
export function validateCustodialEmailProof(proof: CustodialEmailProof,
  expected: CustodialEmailBinding, now: bigint): void {
  if (!proof.binding || !equal(canonicalCustodialEmailBinding(proof.binding),
    canonicalCustodialEmailBinding(expected)) || proof.emailSecret.length !== 32 || now < 0n)
    throw new Error("Binding");
  if (now >= expected.expiresAtUnixSeconds) throw new Error("Expired");
}
export function custodialEmailSecretHash(proof: CustodialEmailProof): Uint8Array {
  if (!proof.binding || proof.emailSecret.length !== 32) throw new Error("Binding");
  return sha256(joined(utf8.encode("heddle-custodial-email-secret-v1"),
    canonicalCustodialEmailBinding(proof.binding), proof.emailSecret));
}
function keyId(key: AuthorizationVerificationKey): Uint8Array {
  return sha256(joined(utf8.encode("heddle-key-v1"), u32(key.algorithm), key.publicKey));
}
function signatureShape(proof: AuthorizationSignature | undefined, key: AuthorizationVerificationKey): boolean {
  return !!proof && equal(proof.signerKeyId, keyId(key)) && proof.signature.length === 64;
}
function signaturesEqual(a: AuthorizationSignature[], b: AuthorizationSignature[]): boolean {
  return a.length === b.length && a.every((v, i) =>
    equal(toBinary(AuthorizationSignatureSchema, v), toBinary(AuthorizationSignatureSchema, b[i])));
}
export function canonicalCustodialRecover(body: OwnerKeyTransition): Uint8Array {
  const next = body.nextAuthorityKey, policy = body.nextRecoveryPolicy, guardian = policy?.guardians[0], key = guardian?.key;
  if (!policy || policy.threshold !== 1 || policy.guardians.length !== 1 || !key) throw new Error("FreshKey");
  if (!next || body.formatVersion !== 1 || body.ownerId.length !== 32 || body.previousStateHash.length !== 32
    || body.sequence <= 0n || body.kind !== 2 || body.nonce.length !== 32 || body.validFromUnixSeconds <= 0n
    || body.previousKeyValidUntilUnixSeconds !== 0n || next.algorithm !== 1 || next.publicKey.length !== 32
    || guardian?.kind !== 3 || key.algorithm !== 1 || key.publicKey.length !== 32
    || (policy.windowSecs ?? 604800n) <= 0n) throw new Error("Proposal");
  const u64 = (v: bigint): Uint8Array => {
    if (v < 0n || v > 0xffffffffffffffffn) throw new Error("Proposal");
    const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, v); return out;
  };
  const counted = (v: Uint8Array) => joined(u32(v.length), v);
  return joined(u32(1), counted(body.ownerId), counted(body.previousStateHash), u64(body.sequence), u32(body.kind),
    u32(next.algorithm), counted(next.publicKey), u32(1), u32(1), u32(guardian.kind), u32(key.algorithm),
    counted(key.publicKey), u64(policy.windowSecs ?? 604800n), i64(body.validFromUnixSeconds), i64(0n), counted(body.nonce));
}
export function custodialProposalSigningDigest(proposal: CustodialRecoverProposal): Uint8Array {
  if (!proposal.recover?.transition) throw new Error("Proposal");
  const canonical = canonicalCustodialRecover(proposal.recover.transition);
  const digest = sha256(joined(utf8.encode("heddle-owner-key-transition-v1"), canonical));
  if (!equal(proposal.canonicalTransition, canonical) || !equal(proposal.signingDigest, digest)) throw new Error("Proposal");
  return digest;
}
/** This is not signature verification or authoritative transaction admission. */
export function validateCustodialSubmission(attempt: RecoveryAttempt, proposal: CustodialRecoverProposal,
  request: SubmitCustodialRecoverRequest, oldGuardian: AuthorizationVerificationKey, now: bigint): void {
  const details = attempt.custodial;
  if (!details) throw new Error("Binding");
  if (attempt.vetoed || attempt.completed || details.state !== 4) throw new Error("State");
  if (!details.binding) throw new Error("Binding");
  canonicalCustodialEmailBinding(details.binding);
  if (!attempt.ref || attempt.ref.spool || !attempt.ref.id || request.recovery?.spool
    || request.recovery?.id !== attempt.ref.id || now < 0n) throw new Error("Binding");
  if (attempt.version.length !== 32 || !equal(request.expectedVersion, attempt.version)) throw new Error("Version");
  const seconds = (time: { seconds: bigint; nanos: number } | undefined): bigint => {
    if (!time || time.nanos !== 0 || time.seconds <= 0n || time.seconds > 0x7fffffffffffffffn)
      throw new Error("Binding");
    return time.seconds;
  };
  const start = seconds(details.startedAt), eligible = seconds(attempt.eligibleAt), expiry = seconds(details.expiresAt);
  if (details.effectiveWindowSecs <= 0n || start + details.effectiveWindowSecs !== eligible
    || eligible + 86400n !== expiry) throw new Error("Binding");
  if (now < eligible) throw new Error("Early");
  if (now >= expiry) throw new Error("Expired");
  const prepared = proposal.recover, signed = request.recover, body = signed?.transition, nextRoot = body?.nextAuthorityKey;
  if (!prepared || !signed || !body || !nextRoot) throw new Error("Proposal");
  custodialProposalSigningDigest(proposal);
  const policy = body.nextRecoveryPolicy, guardian = policy?.guardians[0], fresh = guardian?.key;
  if (!policy || policy.threshold !== 1 || policy.guardians.length !== 1 || !fresh
    || guardian?.kind !== 3 || fresh.algorithm !== 1 || fresh.publicKey.length !== 32
    || equal(keyId(fresh), keyId(oldGuardian)) || equal(keyId(fresh), keyId(nextRoot))
    || signed.nextRecoveryKeyProofs.length !== 1 || !signatureShape(signed.nextRecoveryKeyProofs[0], fresh))
    throw new Error("FreshKey");
  if (body.formatVersion !== 1 || body.kind !== 2 || body.previousStateHash.length !== 32
    || !equal(body.previousStateHash, details.ownerStateHash) || body.validFromUnixSeconds !== eligible
    || body.previousKeyValidUntilUnixSeconds !== 0n || nextRoot.algorithm !== 1
    || !equal(nextRoot.publicKey, details.binding.proposedRootPublicKey)
    || (policy.windowSecs ?? 604800n) !== details.effectiveWindowSecs
    || !proposal.recovery || !equal(toBinary(RecoveryAttemptSchema, proposal.recovery), toBinary(RecoveryAttemptSchema, attempt))
    || !proposal.ownership || !equal(proposal.ownership.version, details.ownerStateHash)
    || prepared.nextAuthorityKeyProof || !prepared.transition
    || !equal(toBinary(OwnerKeyTransitionSchema, prepared.transition), toBinary(OwnerKeyTransitionSchema, body))
    || !signaturesEqual(signed.authorizations, prepared.authorizations)
    || !signaturesEqual(signed.nextRecoveryKeyProofs, prepared.nextRecoveryKeyProofs)
    || signed.authorizations.length !== 1 || !signatureShape(signed.authorizations[0], oldGuardian)
    || !signatureShape(signed.nextAuthorityKeyProof, nextRoot)) throw new Error("Proposal");
}

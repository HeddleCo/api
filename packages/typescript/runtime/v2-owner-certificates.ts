import { clone, create } from "@bufbuild/protobuf";
import { sha256 } from "@noble/hashes/sha2.js";
import { AuthorizationKeyAlgorithm, MintRootAttachmentSchema, SignedMintRootAttachmentSchema,
  type AuthorizationVerificationKey, type MintRootAttachment, type SignedMintRootAttachment } from "./owner_records_pb.js";

const utf8 = new TextEncoder();
const DOMAIN = utf8.encode("heddle-mint-root-attachment-v1");
function bytes(value: Uint8Array, length: number, name: string) {
  if (value.length !== length) throw new Error(`Invalid ${name} length`);
}
function equal(left: Uint8Array, right: Uint8Array) { return left.length === right.length && left.every((byte, index) => byte === right[index]); }
function join(...values: Uint8Array[]) { const result = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0)); let offset = 0; for (const value of values) { result.set(value, offset); offset += value.length; } return result; }
function u32(value: number) { const result = new Uint8Array(4); new DataView(result.buffer).setUint32(0, value); return result; }
function integer(value: bigint, signed: boolean) {
  if (value < (signed ? -(1n << 63n) : 0n) || value >= (signed ? 1n << 63n : 1n << 64n)) throw new Error("Invalid certificate integer range");
  const result = new Uint8Array(8); const view = new DataView(result.buffer);
  if (signed) view.setBigInt64(0, value); else view.setBigUint64(0, value); return result;
}
function sized(value: Uint8Array) { return join(u32(value.length), value); }
function key(value: AuthorizationVerificationKey | undefined): AuthorizationVerificationKey {
  if (!value || value.algorithm !== AuthorizationKeyAlgorithm.ED25519) throw new Error("Certificate requires an Ed25519 key");
  bytes(value.publicKey, 32, "public key"); return value;
}
function encodedKey(value: AuthorizationVerificationKey | undefined) { const valid = key(value); return join(u32(valid.algorithm), sized(valid.publicKey)); }
function keyId(value: AuthorizationVerificationKey) { return sha256(join(utf8.encode("heddle-key-v1"), u32(value.algorithm), value.publicKey)); }

/** Exact fixed-order Rust canonical encoding; protobuf is only the container. */
export function canonicalMintRootAttachment(value: MintRootAttachment): Uint8Array {
  if (value.formatVersion !== 1 || value.notBeforeUnixSeconds < 0n || value.expiresAtUnixSeconds <= value.notBeforeUnixSeconds) throw new Error("Invalid mint-root certificate version or interval");
  bytes(value.accountUuid, 16, "account UUID");
  if (!value.accountUuid.some(Boolean)) throw new Error("Certificate account UUID must be non-nil");
  bytes(value.ownerStateHash, 32, "owner state hash"); bytes(value.nonce, 32, "nonce");
  return join(u32(value.formatVersion), sized(value.accountUuid), sized(value.ownerStateHash), integer(value.ownerSequence, false),
    encodedKey(value.ownerKey), encodedKey(value.mintRootKey), integer(value.notBeforeUnixSeconds, true), integer(value.expiresAtUnixSeconds, true), sized(value.nonce));
}
export function mintRootAttachmentSigningDigest(value: MintRootAttachment): Uint8Array { return sha256(join(DOMAIN, canonicalMintRootAttachment(value))); }
export interface OwnerCertificateSigner {
  publicKey: Uint8Array;
  /** Ed25519 signature over the supplied SHA-256 digest, using the owner key. */
  sign(digest: Uint8Array): Promise<Uint8Array>;
}
/** The caller supplies independently verified current owner state. This
 * association confers no action permissions and is never a Biscuit substitute. */
export interface MintRootAttachmentExpectation {
  accountUuid: Uint8Array; ownerStateHash: Uint8Array; ownerSequence: bigint;
  ownerPublicKey: Uint8Array; mintRootPublicKey: Uint8Array; nowUnixSeconds: bigint;
}
export async function verifyMintRootAttachment(signed: SignedMintRootAttachment, expected: MintRootAttachmentExpectation): Promise<void> {
  const value = signed.attachment;
  if (!value) throw new Error("Missing mint-root certificate");
  const digest = mintRootAttachmentSigningDigest(value);
  if (!equal(value.accountUuid, expected.accountUuid) || !equal(value.ownerStateHash, expected.ownerStateHash)
    || value.ownerSequence !== expected.ownerSequence || !equal(key(value.ownerKey).publicKey, expected.ownerPublicKey)
    || !equal(key(value.mintRootKey).publicKey, expected.mintRootPublicKey)) throw new Error("Certificate differs from independently verified current owner or mint root");
  if (expected.nowUnixSeconds < value.notBeforeUnixSeconds || expected.nowUnixSeconds >= value.expiresAtUnixSeconds) throw new Error("Certificate is not currently valid");
  const signature = signed.ownerSignature;
  if (!signature || !equal(signature.signerKeyId, keyId(key(value.ownerKey)))) throw new Error("Certificate owner signer identity differs");
  bytes(signature.signature, 64, "owner signature");
  const publicKey = await crypto.subtle.importKey("raw", expected.ownerPublicKey as BufferSource, "Ed25519", false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", publicKey, signature.signature as BufferSource, digest as BufferSource)) throw new Error("Invalid certificate owner signature");
}
export async function signMintRootAttachment(value: MintRootAttachment, signer: OwnerCertificateSigner): Promise<SignedMintRootAttachment> {
  const snapshot = clone(MintRootAttachmentSchema, value);
  const owner = key(snapshot.ownerKey);
  if (!equal(owner.publicKey, signer.publicKey)) throw new Error("Certificate signer is not the owner authority");
  const digest = mintRootAttachmentSigningDigest(snapshot);
  const signed = create(SignedMintRootAttachmentSchema, { attachment: snapshot, ownerSignature: { signerKeyId: keyId(owner), signature: await signer.sign(digest) } });
  await verifyMintRootAttachment(signed, { accountUuid: snapshot.accountUuid, ownerStateHash: snapshot.ownerStateHash,
    ownerSequence: snapshot.ownerSequence, ownerPublicKey: owner.publicKey, mintRootPublicKey: key(snapshot.mintRootKey).publicKey, nowUnixSeconds: snapshot.notBeforeUnixSeconds });
  return signed;
}

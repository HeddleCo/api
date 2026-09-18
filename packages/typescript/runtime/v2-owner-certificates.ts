import { clone, create } from "@bufbuild/protobuf";
import { sha256 } from "@noble/hashes/sha2.js";
import { AuthorizationKeyAlgorithm, MintRootAttachmentSchema, SignedMintRootAttachmentSchema,
  PasskeyAuthoritySchema, SignedPasskeyAuthoritySchema,
  type AuthorizationVerificationKey, type MintRootAttachment, type SignedMintRootAttachment,
  type PasskeyAuthority, type SignedPasskeyAuthority, type PasskeyMintDelegation } from "./owner_records_pb.js";

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
  if (signed.passkeyDelegation) {
    if (signed.ownerSignature) throw new Error("Certificate has ambiguous owner proofs");
    await verifyPasskeyMintDelegation(signed.passkeyDelegation, value, expected);
    return;
  }
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

const PASSKEY_DOMAIN = utf8.encode("heddle-passkey-authority-v1");
/** Fixed-order encoding shared with the native pure verifier. */
export function canonicalPasskeyAuthority(value: PasskeyAuthority): Uint8Array {
  bytes(value.accountUuid, 16, "account UUID");
  bytes(value.ownerStateHash, 32, "owner state hash");
  bytes(value.nonce, 32, "nonce");
  if (value.formatVersion !== 1 || !value.accountUuid.some(Boolean)
    || value.credentialId.length === 0 || value.credentialId.length > 1024
    || ![-7, -8].includes(value.coseAlgorithm) || value.publicKeySpki.length === 0 || value.publicKeySpki.length > 512
    || !Number.isInteger(value.maxSessionTtlSeconds) || value.maxSessionTtlSeconds <= 0 || value.maxSessionTtlSeconds > 43200
    || value.relyingPartyId.length === 0 || value.relyingPartyId.length > 253 || !/^[A-Za-z0-9.-]+$/.test(value.relyingPartyId)
    || value.allowedOrigins.length === 0 || value.allowedOrigins.length > 8
    || value.allowedOrigins.some((origin, index) => !origin || utf8.encode(origin).length > 2048 || /[\s*]/.test(origin)
      || (index > 0 && value.allowedOrigins[index - 1]! >= origin))) throw new Error("Invalid passkey authority fields or bounds");
  return join(u32(value.formatVersion), sized(value.accountUuid), sized(value.ownerStateHash), integer(value.ownerSequence, false),
    encodedKey(value.ownerKey), sized(value.credentialId), u32(value.coseAlgorithm), sized(value.publicKeySpki),
    sized(utf8.encode(value.relyingPartyId)), u32(value.allowedOrigins.length),
    ...value.allowedOrigins.map(origin => sized(utf8.encode(origin))), u32(value.maxSessionTtlSeconds), sized(value.nonce));
}
export function passkeyAuthoritySigningDigest(value: PasskeyAuthority): Uint8Array {
  return sha256(join(PASSKEY_DOMAIN, canonicalPasskeyAuthority(value)));
}
type PasskeyOwnerExpectation = Pick<MintRootAttachmentExpectation, "accountUuid" | "ownerStateHash" | "ownerSequence" | "ownerPublicKey">;

async function importPasskey(value: PasskeyAuthority): Promise<CryptoKey> {
  const algorithm = value.coseAlgorithm === -8 ? "Ed25519" : { name: "ECDSA", namedCurve: "P-256" };
  return crypto.subtle.importKey("spki", value.publicKeySpki as BufferSource, algorithm, false, ["verify"]);
}
/** Validate an owner-certified passkey against independently verified current authority. */
export async function verifyPasskeyAuthority(signed: SignedPasskeyAuthority, expected: PasskeyOwnerExpectation): Promise<void> {
  const value = signed.authority;
  if (!value) throw new Error("Missing passkey authority");
  const digest = passkeyAuthoritySigningDigest(value);
  const owner = key(value.ownerKey);
  if (!equal(value.accountUuid, expected.accountUuid) || !equal(value.ownerStateHash, expected.ownerStateHash)
    || value.ownerSequence !== expected.ownerSequence || !equal(owner.publicKey, expected.ownerPublicKey)) throw new Error("Passkey authority differs from current owner");
  const signature = signed.ownerSignature;
  if (!signature || !equal(signature.signerKeyId, keyId(owner))) throw new Error("Passkey owner signer identity differs");
  bytes(signature.signature, 64, "passkey owner signature");
  const publicKey = await crypto.subtle.importKey("raw", owner.publicKey as BufferSource, "Ed25519", false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", publicKey, signature.signature as BufferSource, digest as BufferSource)) throw new Error("Invalid passkey owner signature");
  await importPasskey(value);
}
/** Sign a passkey certificate while the owner's key is available at registration. */
export async function signPasskeyAuthority(value: PasskeyAuthority, signer: OwnerCertificateSigner): Promise<SignedPasskeyAuthority> {
  const snapshot = clone(PasskeyAuthoritySchema, value);
  const owner = key(snapshot.ownerKey);
  if (!equal(owner.publicKey, signer.publicKey)) throw new Error("Passkey certificate signer is not the owner");
  const signed = create(SignedPasskeyAuthoritySchema, { authority: snapshot,
    ownerSignature: { signerKeyId: keyId(owner), signature: await signer.sign(passkeyAuthoritySigningDigest(snapshot)) } });
  await verifyPasskeyAuthority(signed, { accountUuid: snapshot.accountUuid, ownerStateHash: snapshot.ownerStateHash,
    ownerSequence: snapshot.ownerSequence, ownerPublicKey: owner.publicKey });
  return signed;
}

// WebAuthn ES256 uses DER integers; WebCrypto verification requires fixed-width r||s.
function es256RawSignature(der: Uint8Array): Uint8Array {
  if (der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) throw new Error("Invalid ES256 DER sequence");
  let offset = 2;
  const integer = () => {
    if (der[offset++] !== 0x02) throw new Error("Invalid ES256 DER integer");
    const length = der[offset++];
    if (!length || length > 33 || offset + length > der.length) throw new Error("Invalid ES256 integer length");
    let value = der.subarray(offset, offset + length); offset += length;
    if (value[0]! & 0x80) throw new Error("Negative ES256 integer");
    if (value[0] === 0 && value.length > 1) {
      if (!(value[1]! & 0x80)) throw new Error("Noncanonical ES256 integer");
      value = value.subarray(1);
    }
    if (value.length > 32) throw new Error("Oversized ES256 integer");
    const padded = new Uint8Array(32); padded.set(value, 32 - value.length); return padded;
  };
  const result = join(integer(), integer());
  if (offset !== der.length) throw new Error("Trailing ES256 signature data");
  return result;
}
function base64url(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
async function verifyPasskeyMintDelegation(proof: PasskeyMintDelegation, attachment: MintRootAttachment, expected: MintRootAttachmentExpectation): Promise<void> {
  if (!proof.authority?.authority) throw new Error("Missing passkey certificate");
  await verifyPasskeyAuthority(proof.authority, expected);
  const authority = proof.authority.authority;
  const duration = attachment.expiresAtUnixSeconds - attachment.notBeforeUnixSeconds;
  if (duration <= 0n || duration > BigInt(authority.maxSessionTtlSeconds)
    || proof.clientDataJson.length > 8192 || proof.authenticatorData.length < 37 || proof.authenticatorData.length > 4096
    || proof.signature.length === 0 || proof.signature.length > 80) throw new Error("Passkey delegation exceeds bounds");
  const client: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(proof.clientDataJson));
  if (!client || typeof client !== "object") throw new Error("Invalid passkey client data");
  const data = client as Record<string, unknown>;
  if (data.type !== "webauthn.get" || data.challenge !== base64url(mintRootAttachmentSigningDigest(attachment))
    || typeof data.origin !== "string" || !authority.allowedOrigins.includes(data.origin)
    || (data.crossOrigin !== undefined && data.crossOrigin !== false) || data.topOrigin !== undefined) throw new Error("Passkey assertion challenge or origin mismatch");
  const flags = proof.authenticatorData[32]!;
  if (!equal(proof.authenticatorData.subarray(0, 32), sha256(utf8.encode(authority.relyingPartyId)))
    || (flags & 0x05) !== 0x05 || (flags & 0x40) !== 0 || ((flags & 0x10) !== 0 && (flags & 0x08) === 0)) throw new Error("Invalid passkey RP or verification flags");
  const signed = join(proof.authenticatorData, sha256(proof.clientDataJson));
  const algorithm = authority.coseAlgorithm === -8 ? "Ed25519" : { name: "ECDSA", hash: "SHA-256" };
  const signature = authority.coseAlgorithm === -8 ? proof.signature : es256RawSignature(proof.signature);
  if (!await crypto.subtle.verify(algorithm, await importPasskey(authority), signature as BufferSource, signed as BufferSource)) throw new Error("Invalid passkey assertion signature");
}

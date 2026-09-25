import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  PasswordOwnerEnvelopeV1Schema,
  PasswordOwnerSetupSchema,
  type PasswordChallengeMetadata,
  type PasswordChallengeProof,
  type PasswordDeviceAdmission,
  type PasswordOwnerEnvelopeV1,
  type PasswordOwnerSetup,
  type PasswordOwnerSetupAuthorization,
  type SignedPasswordDeviceAdmission,
  type SignedPasswordOwnerSetupAuthorization,
} from "./identity_pb.js";

export const MAX_PASSWORD_ENVELOPE_BYTES = 4096;
export const MAX_PASSWORD_SETUP_BYTES = 4608;
export const PASSWORD_ARGON2_MEMORY_KIB = 65536;
export const PASSWORD_ARGON2_ITERATIONS = 3;
export const PASSWORD_ARGON2_PARALLELISM = 4;
const utf8 = new TextEncoder();

function exact(value: Uint8Array, length: number, name: string): void {
  if (value.length !== length) throw new Error(`Invalid ${name} length`);
}
function nonnil(value: Uint8Array): void {
  exact(value, 16, "account UUID");
  if (!value.some(Boolean)) throw new Error("Nil account UUID");
}
function costs(memory: number, iterations: number, parallelism: number): void {
  if (memory !== PASSWORD_ARGON2_MEMORY_KIB || iterations !== PASSWORD_ARGON2_ITERATIONS || parallelism !== PASSWORD_ARGON2_PARALLELISM) {
    throw new Error("Unsupported password Argon2id costs");
  }
}
function operationId(value: string): Uint8Array {
  const bytes = utf8.encode(value);
  if (bytes.length < 1 || bytes.length > 128) throw new Error("Invalid client operation ID length");
  return bytes;
}
function u32(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) throw new Error("Invalid u32");
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}
function u64(value: bigint): Uint8Array {
  if (value < 0n || value > (1n << 64n) - 1n) throw new Error("Invalid u64");
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value);
  return bytes;
}
function i64(value: bigint): Uint8Array {
  if (value < -(1n << 63n) || value >= (1n << 63n)) throw new Error("Invalid i64");
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigInt64(0, value);
  return bytes;
}
function join(...values: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) { result.set(value, offset); offset += value.length; }
  return result;
}
function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

/** Reject unsupported costs before Argon2 allocates memory. */
export function validatePasswordOwnerEnvelope(value: PasswordOwnerEnvelopeV1): void {
  if (value.formatVersion !== 1 || value.kdfId !== 1) throw new Error("Unsupported password envelope version or KDF");
  costs(value.memoryKib, value.iterations, value.parallelism);
  nonnil(value.accountUuid);
  exact(value.ownerPublicKey, 32, "owner public key");
  exact(value.ownerId, 32, "owner ID");
  exact(value.wrapSalt, 16, "wrap salt");
  exact(value.nonce, 12, "AES-GCM nonce");
  exact(value.ciphertextAndTag, 48, "ciphertext and tag");
  if (toBinary(PasswordOwnerEnvelopeV1Schema, value).length > MAX_PASSWORD_ENVELOPE_BYTES) throw new Error("Password envelope too large");
}

/** AES-256-GCM AAD binds the encrypted seed to the exact root and KDF costs. */
export function passwordOwnerWrapAad(value: PasswordOwnerEnvelopeV1): Uint8Array {
  validatePasswordOwnerEnvelope(value);
  return join(utf8.encode("heddle-owner-wrap-aad-v1\0"), u32(value.formatVersion), value.accountUuid,
    value.ownerPublicKey, value.ownerId, u32(value.kdfId), u32(value.memoryKib),
    u32(value.iterations), u32(value.parallelism), value.wrapSalt);
}

/** Reject unknown/duplicate protobuf fields and noncanonical encodings. */
export function decodePasswordOwnerEnvelopeCanonical(raw: Uint8Array): PasswordOwnerEnvelopeV1 {
  if (raw.length > MAX_PASSWORD_ENVELOPE_BYTES) throw new Error("Password envelope too large");
  const value = fromBinary(PasswordOwnerEnvelopeV1Schema, raw, { readUnknownFields: false });
  validatePasswordOwnerEnvelope(value);
  if (!equal(raw, toBinary(PasswordOwnerEnvelopeV1Schema, value, { writeUnknownFields: false }))) throw new Error("Noncanonical password envelope");
  return value;
}

export function validatePasswordOwnerSetup(value: PasswordOwnerSetup): void {
  if (!value.envelope) throw new Error("Missing password envelope");
  validatePasswordOwnerEnvelope(value.envelope);
  costs(value.authMemoryKib, value.authIterations, value.authParallelism);
  exact(value.authSalt, 16, "authentication salt");
  exact(value.authVerifierPublicKey, 32, "public verifier");
  if (equal(value.authSalt, value.envelope.wrapSalt)) throw new Error("Password salts must be independent");
  if (toBinary(PasswordOwnerSetupSchema, value).length > MAX_PASSWORD_SETUP_BYTES) throw new Error("Password setup too large");
}

/** Validate nested envelope bytes without accepting unknown protobuf fields. */
export function decodePasswordOwnerSetupCanonical(raw: Uint8Array): PasswordOwnerSetup {
  if (raw.length > MAX_PASSWORD_SETUP_BYTES) throw new Error("Password setup too large");
  const value = fromBinary(PasswordOwnerSetupSchema, raw, { readUnknownFields: false });
  validatePasswordOwnerSetup(value);
  if (!equal(raw, toBinary(PasswordOwnerSetupSchema, value, { writeUnknownFields: false }))) throw new Error("Noncanonical password setup");
  return value;
}

export function validatePasswordChallengeMetadata(value: PasswordChallengeMetadata): void {
  costs(value.authMemoryKib, value.authIterations, value.authParallelism);
  nonnil(value.accountUuid);
  exact(value.authSalt, 16, "authentication salt");
  exact(value.challengeId, 32, "challenge ID");
  exact(value.nonce, 32, "challenge nonce");
  if (value.envelopeRevision === 0n) throw new Error("Invalid envelope revision");
}

/** Ed25519 signs this domain-separated digest; the signature gates blob delivery only. */
export function passwordChallengeSigningDigest(challenge: PasswordChallengeMetadata, proof: PasswordChallengeProof,
  clientOperationId: string, expiryUnixSeconds: bigint): Uint8Array {
  validatePasswordChallengeMetadata(challenge);
  exact(proof.callerDevicePublicKey, 32, "caller device key");
  if (!equal(proof.challengeId, challenge.challengeId) || proof.envelopeRevision !== challenge.envelopeRevision) throw new Error("Password proof differs from challenge");
  const operation = operationId(clientOperationId);
  return sha256(join(utf8.encode("heddle-password-proof-v1"), challenge.challengeId, challenge.nonce,
    challenge.accountUuid, u64(challenge.envelopeRevision), proof.callerDevicePublicKey, u32(operation.length), operation,
    i64(expiryUnixSeconds)));
}

/** A verifier proof gates ciphertext delivery; it never supplies owner authority. */
export async function verifyPasswordChallengeSignature(challenge: PasswordChallengeMetadata, proof: PasswordChallengeProof,
  clientOperationId: string, expiryUnixSeconds: bigint, verifierPublicKey: Uint8Array): Promise<void> {
  exact(proof.signature, 64, "password proof signature");
  exact(verifierPublicKey, 32, "public verifier");
  const digest = passwordChallengeSigningDigest(challenge, proof, clientOperationId, expiryUnixSeconds);
  const key = await crypto.subtle.importKey("raw", verifierPublicKey as BufferSource, "Ed25519", false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", key, proof.signature as BufferSource, digest as BufferSource)) {
    throw new Error("Invalid password challenge signature");
  }
}

/** Owner signs this digest; hosts bind it to the current root and continuation. */
export function passwordDeviceAdmissionDigest(value: PasswordDeviceAdmission): Uint8Array {
  if (value.formatVersion !== 1) throw new Error("Unsupported password device admission version");
  nonnil(value.accountUuid);
  exact(value.challengeId, 32, "challenge ID");
  exact(value.continuationId, 32, "continuation ID");
  exact(value.callerDevicePublicKey, 32, "caller device key");
  exact(value.ownerStateHash, 32, "owner state hash");
  const operation = operationId(value.clientOperationId);
  return sha256(join(utf8.encode("heddle-password-device-admission-v1"), u32(value.formatVersion), value.accountUuid,
    value.challengeId, value.continuationId, value.callerDevicePublicKey, value.ownerStateHash,
    u64(value.ownerSequence), u32(operation.length), operation));
}

/** Hosts also compare the admission with the active root, challenge and continuation. */
export async function verifyPasswordDeviceAdmissionSignature(signed: SignedPasswordDeviceAdmission,
  currentOwnerPublicKey: Uint8Array): Promise<void> {
  exact(currentOwnerPublicKey, 32, "current owner public key");
  if (!signed.admission || !signed.ownerSignature) throw new Error("Missing owner device admission signature");
  const signature = signed.ownerSignature;
  exact(signature.signerKeyId, 32, "owner signer key ID");
  exact(signature.signature, 64, "owner signature");
  const expectedKeyId = sha256(join(utf8.encode("heddle-key-v1"), u32(1), currentOwnerPublicKey));
  if (!equal(signature.signerKeyId, expectedKeyId)) throw new Error("Owner signer key ID differs");
  const digest = passwordDeviceAdmissionDigest(signed.admission);
  const key = await crypto.subtle.importKey("raw", currentOwnerPublicKey as BufferSource, "Ed25519", false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", key, signature.signature as BufferSource, digest as BufferSource)) {
    throw new Error("Invalid owner device admission signature");
  }
}

/** SHA-256 over fixed-order v1 setup fields, not protobuf serialization. */
export function passwordOwnerSetupDigest(value: PasswordOwnerSetup): Uint8Array {
  validatePasswordOwnerSetup(value);
  const envelope = value.envelope!;
  return sha256(join(u32(envelope.formatVersion), envelope.accountUuid, envelope.ownerPublicKey, envelope.ownerId,
    u32(envelope.kdfId), u32(envelope.memoryKib), u32(envelope.iterations), u32(envelope.parallelism),
    envelope.wrapSalt, envelope.nonce, envelope.ciphertextAndTag, value.authSalt, value.authVerifierPublicKey,
    u32(value.authMemoryKib), u32(value.authIterations), u32(value.authParallelism)));
}

/** Digest for an owner-authorized, revision-checked PUT or DELETE. */
export function passwordOwnerSetupAuthorizationDigest(value: PasswordOwnerSetupAuthorization,
  setup?: PasswordOwnerSetup): Uint8Array {
  if (value.formatVersion !== 1) throw new Error("Unsupported password setup authorization version");
  nonnil(value.accountUuid);
  exact(value.ownerStateHash, 32, "owner state hash");
  exact(value.setupSha256, 32, "setup digest");
  const operation = operationId(value.clientOperationId);
  let expected: Uint8Array;
  if (value.action === 1 && setup?.envelope) {
    if (!equal(value.accountUuid, setup.envelope.accountUuid)) throw new Error("Setup account differs");
    expected = passwordOwnerSetupDigest(setup);
  } else if (value.action === 2 && !setup) {
    expected = new Uint8Array(32);
  } else {
    throw new Error("Invalid password setup action");
  }
  if (!equal(value.setupSha256, expected)) throw new Error("Password setup digest differs");
  return sha256(join(utf8.encode("heddle-password-owner-setup-change-v1"), u32(value.formatVersion), u32(value.action),
    value.accountUuid, value.ownerStateHash, u64(value.expectedRevision), value.setupSha256, u32(operation.length), operation));
}

export async function verifyPasswordOwnerSetupAuthorizationSignature(signed: SignedPasswordOwnerSetupAuthorization,
  currentOwnerPublicKey: Uint8Array, setup?: PasswordOwnerSetup): Promise<void> {
  if (!signed.authorization || !signed.ownerSignature) throw new Error("Missing owner setup authorization");
  exact(currentOwnerPublicKey, 32, "current owner public key");
  exact(signed.ownerSignature.signerKeyId, 32, "owner signer key ID");
  exact(signed.ownerSignature.signature, 64, "owner signature");
  const keyId = sha256(join(utf8.encode("heddle-key-v1"), u32(1), currentOwnerPublicKey));
  if (!equal(signed.ownerSignature.signerKeyId, keyId)) throw new Error("Owner signer key ID differs");
  const digest = passwordOwnerSetupAuthorizationDigest(signed.authorization, setup);
  const key = await crypto.subtle.importKey("raw", currentOwnerPublicKey as BufferSource, "Ed25519", false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", key, signed.ownerSignature.signature as BufferSource, digest as BufferSource)) {
    throw new Error("Invalid owner setup authorization signature");
  }
}

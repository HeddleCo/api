import { clone, create } from "@bufbuild/protobuf";
import { sha256 } from "@noble/hashes/sha2.js";
import { AuthorizationKeyAlgorithm, AuthorizationVerificationKeySchema, OwnerHistorySchema, SignedMintRootAttachmentSchema, SpoolOwnerGenesisSchema, SignedSpoolOwnerGenesisSchema, SpoolCreationStatementSchema,
  type AuthorizationVerificationKey, type SpoolOwnerGenesis, type SpoolCreationStatement,
  type SignedSpoolOwnerGenesis, type SignedMintRootAttachment, type OwnerHistory } from "./owner_records_pb.js";

const utf8 = new TextEncoder();
function join(...parts: Uint8Array[]): Uint8Array { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let offset = 0; for (const part of parts) { out.set(part, offset); offset += part.length; } return out; }
function u32(n: number): Uint8Array { if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) throw new Error("Invalid creation integer"); const out = new Uint8Array(4); new DataView(out.buffer).setUint32(0, n); return out; }
function u64(n: bigint, signed = false): Uint8Array { if (n < (signed ? -(1n << 63n) : 0n) || n >= (signed ? 1n << 63n : 1n << 64n)) throw new Error("Invalid creation integer"); const out = new Uint8Array(8); const view = new DataView(out.buffer); if (signed) view.setBigInt64(0, n); else view.setBigUint64(0, n); return out; }
function sized(bytes: Uint8Array): Uint8Array { return join(u32(bytes.length), bytes); }
function key(value: AuthorizationVerificationKey | undefined): Uint8Array { if (!value || value.algorithm !== AuthorizationKeyAlgorithm.ED25519 || value.publicKey.length !== 32) throw new Error("Creation requires Ed25519 key"); return join(u32(value.algorithm), sized(value.publicKey)); }
function uuid(value: Uint8Array): void { if (value.length !== 16 || !value.some(Boolean)) throw new Error("Creation UUID must be non-nil"); }
function pathSegment(value: string): void { if (!value || value === "." || value === ".." || value.includes("/") || value.includes("\0") || utf8.encode(value).length > 255) throw new Error("Invalid creation path segment"); }
/** Exact owner/key/Spool binding shared with the native verifier. */
export function spoolGenesisDigest(value: SpoolOwnerGenesis): Uint8Array { uuid(value.spoolUuid); return sha256(join(utf8.encode("heddle-spool-owner-genesis-v1"), sized(value.spoolUuid), key(value.ownerPublicKey))); }
/** Fixed-order creator statement; protobuf is solely the transport container. */
export function canonicalSpoolCreation(value: SpoolCreationStatement): Uint8Array {
  if (value.formatVersion !== 1 || value.genesisDigest.length !== 32 || value.ownerStateHash.length !== 32 || value.createdAtUnixSeconds <= 0n) throw new Error("Invalid creation statement");
  uuid(value.accountUuid);
  if (value.parentSpoolUuid.length) uuid(value.parentSpoolUuid);
  if (!!value.parentSpoolUuid.length !== !!value.parentPathSegments.length) throw new Error("Creation parent UUID and path must occur together");
  if (value.parentPathSegments.length > 64) throw new Error("Creation parent path is too deep");
  value.parentPathSegments.forEach(pathSegment); pathSegment(value.name);
  return join(u32(value.formatVersion), sized(value.genesisDigest), sized(value.accountUuid), sized(value.ownerStateHash), u64(value.ownerSequence), key(value.creatorKey), sized(value.parentSpoolUuid), u32(value.parentPathSegments.length), ...value.parentPathSegments.map(s => sized(utf8.encode(s))), sized(utf8.encode(value.name)), u64(value.createdAtUnixSeconds, true));
}
export function spoolCreationSigningDigest(value: SpoolCreationStatement): Uint8Array { return sha256(join(utf8.encode("heddle-spool-creation-v1"), canonicalSpoolCreation(value))); }
export interface DelegatedSpoolCreationInput {
  spoolUuid: Uint8Array; accountUuid: Uint8Array; ownerStateHash: Uint8Array; ownerSequence: bigint;
  ownerPublicKey: Uint8Array; creatorPublicKey: Uint8Array; parentSpoolUuid?: Uint8Array;
  parentPathSegments?: string[]; name: string; createdAtUnixSeconds: bigint;
  /** Already sealed Biscuit, narrowed to the exact creation request digest. */
  sealedBiscuit: Uint8Array; mintRootAttachment?: SignedMintRootAttachment; ownerHistory: OwnerHistory;
  sign(digest: Uint8Array): Promise<Uint8Array>;
}
/** Assemble the portable proof; the caller narrows and seals its existing bearer first. */
export async function signDelegatedSpoolCreation(input: DelegatedSpoolCreationInput): Promise<SignedSpoolOwnerGenesis> {
  const ownerKey = create(AuthorizationVerificationKeySchema, { algorithm: AuthorizationKeyAlgorithm.ED25519, publicKey: input.ownerPublicKey.slice() });
  const creatorKey = create(AuthorizationVerificationKeySchema, { algorithm: AuthorizationKeyAlgorithm.ED25519, publicKey: input.creatorPublicKey.slice() });
  const genesis = create(SpoolOwnerGenesisSchema, { spoolUuid: input.spoolUuid.slice(), ownerPublicKey: ownerKey });
  const statement = create(SpoolCreationStatementSchema, { formatVersion: 1, genesisDigest: spoolGenesisDigest(genesis), accountUuid: input.accountUuid.slice(),
    ownerStateHash: input.ownerStateHash.slice(), ownerSequence: input.ownerSequence, creatorKey, parentSpoolUuid: input.parentSpoolUuid?.slice() ?? new Uint8Array(),
    parentPathSegments: [...(input.parentPathSegments ?? [])], name: input.name, createdAtUnixSeconds: input.createdAtUnixSeconds });
  const history = clone(OwnerHistorySchema, input.ownerHistory);
  const mintRootAttachment = input.mintRootAttachment ? clone(SignedMintRootAttachmentSchema, input.mintRootAttachment) : undefined;
  const sealedBiscuit = input.sealedBiscuit.slice();
  if (!sealedBiscuit.length || !history.root || history.stateHash.length !== 32 || !history.stateHash.every((byte, index) => byte === statement.ownerStateHash[index])) throw new Error("Incomplete creation bearer or owner history");
  const digest = spoolCreationSigningDigest(statement);
  const signature = await input.sign(digest.slice());
  if (signature.length !== 64) throw new Error("Invalid creator signature length");
  const verifier = await crypto.subtle.importKey("raw", creatorKey.publicKey as BufferSource, "Ed25519", false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", verifier, signature as BufferSource, digest as BufferSource)) throw new Error("Invalid creator signature");
  const signerKeyId = sha256(join(utf8.encode("heddle-key-v1"), key(creatorKey).subarray(0, 4), input.creatorPublicKey));
  return create(SignedSpoolOwnerGenesisSchema, { genesis, delegatedCreation: { statement, creatorSignature: { signerKeyId, signature }, sealedBiscuit,
    mintRootAttachment, ownerHistory: history } });
}

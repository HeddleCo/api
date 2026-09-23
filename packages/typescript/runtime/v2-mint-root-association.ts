import { fromBinary } from "@bufbuild/protobuf";
import { ThreadControlAuthoritySchema, type ThreadControlAuthority } from "./identity_pb.js";
import { SpoolCreationProofSchema, type SpoolCreationProof } from "./owner_records_pb.js";

const OWNER_MINT_ROOT_ATTACHMENT_FIELD = 4n;
const PASSKEY_MINT_ROOT_ATTACHMENT_FIELD = 6n;
const MAX_PROTOBUF_FIELD_NUMBER = (1n << 29n) - 1n;

function malformed(): never {
  throw new Error("Mint-root association contains malformed protobuf wire bytes");
}

function readVarint(bytes: Uint8Array, cursor: { offset: number }): bigint {
  let value = 0n;
  for (let index = 0; index < 10; index++) {
    if (cursor.offset >= bytes.length) malformed();
    const byte = bytes[cursor.offset++]!;
    if (index === 9 && byte > 1) malformed();
    value |= BigInt(byte & 0x7f) << BigInt(index * 7);
    if ((byte & 0x80) === 0) return value;
  }
  return malformed();
}

function skip(bytes: Uint8Array, cursor: { offset: number }, length: bigint): void {
  if (length > BigInt(Number.MAX_SAFE_INTEGER)) malformed();
  const end = cursor.offset + Number(length);
  if (!Number.isSafeInteger(end) || end > bytes.length) malformed();
  cursor.offset = end;
}

/** Scan top-level protobuf tags before oneof last-wins decoding can discard an arm. */
export function verifyMintRootAssociationWire(bytes: Uint8Array): void {
  const cursor = { offset: 0 };
  let owner = false;
  let passkey = false;
  while (cursor.offset < bytes.length) {
    const key = readVarint(bytes, cursor);
    const field = key >> 3n;
    const wireType = key & 7n;
    if (field === 0n || field > MAX_PROTOBUF_FIELD_NUMBER) malformed();
    if (field === OWNER_MINT_ROOT_ATTACHMENT_FIELD) owner = true;
    if (field === PASSKEY_MINT_ROOT_ATTACHMENT_FIELD) passkey = true;
    if (owner && passkey) throw new Error("Mint-root association contains both owner-v1 and passkey-v2 fields");
    switch (wireType) {
      case 0n: readVarint(bytes, cursor); break;
      case 1n: skip(bytes, cursor, 8n); break;
      case 2n: skip(bytes, cursor, readVarint(bytes, cursor)); break;
      case 5n: skip(bytes, cursor, 4n); break;
      default: malformed();
    }
  }
}

/** Check raw oneof tags, then decode authority bytes for verification. */
export function decodeThreadControlAuthorityForVerification(bytes: Uint8Array): ThreadControlAuthority {
  verifyMintRootAssociationWire(bytes);
  return fromBinary(ThreadControlAuthoritySchema, bytes);
}

/** Check raw oneof tags, then decode Spool-creation proof bytes for verification. */
export function decodeSpoolCreationProofForVerification(bytes: Uint8Array): SpoolCreationProof {
  verifyMintRootAssociationWire(bytes);
  return fromBinary(SpoolCreationProofSchema, bytes);
}

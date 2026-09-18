import { create } from "@bufbuild/protobuf";
import { blake3 } from "@noble/hashes/blake3.js";
import { SignedRecordSchema, type SignedRecord } from "./common_pb.js";
import { encode, type Value } from "./_collaboration-msgpack.js";

const FORMAT = "heddle-thread-genesis-v1";
const utf8 = new TextEncoder();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type ThreadGenesisOwner = { kind: "account"; accountId: string } |
  { kind: "local_key"; publicKey: Uint8Array };
export interface ThreadGenesisInput {
  spoolId: string;
  parentId?: Uint8Array;
  baseStateId: Uint8Array;
  name: string;
  intent: string;
  owner: ThreadGenesisOwner;
  nonce: Uint8Array;
}
export interface ThreadGenesisSigner {
  publicKey: Uint8Array;
  sign(bytes: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

/** Exact rmp-serde named ThreadGenesis bytes. The owner/account choice is
 * immutable and must agree with the independently verified authority envelope
 * supplied to StartThread or ImportSource. */
export function canonicalThreadGenesis(input: ThreadGenesisInput, creatorKey: Uint8Array): Uint8Array {
  const spool = uuid(input.spoolId);
  const creator = fixed(creatorKey, 32);
  const base = fixed(input.baseStateId, 32);
  const parent = input.parentId === undefined ? null : Array.from(fixed(input.parentId, 32));
  const nonce = Uint8Array.from(input.nonce);
  if (nonce.length !== 16) throw new Error("Thread genesis requires a fresh 16-byte nonce");
  if (!input.name || utf8.encode(input.name).length > 256 || utf8.encode(input.intent).length > 16_384)
    throw new Error("Thread genesis name or intent exceeds bounds");
  const owner: Value = input.owner.kind === "account"
    ? { account: uuidBytes(uuid(input.owner.accountId)) }
    : { local_key: Array.from(fixed(input.owner.publicKey, 32)) };
  if (input.owner.kind === "local_key" && !equal(creator, input.owner.publicKey))
    throw new Error("Local-key Thread owner must be the original creator");
  const canonical = encode({ version: 1, spool, parent, base: Array.from(base), name: input.name,
    intent: input.intent, owner, creator: Array.from(creator), nonce: Array.from(nonce) });
  if (canonical.length > 256 * 1024) throw new Error("Thread genesis exceeds record bound");
  return canonical;
}

export function threadGenesisId(canonical: Uint8Array): Uint8Array {
  const length = new Uint8Array(8);
  new DataView(length.buffer).setBigUint64(0, BigInt(canonical.length), true);
  return blake3(join(utf8.encode(FORMAT), length, Uint8Array.of(0), canonical));
}

export async function signThreadGenesis(input: ThreadGenesisInput, signer: ThreadGenesisSigner):
  Promise<{ threadId: Uint8Array; signed: SignedRecord }> {
  const creator = fixed(signer.publicKey, 32);
  const canonicalRecord = canonicalThreadGenesis(input, creator);
  const signedBytes = join(utf8.encode(FORMAT), Uint8Array.of(0), canonicalRecord);
  const signature = fixed(await signer.sign(signedBytes.slice()), 64);
  const key = await crypto.subtle.importKey("raw", creator, { name: "Ed25519" }, false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", key, signature, signedBytes))
    throw new Error("Thread genesis signature does not match original creator");
  return { threadId: threadGenesisId(canonicalRecord), signed: create(SignedRecordSchema, {
    format: FORMAT, canonicalRecord, signatures: [{ publicKey: creator, signature }],
  }) };
}

function uuid(value: string): string {
  if (!UUID.test(value) || value === "00000000-0000-0000-0000-000000000000")
    throw new Error("Canonical non-nil UUID required");
  return value;
}
function uuidBytes(value: string): Uint8Array {
  return Uint8Array.from(value.replaceAll("-", "").match(/../g) ?? [], pair => Number.parseInt(pair, 16));
}
function fixed(value: Uint8Array, length: number): Uint8Array {
  if (value.length !== length || value.every(byte => byte === 0)) throw new Error(`Expected nonzero ${length}-byte identity`);
  return Uint8Array.from(value);
}
function equal(a: Uint8Array, b: Uint8Array) {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}
function join(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { blake3 } from "@noble/hashes/blake3.js";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { StartThreadRequestSchema } from "../packages/typescript/dist/v1alpha2/thread_pb.js";
import { canonicalThreadGenesis, signThreadGenesis, threadGenesisId } from "../packages/typescript/dist/v1alpha2/thread-genesis.js";

// Shared verbatim with heddle-thread-api/tests/fixtures/thread-genesis-v1.txt.
// Rust constructs the canonical record; browser clients may relay its exact bytes.
const vector = Object.fromEntries(readFileSync(new URL("fixtures/thread-genesis-v1.txt", import.meta.url), "utf8")
  .trim().split("\n").map(line => line.split("=")));
const format = "heddle-thread-genesis-v1";
const canonical = Buffer.from(vector.canonical, "hex");
const key = Buffer.from(vector.key, "hex");
const signature = Buffer.from(vector.signature, "hex");
const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), key]), format: "der", type: "spki" });
const signingBytes = bytes => Buffer.concat([Buffer.from(format), Buffer.from([0]), bytes]);

test("native genesis retains its typed identity and creator signature through TypeScript protobuf", () => {
  const length = Buffer.alloc(8);
  length.writeBigUInt64LE(BigInt(canonical.length));
  const id = blake3(Buffer.concat([Buffer.from(format), length, Buffer.from([0]), canonical]));
  assert.equal(Buffer.from(id).toString("hex"), vector.id);
  assert.equal(verify(null, signingBytes(canonical), publicKey, signature), true);
  const request = create(StartThreadRequestSchema, {
    clientOperationId: "01980000-0000-7000-8000-000000000002",
    spool: { id: "01980000-0000-7000-8000-000000000001" },
    threadGenesis: { format, canonicalRecord: canonical, signatures: [{ publicKey: key, signature }] },
  });
  const decoded = fromBinary(StartThreadRequestSchema, toBinary(StartThreadRequestSchema, request));
  assert.deepEqual(Buffer.from(decoded.threadGenesis.canonicalRecord), canonical);
  assert.deepEqual(Buffer.from(decoded.threadGenesis.signatures[0].publicKey), key);
  assert.equal(verify(null, signingBytes(decoded.threadGenesis.canonicalRecord), publicKey, decoded.threadGenesis.signatures[0].signature), true);
  const changed = Buffer.from(canonical);
  changed[changed.length - 1] ^= 1;
  assert.equal(verify(null, signingBytes(changed), publicKey, signature), false);
  const changedSignature = Buffer.from(signature);
  changedSignature[0] ^= 1;
  assert.equal(verify(null, signingBytes(canonical), publicKey, changedSignature), false);
});

test("browser canonical authoring matches the Rust local-key genesis fixture", () => {
  const authored = canonicalThreadGenesis({
    spoolId: "01980000-0000-7000-8000-000000000001",
    baseStateId: new Uint8Array(32).fill(17),
    name: "independent work", intent: "retain identity while publishing",
    owner: { kind: "local_key", publicKey: key }, nonce: new Uint8Array(16).fill(23),
  }, key);
  assert.deepEqual(Buffer.from(authored), canonical);
  assert.equal(Buffer.from(threadGenesisId(authored)).toString("hex"), vector.id);
});

test("browser account-owned import genesis matches independent Rust bytes, signature and identity", async () => {
  const account = Object.fromEntries(readFileSync(new URL("fixtures/thread-genesis-browser-v1.txt", import.meta.url), "utf8")
    .trim().split("\n").map(line => line.split("=")));
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 42)]),
    format: "der", type: "pkcs8",
  });
  const creator = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
  assert.equal(creator.toString("hex"), account.key);
  const base = Buffer.from(account.base, "hex");
  const input = { spoolId: "123e4567-e89b-12d3-a456-426614174000", baseStateId: base,
    name: "imported-project", intent: "Import the granted repository",
    owner: { kind: "account", accountId: "123e4567-e89b-12d3-a456-426614174001" },
    nonce: new Uint8Array(16).fill(7) };
  const result = await signThreadGenesis(input, { publicKey: creator, sign: bytes => sign(null, bytes, privateKey) });
  assert.equal(Buffer.from(result.signed.canonicalRecord).toString("hex"), account.canonical);
  assert.equal(Buffer.from(result.signed.signatures[0].signature).toString("hex"), account.signature);
  assert.equal(Buffer.from(result.threadId).toString("hex"), account.id);
  const mutableInput = { ...input, nonce: new Uint8Array(16).fill(7) };
  const mutatingSigner = { publicKey: creator, async sign(bytes) {
    mutableInput.nonce[0] ^= 1;
    mutableInput.name = "changed after signing started";
    bytes[0] ^= 1;
    return sign(null, Buffer.concat([Buffer.from(format), Buffer.from([0]), Buffer.from(account.canonical, "hex")]), privateKey);
  } };
  const safe = await signThreadGenesis(mutableInput, mutatingSigner);
  assert.equal(Buffer.from(safe.signed.canonicalRecord).toString("hex"), account.canonical);
  await assert.rejects(signThreadGenesis(input, { publicKey: creator, sign: () => new Uint8Array(64).fill(1) }), /signature does not match/);
});

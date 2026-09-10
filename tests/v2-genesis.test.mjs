import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createPublicKey, verify } from "node:crypto";
import { blake3 } from "@noble/hashes/blake3.js";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { StartThreadRequestSchema } from "../packages/typescript/dist/v2alpha1/thread_pb.js";

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

import { readFileSync } from "node:fs";
import { unarySigningBytes } from "../packages/typescript/dist/signing.js";

const vector = JSON.parse(readFileSync("tests/fixtures/unary-signing-v1.json", "utf8"));
const fromHex = (value) => Uint8Array.from(value.match(/../g), (pair) => Number.parseInt(pair, 16));
const actual = await unarySigningBytes(
  vector.identity,
  vector.route,
  BigInt(vector.timestamp_millis),
  fromHex(vector.nonce_hex),
  fromHex(vector.request_hex),
);
if (Buffer.from(actual).toString("hex") !== vector.canonical_hex) {
  throw new Error("TypeScript unary signing bytes differ from the shared golden vector");
}

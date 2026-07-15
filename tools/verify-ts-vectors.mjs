import { readFileSync } from "node:fs";
import { fromBinary } from "@bufbuild/protobuf";
import { HandlePrincipalSchema } from "../packages/typescript/dist/identity_pb.js";
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

const handleVector = JSON.parse(
  readFileSync("tests/fixtures/handle-wire-v1.json", "utf8"),
);
const principal = fromBinary(
  HandlePrincipalSchema,
  fromHex(handleVector.legacy_resolved_principal_hex),
);
if ("subject" in principal) {
  throw new Error("legacy subject tag decoded into the public HandlePrincipal shape");
}
for (const [field, expected] of Object.entries(
  handleVector.expected_public_principal,
)) {
  if (principal[field] !== expected) {
    throw new Error(
      `legacy-compatible HandlePrincipal field ${field} decoded as ${String(principal[field])}`,
    );
  }
}

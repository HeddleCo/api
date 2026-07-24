import { readFileSync } from "node:fs";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { HandlePrincipalSchema } from "../packages/typescript/dist/identity_pb.js";
import { CallContextSchema } from "../packages/typescript/dist/contract_pb.js";
import {
  CallFailureCode,
  CallFailureSchema,
} from "../packages/typescript/dist/errors_pb.js";
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

const hostedCall = JSON.parse(
  readFileSync("tests/fixtures/hosted-call-v1.json", "utf8"),
);
const framedRequest = fromHex(hostedCall.framed_request_hex);
const methodLength = (framedRequest[0] << 8) | framedRequest[1];
const contextLength =
  framedRequest[2] * 2 ** 24 +
  framedRequest[3] * 2 ** 16 +
  framedRequest[4] * 2 ** 8 +
  framedRequest[5];
const contextStart = 6 + methodLength;
const contextBytes = framedRequest.slice(
  contextStart,
  contextStart + contextLength,
);
const callContext = fromBinary(CallContextSchema, contextBytes);
if (
  Buffer.from(callContext.bearerCapability).toString("hex") !==
    hostedCall.bearer_capability_hex ||
  callContext.clientOperationId !== hostedCall.client_operation_id ||
  callContext.trace?.traceparent !== hostedCall.traceparent ||
  Buffer.from(toBinary(CallContextSchema, callContext)).toString("hex") !==
    Buffer.from(contextBytes).toString("hex")
) {
  throw new Error("TypeScript call context differs from the hosted-call fixture");
}

const failure = fromBinary(CallFailureSchema, fromHex(hostedCall.failure_hex));
if (
  failure.code !== CallFailureCode.PERMISSION_DENIED ||
  failure.message !== hostedCall.failure_message ||
  failure.details.length !== 1 ||
  failure.details[0].typeUrl !== hostedCall.detail_type_url ||
  Buffer.from(toBinary(CallFailureSchema, failure)).toString("hex") !==
    hostedCall.failure_hex
) {
  throw new Error("TypeScript call failure differs from the hosted-call fixture");
}

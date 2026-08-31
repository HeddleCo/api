import { readFileSync } from "node:fs";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { HandlePrincipalSchema } from "../packages/typescript/dist/identity_pb.js";
import { CallContextSchema } from "../packages/typescript/dist/contract_pb.js";
import {
  CallFailureCode,
  CallFailureSchema,
  ErrorReason,
} from "../packages/typescript/dist/errors_pb.js";
import { errorReasonRetryable } from "../packages/typescript/dist/errors.js";
import { unarySigningBytes } from "../packages/typescript/dist/signing.js";
import {
  FrameError,
  MAX_CALL_CONTEXT,
  MAX_CONTROL_BODY,
  MAX_METHOD_PATH,
  decodeRequestFrame,
  decodeResponseFrame,
  encodeFailureResponse,
  encodeRequestFrame,
  encodeSuccessResponse,
} from "../packages/typescript/dist/framing.js";
import { create } from "@bufbuild/protobuf";

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
const toHex = (value) => Buffer.from(value).toString("hex");

// The hosted-call frame codec must reproduce the shared cross-language golden
// request frame byte-for-byte from the typed CallContext, matching the Rust
// `encode_request_frame` and Python encoders that own the same fixture.
const callContext = create(CallContextSchema, {
  bearerCapability: fromHex(hostedCall.bearer_capability_hex),
  clientOperationId: hostedCall.client_operation_id,
  trace: { traceparent: hostedCall.traceparent },
});
const requestBody = fromHex(hostedCall.request_hex);
const encodedRequest = encodeRequestFrame(
  hostedCall.method,
  callContext,
  requestBody,
);
if (toHex(encodedRequest) !== hostedCall.framed_request_hex) {
  throw new Error(
    "TypeScript request frame differs from the hosted-call golden vector",
  );
}
const decodedRequest = decodeRequestFrame(fromHex(hostedCall.framed_request_hex));
if (
  decodedRequest.method !== hostedCall.method ||
  toHex(decodedRequest.context.bearerCapability) !==
    hostedCall.bearer_capability_hex ||
  decodedRequest.context.clientOperationId !== hostedCall.client_operation_id ||
  decodedRequest.context.trace?.traceparent !== hostedCall.traceparent ||
  toHex(decodedRequest.body) !== hostedCall.request_hex
) {
  throw new Error("TypeScript request frame did not round-trip the golden vector");
}

const failure = fromBinary(CallFailureSchema, fromHex(hostedCall.failure_hex));
if (
  failure.code !== CallFailureCode.PERMISSION_DENIED ||
  failure.message !== hostedCall.failure_message ||
  failure.error?.reason !== ErrorReason.POLICY_DENIED ||
  failure.error.resource !== hostedCall.error_resource ||
  failure.error.context.case !== "policy" ||
  failure.error.context.value.policyId !== hostedCall.policy_id ||
  failure.error.context.value.rule !== hostedCall.policy_rule ||
  failure.error.context.value.humanVerificationCanOverride !==
    hostedCall.policy_human_verification_can_override ||
  Buffer.from(toBinary(CallFailureSchema, failure)).toString("hex") !==
    hostedCall.failure_hex
) {
  throw new Error("TypeScript call failure differs from the hosted-call fixture");
}

// The failure response frame (outcome byte + CallFailure protobuf) must match
// the shared golden and round-trip through the codec.
const encodedFailureResponse = encodeFailureResponse(failure);
if (toHex(encodedFailureResponse) !== hostedCall.framed_failure_hex) {
  throw new Error(
    "TypeScript failure response frame differs from the hosted-call golden vector",
  );
}
const decodedFailureResponse = decodeResponseFrame(
  fromHex(hostedCall.framed_failure_hex),
);
if (
  decodedFailureResponse.outcome !== "failure" ||
  Buffer.from(toBinary(CallFailureSchema, decodedFailureResponse.failure)).toString(
    "hex",
  ) !== hostedCall.failure_hex
) {
  throw new Error("TypeScript failure response frame did not round-trip");
}

// Success responses are `0x00 | body`; assert the exact layout and round-trip.
const successBody = fromHex(hostedCall.request_hex);
const encodedSuccess = encodeSuccessResponse(successBody);
if (toHex(encodedSuccess) !== `00${hostedCall.request_hex}`) {
  throw new Error("TypeScript success response frame has an unexpected layout");
}
const decodedSuccess = decodeResponseFrame(encodedSuccess);
if (
  decodedSuccess.outcome !== "success" ||
  toHex(decodedSuccess.body) !== hostedCall.request_hex
) {
  throw new Error("TypeScript success response frame did not round-trip");
}

// Negative cases: every ceiling and malformed frame must be rejected loudly,
// never silently truncated or accepted (mirrors the Rust FrameError paths).
const rejects = (label, thunk) => {
  let threw = false;
  try {
    thunk();
  } catch (error) {
    threw = true;
    if (!(error instanceof FrameError)) {
      throw new Error(`${label} threw ${error} instead of a FrameError`);
    }
  }
  if (!threw) {
    throw new Error(`${label} was accepted but must be rejected`);
  }
};

const smallContext = create(CallContextSchema, {});
// Over-ceiling method path (byte length > MAX_METHOD_PATH).
rejects("over-ceiling method path", () =>
  encodeRequestFrame(`/${"a".repeat(MAX_METHOD_PATH)}`, smallContext, new Uint8Array()),
);
// Method path not beginning with '/'.
rejects("method without leading slash", () =>
  encodeRequestFrame("heddle.api.v1alpha1.Foo/Bar", smallContext, new Uint8Array()),
);
// Empty method path.
rejects("empty method path", () =>
  encodeRequestFrame("", smallContext, new Uint8Array()),
);
// Over-ceiling request body.
rejects("over-ceiling request body", () =>
  encodeRequestFrame("/x", smallContext, new Uint8Array(MAX_CONTROL_BODY + 1)),
);
// Over-ceiling success body.
rejects("over-ceiling success body", () =>
  encodeSuccessResponse(new Uint8Array(MAX_CONTROL_BODY + 1)),
);
// Truncated prelude: header claims a longer method than the frame carries.
rejects("truncated request prelude", () =>
  decodeRequestFrame(Uint8Array.from([0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x2f])),
);
// Short frame (fewer than the 6-byte prelude header).
rejects("short request frame", () =>
  decodeRequestFrame(Uint8Array.from([0x00, 0x1c])),
);
// Empty response frame.
rejects("empty response frame", () => decodeResponseFrame(new Uint8Array()));
// Unknown response outcome byte.
rejects("unknown response outcome", () =>
  decodeResponseFrame(Uint8Array.from([0x07, 0x01, 0x02])),
);
// Prelude declaring an over-ceiling context length.
rejects("over-ceiling declared context length", () => {
  const bad = new Uint8Array(6);
  const view = new DataView(bad.buffer);
  view.setUint16(0, 1, false);
  view.setUint32(2, MAX_CALL_CONTEXT + 1, false);
  decodeRequestFrame(bad);
});

// Prove a well-formed at-ceiling method path is accepted (the boundary is
// inclusive), so the ceiling check is not simply rejecting everything.
const atCeiling = encodeRequestFrame(
  `/${"a".repeat(MAX_METHOD_PATH - 1)}`,
  smallContext,
  new Uint8Array(),
);
if (decodeRequestFrame(atCeiling).method.length !== MAX_METHOD_PATH) {
  throw new Error("at-ceiling method path did not round-trip");
}

for (const reason of [
  ErrorReason.RATE_LIMITED,
  ErrorReason.QUOTA_EXCEEDED,
  ErrorReason.TRANSIENT,
]) {
  if (!errorReasonRetryable(reason)) {
    throw new Error(`TypeScript error reason ${reason} must be retryable`);
  }
}
for (const reason of [ErrorReason.CURSOR_INVALID, ErrorReason.INTERNAL]) {
  if (errorReasonRetryable(reason)) {
    throw new Error(`TypeScript error reason ${reason} must not be retryable`);
  }
}

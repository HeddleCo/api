// SPDX-License-Identifier: Apache-2.0
//
// Hosted-call frame codec, byte-compatible with the authoritative Rust
// implementation in `src/framing.rs` (crate `heddle-api`). This is the wire
// format the hosted-call ALPN carries over one bidirectional operation stream:
// the stream FIN delimits each control frame.
//
// Request frame:  method_len:u16be | context_len:u32be | method (utf8)
//                 | CallContext (protobuf) | body
// Response frame: outcome:u8 (0 = success, 1 = failure) | body
//                 (a failure body is a CallFailure protobuf envelope)
//
// Only the unary request/response frames are modelled here; that is the shape
// the ADR-0049 browser claim transport uses (see heddle's claim_protocol.rs,
// which frames with encode_request_frame + decode_response_frame).

import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { CallContextSchema, type CallContext } from "./contract_pb.js";
import { CallFailureSchema, type CallFailure } from "./errors_pb.js";

/** Largest fully-qualified method path accepted by the hosted-call protocol. */
export const MAX_METHOD_PATH = 1024;
/** Largest encoded call context accepted before dispatch. */
export const MAX_CALL_CONTEXT = 64 * 1024;
/** Largest protobuf control body carried in a FIN-delimited frame. */
export const MAX_CONTROL_BODY = 8 * 1024 * 1024;

const RESPONSE_SUCCESS = 0;
const RESPONSE_FAILURE = 1;
const PRELUDE_HEADER = 6;

/** Malformed or oversized hosted-call framing. */
export class FrameError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FrameError";
  }
}

/** Decoded request frame; `body` is a view over the supplied frame bytes. */
export interface RequestFrame {
  /** Canonical fully-qualified method path. */
  method: string;
  /** Typed call metadata decoded before routing. */
  context: CallContext;
  /** Encoded method request body. */
  body: Uint8Array;
}

/** Decoded unary response outcome. */
export type ResponseFrame =
  | { readonly outcome: "success"; readonly body: Uint8Array }
  | { readonly outcome: "failure"; readonly failure: CallFailure };

const textEncoder = new TextEncoder();
// `fatal` rejects non-UTF-8 method paths, matching Rust's `str::from_utf8`.
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function validateBodyLen(bodyLen: number): void {
  if (bodyLen > MAX_CONTROL_BODY) {
    throw new FrameError(
      `control body is ${bodyLen} bytes; maximum is ${MAX_CONTROL_BODY}`,
    );
  }
}

function validateMethodBytes(method: string, methodByteLen: number): void {
  if (method.length === 0 || !method.startsWith("/") || methodByteLen > MAX_METHOD_PATH) {
    throw new FrameError(
      "method path must begin with '/' and fit the method-path limit",
    );
  }
}

/**
 * Encodes `method_len:u16be | context_len:u32be | method | context | body`.
 * The operation stream FIN is the outer delimiter.
 */
export function encodeRequestFrame(
  method: string,
  context: CallContext,
  body: Uint8Array,
): Uint8Array {
  validateBodyLen(body.length);
  const prelude = encodeRequestPrelude(method, context);
  const frame = new Uint8Array(prelude.length + body.length);
  frame.set(prelude, 0);
  frame.set(body, prelude.length);
  return frame;
}

/** Encodes the method and typed context that precede a request body. */
export function encodeRequestPrelude(
  method: string,
  context: CallContext,
): Uint8Array {
  const methodBytes = textEncoder.encode(method);
  validateMethodBytes(method, methodBytes.length);
  const contextBytes = toBinary(CallContextSchema, context);
  if (contextBytes.length > MAX_CALL_CONTEXT) {
    throw new FrameError(
      `call context is ${contextBytes.length} bytes; maximum is ${MAX_CALL_CONTEXT}`,
    );
  }
  // `methodBytes.length <= MAX_METHOD_PATH` guarantees the u16, and the context
  // ceiling guarantees the u32; the explicit guards mirror the Rust try_from.
  if (methodBytes.length > 0xffff) {
    throw new FrameError("method path exceeds u16");
  }
  if (contextBytes.length > 0xffff_ffff) {
    throw new FrameError("call context exceeds u32");
  }

  const frame = new Uint8Array(PRELUDE_HEADER + methodBytes.length + contextBytes.length);
  const view = new DataView(frame.buffer);
  view.setUint16(0, methodBytes.length, false);
  view.setUint32(2, contextBytes.length, false);
  frame.set(methodBytes, PRELUDE_HEADER);
  frame.set(contextBytes, PRELUDE_HEADER + methodBytes.length);
  return frame;
}

/** Decodes a complete FIN-delimited request frame. */
export function decodeRequestFrame(frame: Uint8Array): RequestFrame {
  if (frame.length < PRELUDE_HEADER) {
    throw new FrameError("request frame contains a truncated prelude");
  }
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const methodLen = view.getUint16(0, false);
  const contextLen = view.getUint32(2, false);
  if (methodLen === 0 || methodLen > MAX_METHOD_PATH || contextLen > MAX_CALL_CONTEXT) {
    throw new FrameError("request prelude declares an invalid length");
  }
  const contextStart = PRELUDE_HEADER + methodLen;
  const consumed = contextStart + contextLen;
  if (frame.length < consumed) {
    throw new FrameError("request frame contains a truncated prelude");
  }

  let method: string;
  try {
    method = textDecoder.decode(frame.subarray(PRELUDE_HEADER, contextStart));
  } catch {
    throw new FrameError("method path is not UTF-8");
  }
  validateMethodBytes(method, methodLen);

  const context = decodeCallContext(frame.subarray(contextStart, consumed));
  const body = frame.subarray(consumed);
  validateBodyLen(body.length);
  return { method, context, body };
}

/** Encodes a successful unary response; the stream FIN delimits the body. */
export function encodeSuccessResponse(body: Uint8Array): Uint8Array {
  validateBodyLen(body.length);
  const frame = new Uint8Array(1 + body.length);
  frame[0] = RESPONSE_SUCCESS;
  frame.set(body, 1);
  return frame;
}

/** Encodes a contract-owned unary failure; the stream FIN delimits the envelope. */
export function encodeFailureResponse(failure: CallFailure): Uint8Array {
  const body = toBinary(CallFailureSchema, failure);
  validateBodyLen(body.length);
  const frame = new Uint8Array(1 + body.length);
  frame[0] = RESPONSE_FAILURE;
  frame.set(body, 1);
  return frame;
}

/** Decodes a complete FIN-delimited unary response frame. */
export function decodeResponseFrame(frame: Uint8Array): ResponseFrame {
  if (frame.length === 0) {
    throw new FrameError("response frame is empty");
  }
  const outcome = frame[0];
  const body = frame.subarray(1);
  validateBodyLen(body.length);
  switch (outcome) {
    case RESPONSE_SUCCESS:
      return { outcome: "success", body };
    case RESPONSE_FAILURE:
      return { outcome: "failure", failure: decodeCallFailure(body) };
    default:
      throw new FrameError(`unknown response outcome ${outcome}`);
  }
}

function decodeCallContext(bytes: Uint8Array): CallContext {
  try {
    return fromBinary(CallContextSchema, bytes);
  } catch (cause) {
    throw new FrameError(`invalid hosted-call protobuf: ${String(cause)}`);
  }
}

function decodeCallFailure(bytes: Uint8Array): CallFailure {
  try {
    return fromBinary(CallFailureSchema, bytes);
  } catch (cause) {
    throw new FrameError(`invalid hosted-call protobuf: ${String(cause)}`);
  }
}

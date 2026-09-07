import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { create } from "@bufbuild/protobuf";
import {
  encodeStreamMessage, encodeStreamFailure, encodeStreamRawBodyHeader,
  decodeStreamFrame, decodeMessageStream, FrameError, RpcCallError,
} from "../packages/typescript/dist/framing.js";
import { CallFailureSchema } from "../packages/typescript/dist/errors_pb.js";
import { StreamFrameSchema, StreamDataKind } from "../packages/typescript/dist/v2alpha1/stream_pb.js";
import { ObservationState, StreamProtocolError } from "../packages/typescript/dist/v2alpha1/observation.js";

const bytes = (text) => new TextEncoder().encode(text);
const frame = (sequence, kind, value = {}) => create(StreamFrameSchema, { sequence: BigInt(sequence), body: { case: kind, value } });
const opening = (cursor = "", binding = 7) => ({ bindingDigest: new Uint8Array(32).fill(binding), resumedFrom: bytes(cursor) });
const checkpoint = (cursor, previous = "", snapshot = true) => ({ cursor: bytes(cursor), previousCursor: bytes(previous), snapshotComplete: snapshot });
const reason = (expected) => (error) => error instanceof StreamProtocolError && error.reason === expected;

test("stream codecs match shared Rust wire vectors at every truncation", () => {
  const vectors = JSON.parse(readFileSync(new URL("fixtures/v2-stream-wire.json", import.meta.url)));
  for (const vector of vectors) {
    const encoded = vector.kind === "message" ? encodeStreamMessage(Buffer.from(vector.body_hex, "hex"))
      : vector.kind === "failure" ? encodeStreamFailure(create(CallFailureSchema, { code: vector.code, message: vector.message }))
      : encodeStreamRawBodyHeader(BigInt(vector.length));
    assert.equal(Buffer.from(encoded).toString("hex"), vector.frame_hex);
    for (let cut = 0; cut < encoded.length; cut++) assert.equal(decodeStreamFrame(encoded.subarray(0, cut)), undefined);
    assert.equal(decodeStreamFrame(encoded).consumed, encoded.length);
  }
});

test("protobuf stream reads survive every network chunk boundary", async () => {
  const wire = Buffer.concat([encodeStreamMessage(bytes("first")), encodeStreamMessage(bytes("second"))]);
  for (let cut = 0; cut <= wire.length; cut++) {
    const input = async function* () { yield wire.subarray(0, cut); yield wire.subarray(cut); };
    const output = [];
    for await (const message of decodeMessageStream(input())) output.push(new TextDecoder().decode(message));
    assert.deepEqual(output, ["first", "second"]);
  }
});

test("oversized declaration is rejected before pulling its body", async () => {
  let pulls = 0;
  const input = async function* () {
    pulls++; yield new Uint8Array([0, 0, 0, 0, 3]);
    pulls++; yield bytes("abc");
  };
  await assert.rejects(async () => { for await (const _ of decodeMessageStream(input(), 2)) {} }, FrameError);
  assert.equal(pulls, 1);
  assert.throws(() => encodeStreamMessage(bytes("abc"), 2), FrameError);
  assert.throws(() => decodeStreamFrame(new Uint8Array([0, 0, 0, 0, 3]), 2), FrameError);
});

test("canceling consumption returns the source without read-ahead", async () => {
  let returned = false;
  let pulls = 0;
  const input = async function* () {
    try { pulls++; yield encodeStreamMessage(bytes("first")); pulls++; yield encodeStreamMessage(bytes("second")); }
    finally { returned = true; }
  };
  for await (const _ of decodeMessageStream(input())) break;
  assert.equal(pulls, 1);
  assert.equal(returned, true);
});

test("truncated streams and typed terminal failures cannot appear successful", async () => {
  const input = async function* () { yield new Uint8Array([0, 0, 0, 0, 3, 1]); };
  await assert.rejects(async () => { for await (const _ of decodeMessageStream(input())) {} }, FrameError);
  const failure = create(CallFailureSchema, { code: 7, message: "denied" });
  const failed = async function* () { yield encodeStreamFailure(failure); };
  await assert.rejects(async () => { for await (const _ of decodeMessageStream(failed())) {} }, (error) => error instanceof RpcCallError && error.failure.code === 7);
});

test("only committed observations are resumed after capture reply loss", () => {
  const state = new ObservationState(new Uint8Array(32).fill(7));
  state.accept(frame(1, "open", opening()), false);
  state.accept(frame(2, "data", { kind: StreamDataKind.SNAPSHOT }), true);
  assert.deepEqual(state.cursor, bytes(""));
  state.accept(frame(3, "checkpoint", checkpoint("s0")), false);
  state.accept(frame(4, "data", { kind: StreamDataKind.UPSERT }), true);
  assert.deepEqual(state.cursor, bytes("s0"));
  const resumed = new ObservationState(new Uint8Array(32).fill(7), state.cursor);
  resumed.accept(frame(1, "open", opening("s0")), false);
  resumed.accept(frame(2, "data", { kind: StreamDataKind.UPSERT }), true);
  resumed.accept(frame(3, "checkpoint", checkpoint("s1", "s0", false)), false);
  assert.deepEqual(resumed.cursor, bytes("s1"));
});

test("bad sequence, binding, resume and phase leave the checkpoint unchanged", () => {
  const state = new ObservationState(new Uint8Array(32).fill(7));
  assert.throws(() => state.accept(frame(1, "open", opening("", 8)), false), reason("binding"));
  state.accept(frame(1, "open", opening()), false);
  assert.throws(() => state.accept(frame(3, "checkpoint", checkpoint("s0")), false), reason("sequence"));
  assert.throws(() => state.accept(frame(2, "complete"), false), reason("phase"));
  assert.throws(() => state.accept(frame(2, "data", { kind: 999 }), true), reason("phase"));
  assert.deepEqual(state.cursor, bytes(""));
  const resumed = new ObservationState(new Uint8Array(32).fill(7), bytes("s0"));
  assert.throws(() => resumed.accept(frame(1, "open", opening("other")), false), reason("resume"));
});

test("checkpoint cursor bounds and payload rules are enforced", () => {
  const state = new ObservationState(new Uint8Array(32).fill(7));
  assert.throws(() => state.accept(frame(1, "open", opening()), true), reason("payload"));
  state.accept(frame(1, "open", opening()), false);
  assert.throws(() => state.accept(frame(2, "checkpoint", checkpoint("x".repeat(4097))), false), reason("cursor"));
  assert.deepEqual(state.cursor, bytes(""));
  state.accept(frame(2, "checkpoint", checkpoint("s0")), false);
  const external = state.cursor; external[0] = 0;
  assert.deepEqual(state.cursor, bytes("s0"));
});

test("reset discards resumability and terminates the stream", () => {
  const state = new ObservationState(new Uint8Array(32).fill(7), bytes("s0"));
  state.accept(frame(1, "reset", { reason: 1 }), false);
  assert.deepEqual(state.cursor, bytes(""));
  assert.equal(state.isComplete, false);
  assert.throws(() => state.accept(frame(2, "open", opening()), false), reason("phase"));
});

test("failed view reducer cannot advance the resume cursor", async () => {
  const state = new ObservationState(new Uint8Array(32).fill(7));
  state.accept(frame(1, "open", opening()), false);
  const next = frame(2, "checkpoint", checkpoint("s0"));
  await assert.rejects(state.apply(next, false, () => { throw new Error("storage unavailable"); }), /storage unavailable/);
  assert.deepEqual(state.cursor, bytes(""));
  await state.apply(next, false, (action, cursor) => { assert.equal(action.kind, "commit"); assert.deepEqual(cursor, bytes("s0")); });
  assert.deepEqual(state.cursor, bytes("s0"));
});

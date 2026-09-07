import { StreamDataKind, type StreamFrame } from "./stream_pb.js";

export const MAX_CURSOR_BYTES = 4096;
export type StreamProtocolReason = "sequence" | "binding" | "resume" | "phase" | "payload" | "cursor";
export class StreamProtocolError extends Error {
  constructor(readonly reason: StreamProtocolReason) {
    super(`Invalid observation stream: ${reason}`);
    this.name = "StreamProtocolError";
  }
}

export type ObservationAction =
  | { kind: "beginSnapshot" }
  | { kind: "resumed" }
  | { kind: "stage"; dataKind: StreamDataKind }
  | { kind: "commit" }
  | { kind: "heartbeat" }
  | { kind: "reset" }
  | { kind: "complete" };

type Phase = "opening" | "snapshot" | "live" | "reset" | "complete";
const equal = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((value, index) => value === b[index]);

/** Transport adapters enforce byte budgets before decoding and authenticate
 * the endpoint. Typed reducers stage data and persist a checkpoint only after
 * applying the corresponding batch. A rejected frame leaves this state intact.
 */
export class ObservationState {
  private readonly binding: Uint8Array;
  private committedCursor: Uint8Array;
  private sequence = 0n;
  private phase: Phase = "opening";
  private pending = false;
  private applying = false;

  constructor(bindingDigest: Uint8Array, cursor = new Uint8Array()) {
    if (bindingDigest.length !== 32) throw new StreamProtocolError("binding");
    this.binding = bindingDigest.slice();
    this.committedCursor = cursor.slice();
  }

  get cursor(): Uint8Array { return this.committedCursor.slice(); }
  get isComplete(): boolean { return this.phase === "complete"; }

  clone(): ObservationState {
    const copy = new ObservationState(this.binding, this.committedCursor);
    copy.sequence = this.sequence;
    copy.phase = this.phase;
    copy.pending = this.pending;
    return copy;
  }

  accept(frame: StreamFrame, hasPayload: boolean): ObservationAction {
    if (this.applying) throw new StreamProtocolError("phase");
    if (this.phase === "reset" || this.phase === "complete") throw new StreamProtocolError("phase");
    if (frame.sequence !== this.sequence + 1n || frame.sequence > 0xffff_ffff_ffff_ffffn) {
      throw new StreamProtocolError("sequence");
    }
    const body = frame.body;
    if (body.case === undefined) throw new StreamProtocolError("phase");
    if (hasPayload !== (body.case === "data")) throw new StreamProtocolError("payload");
    let action: ObservationAction;
    switch (body.case) {
      case "open": {
        if (this.phase !== "opening") throw new StreamProtocolError("phase");
        if (!equal(body.value.bindingDigest, this.binding)) throw new StreamProtocolError("binding");
        if (!equal(body.value.resumedFrom, this.committedCursor)) throw new StreamProtocolError("resume");
        if (this.committedCursor.length > MAX_CURSOR_BYTES) throw new StreamProtocolError("cursor");
        this.phase = this.committedCursor.length === 0 ? "snapshot" : "live";
        action = { kind: this.phase === "snapshot" ? "beginSnapshot" : "resumed" };
        break;
      }
      case "data": {
        const dataKind = body.value.kind;
        const valid = this.phase === "snapshot"
          ? dataKind === StreamDataKind.SNAPSHOT
          : this.phase === "live" && (dataKind === StreamDataKind.UPSERT || dataKind === StreamDataKind.REMOVE);
        if (!valid) throw new StreamProtocolError("phase");
        this.pending = true;
        action = { kind: "stage", dataKind };
        break;
      }
      case "checkpoint": {
        const checkpoint = body.value;
        if ((this.phase !== "snapshot" && this.phase !== "live") || checkpoint.snapshotComplete !== (this.phase === "snapshot")) {
          throw new StreamProtocolError("phase");
        }
        if (!equal(checkpoint.previousCursor, this.committedCursor) || checkpoint.cursor.length === 0
          || checkpoint.cursor.length > MAX_CURSOR_BYTES || equal(checkpoint.cursor, this.committedCursor)) {
          throw new StreamProtocolError("cursor");
        }
        this.committedCursor = checkpoint.cursor.slice();
        this.phase = "live";
        this.pending = false;
        action = { kind: "commit" };
        break;
      }
      case "reset": {
        this.phase = "reset";
        this.committedCursor = new Uint8Array();
        this.pending = false;
        action = { kind: "reset" };
        break;
      }
      case "complete": {
        if (this.phase !== "live" || this.pending) throw new StreamProtocolError("phase");
        if (!equal(body.value.cursor, this.committedCursor)) throw new StreamProtocolError("cursor");
        this.phase = "complete";
        action = { kind: "complete" };
        break;
      }
      case "heartbeat": {
        if (this.phase === "opening") throw new StreamProtocolError("phase");
        action = { kind: "heartbeat" };
        break;
      }
    }
    this.sequence = frame.sequence;
    return action;
  }

  /** The reducer must atomically apply a committed batch and persist its cursor.
   * Await each call: concurrent reducers are rejected rather than reordered.
   */
  async apply(frame: StreamFrame, hasPayload: boolean,
    reducer: (action: ObservationAction, cursor: Uint8Array) => void | Promise<void>,
  ): Promise<ObservationAction> {
    if (this.applying) throw new StreamProtocolError("phase");
    const next = this.clone();
    const action = next.accept(frame, hasPayload);
    this.applying = true;
    try {
      await reducer(action, next.cursor);
      this.sequence = next.sequence;
      this.phase = next.phase;
      this.pending = next.pending;
      this.committedCursor = next.cursor;
      return action;
    } finally {
      this.applying = false;
    }
  }
}

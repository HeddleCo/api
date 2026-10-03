import { create } from "@bufbuild/protobuf";
import { ReadBudgetSchema, type ReadBudget } from "./stream_pb.js";

/** Minimum advertised maximum on every endpoint, including devices/providers. */
export const GUARANTEED_READ_BUDGET: Readonly<ReadBudget> = Object.freeze(create(ReadBudgetSchema, {
  maxItems: 1024, maxFrameBytes: 524288, maxSnapshotBytes: 4194304n,
}));
export class ReadBudgetError extends Error {
  constructor(readonly reason: "advertisement" | "shape" | "capacity" | "echo") {
    super(`Invalid ReadBudget ${reason}`);
    this.name = "ReadBudgetError";
  }
}
const nonzero = (b: ReadBudget): boolean => b.maxItems > 0 && b.maxFrameBytes > 0 && b.maxSnapshotBytes > 0n;
const within = (a: ReadBudget, b: ReadBudget): boolean => a.maxItems <= b.maxItems
  && a.maxFrameBytes <= b.maxFrameBytes && a.maxSnapshotBytes <= b.maxSnapshotBytes;
const minimum = (a: ReadBudget, b: ReadBudget): ReadBudget => create(ReadBudgetSchema, {
  maxItems: Math.min(a.maxItems, b.maxItems), maxFrameBytes: Math.min(a.maxFrameBytes, b.maxFrameBytes),
  maxSnapshotBytes: a.maxSnapshotBytes < b.maxSnapshotBytes ? a.maxSnapshotBytes : b.maxSnapshotBytes,
});
const resolve = (requested: ReadBudget, defaults: ReadBudget): ReadBudget => create(ReadBudgetSchema, {
  maxItems: requested.maxItems || defaults.maxItems,
  maxFrameBytes: requested.maxFrameBytes || defaults.maxFrameBytes,
  maxSnapshotBytes: requested.maxSnapshotBytes || defaults.maxSnapshotBytes,
});
const validWire = (b: ReadBudget): boolean => Number.isInteger(b.maxItems) && b.maxItems >= 0 && b.maxItems <= 0xffffffff
  && Number.isInteger(b.maxFrameBytes) && b.maxFrameBytes >= 0 && b.maxFrameBytes <= 0xffffffff
  && b.maxSnapshotBytes >= 0n && b.maxSnapshotBytes <= 0xffffffffffffffffn;

/** Clamp before matching data. Hosts also check fixed selection overhead.
 * Map shape to INVALID_ARGUMENT and capacity to retryable UNAVAILABLE. */
export function negotiateReadBudget(requested: ReadBudget, defaults: ReadBudget,
  maximum: ReadBudget, capacity: ReadBudget): ReadBudget {
  if (!validWire(requested)) throw new ReadBudgetError("shape");
  if (!validWire(defaults) || !validWire(maximum) || !nonzero(defaults) || !within(defaults, maximum)
    || !within(GUARANTEED_READ_BUDGET, maximum) || defaults.maxFrameBytes < 1024
    || defaults.maxSnapshotBytes < BigInt(defaults.maxFrameBytes)) throw new ReadBudgetError("advertisement");
  if (!validWire(capacity)) throw new ReadBudgetError("capacity");
  const resolved = resolve(requested, defaults);
  const bounded = minimum(resolved, maximum);
  if (bounded.maxFrameBytes < 1024 || bounded.maxSnapshotBytes < BigInt(bounded.maxFrameBytes)) {
    throw new ReadBudgetError("shape");
  }
  const accepted = minimum(bounded, capacity);
  if (!within(minimum(resolved, GUARANTEED_READ_BUDGET), accepted)
    || accepted.maxFrameBytes < 1024 || accepted.maxSnapshotBytes < BigInt(accepted.maxFrameBytes)) {
    throw new ReadBudgetError("capacity");
  }
  return accepted;
}

/** Validate the echo without DescribeEndpoint; zero fields have no known default. */
export function validateAcceptedReadBudget(requested: ReadBudget, accepted: ReadBudget | undefined): void {
  const unlimited = create(ReadBudgetSchema, { maxItems: 0xffffffff, maxFrameBytes: 0xffffffff, maxSnapshotBytes: 0xffffffffffffffffn });
  if (!validWire(requested) || !accepted || !validWire(accepted) || !nonzero(accepted)
    || !within(accepted, resolve(requested, unlimited)) || !within(minimum(requested, GUARANTEED_READ_BUDGET), accepted)
    || accepted.maxFrameBytes < 1024 || accepted.maxSnapshotBytes < BigInt(accepted.maxFrameBytes)) {
    throw new ReadBudgetError("echo");
  }
}

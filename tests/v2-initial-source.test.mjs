import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { create, toBinary, fromBinary } from "@bufbuild/protobuf";
import { ImportSourceRequestSchema } from "../packages/typescript/dist/v2alpha1/integration_pb.js";
import { syntheticInitialBase } from "../packages/typescript/dist/v2alpha1/initial-source.js";

const vector = Object.fromEntries(readFileSync(new URL("fixtures/synthetic-initial-base-v2.txt", import.meta.url), "utf8").trim().split("\n").map(line => line.split("=")));
test("browser import bootstrap preserves Rust's exact synthetic seed bytes and identity", () => {
  const seed = syntheticInitialBase();
  assert.equal(Buffer.from(seed.stateId).toString("hex"), vector.id);
  assert.equal(Buffer.from(seed.canonicalState).toString("hex"), vector.canonical);
  const request = create(ImportSourceRequestSchema, { initialBaseState: seed.canonicalState });
  assert.deepEqual(fromBinary(ImportSourceRequestSchema, toBinary(ImportSourceRequestSchema, request)).initialBaseState, seed.canonicalState);
  seed.stateId.fill(0);
  seed.canonicalState.fill(0);
  const fresh = syntheticInitialBase();
  assert.equal(Buffer.from(fresh.stateId).toString("hex"), vector.id);
  assert.equal(Buffer.from(fresh.canonicalState).toString("hex"), vector.canonical);
});

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import * as api from "../packages/typescript/dist/v1alpha2/index.js";

const fixture = JSON.parse(readFileSync(new URL("fixtures/v2-alpha22.json", import.meta.url)));
const budget = (v) => create(api.ReadBudgetSchema, {
  maxItems: v[0], maxFrameBytes: v[1], maxSnapshotBytes: BigInt(v[2]),
});

test("alpha22 clear semantics preserve hidden settings and authorize explicit clears", () => {
  assert.equal(typeof api.applySpoolSettingsPatch, "function", "explicit-clear helper must be exported");
  const stored = create(api.SpoolSettingsSchema, {
    description: "before", defaultThread: { id: { value: new Uint8Array(32).fill(3) } },
    defaultReviewPolicy: { id: "policy" },
  });
  const filtered = create(api.SpoolSettingsSchema, { description: "after" });
  const updated = api.applySpoolSettingsPatch(stored, filtered, { paths: ["description"] }, () => false);
  assert.deepEqual(updated.defaultThread, stored.defaultThread);
  assert.deepEqual(updated.defaultReviewPolicy, stored.defaultReviewPolicy);
  assert.equal(updated.description, "after");
  assert.deepEqual(api.applySpoolSettingsPatch(stored, filtered, undefined, () => false), stored);
  for (const field of ["default_thread", "default_review_policy"]) {
    const mask = { paths: [field] };
    assert.throws(() => api.applySpoolSettingsPatch(stored, filtered, mask, () => false), /clearDenied/);
    const cleared = api.applySpoolSettingsPatch(stored, filtered, mask, () => true);
    assert.equal(cleared[field === "default_thread" ? "defaultThread" : "defaultReviewPolicy"], undefined);
  }
  assert.equal(stored.description, "before", "patches never mutate stored settings");
  for (const path of ["*", "default_thread.id", "settings.description", "unknown"]) {
    assert.throws(() => api.applySpoolSettingsPatch(stored, filtered, { paths: [path] }, () => true), /mask/);
  }
  assert.throws(() => api.applySpoolSettingsPatch(stored, filtered, { paths: ["description", "description"] }, () => true), /mask/);
  for (const [path, property] of Object.entries(fixture.settings_fields)) {
    const result = api.applySpoolSettingsPatch(stored, undefined, { paths: [path] }, () => true);
    assert.deepEqual(result[property], create(api.SpoolSettingsSchema)[property]);
  }
});

test("alpha22 ReadBudget clamps fixed requests and enforces the guaranteed floor", () => {
  assert.equal(typeof api.negotiateReadBudget, "function", "ReadBudget clamp helper must be exported");
  assert.deepEqual(budget(fixture.floor), api.GUARANTEED_READ_BUDGET);
  for (const vector of fixture.budgets) {
    const args = [vector.requested, vector.defaults, vector.maximum, vector.capacity].map(budget);
    if (vector.error) {
      assert.throws(() => api.negotiateReadBudget(...args), new RegExp(vector.error), vector.name);
    } else {
      const accepted = api.negotiateReadBudget(...args);
      assert.deepEqual(accepted, budget(vector.accepted), vector.name);
      api.validateAcceptedReadBudget(args[0], accepted);
    }
  }
  const requested = budget(fixture.floor);
  for (const echo of [undefined, budget([0, 0, "0"]), budget([1025, 524288, "4194304"]), budget([1023, 524288, "4194304"])]) {
    assert.throws(() => api.validateAcceptedReadBudget(requested, echo), /echo/);
  }
});

test("alpha22 integrated_at round trips the landing time independently of updated_at", () => {
  const bytes = Buffer.from(fixture.thread_wire_hex, "hex");
  const overview = fromBinary(api.ThreadOverviewSchema, bytes);
  assert.equal(overview.integratedAt.seconds, BigInt(fixture.integrated_at));
  assert.notDeepEqual(overview.updatedAt, overview.integratedAt);
  assert.equal(Buffer.from(toBinary(api.ThreadOverviewSchema, overview)).toString("hex"), fixture.thread_wire_hex);
  assert.equal(create(api.ThreadOverviewSchema).integratedAt, undefined);
});

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
    audience: 3, defaultStateAudience: 2, allowChildCreation: true, requireReviewToLand: true,
    abandonedThreadRetention: { seconds: 20n }, holdLifecycle: 1, blockingDiscussionResolveRule: 1,
    description: "before", defaultThread: { id: { value: new Uint8Array(32).fill(3) } },
    defaultReviewPolicy: { id: "policy" },
  });
  assert.equal(Buffer.from(toBinary(api.SpoolSettingsSchema, stored)).toString("hex"), fixture.settings_wire_hex);
  assert.deepEqual(api.applySpoolSettingsPatch(create(api.SpoolSettingsSchema), stored,
    { paths: Object.keys(fixture.settings_fields) }, () => false), stored);
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
    assert.equal(Buffer.from(toBinary(api.SpoolSettingsSchema, result)).toString("hex"), fixture.cleared_settings_wire_hex[path]);
    assert.throws(() => api.applySpoolSettingsPatch(stored, undefined, { paths: [path] }, () => false), /clearDenied/);
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
      assert.equal(Buffer.from(toBinary(api.ReadBudgetSchema, accepted)).toString("hex"), vector.accepted_wire_hex);
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

test("alpha22 mask and finite echoes share Rust wire vectors", () => {
  for (const [message, wire] of Object.entries(fixture.echoes_wire_hex)) {
    const schema = api[`${message}Schema`];
    const decoded = fromBinary(schema, Buffer.from(wire, "hex"));
    const accepted = message.endsWith("Event") ? decoded.payload.value : decoded.acceptedBudget;
    if (message.endsWith("Event")) assert.equal(decoded.payload.case, "acceptedBudget");
    api.validateAcceptedReadBudget(budget(fixture.floor), accepted);
    assert.equal(Buffer.from(toBinary(schema, decoded)).toString("hex"), wire);
  }
  const request = fromBinary(api.ReviseSpoolRequestSchema, Buffer.from(fixture.clear_request_wire_hex, "hex"));
  assert.deepEqual(request.settingsMask.paths, ["default_thread", "default_review_policy"]);
  assert.equal(request.settings, undefined, "mask alone explicitly clears selected messages");
});

test("alpha22 replacements authorize both stored references and fail atomically", () => {
  const stored = fromBinary(api.SpoolSettingsSchema, Buffer.from(fixture.settings_wire_hex, "hex"));
  for (const vector of fixture.replacement_cases) {
    const patch = fromBinary(api.SpoolSettingsSchema, Buffer.from(vector.patch_wire_hex, "hex"));
    const mask = { paths: vector.mask };
    const calls = [];
    assert.throws(() => api.applySpoolSettingsPatch(stored, patch, mask, (field) => {
      calls.push(field);
      return !vector.denied.includes(field);
    }), /clearDenied/, vector.field);
    assert.deepEqual(calls, vector.mask.filter((field) => field !== "description"), "check the stored references");
    const authorized = api.applySpoolSettingsPatch(stored, patch, mask, () => true);
    for (const field of vector.mask) assert.deepEqual(authorized[fixture.settings_fields[field]], patch[fixture.settings_fields[field]]);
    assert.equal(Buffer.from(toBinary(api.SpoolSettingsSchema, stored)).toString("hex"), fixture.settings_wire_hex);
  }
  // Equal references (including separate decoded objects) do not remove a value.
  const same = fromBinary(api.SpoolSettingsSchema, Buffer.from(fixture.settings_wire_hex, "hex"));
  assert.deepEqual(api.applySpoolSettingsPatch(stored, same,
    { paths: ["default_thread", "default_review_policy"] }, () => false), stored);
});

for (const [index, dimension] of ["items", "frame", "snapshot"].entries()) {
  test(`alpha22 advertised floor isolates ${dimension}`, () => {
    const vector = fixture.budgets.find((v) => v.name === `below floor ${dimension} only`);
    assert.ok(vector, `missing isolated ${dimension} floor vector`);
    const [requested, defaults, maximum, capacity] = [vector.requested, vector.defaults, vector.maximum, vector.capacity].map(budget);
    for (let i = 0; i < 3; i++) {
      assert.ok(BigInt(vector.defaults[i]) <= BigInt(vector.maximum[i]), "defaults <= maximum");
      assert.equal(BigInt(vector.maximum[i]) < BigInt(fixture.floor[i]), i === index, "one deficient dimension");
    }
    assert.throws(() => api.negotiateReadBudget(requested, defaults, maximum, capacity), /advertisement/);
  });
}

const contract = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8").replace(/\s+/g, " ");
function methodMinimum(path, name) {
  const source = contract(path);
  const match = source.match(new RegExp(`${name} = \\{ max_items: (\\d+), max_frame_bytes: (\\d+), max_snapshot_bytes: (\\d+) \\}`));
  assert.ok(match, `missing pre-matching ${name}`);
  return budget([Number(match[1]), Number(match[2]), match[3]]);
}

test("alpha22 oversized first paths and unary definitions have pre-matching bounds", () => {
  const navigation = contract("docs/alpha-v2/code-navigation.md");
  const paths = contract("docs/alpha-v2/cleanup-lane.md");
  const navMinimum = methodMinimum("docs/alpha-v2/code-navigation.md", "CODE_NAVIGATION_MIN_READ_BUDGET");
  const pathMinimum = methodMinimum("docs/alpha-v2/cleanup-lane.md", "LIST_PATHS_MIN_READ_BUDGET");
  for (const [type, limit] of [["CodeSymbol", 16384], ["CodeOccurrence", 16384], ["CodeSemanticRef", 32768], ["CodeImporter", 32768], ["CodeNavigationMetadata", 8192], ["PageInfo", 8192]]) {
    assert.ok(navigation.includes(`\`${type}\` | ${limit} |`), `${type} must have an encoded bound`);
  }
  assert.match(navigation, /admission.*INVALID_ARGUMENT/);
  assert.match(navigation, /existing.*NO_INDEX/);
  assert.match(paths, /leaf path.*16384 UTF-8 bytes/);
  assert.match(paths, /admission.*INVALID_ARGUMENT/);
  assert.match(paths, /existing.*UNAVAILABLE/);
  const small = api.negotiateReadBudget(budget([20, 1024, "2048"]), budget(fixture.floor), budget(fixture.floor), budget(fixture.floor));
  const definition = create(api.GetDefinitionResponseSchema, {
    outcome: { case: "definition", value: { name: "x".repeat(1500) } }, acceptedBudget: small,
  });
  const firstPath = create(api.ListPathsEventSchema, { payload: { case: "path", value: "x".repeat(1500) } });
  assert.ok(toBinary(api.GetDefinitionResponseSchema, definition).length > small.maxFrameBytes);
  assert.ok(toBinary(api.ListPathsEventSchema, firstPath).length > small.maxFrameBytes);
  for (const minimum of [navMinimum, pathMinimum]) {
    // The method rejects this request before inspecting either oversized match.
    assert.ok(small.maxFrameBytes < minimum.maxFrameBytes);
    assert.ok(small.maxSnapshotBytes < minimum.maxSnapshotBytes);
    const accepted = api.negotiateReadBudget(minimum, budget(fixture.floor), budget(fixture.floor), budget(fixture.floor));
    assert.deepEqual(accepted, minimum);
    assert.ok(32768 + 8192 + 8192 + 1024 <= accepted.maxFrameBytes, "maximum row + metadata/page/control envelope fits");
    assert.ok(32768 + 8192 + 8192 + 1024 <= accepted.maxSnapshotBytes, "first visible row always makes progress");
  }
  // Largest admitted definition/occurrence pair fits, including its wire wrappers.
  const symbol = create(api.CodeSymbolSchema, { name: "x".repeat(16380) });
  const occurrence = create(api.CodeOccurrenceSchema, { name: "x".repeat(16380) });
  assert.equal(toBinary(api.CodeSymbolSchema, symbol).length, 16384);
  assert.equal(toBinary(api.CodeOccurrenceSchema, occurrence).length, 16384);
  const maximumDefinition = create(api.GetDefinitionResponseSchema, {
    occurrence, outcome: { case: "definition", value: symbol }, acceptedBudget: navMinimum,
  });
  assert.ok(toBinary(api.GetDefinitionResponseSchema, maximumDefinition).length + 8192 + 1024 <= navMinimum.maxFrameBytes);
  const maximumPath = create(api.ListPathsEventSchema, { payload: { case: "path", value: "é".repeat(8192) } });
  assert.ok(toBinary(api.ListPathsEventSchema, maximumPath).length + 8192 < 32768);
  for (const file of ["proto/heddle/api/v1alpha2/code_navigation.proto", "proto/heddle/api/v1alpha2/content.proto", "proto/heddle/api/v1alpha2/stream.proto", "docs/alpha-v2/streams.md"]) {
    assert.match(contract(file), /per-method.*(minimum|bounds)/, `${file} must reference the method bounds`);
  }
});

test("alpha22 LATEST resumes the fixed initial remainder before newer records", () => {
  const source = contract("proto/heddle/api/v1alpha2/device.proto");
  for (const rule of [/cursor retains.*initial.*boundary/, /PARTIAL.*empty next_page/, /remainder.*UPSERT/, /before.*newer positions/, /snapshot_complete.*coverage/, /after_cursor.*remainder/]) {
    assert.match(source, rule, "LATEST must define a consumable stream continuation");
  }
  const text = contract("docs/alpha-v2/streams.md");
  assert.match(text, /LATEST.*initial.*boundary.*remainder/);
  const bytes = (s) => new TextEncoder().encode(s);
  const binding = new Uint8Array(32).fill(7);
  const accepted = budget([6, 65536, "65536"]);
  const event = (sequence, body, payload) => fromBinary(api.RunEventSchema, toBinary(api.RunEventSchema, create(api.RunEventSchema, {
    frame: { sequence: BigInt(sequence), body }, payload,
  })));
  let state = new api.ObservationState(binding);
  let staged = [];
  const positions = [];
  let coverage;
  const accept = (e) => {
    const action = state.accept(e.frame, e.payload.case !== undefined);
    if (action.kind === "stage") staged.push(e.payload);
    if (action.kind === "commit") {
      for (const p of staged) {
        if (p.case === "timeline") positions.push(Number(p.value.position));
        if (p.case === "status") coverage = p.value.coverage;
      }
      staged = [];
    }
  };
  const open = (resumedFrom = new Uint8Array()) => ({ case: "open", value: { bindingDigest: binding, acceptedBudget: accepted, resumedFrom } });
  const data = (kind) => ({ case: "data", value: { kind } });
  const status = (complete) => ({ case: "status", value: { section: "timeline", coverage: complete ? api.Coverage.COMPLETE : api.Coverage.PARTIAL, page: { exhausted: complete } } });
  const checkpoint = (cursor, previousCursor, snapshotComplete) => ({ case: "checkpoint", value: { cursor: bytes(cursor), previousCursor: bytes(previousCursor), snapshotComplete } });
  accept(event(1, open()));
  accept(event(2, data(api.StreamDataKind.SNAPSHOT), { case: "run", value: { ref: { id: "run-7" } } }));
  accept(event(3, data(api.StreamDataKind.SNAPSHOT), { case: "policy", value: {} }));
  accept(event(4, data(api.StreamDataKind.SNAPSHOT), { case: "timeline", value: { position: 98n } }));
  accept(event(5, data(api.StreamDataKind.SNAPSHOT), status(false)));
  accept(event(6, checkpoint("fixed-98-100:98", "", true)));
  assert.deepEqual(positions, [98]);
  assert.equal(coverage, api.Coverage.PARTIAL, "committed snapshot does not mean selection complete");
  // Position 101 arrives after the original latest-3 boundary (98..100).
  // Reconnect using only after_cursor, never a page token or a new latest-N query.
  const request = create(api.ObserveRunsRequestSchema, {
    runs: [{ id: "run-7" }], includeTimeline: true, timelineStart: api.TimelineStart.LATEST, timelineLimit: 3,
    observe: { afterCursor: state.cursor, budget: accepted },
  });
  assert.equal(request.page, undefined);
  state = new api.ObservationState(binding, request.observe.afterCursor);
  accept(event(1, open(request.observe.afterCursor)));
  accept(event(2, data(api.StreamDataKind.UPSERT), { case: "timeline", value: { position: 99n } }));
  accept(event(3, data(api.StreamDataKind.UPSERT), { case: "timeline", value: { position: 100n } }));
  accept(event(4, data(api.StreamDataKind.UPSERT), status(true)));
  accept(event(5, checkpoint("fixed-98-100:100", "fixed-98-100:98", false)));
  assert.deepEqual(positions, [98, 99, 100]);
  assert.equal(coverage, api.Coverage.COMPLETE);
  accept(event(6, data(api.StreamDataKind.UPSERT), { case: "timeline", value: { position: 101n } }));
  accept(event(7, checkpoint("live:101", "fixed-98-100:100", false)));
  assert.deepEqual(positions, [98, 99, 100, 101]);
});

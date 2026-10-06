import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { create, toBinary, fromBinary } from "@bufbuild/protobuf";
import { TimestampSchema } from "@bufbuild/protobuf/wkt";
import { CallFailureSchema, ErrorDetailSchema, CallFailureCode, ErrorReason } from "../packages/typescript/dist/common/errors_pb.js";
import { GrantRecordSchema } from "../packages/typescript/dist/v1alpha2/administration_pb.js";
import { ActionAvailabilitySchema, Capability, RecordRefSchema, RequirementKind, RequirementSchema, SpoolRefSchema } from "../packages/typescript/dist/v1alpha2/common_pb.js";
import { EndpointRefSchema } from "../packages/typescript/dist/v1alpha2/stream_pb.js";
import { membershipFloor, membershipFloorActions, membershipFloorBatch } from "../packages/typescript/dist/v1alpha2/membership-floor.js";
const fixture = JSON.parse(readFileSync(new URL("./fixtures/membership-floors.json", import.meta.url)));
assert.equal(fixture.cases.length, 30);
const time = value => value ? create(TimestampSchema, { seconds: BigInt(value.seconds), nanos: value.nanos }) : undefined;
const ref = value => create(RecordRefSchema, { id: value.id, spool: create(SpoolRefSchema, { id: value.spool }) });
const candidate = p => ({ grant: ref(p.grant), subject: p.subject, role: p.role, kind: p.kind, personalOwner: p.personal_owner, expiresAt: time(p.expires_at) });
const change = c => ({ grant: ref(c.grant), role: c.role, field: c.field, expiresAt: time(c.expires_at) });
const fallback = create(CallFailureSchema, { code: CallFailureCode.NOT_FOUND, message: "grant unavailable", error: create(ErrorDetailSchema, { reason: ErrorReason.RESOURCE_NOT_FOUND, field: "grant" }) });
const context = (authorized, operationAuthorized = authorized) => ({ now: time(fixture.now), canManageGrants: authorized, operationAuthorized, existingRefusal: fallback });
const removed = process.env.MEMBERSHIP_FLOOR_REMOVED_RULE;
assert.ok(!removed || fixture.cases.some(c => (c.removed_rule ?? c.reason.toString()) === removed));
for (const v of fixture.cases.filter(c => !removed || (c.removed_rule ?? c.reason.toString()) === removed)) {
  test(v.name, () => {
    const failure = v.changes
      ? membershipFloorBatch(v.candidates.map(candidate), v.changes.map(change), v.change.field, context(v.can_manage_grants, v.operation_authorized))
      : membershipFloor(v.candidates.map(candidate), change(v.change), context(v.can_manage_grants, v.operation_authorized));
    if (removed || v.reason === 0) { assert.equal(failure, undefined, v.name); return; }
    assert.ok(failure, v.name);
    if (!v.can_manage_grants || !v.operation_authorized) assert.deepEqual(failure, fallback);
    else {
      assert.equal(failure.code, CallFailureCode.FAILED_PRECONDITION);
      assert.equal(failure.error.reason, v.reason);
      assert.equal(failure.error.field, v.change.field);
      assert.equal(failure.error.resource, "");
      assert.equal(failure.error.context.case, undefined);
    }
    assert.deepEqual(fromBinary(CallFailureSchema, toBinary(CallFailureSchema, failure)), failure);
  });
}
if (!removed) {
  test("personal owner precedes both count floors", () => {
    const v = fixture.cases[0];
    assert.equal(membershipFloor([candidate(v.candidates[0])], change(v.change), context(true)).error.reason, 506);
  });
  test("per-visible-grant advice is targeted, typed and wire safe", () => {
    const v = fixture.cases[4];
    const candidates = v.candidates.map(candidate);
    const visible = candidates.map(p => create(GrantRecordSchema, { ref: p.grant, role: p.role, version: new Uint8Array([1]) }));
    for (const authorized of [true, false]) {
      const actions = membershipFloorActions(visible, candidates, { floor: context(authorized), endpoint: create(EndpointRefSchema), implemented: true });
      assert.equal(actions.length, 4);
      actions.forEach((action, i) => {
        assert.equal(action.authorized, authorized);
        assert.equal(action.implemented, true);
        assert.equal(action.target.entity.case, "grant");
        assert.deepEqual(action.target.entity.value, visible[Math.floor(i / 2)].ref);
        assert.deepEqual(action.observedVersions[0].resource, action.target);
        assert.deepEqual(action.observedVersions[0].version, new Uint8Array([1]));
        assert.equal(action.method, `/heddle.api.v1alpha2.SpoolService/${i % 2 === 0 ? "RevokeGrant" : "PutGrant"}`);
        assert.equal(action.capability, i % 2 === 0 ? Capability.REVOKE_GRANT : Capability.PUT_GRANT);
        if (authorized && i < 2) {
          assert.equal(action.requirements[0].kind, RequirementKind.POLICY);
          assert.deepEqual(action.requirements[0].subject, action.target);
          assert.equal(action.requirements[0].error.reason, 508);
          assert.equal(action.requirements[0].error.field, i === 0 ? "grant" : "grant.role");
        } else if (authorized) assert.deepEqual(action.requirements, []);
        else assert.ok(action.requirements.every(r => !r.error));
        assert.deepEqual(fromBinary(ActionAvailabilitySchema, toBinary(ActionAvailabilitySchema, action)), action);
      });
    }
    const hidden = fixture.cases[12].candidates.map(candidate);
    const actions = membershipFloorActions(visible.slice(0, 1), hidden, { floor: context(true), endpoint: create(EndpointRefSchema), implemented: true });
    assert.equal(actions.length, 2);
    assert.ok(actions.every(a => a.requirements.length === 0));
    assert.ok(!JSON.stringify(actions).includes('"hidden"'));
  });
  test("JavaScript authorization flags and absent fallbacks fail closed", () => {
    const v = fixture.cases[0];
    const unreadable = [{ get kind() { assert.fail("unauthorized membership inspection"); } }];
    for (const operationAuthorized of [false, undefined, null, "true", "false", 1]) {
      const floor = { ...context(false), operationAuthorized };
      assert.equal(membershipFloor(unreadable, change(v.change), floor), fallback);
      const actions = membershipFloorActions([create(GrantRecordSchema, { ref: ref(v.change.grant), role: 3 })], unreadable,
        { floor, endpoint: create(EndpointRefSchema), implemented: true });
      assert.ok(actions.every(a => a.authorized === false && a.requirements[0].kind === RequirementKind.CAPABILITY && !a.requirements[0].error));
    }
    const protectedCandidates = v.candidates.map(candidate);
    for (const canManageGrants of [false, undefined, null, "true", "false", 1]) {
      const floor = { ...context(true), canManageGrants };
      assert.equal(membershipFloor(protectedCandidates, change(v.change), floor), fallback);
      const actions = membershipFloorActions([create(GrantRecordSchema, { ref: ref(v.change.grant), role: 3 })], protectedCandidates,
        { floor, endpoint: create(EndpointRefSchema), implemented: true });
      assert.equal(actions[0].authorized, true);
      assert.equal(actions[0].requirements.length, 1);
      assert.equal(actions[0].requirements[0].error, undefined);
      assert.equal(actions[1].authorized, true);
      assert.equal(actions[1].requirements.length, 0);
    }
    for (const existingRefusal of [undefined, null, false, 0, ""]) {
      assert.throws(() => membershipFloor(unreadable, change(v.change), { ...context(false), existingRefusal }), /MembershipFloorContext:/);
    }
  });
  test("stable reason numbers and minimal requirement wire addition", () => {
    assert.deepEqual([ErrorReason.PERSONAL_SPOOL_OWNER_ACCESS_REQUIRED, ErrorReason.SPOOL_LAST_MEMBER, ErrorReason.SPOOL_LAST_ADMINISTRATOR], [506, 507, 508]);
    assert.equal(RequirementSchema.fields.find(f => f.name === "error").number, 8);
    assert.equal(Capability.REVOKE_GRANT, 12);
  });
}

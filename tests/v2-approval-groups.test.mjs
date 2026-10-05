import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { create, toBinary, fromBinary } from "@bufbuild/protobuf";
import { ApprovalGroupRecordSchema, ReviewPolicyRecordSchema, ApprovalGroupViewSchema } from "../packages/typescript/dist/v1alpha2/administration_pb.js";
import { SuggestedPrincipalSchema } from "../packages/typescript/dist/v1alpha2/identity_pb.js";
import { ErrorDetailSchema, ErrorReason } from "../packages/typescript/dist/common/errors_pb.js";
import { approvalGroupView, effectiveResourceRole, groupApprovalCount, validateApprovalGroup, validateApprovalGroupView, validateReviewPolicy } from "../packages/typescript/dist/v1alpha2/approval-groups.js";

const adminView = { canReadMembers: true, isAdministrator: true };
const fixture = JSON.parse(readFileSync(new URL("./fixtures/role-approval-groups.json", import.meta.url)));
for (const v of fixture.cases) {
  test(v.name, () => {
    const group = create(ApprovalGroupRecordSchema, { memberRole: v.member_role, explicitMemberHandles: [...fixture.principals, ...v.extra].filter(p => v.explicit.includes(p.subject)).map(p => p.handle) });
    const policy = create(ReviewPolicyRecordSchema, { minimumRole: v.minimum_role });
    const current = [...fixture.principals, ...v.extra].map(p => ({ subject: p.subject,
      person: create(SuggestedPrincipalSchema, { handle: p.handle, displayName: p.display_name, kind: p.kind }),
      effectiveRole: effectiveResourceRole(v.overrides[p.handle] ?? [p.direct_role, p.inherited_role]), isAgent: p.is_agent, explicitMember: v.explicit.includes(p.subject), handleVisible: true,
    }));
    if (v.error) { assert.throws(() => validateApprovalGroup(group), new RegExp(`^Error: ${v.error}:`)); return; }
    validateApprovalGroup(group);
    const view = approvalGroupView(group, current, adminView);
    assert.deepEqual(view.resolvedMembers.map(p => p.handle), v.expected);
    assert.equal(groupApprovalCount(group, policy, current, v.approvers), v.count);
    if (v.name === "role_group_member_counts_inherited_admin") assert.deepEqual(view.roleMemberHandles, ["ada", "mara"]);
    validateApprovalGroupView(view, group, current, adminView);
    assert.deepEqual(fromBinary(ApprovalGroupViewSchema, toBinary(ApprovalGroupViewSchema, view)), view);
    assert.ok(!JSON.stringify(view).includes("account-id"));
    view.resolvedMembers.push(current[3].person);
    assert.throws(() => validateApprovalGroupView(view, group, current, adminView), /Projection:/);
  });
}
test("READER policies refused with typed wire reason", () => {
  for (const role of fixture.refused_policy_roles) {
    assert.throws(() => validateReviewPolicy(create(ReviewPolicyRecordSchema, { minimumRole: role })), role === 1 ? /RoleBelowEligibilityFloor:/ : /Role:/);
  }
  assert.equal(ErrorReason.APPROVAL_ROLE_BELOW_ELIGIBILITY_FLOOR, 403);
  for (const field of ["group.member_role", "policy.minimum_role"]) {
    const detail = create(ErrorDetailSchema, { reason: ErrorReason.APPROVAL_ROLE_BELOW_ELIGIBILITY_FLOOR, field });
    assert.deepEqual(fromBinary(ErrorDetailSchema, toBinary(ErrorDetailSchema, detail)), detail);
  }
});
test("resolved group view rejects IDs at JavaScript boundaries", () => {
  const group = create(ApprovalGroupRecordSchema, { memberRole: 3 });
  const current = [{ subject: "private-account-id", person: create(SuggestedPrincipalSchema, { handle: "ada", displayName: "Ada", kind: 1 }), effectiveRole: 3, isAgent: false, explicitMember: false, handleVisible: true }];
  for (const extra of [{ principalIds: ["private-account-id"] }, { $unknown: [] }]) {
    const view = approvalGroupView(group, current, adminView);
    Object.assign(view, extra);
    assert.throws(() => validateApprovalGroupView(view, group, current, adminView), /Projection:/);
  }
});

test("group disclosure vectors require MEMBERS read and admin for explicit edits", async () => {
  const { resolveApprovalGroupMembers } = await import("../packages/typescript/dist/v1alpha2/approval-groups.js");
  const visibility = JSON.parse(readFileSync(new URL("./fixtures/approval-group-visibility.json", import.meta.url)));
  const group = create(ApprovalGroupRecordSchema, { memberRole: 3, explicitMemberHandles: ["jun"] });
  const current = visibility.principals.map(p => ({ subject: p.subject, person: create(SuggestedPrincipalSchema, { handle: p.handle, kind: 1 }), effectiveRole: p.role, explicitMember: p.explicit, handleVisible: p.visible, isAgent: false }));
  for (const v of visibility.cases) {
    const context = { canReadMembers: v.members, isAdministrator: v.admin };
    const view = approvalGroupView(group, current, context);
    assert.deepEqual(view.resolvedMembers.map(p => p.handle), v.resolved, v.name);
    assert.deepEqual(view.roleMemberHandles, v.role, v.name);
    assert.deepEqual(view.explicitMemberHandles, v.explicit, v.name);
    assert.deepEqual([view.resolvedMemberCount, view.roleMemberCount, view.explicitMemberCount], [3, 2, 3]);
    validateApprovalGroupView(view, group, current, context);
    if (v.members && v.admin) {
      const edited = create(ApprovalGroupRecordSchema, { ...group, name: "renamed", explicitMemberHandles: view.explicitMemberHandles });
      assert.deepEqual(resolveApprovalGroupMembers(edited, true, current, handle => current.find(p => p.person.handle === handle && p.handleVisible && !p.isAgent)?.subject), ["absent-private", "hidden-private", "jun-private"]);
    }
  }
  assert.throws(() => resolveApprovalGroupMembers(group, false, [], () => assert.fail("authorize before lookup")), /Administrator:/);
  assert.throws(() => resolveApprovalGroupMembers(group, true, [], () => undefined), /HandleNotFound:/);
  const clearedVisible = create(ApprovalGroupRecordSchema, { ...group, explicitMemberHandles: [] });
  assert.deepEqual(resolveApprovalGroupMembers(clearedVisible, true, current, () => assert.fail("no visible handles to resolve")), ["absent-private", "hidden-private"]);
  current[1].person.handle = "jun-renamed";
  assert.deepEqual(approvalGroupView(group, current, adminView).explicitMemberHandles, ["jun-renamed"]);
});
test("approval group writes hard-cut IDs to handles", () => {
  assert.ok(!ApprovalGroupRecordSchema.fields.some(f => f.name === "principal_ids" || f.number === 5));
  assert.equal(ApprovalGroupRecordSchema.fields.find(f => f.name === "explicit_member_handles").number, 7);
  const group = create(ApprovalGroupRecordSchema, { principalIds: ["private-account-id"] });
  group.principalIds = ["private-account-id"];
  assert.throws(() => validateApprovalGroup(group), /Metadata:/);
});

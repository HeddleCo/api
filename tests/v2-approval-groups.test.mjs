import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { create, toBinary, fromBinary } from "@bufbuild/protobuf";
import { ApprovalGroupRecordSchema, ReviewPolicyRecordSchema, ApprovalGroupViewSchema } from "../packages/typescript/dist/v1alpha2/administration_pb.js";
import { SuggestedPrincipalSchema } from "../packages/typescript/dist/v1alpha2/identity_pb.js";
import { ErrorDetailSchema, ErrorReason } from "../packages/typescript/dist/common/errors_pb.js";
import { approvalGroupView, effectiveResourceRole, groupApprovalCount, validateApprovalGroup, validateApprovalGroupView, validateReviewPolicy } from "../packages/typescript/dist/v1alpha2/approval-groups.js";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/role-approval-groups.json", import.meta.url)));
for (const v of fixture.cases) {
  test(v.name, () => {
    const group = create(ApprovalGroupRecordSchema, { memberRole: v.member_role, principalIds: v.explicit });
    const policy = create(ReviewPolicyRecordSchema, { minimumRole: v.minimum_role });
    const current = [...fixture.principals, ...v.extra].map(p => ({ subject: p.subject,
      person: create(SuggestedPrincipalSchema, { handle: p.handle, displayName: p.display_name, kind: p.kind }),
      effectiveRole: effectiveResourceRole(v.overrides[p.handle] ?? [p.direct_role, p.inherited_role]), isAgent: p.is_agent,
    }));
    if (v.error) { assert.throws(() => validateApprovalGroup(group), new RegExp(`^Error: ${v.error}:`)); return; }
    validateApprovalGroup(group);
    const view = approvalGroupView(group, current);
    assert.deepEqual(view.resolvedMembers.map(p => p.handle), v.expected);
    assert.equal(groupApprovalCount(group, policy, current, v.approvers), v.count);
    if (v.name === "role_group_member_counts_inherited_admin") assert.deepEqual(view.roleMemberHandles, ["ada", "mara"]);
    validateApprovalGroupView(view, group, current);
    assert.deepEqual(fromBinary(ApprovalGroupViewSchema, toBinary(ApprovalGroupViewSchema, view)), view);
    assert.ok(!JSON.stringify(view).includes("account-id"));
    view.resolvedMembers.push(current[3].person);
    assert.throws(() => validateApprovalGroupView(view, group, current), /Projection:/);
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
  const current = [{ subject: "private-account-id", person: create(SuggestedPrincipalSchema, { handle: "ada", displayName: "Ada", kind: 1 }), effectiveRole: 3, isAgent: false }];
  for (const extra of [{ principalIds: ["private-account-id"] }, { $unknown: [] }]) {
    const view = approvalGroupView(group, current);
    Object.assign(view, extra);
    assert.throws(() => validateApprovalGroupView(view, group, current), /Projection:/);
  }
});

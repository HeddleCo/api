/** Hosts bind current role/membership lookup to the landing transaction. */
import { create } from "@bufbuild/protobuf";
import { ApprovalGroupViewSchema, ResourceRole } from "./administration_pb.js";
import type { ApprovalGroupRecord, ApprovalGroupView, ReviewPolicyRecord } from "./administration_pb.js";
import { SuggestedPrincipalSchema } from "./identity_pb.js";
import type { SuggestedPrincipal } from "./identity_pb.js";
import { comparePeopleHandles, validateSuggestedPrincipal } from "./people.js";

/** Host-resolved effective role over applicable current ancestor grants.
 * Missing/removed membership is UNSPECIFIED. Never use approval-time roles. */
export type ApprovalPrincipal = {
  subject: string;
  person: SuggestedPrincipal;
  effectiveRole: ResourceRole;
  isAgent: boolean;
};
const knownRole = (role: ResourceRole): void => {
  if (![ResourceRole.UNSPECIFIED, ResourceRole.READER, ResourceRole.WRITER, ResourceRole.ADMINISTRATOR].includes(role)) {
    throw new Error("Role: invalid ResourceRole");
  }
};
/** Host loads only ancestor grants whose include_descendants covers this spool. */
export function effectiveResourceRole(roles: readonly ResourceRole[]): ResourceRole {
  roles.forEach(knownRole);
  return Math.max(ResourceRole.UNSPECIFIED, ...roles) as ResourceRole;
}
function validateThreshold(role: ResourceRole): void {
  knownRole(role);
  if (role === ResourceRole.READER) throw new Error("RoleBelowEligibilityFloor: APPROVAL_ROLE_BELOW_ELIGIBILITY_FLOOR");
}
/** Map to INVALID_ARGUMENT / APPROVAL_ROLE_BELOW_ELIGIBILITY_FLOOR, group.member_role. */
export function validateApprovalGroup(group: ApprovalGroupRecord): void { validateThreshold(group.memberRole); }
/** Same reason, policy.minimum_role. */
export function validateReviewPolicy(policy: ReviewPolicyRecord): void { validateThreshold(policy.minimumRole); }
function roleMember(group: ApprovalGroupRecord, principal: ApprovalPrincipal): boolean {
  return group.memberRole !== ResourceRole.UNSPECIFIED && principal.effectiveRole >= group.memberRole;
}
function isMember(group: ApprovalGroupRecord, principal: ApprovalPrincipal): boolean {
  knownRole(principal.effectiveRole);
  return !principal.isAgent && !!principal.subject && principal.effectiveRole >= ResourceRole.WRITER &&
    (group.principalIds.includes(principal.subject) ||
      roleMember(group, principal));
}
export function approvalGroupView(group: ApprovalGroupRecord, current: readonly ApprovalPrincipal[]): ApprovalGroupView {
  validateApprovalGroup(group);
  const seen = new Set<string>();
  const resolvedMembers = current.filter(p => isMember(group, p)).map(p => {
    validateSuggestedPrincipal(p.person);
    return create(SuggestedPrincipalSchema, { handle: p.person.handle, displayName: p.person.displayName, kind: p.person.kind });
  }).sort(comparePeopleHandles).filter(person => {
    if (seen.has(person.handle)) return false;
    seen.add(person.handle);
    return true;
  });
  return create(ApprovalGroupViewSchema, {
    ref: group.ref, version: group.version, name: group.name, description: group.description,
    memberRole: group.memberRole, resolvedMembers,
    roleMemberHandles: resolvedMembers.filter(person => current.some(p => p.person.handle === person.handle &&
      isMember(group, p) && roleMember(group, p))).map(p => p.handle),
  });
}
export function validateApprovalGroupView(view: ApprovalGroupView, group: ApprovalGroupRecord, current: readonly ApprovalPrincipal[]): void {
  view.resolvedMembers.forEach(validateSuggestedPrincipal);
  const expected = approvalGroupView(group, current);
  if (Object.keys(view).some(key => !["$typeName", "ref", "version", "name", "description", "memberRole", "resolvedMembers", "roleMemberHandles"].includes(key)) ||
    JSON.stringify(view.ref) !== JSON.stringify(expected.ref) ||
    view.version.length !== expected.version.length || view.version.some((b, i) => b !== expected.version[i]) ||
    view.name !== expected.name || view.description !== expected.description || view.memberRole !== expected.memberRole ||
    view.roleMemberHandles.length !== expected.roleMemberHandles.length || view.roleMemberHandles.some((h, i) => h !== expected.roleMemberHandles[i]) ||
    view.resolvedMembers.length !== expected.resolvedMembers.length || view.resolvedMembers.some((p, i) =>
      p.handle !== expected.resolvedMembers[i].handle || p.displayName !== expected.resolvedMembers[i].displayName || p.kind !== expected.resolvedMembers[i].kind)) {
    throw new Error("Projection: approval group differs from live membership");
  }
}
/** Approvers must already exclude revoked/stale/expired, wrong-revision and
 * author-forbidden approvals. This supplies only the live group/role check.
 * Legacy stored minimum_role=READER evaluates as WRITER; new writes refuse it. */
export function groupApprovalCount(group: ApprovalGroupRecord, policy: ReviewPolicyRecord, current: readonly ApprovalPrincipal[], approvers: readonly string[]): number {
  validateApprovalGroup(group);
  knownRole(policy.minimumRole);
  const minimum = Math.max(policy.minimumRole, ResourceRole.WRITER);
  const eligible = new Set(current.filter(p => isMember(group, p) && p.effectiveRole >= minimum).map(p => p.subject));
  return new Set(approvers.filter(subject => eligible.has(subject))).size;
}

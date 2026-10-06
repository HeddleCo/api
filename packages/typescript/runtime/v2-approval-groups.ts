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
  /** From THIS group's private stable bindings, never wire handles.
   * Rebuild for each group evaluated; not a global person flag. */
  explicitMember: boolean;
  handleVisible: boolean;
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
export function validateApprovalGroup(group: ApprovalGroupRecord): void {
  validateThreshold(group.memberRole);
  if (Object.keys(group).some(key => !["$typeName", "ref", "version", "name", "description", "memberRole", "explicitMemberHandles"].includes(key))) throw new Error("Metadata: invalid group input");
  group.explicitMemberHandles.forEach(handle => validateSuggestedPrincipal(create(SuggestedPrincipalSchema, { handle, kind: 1 })));
}
/** Same reason, policy.minimum_role. */
export function validateReviewPolicy(policy: ReviewPolicyRecord): void { validateThreshold(policy.minimumRole); }
function roleMember(group: ApprovalGroupRecord, principal: ApprovalPrincipal): boolean {
  return group.memberRole !== ResourceRole.UNSPECIFIED && principal.effectiveRole >= group.memberRole;
}
function isMember(group: ApprovalGroupRecord, principal: ApprovalPrincipal): boolean {
  knownRole(principal.effectiveRole);
  return !principal.isAgent && !!principal.subject && principal.effectiveRole >= ResourceRole.WRITER &&
    (principal.explicitMember ||
      roleMember(group, principal));
}
/** Host-authorized current membership AND MEMBERS-section read. */
export type ApprovalGroupViewContext = { canReadMembers: boolean; isAdministrator: boolean };
/** SERVER ONLY: authorized visible-human lookup; store resulting stable subjects
 * privately. Returns a full replacement set preserving current hidden/no-handle
 * explicit humans. Load current for THIS group under the write/auth lock. */
export function resolveApprovalGroupMembers(group: ApprovalGroupRecord, isAdministrator: boolean, current: readonly ApprovalPrincipal[], resolveVisibleHuman: (handle: string) => string | undefined): string[] {
  if (!isAdministrator) throw new Error("Administrator: approval-group administrator required");
  validateApprovalGroup(group);
  const subjects = group.explicitMemberHandles.map(handle => {
    const subject = resolveVisibleHuman(handle);
    if (!subject) throw new Error("HandleNotFound: explicit member unavailable");
    return subject;
  });
  const retained = current.filter(p => p.explicitMember && !p.isAgent && !!p.subject &&
    (!p.handleVisible || !p.person.handle)).map(p => p.subject);
  return [...new Set([...subjects, ...retained])].sort();
}
export function approvalGroupView(group: ApprovalGroupRecord, current: readonly ApprovalPrincipal[], context: ApprovalGroupViewContext): ApprovalGroupView {
  validateApprovalGroup(group);
  const members = current.filter(p => isMember(group, p));
  const explicit = current.filter(p => p.explicitMember && !p.isAgent && !!p.subject);
  const count = (rows: readonly ApprovalPrincipal[]) => new Set(rows.map(p => p.subject)).size;
  const visible = (p: ApprovalPrincipal) => p.handleVisible && !!p.person.handle;
  const unique = (handles: string[]) => [...new Set(handles)].sort((a, b) => comparePeopleHandles({ handle: a } as SuggestedPrincipal, { handle: b } as SuggestedPrincipal));
  const disclosed = context.canReadMembers ? members.filter(visible) : [];
  const disclosedExplicit = context.isAdministrator && context.canReadMembers ? explicit.filter(visible) : [];
  [...disclosed, ...disclosedExplicit].forEach(p => validateSuggestedPrincipal(p.person));
  const seen = new Set<string>();
  const resolvedMembers = disclosed.map(p => create(SuggestedPrincipalSchema, {
    handle: p.person.handle, displayName: p.person.displayName, kind: p.person.kind,
  })).sort(comparePeopleHandles).filter(person => {
    if (seen.has(person.handle)) return false;
    seen.add(person.handle); return true;
  });
  return create(ApprovalGroupViewSchema, {
    ref: group.ref, version: group.version, name: group.name, description: group.description,
    memberRole: group.memberRole, resolvedMembers,
    roleMemberHandles: unique(disclosed.filter(p => roleMember(group, p)).map(p => p.person.handle)),
    explicitMemberHandles: unique(disclosedExplicit.map(p => p.person.handle)),
    resolvedMemberCount: count(members), roleMemberCount: count(members.filter(p => roleMember(group, p))),
    explicitMemberCount: count(explicit),
  });
}
export function validateApprovalGroupView(view: ApprovalGroupView, group: ApprovalGroupRecord, current: readonly ApprovalPrincipal[], context: ApprovalGroupViewContext): void {
  view.resolvedMembers.forEach(validateSuggestedPrincipal);
  const expected = approvalGroupView(group, current, context);
  const handlesEqual = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((h, i) => h === b[i]);
  if (Object.keys(view).some(key => !["$typeName", "ref", "version", "name", "description", "memberRole", "resolvedMembers", "roleMemberHandles", "explicitMemberHandles", "resolvedMemberCount", "roleMemberCount", "explicitMemberCount"].includes(key)) ||
    JSON.stringify(view.ref) !== JSON.stringify(expected.ref) ||
    view.version.length !== expected.version.length || view.version.some((b, i) => b !== expected.version[i]) ||
    view.name !== expected.name || view.description !== expected.description || view.memberRole !== expected.memberRole ||
    view.resolvedMemberCount !== expected.resolvedMemberCount || view.roleMemberCount !== expected.roleMemberCount || view.explicitMemberCount !== expected.explicitMemberCount ||
    !handlesEqual(view.roleMemberHandles, expected.roleMemberHandles) || !handlesEqual(view.explicitMemberHandles, expected.explicitMemberHandles) ||
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

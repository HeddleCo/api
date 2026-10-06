/** Pure membership floors; hosts own authorization, loading and atomic commit. */
import { create } from "@bufbuild/protobuf";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { CallFailureCode, CallFailureSchema, ErrorDetailSchema, ErrorReason } from "../common/errors_pb.js";
import type { CallFailure } from "../common/errors_pb.js";
import { ResourceRole } from "./administration_pb.js";
import type { GrantRecord } from "./administration_pb.js";
import { ActionAvailabilitySchema, Capability, EntityRefSchema, ExpectedVersionSchema, RequirementKind, RequirementSchema } from "./common_pb.js";
import type { EndpointRef } from "./stream_pb.js";
import type { ActionAvailability, RecordRef } from "./common_pb.js";

/** Applicable direct or descendant-covering ancestor grants. No invitations or
 * support access. Stable subjects deduplicate humans; agents never count. */
export type MembershipCandidate = {
  grant: RecordRef;
  subject: string;
  role: ResourceRole;
  kind: "human" | "agent";
  /** Owner of THIS personal spool, independent of caller identity. */
  personalOwner: boolean;
  expiresAt?: Timestamp;
};
/** Revoke/leave/coverage removal uses UNSPECIFIED. Other writes supply the
 * resulting role and expiry, preserving unchanged values. */
export type MembershipChange = {
  grant: RecordRef;
  role: ResourceRole;
  expiresAt?: Timestamp;
  field: "grant" | "grant.role" | "grant.expires_at";
};
/** Trusted host context: validate timestamps/roles and resolve/authorize target
 * first. Denied operations preserve the existing refusal before membership
 * lookup. Healthy authorized operations need no affected-spool management;
 * violating floors are opaque without that disclosure permission. */
export type MembershipFloorContext = {
  now: Timestamp;
  /** Actual operation/target authorization, including credential gates. */
  operationAuthorized: boolean;
  /** Disclosure permission on THIS affected spool. Healthy results do not
   * require management of otherwise unreadable descendants/shared spools. */
  canManageGrants: boolean;
  existingRefusal: CallFailure;
};
function existingMembershipRefusal(context: MembershipFloorContext): CallFailure {
  if (!context.existingRefusal || typeof context.existingRefusal !== "object") {
    throw new TypeError("MembershipFloorContext: existing refusal required");
  }
  return context.existingRefusal;
}
const sameGrant = (a: RecordRef, b: RecordRef): boolean => a.id === b.id && a.spool?.id === b.spool?.id;
function live(role: ResourceRole, expiry: Timestamp | undefined, now: Timestamp): boolean {
  return role !== ResourceRole.UNSPECIFIED && (!expiry || expiry.seconds > now.seconds ||
    (expiry.seconds === now.seconds && expiry.nanos > now.nanos));
}
/** Undefined means allowed. Evaluate each affected spool again under the commit
 * lock. No subjects, counts or hidden references enter the refusal envelope. */
export function membershipFloor(candidates: readonly MembershipCandidate[], change: MembershipChange, context: MembershipFloorContext): CallFailure | undefined {
  return membershipFloorBatch(candidates, [change], change.field, context);
}
/** Combined result of a cascade/ancestry change on one surviving spool. Changes
 * must be unique per grant and include all effects, not individual prechecks. */
export function membershipFloorBatch(candidates: readonly MembershipCandidate[], changes: readonly MembershipChange[], field: MembershipChange["field"], context: MembershipFloorContext): CallFailure | undefined {
  if (context.operationAuthorized !== true) return existingMembershipRefusal(context);
  const members = new Map<string, ResourceRole>();
  for (const candidate of candidates) {
    if (candidate.kind !== "human") continue;
    const change = changes.find(c => sameGrant(candidate.grant, c.grant));
    const [role, expiry] = change ? [change.role, change.expiresAt] : [candidate.role, candidate.expiresAt];
    if (live(role, expiry, context.now)) members.set(candidate.subject, Math.max(members.get(candidate.subject) ?? ResourceRole.UNSPECIFIED, role));
  }
  const ownerLost = candidates.some(p => p.kind === "human" && p.personalOwner && !members.has(p.subject));
  let reason: ErrorReason;
  if (ownerLost) reason = ErrorReason.PERSONAL_SPOOL_OWNER_ACCESS_REQUIRED;
  else if (members.size === 0) reason = ErrorReason.SPOOL_LAST_MEMBER;
  else if (members.size > 0 && ![...members.values()].includes(ResourceRole.ADMINISTRATOR)) reason = ErrorReason.SPOOL_LAST_ADMINISTRATOR;
  else return undefined;
  if (context.canManageGrants !== true) return existingMembershipRefusal(context);
  return create(CallFailureSchema, {
    code: CallFailureCode.FAILED_PRECONDITION, message: "spool membership required",
    error: create(ErrorDetailSchema, { reason, field }),
  });
}
export type MembershipAdviceContext = {
  floor: MembershipFloorContext;
  endpoint: EndpointRef;
  implemented: boolean;
};
/** Append to SpoolOverview.actions: one revoke and below-admin role proposal per
 * unique caller-visible grant. Batch targets with the same trusted authorization
 * result (actual grant spool and affected descendants); hosts compose other gates. */
export function membershipFloorActions(visibleGrants: readonly GrantRecord[], candidates: readonly MembershipCandidate[], context: MembershipAdviceContext): ActionAvailability[] {
  const authorized = context.floor.operationAuthorized === true;
  return visibleGrants.flatMap(grant => {
    if (!grant.ref) return [];
    return ([
      ["RevokeGrant", Capability.REVOKE_GRANT, ResourceRole.UNSPECIFIED, "grant"],
      ["PutGrant", Capability.PUT_GRANT, ResourceRole.WRITER, "grant.role"],
    ] as const).map(([method, capability, role, field]) => {
      const target = create(EntityRefSchema, { entity: { case: "grant", value: grant.ref! } });
      const failure = membershipFloor(candidates, { grant: grant.ref!, role, expiresAt: grant.expiresAt, field }, context.floor);
      return create(ActionAvailabilitySchema, {
        method: `/heddle.api.v1alpha2.SpoolService/${method}`, endpoint: context.endpoint,
        target, implemented: context.implemented, authorized, capability,
        observedVersions: [create(ExpectedVersionSchema, { resource: target, version: grant.version })],
        requirements: !failure ? [] : [create(RequirementSchema, {
          kind: authorized ? RequirementKind.POLICY : RequirementKind.CAPABILITY,
          subject: target, error: context.floor.canManageGrants === true && authorized ? failure.error : undefined,
        })],
      });
    });
  });
}

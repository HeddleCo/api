//! Pure membership floors. Hosts own authorization, effective-grant loading and
//! atomic mutation/expiry scheduling; see docs/alpha-v2/administration.md.
use std::collections::BTreeMap;

use prost_types::Timestamp;

use crate::heddle::api::common::{CallFailure, CallFailureCode, ErrorDetail, ErrorReason};
use crate::heddle::api::v1alpha2::{
    ActionAvailability, Capability, EndpointRef, EntityRef, ExpectedVersion, GrantRecord,
    RecordRef, Requirement, RequirementKind, ResourceRole, entity_ref,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberKind {
    Human,
    Agent,
}

/// One applicable direct or descendant-covering ancestor grant. Stable subject
/// deduplicates humans; hosts exclude invitations and support-access rows.
#[derive(Clone, Debug)]
pub struct MembershipCandidate {
    pub grant: RecordRef,
    pub subject: String,
    pub role: ResourceRole,
    pub kind: MemberKind,
    /// True only for the human owner of THIS personal spool, for any caller.
    pub personal_owner: bool,
    pub expires_at: Option<Timestamp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipField {
    Grant,
    Role,
    ExpiresAt,
}
impl MembershipField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Role => "grant.role",
            Self::ExpiresAt => "grant.expires_at",
        }
    }
}

/// Replacement of the resolved target on the spool being evaluated. Revoke,
/// leave or removal of descendant coverage uses UNSPECIFIED. Role/expiry writes
/// supply the resulting role AND expiry, preserving unchanged values.
#[derive(Clone, Debug)]
pub struct MembershipChange {
    pub grant: RecordRef,
    pub role: ResourceRole,
    pub expires_at: Option<Timestamp>,
    pub field: MembershipField,
}

/// Trusted host inputs. Validate timestamps/roles and resolve/authorize the
/// target before calling. Denied operations preserve the existing envelope
/// before membership inspection. Authorized operations with healthy floors are
/// allowed even without affected-spool management; violating floors are opaque
/// unless the caller can manage grants on that affected spool.
pub struct MembershipFloorContext<'a> {
    pub now: &'a Timestamp,
    /// Authorization for the actual operation/target, including credential gates.
    pub operation_authorized: bool,
    /// Permission to disclose a floor on THIS affected spool, not permission to
    /// require management of otherwise healthy descendants/shared spools.
    pub can_manage_grants: bool,
    pub existing_refusal: &'a CallFailure,
}

fn live(role: ResourceRole, expiry: Option<&Timestamp>, now: &Timestamp) -> bool {
    role != ResourceRole::Unspecified
        && expiry.is_none_or(|t| (t.seconds, t.nanos) > (now.seconds, now.nanos))
}

/// None means allowed; Some carries the refusal. Evaluate one affected spool.
/// Recompute at commit and for every affected descendant. Applicable grants
/// count once per human at their maximum
/// live role. Hidden grants are never action targets or error resource/context.
pub fn membership_floor(
    candidates: &[MembershipCandidate],
    change: &MembershipChange,
    context: &MembershipFloorContext<'_>,
) -> Option<CallFailure> {
    membership_floor_batch(
        candidates,
        std::slice::from_ref(change),
        change.field,
        context,
    )
}

/// Evaluate the combined result of a cascade/ancestry change on one surviving
/// spool. Changes MUST be unique per grant and include every affected grant;
/// checking each removal against the unchanged snapshot is insufficient.
pub fn membership_floor_batch(
    candidates: &[MembershipCandidate],
    changes: &[MembershipChange],
    field: MembershipField,
    context: &MembershipFloorContext<'_>,
) -> Option<CallFailure> {
    if !context.operation_authorized {
        return Some(context.existing_refusal.clone());
    }
    let mut members = BTreeMap::new();
    for candidate in candidates {
        if candidate.kind != MemberKind::Human {
            continue;
        }
        let (role, expiry) =
            if let Some(change) = changes.iter().find(|c| c.grant == candidate.grant) {
                (change.role, change.expires_at.as_ref())
            } else {
                (candidate.role, candidate.expires_at.as_ref())
            };
        if live(role, expiry, context.now) {
            let current = members
                .entry(&candidate.subject)
                .or_insert(ResourceRole::Unspecified);
            if role as i32 > *current as i32 {
                *current = role;
            }
        }
    }
    let owner_lost = candidates.iter().any(|p| {
        p.kind == MemberKind::Human && p.personal_owner && !members.contains_key(&p.subject)
    });
    let reason = if owner_lost {
        ErrorReason::PersonalSpoolOwnerAccessRequired
    } else if members.is_empty() {
        ErrorReason::SpoolLastMember
    } else if !members.is_empty()
        && !members
            .values()
            .any(|role| *role == ResourceRole::Administrator)
    {
        ErrorReason::SpoolLastAdministrator
    } else {
        return None;
    };
    if !context.can_manage_grants {
        return Some(context.existing_refusal.clone());
    }
    Some(CallFailure {
        code: CallFailureCode::FailedPrecondition as i32,
        message: "spool membership required".into(),
        error: Some(ErrorDetail {
            reason: reason as i32,
            field: field.as_str().into(),
            ..Default::default()
        }),
    })
}

pub struct MembershipAdviceContext<'a> {
    pub floor: MembershipFloorContext<'a>,
    pub endpoint: &'a EndpointRef,
    pub implemented: bool,
}

/// Append to SpoolOverview.actions. `visible_grants` MUST be caller-filtered,
/// unique records; candidates are complete trusted effective grants for THIS
/// spool. These entries advertise revoke and below-admin role proposals only.
/// Batch only targets with the same trusted authorization result, including
/// their actual grant spool and affected descendants. Hosts compose other
/// policy/credential requirements before emission.
pub fn membership_floor_actions(
    visible_grants: &[GrantRecord],
    candidates: &[MembershipCandidate],
    context: &MembershipAdviceContext<'_>,
) -> Vec<ActionAvailability> {
    let mut actions = Vec::new();
    for grant in visible_grants {
        let Some(reference) = &grant.r#ref else {
            continue;
        };
        for (method, capability, role, field) in [
            (
                "RevokeGrant",
                Capability::RevokeGrant,
                ResourceRole::Unspecified,
                MembershipField::Grant,
            ),
            (
                "PutGrant",
                Capability::PutGrant,
                ResourceRole::Writer,
                MembershipField::Role,
            ),
        ] {
            let target = EntityRef {
                entity: Some(entity_ref::Entity::Grant(reference.clone())),
            };
            let change = MembershipChange {
                grant: reference.clone(),
                role,
                expires_at: grant.expires_at,
                field,
            };
            let requirements = match membership_floor(candidates, &change, &context.floor) {
                None => Vec::new(),
                Some(failure) => vec![Requirement {
                    kind: if context.floor.operation_authorized {
                        RequirementKind::Policy
                    } else {
                        RequirementKind::Capability
                    } as i32,
                    subject: Some(target.clone()),
                    error: if context.floor.can_manage_grants && context.floor.operation_authorized
                    {
                        failure.error
                    } else {
                        None
                    },
                    ..Default::default()
                }],
            };
            actions.push(ActionAvailability {
                method: format!("/heddle.api.v1alpha2.SpoolService/{method}"),
                endpoint: Some(context.endpoint.clone()),
                target: Some(target.clone()),
                implemented: context.implemented,
                authorized: context.floor.operation_authorized,
                requirements,
                capability: capability as i32,
                observed_versions: vec![ExpectedVersion {
                    resource: Some(target),
                    version: grant.version.clone(),
                }],
            });
        }
    }
    actions
}

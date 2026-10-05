//! Live role-group membership; hosts bind this lookup to landing evaluation.
use crate::heddle::api::v1alpha2::{
    ApprovalGroupRecord, ApprovalGroupView, ResourceRole, ReviewPolicyRecord, SuggestedPrincipal,
};
use crate::v2::people::validate_person;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ApprovalGroupError {
    #[error("APPROVAL_ROLE_BELOW_ELIGIBILITY_FLOOR")]
    RoleBelowEligibilityFloor,
    #[error("invalid ResourceRole")]
    Role,
    #[error("invalid resolved member metadata")]
    Metadata,
    #[error("approval group projection differs from live membership")]
    Projection,
}

/// Trusted current human/agent record. `effective_role` is resolved over the
/// spool and all applicable ancestor grants at this evaluation, not approval
/// creation. Missing/removed membership is UNSPECIFIED.
pub struct ApprovalPrincipal {
    pub subject: String,
    pub person: SuggestedPrincipal,
    pub effective_role: ResourceRole,
    pub is_agent: bool,
}

/// Combine current direct and applicable inherited roles. The host must load
/// only ancestor grants whose include_descendants permits this spool.
pub fn effective_resource_role(roles: &[ResourceRole]) -> ResourceRole {
    roles
        .iter()
        .copied()
        .max_by_key(|role| *role as i32)
        .unwrap_or(ResourceRole::Unspecified)
}

fn validate_threshold(role: i32) -> Result<(), ApprovalGroupError> {
    let role = ResourceRole::try_from(role).map_err(|_| ApprovalGroupError::Role)?;
    if role == ResourceRole::Reader {
        return Err(ApprovalGroupError::RoleBelowEligibilityFloor);
    }
    Ok(())
}

/// PutApprovalGroup: map RoleBelowEligibilityFloor to INVALID_ARGUMENT,
/// ErrorReason::ApprovalRoleBelowEligibilityFloor, field group.member_role.
pub fn validate_approval_group(group: &ApprovalGroupRecord) -> Result<(), ApprovalGroupError> {
    validate_threshold(group.member_role)
}

/// PutReviewPolicy: same typed reason, field policy.minimum_role.
pub fn validate_review_policy(policy: &ReviewPolicyRecord) -> Result<(), ApprovalGroupError> {
    validate_threshold(policy.minimum_role)
}

fn role_member(group: &ApprovalGroupRecord, principal: &ApprovalPrincipal) -> bool {
    group.member_role != ResourceRole::Unspecified as i32
        && principal.effective_role as i32 >= group.member_role
}

fn is_member(group: &ApprovalGroupRecord, principal: &ApprovalPrincipal) -> bool {
    !principal.is_agent
        && !principal.subject.is_empty()
        && principal.effective_role as i32 >= ResourceRole::Writer as i32
        && (group.principal_ids.contains(&principal.subject) || role_member(group, principal))
}

/// Complete union of current eligible explicit and role members. Presentation
/// data never contains subject IDs; view ref is the group/spool record ref.
pub fn approval_group_view(
    group: &ApprovalGroupRecord,
    current: &[ApprovalPrincipal],
) -> Result<ApprovalGroupView, ApprovalGroupError> {
    validate_approval_group(group)?;
    let mut resolved_members = Vec::new();
    for principal in current
        .iter()
        .filter(|principal| is_member(group, principal))
    {
        validate_person(&principal.person).map_err(|_| ApprovalGroupError::Metadata)?;
        resolved_members.push(principal.person.clone());
    }
    resolved_members.sort_by(|a, b| a.handle.cmp(&b.handle));
    resolved_members.dedup_by(|a, b| a.handle == b.handle);
    Ok(ApprovalGroupView {
        r#ref: group.r#ref.clone(),
        version: group.version.clone(),
        name: group.name.clone(),
        description: group.description.clone(),
        member_role: group.member_role,
        role_member_handles: resolved_members
            .iter()
            .filter(|person| {
                current.iter().any(|principal| {
                    principal.person.handle == person.handle
                        && is_member(group, principal)
                        && role_member(group, principal)
                })
            })
            .map(|person| person.handle.clone())
            .collect(),
        resolved_members,
    })
}

pub fn validate_approval_group_view(
    view: &ApprovalGroupView,
    group: &ApprovalGroupRecord,
    current: &[ApprovalPrincipal],
) -> Result<(), ApprovalGroupError> {
    if view != &approval_group_view(group, current)? {
        return Err(ApprovalGroupError::Projection);
    }
    Ok(())
}

/// Count distinct admitted approvers who are STILL eligible and members.
/// `approvers` must already exclude revoked, stale, expired, author-forbidden,
/// wrong-revision, or otherwise invalid approvals. This is the group/role
/// portion of evaluation, not a replacement for the full landing evaluator.
/// Stored legacy minimum_role=READER evaluates at WRITER; new writes refuse it.
pub fn group_approval_count(
    group: &ApprovalGroupRecord,
    policy: &ReviewPolicyRecord,
    current: &[ApprovalPrincipal],
    approvers: &[String],
) -> Result<usize, ApprovalGroupError> {
    validate_approval_group(group)?;
    ResourceRole::try_from(policy.minimum_role).map_err(|_| ApprovalGroupError::Role)?;
    let minimum = policy.minimum_role.max(ResourceRole::Writer as i32);
    let eligible: BTreeSet<_> = current
        .iter()
        .filter(|principal| {
            is_member(group, principal) && principal.effective_role as i32 >= minimum
        })
        .map(|principal| &principal.subject)
        .collect();
    Ok(approvers
        .iter()
        .filter(|subject| eligible.contains(subject))
        .collect::<BTreeSet<_>>()
        .len())
}

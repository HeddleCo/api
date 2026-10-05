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
    #[error("approval-group administrator required")]
    Administrator,
    #[error("explicit member handle unavailable")]
    HandleNotFound,
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
    /// Derived from THIS group's private stable bindings, never wire handles.
    /// Rebuild this flag for each group evaluated; it is not a global person flag.
    pub explicit_member: bool,
    pub handle_visible: bool,
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
    validate_threshold(group.member_role)?;
    for handle in &group.explicit_member_handles {
        validate_person(&SuggestedPrincipal {
            handle: handle.clone(),
            kind: 1,
            ..Default::default()
        })
        .map_err(|_| ApprovalGroupError::Metadata)?;
    }
    Ok(())
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
        && (principal.explicit_member || role_member(group, principal))
}

/// Trusted live disclosure decisions. can_read_members means BOTH current
/// membership and MEMBERS-section read, in addition to approval-group read.
pub struct ApprovalGroupViewContext {
    pub can_read_members: bool,
    pub is_administrator: bool,
}

/// SERVER ONLY: PutApprovalGroup after current admin authorization. Resolve each
/// visible human handle within authorized indexes and bind stable subjects in
/// private storage. A missing/hidden/agent handle uniformly returns unavailable.
/// Returns the full replacement binding set, preserving current hidden/no-handle
/// explicit humans when replacing visible configuration. Load current for THIS
/// group under the same write/authorization lock.
pub fn resolve_approval_group_members(
    group: &ApprovalGroupRecord,
    is_administrator: bool,
    current: &[ApprovalPrincipal],
    mut resolve_visible_human: impl FnMut(&str) -> Option<String>,
) -> Result<Vec<String>, ApprovalGroupError> {
    if !is_administrator {
        return Err(ApprovalGroupError::Administrator);
    }
    validate_approval_group(group)?;
    group
        .explicit_member_handles
        .iter()
        .map(|handle| {
            resolve_visible_human(handle)
                .filter(|subject| !subject.is_empty())
                .ok_or(ApprovalGroupError::HandleNotFound)
        })
        .collect::<Result<BTreeSet<_>, _>>()
        .map(|mut subjects| {
            subjects.extend(
                current
                    .iter()
                    .filter(|p| {
                        p.explicit_member
                            && !p.is_agent
                            && !p.subject.is_empty()
                            && (!p.handle_visible || p.person.handle.is_empty())
                    })
                    .map(|p| p.subject.clone()),
            );
            subjects.into_iter().collect()
        })
}

/// Counts use stable subjects, including members whose handle is hidden/absent.
/// Hosts load all explicit bindings, including ineligible extras, for edits.
pub fn approval_group_view(
    group: &ApprovalGroupRecord,
    current: &[ApprovalPrincipal],
    context: &ApprovalGroupViewContext,
) -> Result<ApprovalGroupView, ApprovalGroupError> {
    validate_approval_group(group)?;
    let members: Vec<_> = current.iter().filter(|p| is_member(group, p)).collect();
    let count = |principals: Vec<&ApprovalPrincipal>| -> u32 {
        principals
            .iter()
            .map(|p| &p.subject)
            .collect::<BTreeSet<_>>()
            .len() as u32
    };
    let mut view = ApprovalGroupView {
        r#ref: group.r#ref.clone(),
        version: group.version.clone(),
        name: group.name.clone(),
        description: group.description.clone(),
        member_role: group.member_role,
        resolved_member_count: count(members.clone()),
        role_member_count: count(
            members
                .iter()
                .copied()
                .filter(|p| role_member(group, p))
                .collect(),
        ),
        explicit_member_count: count(
            current
                .iter()
                .filter(|p| p.explicit_member && !p.is_agent && !p.subject.is_empty())
                .collect(),
        ),
        ..Default::default()
    };
    if context.can_read_members {
        for principal in &members {
            if !principal.handle_visible || principal.person.handle.is_empty() {
                continue;
            }
            validate_person(&principal.person).map_err(|_| ApprovalGroupError::Metadata)?;
            view.resolved_members.push(principal.person.clone());
            if role_member(group, principal) {
                view.role_member_handles
                    .push(principal.person.handle.clone());
            }
        }
    }
    if context.is_administrator && context.can_read_members {
        for principal in current
            .iter()
            .filter(|p| p.explicit_member && !p.is_agent && !p.subject.is_empty())
        {
            if !principal.handle_visible || principal.person.handle.is_empty() {
                continue;
            }
            validate_person(&principal.person).map_err(|_| ApprovalGroupError::Metadata)?;
            view.explicit_member_handles
                .push(principal.person.handle.clone());
        }
    }
    view.resolved_members
        .sort_by(|a, b| a.handle.cmp(&b.handle));
    view.resolved_members.dedup_by(|a, b| a.handle == b.handle);
    view.role_member_handles.sort();
    view.role_member_handles.dedup();
    view.explicit_member_handles.sort();
    view.explicit_member_handles.dedup();
    Ok(view)
}

pub fn validate_approval_group_view(
    view: &ApprovalGroupView,
    group: &ApprovalGroupRecord,
    current: &[ApprovalPrincipal],
    context: &ApprovalGroupViewContext,
) -> Result<(), ApprovalGroupError> {
    if view != &approval_group_view(group, current, context)? {
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

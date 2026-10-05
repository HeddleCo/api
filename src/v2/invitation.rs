//! Portable invitation validation and host transaction planning.

use crate::heddle::api::common::{CallFailure, CallFailureCode, ErrorDetail, ErrorReason};
use crate::heddle::api::v1alpha2::{
    CreateInvitationRequest, CreateInvitationResponse, InvitationRecord, InvitationState,
    invitation_record::Recipient,
};
use crate::heddle::api::v1alpha2::{InvitationResolution, invitation_resolution::Status};
use prost_types::Timestamp;

pub const SPOOL_INVITATION: &str = "spool_invitation";
pub const SPOOL_INVITATION_DECLINED: &str = "spool_invitation_declined";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvitationError {
    #[error("recipient required")]
    RecipientRequired,
    #[error("invalid email")]
    InvalidEmail,
    #[error("invalid handle")]
    InvalidHandle,
    #[error("invalid human account UUID")]
    InvalidAccountId,
    #[error("no such user")]
    HandleNotFound,
    #[error("sign in required")]
    Unauthenticated,
    #[error("invitation unavailable")]
    Unavailable,
    #[error("invitation is in a terminal or invalid state")]
    Lifecycle,
    #[error("invalid invitation input or projection")]
    InvalidRecord,
    #[error("human session required")]
    HumanSessionRequired,
    #[error("inviter authority lost")]
    InviterAuthorityLost,
}

impl InvitationError {
    pub const fn code(self) -> CallFailureCode {
        match self {
            Self::HandleNotFound | Self::Unavailable => CallFailureCode::NotFound,
            Self::Unauthenticated => CallFailureCode::Unauthenticated,
            Self::Lifecycle | Self::InviterAuthorityLost => CallFailureCode::FailedPrecondition,
            Self::HumanSessionRequired => CallFailureCode::PermissionDenied,
            _ => CallFailureCode::InvalidArgument,
        }
    }
    pub const fn reason(self) -> ErrorReason {
        match self {
            Self::HumanSessionRequired => ErrorReason::InvitationHumanSessionRequired,
            Self::InviterAuthorityLost => ErrorReason::InvitationInviterAuthorityLost,
            Self::HandleNotFound => ErrorReason::InvitationHandleNotFound,
            Self::Unavailable => ErrorReason::ResourceNotFound,
            Self::Unauthenticated => ErrorReason::CredentialMissing,
            Self::Lifecycle => ErrorReason::LifecycleState,
            Self::RecipientRequired => ErrorReason::FieldRequired,
            _ => ErrorReason::FieldInvalid,
        }
    }
    pub const fn field(self) -> &'static str {
        match self {
            Self::RecipientRequired => "invitation.recipient",
            Self::InvalidEmail => "invitation.email",
            Self::InvalidHandle | Self::HandleNotFound => "invitation.handle",
            Self::InvalidAccountId => "invitation.account_id",
            Self::Unauthenticated => "",
            _ => "invitation",
        }
    }
    pub fn failure(self) -> CallFailure {
        CallFailure {
            code: self.code() as i32,
            message: self.to_string(),
            error: Some(ErrorDetail {
                reason: self.reason() as i32,
                field: self.field().into(),
                ..Default::default()
            }),
        }
    }
}

/// Input shape only; host grammar/provider binding validation remains required.
pub fn normalize_invitation_recipient(
    record: &InvitationRecord,
) -> Result<Recipient, InvitationError> {
    match record
        .recipient
        .as_ref()
        .ok_or(InvitationError::RecipientRequired)?
    {
        Recipient::Email(value) => {
            if value.len() > 320 {
                return Err(InvitationError::InvalidEmail);
            }
            let normalized = value.trim().to_ascii_lowercase();
            let parts: Vec<_> = normalized.split('@').collect();
            if parts.len() != 2
                || parts.iter().any(|p| p.is_empty())
                || normalized
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(InvitationError::InvalidEmail);
            }
            Ok(Recipient::Email(normalized))
        }
        Recipient::Handle(value) => {
            if value.len() > 256 {
                return Err(InvitationError::InvalidHandle);
            }
            let normalized = value.trim().to_ascii_lowercase();
            if normalized.is_empty()
                || normalized
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
                || normalized.contains(['/', '@', '#'])
            {
                return Err(InvitationError::InvalidHandle);
            }
            Ok(Recipient::Handle(normalized))
        }
        Recipient::AccountId(value) => {
            if !is_account_uuid(value) {
                return Err(InvitationError::InvalidAccountId);
            }
            Ok(Recipient::AccountId(value.to_ascii_lowercase()))
        }
    }
}

fn is_account_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

/// SERVER ONLY: call after spool administration authorization. The resolver MUST
/// reuse ResolveHandles' publicly claimed eligibility, lookup and rate budget.
/// The returned account binding is private storage; never serialize it into a
/// handle invitation or response. Explicit account IDs still need host validation
/// that they identify a human account, never an independent agent principal.
pub fn resolve_invitation_recipient(
    record: &InvitationRecord,
    resolve_public_handle: impl FnOnce(&str) -> Option<String>,
) -> Result<Option<String>, InvitationError> {
    match normalize_invitation_recipient(record)? {
        Recipient::Email(_) => Ok(None),
        Recipient::AccountId(id) => Ok(Some(id)),
        Recipient::Handle(handle) => {
            let id = resolve_public_handle(&handle).ok_or(InvitationError::HandleNotFound)?;
            if !is_account_uuid(&id) {
                return Err(InvitationError::HandleNotFound);
            }
            Ok(Some(id.to_ascii_lowercase()))
        }
    }
}

/// Create rejects every server projection field. The host additionally checks
/// reference validity, authorization, future expiry, explicit human UUIDs and quotas.
pub fn validate_create_invitation(record: &InvitationRecord) -> Result<(), InvitationError> {
    normalize_invitation_recipient(record)?;
    if !record.version.is_empty()
        || !(1..=3).contains(&record.role)
        || record.state != InvitationState::Unspecified as i32
        || record.created_at.is_some()
        || record.updated_at.is_some()
        || record.inviter.is_some()
        || !record.inviter_via_agent_label.is_empty()
        || !record.spool_name.is_empty()
        || record.spool_address.is_some()
    {
        return Err(InvitationError::InvalidRecord);
    }
    Ok(())
}

/// Prevent exposing a private handle binding by substituting the account_id
/// arm, or exposing a link secret on an account/handle invitation.
pub fn validate_create_invitation_response(
    request: &CreateInvitationRequest,
    response: &CreateInvitationResponse,
) -> Result<(), InvitationError> {
    let input = request
        .invitation
        .as_ref()
        .ok_or(InvitationError::InvalidRecord)?;
    let output = response
        .invitation
        .as_ref()
        .ok_or(InvitationError::InvalidRecord)?;
    let recipient = normalize_invitation_recipient(input)?;
    if normalize_invitation_recipient(output)? != recipient
        || output.state != InvitationState::Pending as i32
        || output.r#ref != input.r#ref
        || output.role != input.role
        || output.expires_at != input.expires_at
        || matches!(recipient, Recipient::Email(_)) == response.redemption_secret.is_empty()
    {
        return Err(InvitationError::InvalidRecord);
    }
    validate_invitation_record_projection(output, &recipient)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationResponseAction {
    Accept,
    Decline,
}

/// A transaction plan, not a mutation or proof of authority. Hosts commit the
/// state/version, grant, attention update, receipt and notification/outbox once
/// atomically, serializing all Accept/Decline/Redeem/Revoke/expiry races.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvitationResponsePlan {
    pub state: InvitationState,
    pub changed: bool,
    pub grant_role: bool,
    pub notification_kind: Option<&'static str>,
}

pub fn effective_invitation_state(
    record: &InvitationRecord,
    now: &Timestamp,
) -> Result<InvitationState, InvitationError> {
    let state = InvitationState::try_from(record.state).map_err(|_| InvitationError::Lifecycle)?;
    if state == InvitationState::Unspecified {
        return Err(InvitationError::Lifecycle);
    }
    if state == InvitationState::Pending
        && record
            .expires_at
            .as_ref()
            .is_some_and(|expiry| (expiry.seconds, expiry.nanos) <= (now.seconds, now.nanos))
    {
        return Ok(InvitationState::Expired);
    }
    Ok(state)
}

/// Account values MUST come from verified session/credential and private stored
/// binding, never request fields, public handles or caller-selected principals.
/// Accept/Decline require a verified human session; delegation is insufficient.
/// This gate MUST run again before replaying a receipt, even for terminal states.
pub fn plan_invitation_response(
    record: &InvitationRecord,
    stored_recipient_account: Option<&str>,
    authenticated_account: Option<&str>,
    action: InvitationResponseAction,
    now: &Timestamp,
    human_session: bool,
    inviter_role: i32,
) -> Result<InvitationResponsePlan, InvitationError> {
    let caller = authenticated_account
        .filter(|id| !id.is_empty())
        .ok_or(InvitationError::Unauthenticated)?;
    if !human_session {
        return Err(InvitationError::HumanSessionRequired);
    }
    let recipient = stored_recipient_account.ok_or(InvitationError::Unavailable)?;
    if !is_account_uuid(caller)
        || !is_account_uuid(recipient)
        || !caller.eq_ignore_ascii_case(recipient)
        || !matches!(
            record.recipient,
            Some(Recipient::Handle(_) | Recipient::AccountId(_))
        )
    {
        return Err(InvitationError::Unavailable);
    }
    let state = effective_invitation_state(record, now)?;
    let target = match action {
        InvitationResponseAction::Accept => InvitationState::Accepted,
        InvitationResponseAction::Decline => InvitationState::Declined,
    };
    if state == target {
        return Ok(InvitationResponsePlan {
            state,
            changed: false,
            grant_role: false,
            notification_kind: None,
        });
    }
    if action == InvitationResponseAction::Accept {
        validate_inviter_authority(record.role, inviter_role)?;
    }
    if state != InvitationState::Pending {
        return Err(InvitationError::Lifecycle);
    }
    Ok(InvitationResponsePlan {
        state: target,
        changed: true,
        grant_role: action == InvitationResponseAction::Accept,
        notification_kind: (action == InvitationResponseAction::Decline)
            .then_some(SPOOL_INVITATION_DECLINED),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvitationResolutionError {
    #[error("UNAVAILABLE invitation resolution contains disclosed details")]
    UnavailableDetails,
    #[error("inviter requires an already-public handle")]
    InviterHandle,
    #[error("agent label requires an inviter handle")]
    AgentWithoutInviter,
}

/// Validate the wire-visible invitation preview before a client displays it.
/// The server remains responsible for checking the secret and resolving the
/// public handle, account lifecycle and agent label at read time.
pub fn validate_invitation_resolution(
    response: &InvitationResolution,
) -> Result<(), InvitationResolutionError> {
    if response.status == Status::Unavailable as i32
        && (response.spool.is_some()
            || !response.spool_name.is_empty()
            || response.role != 0
            || response.expires_at.is_some()
            || response.inviter.is_some()
            || !response.inviter_via_agent_label.is_empty())
    {
        return Err(InvitationResolutionError::UnavailableDetails);
    }
    if response
        .inviter
        .as_ref()
        .is_some_and(|owner| owner.handle.is_empty() || is_account_uuid(&owner.handle))
    {
        return Err(InvitationResolutionError::InviterHandle);
    }
    if !response.inviter_via_agent_label.is_empty()
        && !response
            .inviter
            .as_ref()
            .is_some_and(|owner| !owner.handle.is_empty())
    {
        return Err(InvitationResolutionError::AgentWithoutInviter);
    }
    Ok(())
}

/// Trusted CURRENT effective inviter role/credential ceilings, loaded under the
/// transition lock. Every offered role requires ADMINISTRATOR on Create,
/// pending Accept, email Redeem and GetInvitationCode. Accepted retries are no-ops.
/// Also use on every authority change to auto-revoke affected pending invites.
pub fn validate_inviter_authority(
    offered_role: i32,
    inviter_role: i32,
) -> Result<(), InvitationError> {
    if !(1..=3).contains(&offered_role) || inviter_role != 3 {
        return Err(InvitationError::InviterAuthorityLost);
    }
    Ok(())
}

/// Validate every wire projection against the originally stored recipient arm,
/// never the resolved private binding. Hosts must call before emit/replay.
pub fn validate_invitation_record_projection(
    record: &InvitationRecord,
    original: &Recipient,
) -> Result<(), InvitationError> {
    if normalize_invitation_recipient(record)? != *original
        || !(1..=3).contains(&record.role)
        || !(1..=5).contains(&record.state)
    {
        return Err(InvitationError::InvalidRecord);
    }
    validate_invitation_resolution(&InvitationResolution {
        inviter: record.inviter.clone(),
        inviter_via_agent_label: record.inviter_via_agent_label.clone(),
        ..Default::default()
    })
    .map_err(|_| InvitationError::InvalidRecord)
}

pub fn validate_spool_invitation_projection(
    event: &crate::heddle::api::v1alpha2::SpoolEvent,
    original: &Recipient,
) -> Result<(), InvitationError> {
    if let Some(crate::heddle::api::v1alpha2::spool_event::Payload::Invitation(record)) =
        &event.payload
    {
        validate_invitation_record_projection(record, original)?;
    }
    Ok(())
}

pub fn validate_notification_invitation_projection(
    record: &crate::heddle::api::v1alpha2::NotificationRecord,
    original: &Recipient,
) -> Result<(), InvitationError> {
    if let Some(invitation) = &record.invitation {
        validate_invitation_record_projection(invitation, original)?;
    }
    Ok(())
}

pub fn validate_attention_invitation_projection(
    item: &crate::heddle::api::v1alpha2::AttentionItem,
    original: &Recipient,
) -> Result<(), InvitationError> {
    if let Some(invitation) = &item.invitation {
        validate_invitation_record_projection(invitation, original)?;
    }
    Ok(())
}

/// SERVER ONLY: host loads ALL invitations by the immutable inviter subject on
/// this spool. On loss of admin, atomically persist these replacements with new
/// versions, dismiss attention, destroy codes and emit stream updates. Serialize
/// with acceptance; includes every pending offered role, even expired records.
pub fn plan_inviter_authority_loss(
    invitations: &[InvitationRecord],
    inviter_role: i32,
    now: &Timestamp,
) -> Vec<InvitationRecord> {
    if inviter_role == 3 {
        return Vec::new();
    }
    invitations
        .iter()
        .filter(|record| record.state == InvitationState::Pending as i32)
        .map(|record| InvitationRecord {
            state: InvitationState::Revoked as i32,
            updated_at: Some(*now),
            ..record.clone()
        })
        .collect()
}

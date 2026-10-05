//! Shape validation for the public invitation capability preview.

use crate::heddle::api::common::{CallFailure, CallFailureCode, ErrorDetail, ErrorReason};
use crate::heddle::api::v1alpha2::{
    InvitationRecord, InvitationState, invitation_record::Recipient,
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
}

impl InvitationError {
    pub const fn code(self) -> CallFailureCode {
        match self {
            Self::HandleNotFound | Self::Unavailable => CallFailureCode::NotFound,
            Self::Unauthenticated => CallFailureCode::Unauthenticated,
            Self::Lifecycle => CallFailureCode::FailedPrecondition,
            _ => CallFailureCode::InvalidArgument,
        }
    }
    pub const fn reason(self) -> ErrorReason {
        match self {
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
            let normalized = value.trim().to_ascii_lowercase();
            let parts: Vec<_> = normalized.split('@').collect();
            if value.len() > 320
                || parts.len() != 2
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
            let normalized = value.trim().to_ascii_lowercase();
            if value.len() > 256
                || normalized.is_empty()
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
    let _ = resolve_public_handle;
    match normalize_invitation_recipient(record)? {
        Recipient::Email(_) => Ok(None),
        Recipient::AccountId(id) => Ok(Some(id)),
        Recipient::Handle(_) => Err(InvitationError::Unavailable),
    }
}

/// Create rejects every server projection field. The host additionally checks
/// reference validity, authorization, future expiry, account lifecycle and quotas.
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
/// Delegations act as their human account and still obey their own ceilings.
/// This gate MUST run again before replaying a receipt, even for terminal states.
pub fn plan_invitation_response(
    record: &InvitationRecord,
    stored_recipient_account: Option<&str>,
    authenticated_account: Option<&str>,
    action: InvitationResponseAction,
    now: &Timestamp,
) -> Result<InvitationResponsePlan, InvitationError> {
    let _ = (stored_recipient_account, authenticated_account, action, now);
    Ok(InvitationResponsePlan {
        state: InvitationState::try_from(record.state).map_err(|_| InvitationError::Lifecycle)?,
        changed: true,
        grant_role: false,
        notification_kind: Some(SPOOL_INVITATION_DECLINED),
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
        .is_some_and(|owner| owner.handle.is_empty())
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

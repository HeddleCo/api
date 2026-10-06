//! Creator-only invitation code response validation. Hosts supply authenticated
//! subjects and current transactional state; projections never establish access.

use crate::heddle::api::v1alpha2::{
    GetInvitationCodeResponse, GetSignupInvitationCodeResponse, InvitationRecord, InvitationState,
    SignupInvitation, invitation_record,
};
use prost_types::Timestamp;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvitationCodeError {
    #[error("Creator: invitation code read requires the original creator")]
    Creator,
    #[error("Authority: invitation code read requires current inviter admin authority")]
    Authority,
    #[error("Expiry: invitation code read requires valid current time and finite expiry")]
    Expiry,
    #[error("NotPending: terminal invitation code response must be empty")]
    NotPending,
}

/// Trusted host context, never caller-supplied request fields. Clients may use
/// independently known state as a disclosure check, never as authorization.
pub struct InvitationCodeReadContext<'a> {
    pub caller_subject: &'a str,
    pub creator_subject: &'a str,
    pub now: &'a Timestamp,
}

pub fn validate_signup_invitation_code_response(
    response: &GetSignupInvitationCodeResponse,
    invitation: &SignupInvitation,
    context: &InvitationCodeReadContext<'_>,
) -> Result<(), InvitationCodeError> {
    validate_code_response(
        &response.redemption_secret,
        invitation.redeemed,
        invitation.revoked,
        invitation.expires_at.as_ref(),
        context,
    )
}

pub fn validate_invitation_code_response(
    response: &GetInvitationCodeResponse,
    invitation: &InvitationRecord,
    context: &InvitationCodeReadContext<'_>,
    inviter_role: i32,
) -> Result<(), InvitationCodeError> {
    validate_creator(context)?;
    if inviter_role != 3 {
        return Err(InvitationCodeError::Authority);
    }
    let non_link = !matches!(
        invitation.recipient.as_ref(),
        Some(invitation_record::Recipient::Email(email)) if !email.is_empty()
    );
    validate_code_response(
        &response.redemption_secret,
        invitation.state != InvitationState::Pending as i32,
        non_link,
        invitation.expires_at.as_ref(),
        context,
    )
}

fn valid_timestamp(time: &Timestamp) -> bool {
    (-62_135_596_800..=253_402_300_799).contains(&time.seconds)
        && (0..1_000_000_000).contains(&time.nanos)
}

fn validate_code_response(
    secret: &[u8],
    redeemed: bool,
    revoked: bool,
    expires_at: Option<&Timestamp>,
    context: &InvitationCodeReadContext<'_>,
) -> Result<(), InvitationCodeError> {
    validate_creator(context)?;
    let expiry = expires_at.ok_or(InvitationCodeError::Expiry)?;
    if !valid_timestamp(expiry) || !valid_timestamp(context.now) {
        return Err(InvitationCodeError::Expiry);
    }
    let expired = (context.now.seconds, context.now.nanos) >= (expiry.seconds, expiry.nanos);
    if !secret.is_empty() && (redeemed || revoked || expired) {
        return Err(InvitationCodeError::NotPending);
    }
    Ok(())
}

fn validate_creator(context: &InvitationCodeReadContext<'_>) -> Result<(), InvitationCodeError> {
    if context.caller_subject.is_empty()
        || context.creator_subject.is_empty()
        || context.caller_subject != context.creator_subject
    {
        return Err(InvitationCodeError::Creator);
    }
    Ok(())
}

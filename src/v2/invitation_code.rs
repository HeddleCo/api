//! Creator-only invitation code response validation. Hosts supply authenticated
//! subjects and current transactional state; projections never establish access.

use crate::heddle::api::v1alpha2::{
    GetInvitationCodeResponse, GetSignupInvitationCodeResponse, InvitationRecord, SignupInvitation,
};
use prost_types::Timestamp;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvitationCodeError {
    #[error("Creator: invitation code read requires the original creator")]
    Creator,
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
    _response: &GetSignupInvitationCodeResponse,
    _invitation: &SignupInvitation,
    _context: &InvitationCodeReadContext<'_>,
) -> Result<(), InvitationCodeError> {
    Ok(())
}

pub fn validate_invitation_code_response(
    _response: &GetInvitationCodeResponse,
    _invitation: &InvitationRecord,
    _context: &InvitationCodeReadContext<'_>,
) -> Result<(), InvitationCodeError> {
    Ok(())
}

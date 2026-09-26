//! Shape validation for the public invitation capability preview.

use crate::heddle::api::v1alpha2::{InvitationResolution, invitation_resolution::Status};

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

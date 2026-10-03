//! Advisory identity metadata bounds shared with TypeScript. No metadata here
//! grants account authority or establishes an authenticator's trustworthiness.

use super::passkey_label::{PasskeyLabelError, normalize_passkey_label};

pub const MAX_SESSION_USER_AGENT_BYTES: usize = 8192;
pub const MAX_PASSKEY_CREDENTIAL_ID_BYTES: usize = 1024;
pub const HELD_NAME_REQUESTED: &str = "HELD_NAME_REQUESTED";
pub const HELD_NAME_REQUEST_LAPSED: &str = "HELD_NAME_REQUEST_LAPSED";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AccountMetadataError {
    #[error("AAGUID must be absent or exactly 16 bytes")]
    Aaguid,
    #[error("passkey credential ID must be absent or 1..1024 bytes")]
    CredentialId,
    #[error("user agent exceeds 8192 UTF-8 bytes")]
    UserAgentTooLong,
    #[error("user agent contains a control character")]
    UserAgentControl,
}

/// Empty clears the explicit display name. Observation then uses the account's
/// primary handle, or its generated pet name while unclaimed.
pub fn normalize_display_name(value: &str) -> Result<String, PasskeyLabelError> {
    normalize_passkey_label(value)
}

/// Device labels and authenticator names use the same NFC/256-byte policy as
/// passkey labels. Empty means no advisory label, without a "Passkey" fallback.
pub fn normalize_advisory_label(value: &str) -> Result<String, PasskeyLabelError> {
    normalize_passkey_label(value)
}

pub fn validate_aaguid(value: Option<&[u8]>) -> Result<(), AccountMetadataError> {
    if value.is_some_and(|bytes| bytes.len() != 16) {
        return Err(AccountMetadataError::Aaguid);
    }
    Ok(())
}

pub fn validate_passkey_credential_id(value: Option<&[u8]>) -> Result<(), AccountMetadataError> {
    if value.is_some_and(|bytes| bytes.is_empty() || bytes.len() > MAX_PASSKEY_CREDENTIAL_ID_BYTES)
    {
        return Err(AccountMetadataError::CredentialId);
    }
    Ok(())
}

/// User agents are retained verbatim, without trimming or Unicode normalization.
/// Empty means unavailable; reject Unicode Cc before persistence or rendering.
pub fn validate_session_user_agent(value: &str) -> Result<(), AccountMetadataError> {
    if value.len() > MAX_SESSION_USER_AGENT_BYTES {
        return Err(AccountMetadataError::UserAgentTooLong);
    }
    if value.chars().any(char::is_control) {
        return Err(AccountMetadataError::UserAgentControl);
    }
    Ok(())
}

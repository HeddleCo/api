//! Passkey display labels are account metadata, outside PasskeyAuthority.

pub const DEFAULT_PASSKEY_LABEL: &str = "Passkey";
pub const MAX_PASSKEY_LABEL_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PasskeyLabelError {
    #[error("passkey label contains a control character")]
    ControlCharacter,
    #[error("passkey label exceeds 256 UTF-8 bytes after trimming")]
    TooLong,
}

/// Validate and trim a registration or rename label before storage. An empty
/// result clears the stored label so observations use the server default.
pub fn normalize_passkey_label(label: &str) -> Result<&str, PasskeyLabelError> {
    if label.chars().any(char::is_control) {
        return Err(PasskeyLabelError::ControlCharacter);
    }
    let trimmed = label.trim();
    if trimmed.len() > MAX_PASSKEY_LABEL_BYTES {
        return Err(PasskeyLabelError::TooLong);
    }
    Ok(trimmed)
}

/// Display the stored label, falling back to the server default for older
/// passkeys and for labels reset to empty by RenamePasskey.
pub fn passkey_display_label(stored_label: &str) -> &str {
    if stored_label.is_empty() {
        DEFAULT_PASSKEY_LABEL
    } else {
        stored_label
    }
}

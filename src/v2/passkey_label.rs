//! Passkey display labels are account metadata, outside PasskeyAuthority.

use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

pub const DEFAULT_PASSKEY_LABEL: &str = "Passkey";
pub const MAX_PASSKEY_LABEL_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PasskeyLabelError {
    #[error("passkey label contains a forbidden Unicode character")]
    InvalidCharacter,
    #[error("passkey label exceeds 256 UTF-8 bytes after NFC")]
    TooLong,
}

/// Validate and normalize a registration or rename label before storage. An empty
/// result clears the stored label so observations use the server default.
pub fn normalize_passkey_label(label: &str) -> Result<String, PasskeyLabelError> {
    let normalized: String = label.trim().nfc().collect();
    if normalized.chars().any(|character| {
        matches!(
            get_general_category(character),
            GeneralCategory::Control
                | GeneralCategory::Format
                | GeneralCategory::Surrogate
                | GeneralCategory::PrivateUse
                | GeneralCategory::Unassigned
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator
        )
    }) {
        return Err(PasskeyLabelError::InvalidCharacter);
    }
    if normalized.len() > MAX_PASSKEY_LABEL_BYTES {
        return Err(PasskeyLabelError::TooLong);
    }
    Ok(normalized)
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

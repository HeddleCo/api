//! Native source format negotiation is separate from signed-record support.
//!
//! These helpers validate the advertised contract; consumers must additionally
//! derive requirements from decoded States/packs and enforce closure atomically.

use crate::heddle::api::common::NativeSourceFormat;

/// Complete format-6 State / HCS3 / attribution-evidence v1 capability bundle.
pub const STATE_V6_ATTRIBUTION_V1: i32 = NativeSourceFormat::StateV6AttributionV1 as i32;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeSourceFormatError {
    #[error("invalid or unsupported required native source format {0}")]
    InvalidRequiredFormat(i32),
    #[error("duplicate required native source format {0}")]
    DuplicateRequiredFormat(i32),
    #[error(
        "peer does not support required native source format {0}; upgrade the peer, never strip attribution"
    )]
    UnsupportedByPeer(i32),
}

/// Validate required additions against explicit peer support. Empty support
/// never accepts format-6. Unknown advertisements do not imply known support;
/// unknown requirements fail closed until this implementation understands them.
pub fn require_native_source_formats(
    required: &[i32],
    understood: &[i32],
) -> Result<(), NativeSourceFormatError> {
    for (index, &format) in required.iter().enumerate() {
        if format != STATE_V6_ATTRIBUTION_V1 {
            return Err(NativeSourceFormatError::InvalidRequiredFormat(format));
        }
        if required[..index].contains(&format) {
            return Err(NativeSourceFormatError::DuplicateRequiredFormat(format));
        }
        if !understood.contains(&format) {
            return Err(NativeSourceFormatError::UnsupportedByPeer(format));
        }
    }
    Ok(())
}

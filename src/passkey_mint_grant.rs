//! Canonical account-free statement signed by a WebAuthn passkey when it
//! delegates a temporary mint root.

use sha2::{Digest, Sha256};

use crate::heddle::api::v1alpha2::{
    AuthorizationKeyAlgorithm, AuthorizationVerificationKey, PasskeyMintGrant,
};

/// Exact domain prepended to the canonical grant before SHA-256.
pub const PASSKEY_MINT_GRANT_DOMAIN: &[u8] = b"heddle-passkey-mint-grant-v1";

/// A malformed or unsupported passkey mint grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PasskeyMintGrantError {
    /// The statement uses an unsupported format version.
    #[error("passkey mint grant format_version must be 1")]
    FormatVersion,
    /// The temporary mint key is absent, malformed, or not Ed25519.
    #[error("passkey mint grant requires a 32-byte Ed25519 mint_root_key")]
    MintRootKey,
    /// The validity interval is negative, empty, reversed, or outside i64.
    #[error("passkey mint grant validity interval is invalid")]
    ValidityInterval,
    /// The freshness nonce is not exactly 32 bytes.
    #[error("passkey mint grant nonce must be 32 bytes")]
    Nonce,
    /// The relying-party ID is empty, oversized, or contains unsupported bytes.
    #[error("passkey mint grant relying_party_id is invalid")]
    RelyingPartyId,
    /// A variable-width field exceeds the canonical u32 length prefix.
    #[error("passkey mint grant field is too long")]
    FieldTooLong,
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), PasskeyMintGrantError> {
    let len = u32::try_from(value.len()).map_err(|_| PasskeyMintGrantError::FieldTooLong)?;
    push_u32(out, len);
    out.extend_from_slice(value);
    Ok(())
}

fn mint_root_key(
    value: Option<&AuthorizationVerificationKey>,
) -> Result<&AuthorizationVerificationKey, PasskeyMintGrantError> {
    value
        .filter(|key| {
            key.algorithm == AuthorizationKeyAlgorithm::Ed25519 as i32 && key.public_key.len() == 32
        })
        .ok_or(PasskeyMintGrantError::MintRootKey)
}

fn valid_relying_party_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

/// Encode a grant as fixed-width big-endian integers and u32-length-prefixed
/// key/byte/string fields, in protobuf tag order. Protobuf serialization does
/// not participate in the signing bytes.
pub fn canonical_passkey_mint_grant(
    value: &PasskeyMintGrant,
) -> Result<Vec<u8>, PasskeyMintGrantError> {
    if value.format_version != 1 {
        return Err(PasskeyMintGrantError::FormatVersion);
    }
    let key = mint_root_key(value.mint_root_key.as_ref())?;
    if value.not_before_unix_seconds < 0
        || value.expires_at_unix_seconds <= value.not_before_unix_seconds
    {
        return Err(PasskeyMintGrantError::ValidityInterval);
    }
    if value.nonce.len() != 32 {
        return Err(PasskeyMintGrantError::Nonce);
    }
    if !valid_relying_party_id(&value.relying_party_id) {
        return Err(PasskeyMintGrantError::RelyingPartyId);
    }

    let mut out = Vec::with_capacity(109 + value.relying_party_id.len());
    push_u32(&mut out, value.format_version);
    push_u32(&mut out, key.algorithm as u32);
    push_bytes(&mut out, &key.public_key)?;
    push_i64(&mut out, value.not_before_unix_seconds);
    push_i64(&mut out, value.expires_at_unix_seconds);
    push_bytes(&mut out, &value.nonce)?;
    push_bytes(&mut out, value.relying_party_id.as_bytes())?;
    Ok(out)
}

/// Return the exact 32-byte WebAuthn challenge digest for a grant.
pub fn passkey_mint_grant_signing_digest(
    value: &PasskeyMintGrant,
) -> Result<[u8; 32], PasskeyMintGrantError> {
    let canonical = canonical_passkey_mint_grant(value)?;
    let mut digest = Sha256::new();
    digest.update(PASSKEY_MINT_GRANT_DOMAIN);
    digest.update(canonical);
    Ok(digest.finalize().into())
}

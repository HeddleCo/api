//! Bounds and canonical signing inputs for password-unlocked client owner keys.
//! These checks do not turn a password proof into owner authorization.

use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::heddle::api::v1alpha2::{
    AuthenticationChallenge, CompleteAuthenticationRequest, PasswordChallengeMetadata,
    PasswordChallengeProof, PasswordDeviceAdmission, PasswordOwnerEnvelopeV1, PasswordOwnerSetup,
    PasswordOwnerSetupAuthorization, PasswordUnlockContinuation, SignedPasswordDeviceAdmission,
    SignedPasswordOwnerSetupAuthorization,
};

pub const MAX_PASSWORD_ENVELOPE_BYTES: usize = 4096;
pub const MAX_PASSWORD_SETUP_BYTES: usize = 4608;
pub const PASSWORD_ARGON2_MEMORY_KIB: u32 = 65_536;
pub const PASSWORD_ARGON2_ITERATIONS: u32 = 3;
pub const PASSWORD_ARGON2_PARALLELISM: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PasswordOwnerError {
    #[error("unsupported password owner format or KDF")]
    Version,
    #[error("unsupported password Argon2id costs")]
    KdfCosts,
    #[error("invalid password owner field length")]
    Length,
    #[error("password owner envelope is oversized or noncanonical")]
    EnvelopeEncoding,
    #[error("password owner field binding mismatch")]
    Binding,
    #[error("invalid password verifier or owner signature")]
    Signature,
}

fn cost(memory: u32, iterations: u32, parallelism: u32) -> Result<(), PasswordOwnerError> {
    if (memory, iterations, parallelism)
        != (
            PASSWORD_ARGON2_MEMORY_KIB,
            PASSWORD_ARGON2_ITERATIONS,
            PASSWORD_ARGON2_PARALLELISM,
        )
    {
        return Err(PasswordOwnerError::KdfCosts);
    }
    Ok(())
}

fn size(value: &[u8], expected: usize) -> Result<(), PasswordOwnerError> {
    if value.len() != expected {
        return Err(PasswordOwnerError::Length);
    }
    Ok(())
}

fn public_key(value: &[u8]) -> Result<VerifyingKey, PasswordOwnerError> {
    size(value, 32)?;
    let bytes: &[u8; 32] = value.try_into().map_err(|_| PasswordOwnerError::Length)?;
    let mut y = *bytes;
    y[31] &= 0x7f;
    let mut prime = [0xff; 32];
    prime[0] = 0xed;
    prime[31] = 0x7f;
    for index in (0..32).rev() {
        if y[index] < prime[index] {
            break;
        }
        if y[index] > prime[index] || index == 0 {
            return Err(PasswordOwnerError::Signature);
        }
    }
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| PasswordOwnerError::Signature)?;
    if key.is_weak() {
        return Err(PasswordOwnerError::Signature);
    }
    Ok(key)
}

fn operation_id(value: &str) -> Result<(), PasswordOwnerError> {
    if value.is_empty() || value.len() > 128 {
        return Err(PasswordOwnerError::Length);
    }
    Ok(())
}

/// Reject unsupported versions/costs before a caller allocates Argon2 memory.
pub fn validate_password_owner_envelope(
    value: &PasswordOwnerEnvelopeV1,
) -> Result<(), PasswordOwnerError> {
    if value.format_version != 1 || value.kdf_id != 1 {
        return Err(PasswordOwnerError::Version);
    }
    cost(value.memory_kib, value.iterations, value.parallelism)?;
    size(&value.account_uuid, 16)?;
    if value.account_uuid.iter().all(|byte| *byte == 0) {
        return Err(PasswordOwnerError::Binding);
    }
    public_key(&value.owner_public_key)?;
    size(&value.owner_id, 32)?;
    size(&value.wrap_salt, 16)?;
    size(&value.nonce, 12)?;
    size(&value.ciphertext_and_tag, 48)?;
    if value.encoded_len() > MAX_PASSWORD_ENVELOPE_BYTES {
        return Err(PasswordOwnerError::EnvelopeEncoding);
    }
    Ok(())
}

/// Decode known fields; callers persist the canonical re-encoding, never raw input.
pub fn decode_password_owner_envelope_canonical(
    raw: &[u8],
) -> Result<PasswordOwnerEnvelopeV1, PasswordOwnerError> {
    if raw.len() > MAX_PASSWORD_ENVELOPE_BYTES {
        return Err(PasswordOwnerError::EnvelopeEncoding);
    }
    let value =
        PasswordOwnerEnvelopeV1::decode(raw).map_err(|_| PasswordOwnerError::EnvelopeEncoding)?;
    validate_password_owner_envelope(&value)?;
    Ok(value)
}

/// Exact AES-256-GCM associated data; this binds ciphertext to its root and
/// Argon2id parameters without giving the server a decrypting key.
pub fn password_owner_wrap_aad(
    value: &PasswordOwnerEnvelopeV1,
) -> Result<Vec<u8>, PasswordOwnerError> {
    validate_password_owner_envelope(value)?;
    let mut aad = Vec::with_capacity(28 + 4 + 16 + 32 + 32 + 4 * 4 + 16);
    aad.extend_from_slice(b"heddle-owner-wrap-aad-v1\0");
    aad.extend_from_slice(&value.format_version.to_be_bytes());
    aad.extend_from_slice(&value.account_uuid);
    aad.extend_from_slice(&value.owner_public_key);
    aad.extend_from_slice(&value.owner_id);
    aad.extend_from_slice(&value.kdf_id.to_be_bytes());
    aad.extend_from_slice(&value.memory_kib.to_be_bytes());
    aad.extend_from_slice(&value.iterations.to_be_bytes());
    aad.extend_from_slice(&value.parallelism.to_be_bytes());
    aad.extend_from_slice(&value.wrap_salt);
    Ok(aad)
}

fn validate_password_owner_setup_fields(
    value: &PasswordOwnerSetup,
) -> Result<(), PasswordOwnerError> {
    let envelope = value.envelope.as_ref().ok_or(PasswordOwnerError::Length)?;
    validate_password_owner_envelope(envelope)?;
    cost(
        value.auth_memory_kib,
        value.auth_iterations,
        value.auth_parallelism,
    )?;
    size(&value.auth_salt, 16)?;
    public_key(&value.auth_verifier_public_key)?;
    if value.format_version != 1 || value.auth_kdf_id != 1 {
        return Err(PasswordOwnerError::Version);
    }
    if value.auth_salt == envelope.wrap_salt {
        return Err(PasswordOwnerError::Binding);
    }
    if value.encoded_len() > MAX_PASSWORD_SETUP_BYTES {
        return Err(PasswordOwnerError::EnvelopeEncoding);
    }
    Ok(())
}

pub fn validate_password_owner_setup(value: &PasswordOwnerSetup) -> Result<(), PasswordOwnerError> {
    validate_password_owner_setup_fields(value)?;
    size(&value.auth_verifier_possession_signature, 64)
}

/// Decode known fields, including nested fields; persist the canonical re-encoding.
pub fn decode_password_owner_setup_canonical(
    raw: &[u8],
) -> Result<PasswordOwnerSetup, PasswordOwnerError> {
    if raw.len() > MAX_PASSWORD_SETUP_BYTES {
        return Err(PasswordOwnerError::EnvelopeEncoding);
    }
    let value =
        PasswordOwnerSetup::decode(raw).map_err(|_| PasswordOwnerError::EnvelopeEncoding)?;
    validate_password_owner_setup(&value)?;
    Ok(value)
}

/// Bind an envelope to the accepted account and active owner root.
pub fn validate_password_owner_setup_binding(
    setup: &PasswordOwnerSetup,
    account_uuid: &[u8],
    owner_public_key: &[u8],
    owner_id: &[u8],
) -> Result<(), PasswordOwnerError> {
    validate_password_owner_setup(setup)?;
    let envelope = setup.envelope.as_ref().ok_or(PasswordOwnerError::Binding)?;
    public_key(owner_public_key)?;
    size(account_uuid, 16)?;
    size(owner_id, 32)?;
    if envelope.account_uuid != account_uuid
        || envelope.owner_public_key != owner_public_key
        || envelope.owner_id != owner_id
    {
        return Err(PasswordOwnerError::Binding);
    }
    Ok(())
}

/// At registration hash the challenge with this domain before signing.
pub fn password_registration_verifier_possession_digest(
    challenge: &[u8],
) -> Result<[u8; 32], PasswordOwnerError> {
    size(challenge, 32)?;
    let mut hash = Sha256::new();
    hash.update(b"heddle-password-verifier-possession-v1");
    hash.update(challenge);
    Ok(hash.finalize().into())
}

/// Verify a domain-separated registration digest or setup authorization digest.
pub fn verify_password_auth_verifier_possession(
    setup: &PasswordOwnerSetup,
    digest: &[u8; 32],
) -> Result<(), PasswordOwnerError> {
    validate_password_owner_setup(setup)?;
    let signature: &[u8; 64] = setup
        .auth_verifier_possession_signature
        .as_slice()
        .try_into()
        .map_err(|_| PasswordOwnerError::Length)?;
    public_key(&signature[..32])?;
    public_key(&setup.auth_verifier_public_key)?
        .verify_strict(digest, &Signature::from_bytes(signature))
        .map_err(|_| PasswordOwnerError::Signature)
}

/// Verify signup possession against the registration challenge.
pub fn verify_password_auth_verifier_registration_possession(
    setup: &PasswordOwnerSetup,
    challenge: &[u8],
) -> Result<(), PasswordOwnerError> {
    let digest = password_registration_verifier_possession_digest(challenge)?;
    verify_password_auth_verifier_possession(setup, &digest)
}

/// Every successful PUT or DELETE advances the lifetime revision, including a tombstone.
pub fn next_password_envelope_revision(
    current: Option<u64>,
    expected: u64,
) -> Result<u64, PasswordOwnerError> {
    let actual = current.unwrap_or(0);
    if expected != actual || (current.is_some() && actual == 0) {
        return Err(PasswordOwnerError::Binding);
    }
    actual.checked_add(1).ok_or(PasswordOwnerError::Binding)
}

/// The owner attachment nonce is specific to this challenge and continuation.
pub fn password_mint_attachment_nonce(
    challenge_nonce: &[u8],
    continuation_id: &[u8],
) -> Result<[u8; 32], PasswordOwnerError> {
    size(challenge_nonce, 32)?;
    size(continuation_id, 32)?;
    let mut hash = Sha256::new();
    hash.update(b"heddle-password-mint-nonce-v1");
    hash.update(challenge_nonce);
    hash.update(continuation_id);
    Ok(hash.finalize().into())
}

/// Bind password completion fields to the stored challenge and continuation.
/// The host still checks expiry, current accepted root, one-use state and PoP,
/// and compares the continuation revision with its stored challenge revision.
pub fn validate_password_completion_bindings(
    request: &CompleteAuthenticationRequest,
    challenge: &AuthenticationChallenge,
    continuation: &PasswordUnlockContinuation,
    bound_device_key: &[u8],
) -> Result<(), PasswordOwnerError> {
    let password_challenge = challenge
        .password_challenge
        .as_ref()
        .ok_or(PasswordOwnerError::Binding)?;
    let completion = match request.proof.as_ref() {
        Some(
            crate::heddle::api::v1alpha2::complete_authentication_request::Proof::PasswordUnlock(
                value,
            ),
        ) => value,
        _ => return Err(PasswordOwnerError::Binding),
    };
    let admission = completion
        .owner_admission
        .as_ref()
        .and_then(|signed| signed.admission.as_ref())
        .ok_or(PasswordOwnerError::Binding)?;
    let attachment = completion
        .mint_root_attachment
        .as_ref()
        .and_then(|signed| signed.attachment.as_ref())
        .ok_or(PasswordOwnerError::Binding)?;
    let envelope = continuation
        .envelope
        .as_ref()
        .ok_or(PasswordOwnerError::Binding)?;
    let credential_expiry = challenge
        .credential_expires_at
        .as_ref()
        .ok_or(PasswordOwnerError::Binding)?;
    size(bound_device_key, 32)?;
    if challenge.method != 2
        || request.challenge.is_none()
        || challenge.r#ref.is_none()
        || request.challenge != challenge.r#ref
        || !request.enroll_device
        || !request.ephemeral_public_key.is_empty()
        || completion.continuation_id != continuation.continuation_id
        || admission.challenge_id != password_challenge.challenge_id
        || admission.continuation_id != continuation.continuation_id
        || admission.account_uuid != envelope.account_uuid
        || admission.caller_device_public_key != request.caller_public_key
        || admission.caller_device_public_key != bound_device_key
        || admission.client_operation_id != request.client_operation_id
        || admission.owner_state_hash != attachment.owner_state_hash
        || admission.owner_sequence != attachment.owner_sequence
        || admission.account_uuid != attachment.account_uuid
        || attachment.mint_root_key.as_ref().is_none_or(|key| {
            key.public_key != admission.caller_device_public_key || key.algorithm != 1
        })
        || attachment.nonce
            != password_mint_attachment_nonce(
                &password_challenge.nonce,
                &continuation.continuation_id,
            )?
        || continuation.envelope_revision == 0
        || attachment.expires_at_unix_seconds > credential_expiry.seconds
    {
        return Err(PasswordOwnerError::Binding);
    }
    Ok(())
}

pub fn validate_password_challenge_metadata(
    value: &PasswordChallengeMetadata,
) -> Result<(), PasswordOwnerError> {
    cost(
        value.auth_memory_kib,
        value.auth_iterations,
        value.auth_parallelism,
    )?;
    if value.auth_kdf_id != 1 || value.format_version != 1 {
        return Err(PasswordOwnerError::Version);
    }
    size(&value.auth_salt, 16)?;
    size(&value.challenge_id, 32)?;
    size(&value.nonce, 32)?;
    Ok(())
}

/// The exact bytes hashed for an Ed25519 password-verifier signature.
pub fn password_challenge_signing_digest(
    challenge: &PasswordChallengeMetadata,
    proof: &PasswordChallengeProof,
    operation: &str,
    expiry_unix_seconds: i64,
) -> Result<[u8; 32], PasswordOwnerError> {
    validate_password_challenge_metadata(challenge)?;
    operation_id(operation)?;
    size(&proof.caller_device_public_key, 32)?;
    if proof.challenge_id != challenge.challenge_id {
        return Err(PasswordOwnerError::Binding);
    }
    let mut canonical = Vec::with_capacity(32 + 32 + 32 + 4 + operation.len() + 8);
    canonical.extend_from_slice(&challenge.challenge_id);
    canonical.extend_from_slice(&challenge.nonce);
    canonical.extend_from_slice(&proof.caller_device_public_key);
    canonical.extend_from_slice(&(operation.len() as u32).to_be_bytes());
    canonical.extend_from_slice(operation.as_bytes());
    canonical.extend_from_slice(&expiry_unix_seconds.to_be_bytes());
    let mut hash = Sha256::new();
    hash.update(b"heddle-password-proof-v1");
    hash.update(canonical);
    Ok(hash.finalize().into())
}

/// Verify a public password verifier proof. A successful result permits only
/// blob delivery and a bound continuation, never an account credential.
pub fn verify_password_challenge_signature(
    challenge: &PasswordChallengeMetadata,
    proof: &PasswordChallengeProof,
    operation: &str,
    expiry_unix_seconds: i64,
    verifier_public_key: &[u8],
) -> Result<(), PasswordOwnerError> {
    size(&proof.signature, 64)?;
    size(verifier_public_key, 32)?;
    let digest =
        password_challenge_signing_digest(challenge, proof, operation, expiry_unix_seconds)?;
    let signature: &[u8; 64] = proof
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| PasswordOwnerError::Length)?;
    public_key(&signature[..32])?;
    public_key(verifier_public_key)?
        .verify_strict(&digest, &Signature::from_bytes(signature))
        .map_err(|_| PasswordOwnerError::Signature)
}

/// Canonical owner-signed admission digest. Verifiers must also compare the
/// statement with the one-use continuation and independently current owner.
pub fn password_device_admission_digest(
    value: &PasswordDeviceAdmission,
) -> Result<[u8; 32], PasswordOwnerError> {
    if value.format_version != 1 {
        return Err(PasswordOwnerError::Version);
    }
    operation_id(&value.client_operation_id)?;
    size(&value.account_uuid, 16)?;
    if value.account_uuid.iter().all(|byte| *byte == 0) {
        return Err(PasswordOwnerError::Binding);
    }
    size(&value.challenge_id, 32)?;
    size(&value.continuation_id, 32)?;
    size(&value.caller_device_public_key, 32)?;
    size(&value.owner_state_hash, 32)?;
    let mut hash = Sha256::new();
    hash.update(b"heddle-password-device-admission-v1");
    hash.update(value.format_version.to_be_bytes());
    hash.update(&value.account_uuid);
    hash.update(&value.challenge_id);
    hash.update(&value.continuation_id);
    hash.update(&value.caller_device_public_key);
    hash.update(&value.owner_state_hash);
    hash.update(value.owner_sequence.to_be_bytes());
    hash.update((value.client_operation_id.len() as u32).to_be_bytes());
    hash.update(value.client_operation_id.as_bytes());
    Ok(hash.finalize().into())
}

/// Verify the independently owner-signed admission against the active root.
/// The host must additionally bind every admission field to its challenge,
/// continuation, completion and current owner state before enrolling a key.
pub fn verify_password_device_admission_signature(
    signed: &SignedPasswordDeviceAdmission,
    current_owner_public_key: &[u8],
) -> Result<(), PasswordOwnerError> {
    let statement = signed
        .admission
        .as_ref()
        .ok_or(PasswordOwnerError::Binding)?;
    let signature = signed
        .owner_signature
        .as_ref()
        .ok_or(PasswordOwnerError::Signature)?;
    let digest = password_device_admission_digest(statement)?;
    verify_owner_signature(&digest, signature, current_owner_public_key)
}

/// Hash the fixed-order setup fields named in the wire contract. This is not
/// protobuf serialization, so changing field order or adding unknowns fails.
pub fn password_owner_setup_digest(
    value: &PasswordOwnerSetup,
) -> Result<[u8; 32], PasswordOwnerError> {
    validate_password_owner_setup_fields(value)?;
    let envelope = value.envelope.as_ref().ok_or(PasswordOwnerError::Length)?;
    let mut hash = Sha256::new();
    hash.update(envelope.format_version.to_be_bytes());
    hash.update(&envelope.account_uuid);
    hash.update(&envelope.owner_public_key);
    hash.update(&envelope.owner_id);
    hash.update(envelope.kdf_id.to_be_bytes());
    hash.update(envelope.memory_kib.to_be_bytes());
    hash.update(envelope.iterations.to_be_bytes());
    hash.update(envelope.parallelism.to_be_bytes());
    hash.update(&envelope.wrap_salt);
    hash.update(&envelope.nonce);
    hash.update(&envelope.ciphertext_and_tag);
    hash.update(&value.auth_salt);
    hash.update(&value.auth_verifier_public_key);
    hash.update(value.auth_memory_kib.to_be_bytes());
    hash.update(value.auth_iterations.to_be_bytes());
    hash.update(value.auth_parallelism.to_be_bytes());
    hash.update(value.auth_kdf_id.to_be_bytes());
    hash.update(value.format_version.to_be_bytes());
    Ok(hash.finalize().into())
}

/// Digest signed by the active owner for a compare-and-swap PUT or DELETE.
/// The host must compare the expected revision and owner-state hash atomically.
pub fn password_owner_setup_authorization_digest(
    value: &PasswordOwnerSetupAuthorization,
    setup: Option<&PasswordOwnerSetup>,
) -> Result<[u8; 32], PasswordOwnerError> {
    if value.format_version != 1 {
        return Err(PasswordOwnerError::Version);
    }
    operation_id(&value.client_operation_id)?;
    size(&value.account_uuid, 16)?;
    size(&value.owner_state_hash, 32)?;
    size(&value.setup_sha256, 32)?;
    if value.account_uuid.iter().all(|byte| *byte == 0) {
        return Err(PasswordOwnerError::Binding);
    }
    let expected_digest = match (value.action, setup) {
        (1, Some(setup)) => {
            let envelope = setup.envelope.as_ref().ok_or(PasswordOwnerError::Length)?;
            if envelope.account_uuid != value.account_uuid {
                return Err(PasswordOwnerError::Binding);
            }
            password_owner_setup_digest(setup)?
        }
        (2, None) => [0; 32],
        _ => return Err(PasswordOwnerError::Binding),
    };
    if value.setup_sha256 != expected_digest {
        return Err(PasswordOwnerError::Binding);
    }
    let expiry = value
        .expires_at
        .as_ref()
        .ok_or(PasswordOwnerError::Binding)?;
    if expiry.nanos != 0 || expiry.seconds <= 0 {
        return Err(PasswordOwnerError::Binding);
    }
    let mut hash = Sha256::new();
    hash.update(b"heddle-password-owner-setup-change-v1");
    hash.update(value.format_version.to_be_bytes());
    hash.update(value.action.to_be_bytes());
    hash.update(&value.account_uuid);
    hash.update(&value.owner_state_hash);
    hash.update(value.expected_revision.to_be_bytes());
    hash.update(&value.setup_sha256);
    hash.update((value.client_operation_id.len() as u32).to_be_bytes());
    hash.update(value.client_operation_id.as_bytes());
    hash.update(expiry.seconds.to_be_bytes());
    Ok(hash.finalize().into())
}

/// Check the signed short-lived authorization at the server's verification time.
pub fn validate_password_owner_setup_authorization_expiry(
    value: &PasswordOwnerSetupAuthorization,
    now_unix_seconds: i64,
) -> Result<(), PasswordOwnerError> {
    let expiry = value
        .expires_at
        .as_ref()
        .ok_or(PasswordOwnerError::Binding)?;
    let latest = now_unix_seconds
        .checked_add(600)
        .ok_or(PasswordOwnerError::Binding)?;
    if expiry.nanos != 0 || expiry.seconds <= now_unix_seconds || expiry.seconds > latest {
        return Err(PasswordOwnerError::Binding);
    }
    Ok(())
}

/// Verify that a setup change has the current owner's signature. Caller PoP
/// and account authorization remain separate RPC requirements.
pub fn verify_password_owner_setup_authorization_signature(
    signed: &SignedPasswordOwnerSetupAuthorization,
    setup: Option<&PasswordOwnerSetup>,
    current_owner_public_key: &[u8],
) -> Result<(), PasswordOwnerError> {
    let statement = signed
        .authorization
        .as_ref()
        .ok_or(PasswordOwnerError::Binding)?;
    let signature = signed
        .owner_signature
        .as_ref()
        .ok_or(PasswordOwnerError::Signature)?;
    let digest = password_owner_setup_authorization_digest(statement, setup)?;
    if let Some(setup) = setup {
        let envelope = setup.envelope.as_ref().ok_or(PasswordOwnerError::Binding)?;
        if envelope.owner_public_key != current_owner_public_key {
            return Err(PasswordOwnerError::Binding);
        }
        verify_password_auth_verifier_possession(setup, &digest)?;
    }
    verify_owner_signature(&digest, signature, current_owner_public_key)
}

fn verify_owner_signature(
    digest: &[u8; 32],
    signature: &crate::heddle::api::v1alpha2::AuthorizationSignature,
    current_owner_public_key: &[u8],
) -> Result<(), PasswordOwnerError> {
    size(current_owner_public_key, 32)?;
    size(&signature.signer_key_id, 32)?;
    size(&signature.signature, 64)?;
    let mut key_id = Sha256::new();
    key_id.update(b"heddle-key-v1");
    key_id.update(1_u32.to_be_bytes());
    key_id.update(current_owner_public_key);
    if signature.signer_key_id != key_id.finalize().as_slice() {
        return Err(PasswordOwnerError::Signature);
    }
    let signature: &[u8; 64] = signature
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| PasswordOwnerError::Length)?;
    public_key(&signature[..32])?;
    public_key(current_owner_public_key)?
        .verify_strict(digest, &Signature::from_bytes(signature))
        .map_err(|_| PasswordOwnerError::Signature)
}

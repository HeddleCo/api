//! Canonical email binding and preliminary custody admission gates.
//! These checks do not authenticate an email secret, verify portable signatures,
//! consult current owner state, or replace the shared capability verifier.
use crate::heddle::api::v1alpha2 as api;
use sha2::{Digest, Sha256};

pub const CUSTODIAL_VETO: &str = "heddle.custodial-recovery-veto.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid custody binding")]
    Binding,
    #[error("custody attempt is closed or not prepared")]
    State,
    #[error("custody attempt version conflict")]
    Version,
    #[error("custody attempt is not yet eligible")]
    Early,
    #[error("custody attempt expired")]
    Expired,
    #[error("custody Recover is missing a fresh guardian or its proof")]
    FreshKey,
    #[error("custody Recover differs from its prepared proposal")]
    Proposal,
}

/// Fixed-width v1; protobuf serialization never participates in this binding.
pub fn canonical_email_binding(binding: &api::CustodialEmailBinding) -> Result<Vec<u8>, Error> {
    if binding.format_version != 1
        || binding.account_uuid.len() != 16
        || binding.attempt_uuid.len() != 16
        || binding.proposed_root_public_key.len() != 32
        || binding.challenge.len() != 32
        || binding.expires_at_unix_seconds <= 0
    {
        return Err(Error::Binding);
    }
    let mut bytes = Vec::with_capacity(108);
    bytes.extend_from_slice(&binding.format_version.to_be_bytes());
    for field in [
        &binding.account_uuid,
        &binding.attempt_uuid,
        &binding.proposed_root_public_key,
        &binding.challenge,
    ] {
        bytes.extend_from_slice(field);
    }
    bytes.extend_from_slice(&binding.expires_at_unix_seconds.to_be_bytes());
    Ok(bytes)
}

/// Checks intent/expiry only. The service separately constant-time compares the
/// stored secret hash and consumes it with email-version/consent/current-tip CAS.
pub fn validate_email_proof(
    proof: &api::CustodialEmailProof,
    expected: &api::CustodialEmailBinding,
    now: i64,
) -> Result<(), Error> {
    let binding = proof.binding.as_ref().ok_or(Error::Binding)?;
    if canonical_email_binding(binding)? != canonical_email_binding(expected)?
        || proof.email_secret.len() != 32
        || now < 0
    {
        return Err(Error::Binding);
    }
    if now >= expected.expires_at_unix_seconds {
        return Err(Error::Expired);
    }
    Ok(())
}

pub fn email_secret_hash(proof: &api::CustodialEmailProof) -> Result<[u8; 32], Error> {
    if proof.email_secret.len() != 32 {
        return Err(Error::Binding);
    }
    let binding = canonical_email_binding(proof.binding.as_ref().ok_or(Error::Binding)?)?;
    let mut hash = Sha256::new();
    hash.update(b"heddle-custodial-email-secret-v1");
    hash.update(binding);
    hash.update(&proof.email_secret);
    Ok(hash.finalize().into())
}

fn key_id(key: &api::AuthorizationVerificationKey) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"heddle-key-v1");
    hash.update(key.algorithm.to_be_bytes());
    hash.update(&key.public_key);
    hash.finalize().to_vec()
}

fn signature_shape(
    proof: &api::AuthorizationSignature,
    key: &api::AuthorizationVerificationKey,
) -> bool {
    proof.signer_key_id == key_id(key) && proof.signature.len() == 64
}

/// The existing verifier's canonical v1 encoding, restricted to the custody
/// Recover shape. This is an encoding check, not owner-history verification.
pub fn canonical_recover(body: &api::OwnerKeyTransition) -> Result<Vec<u8>, Error> {
    let next = body.next_authority_key.as_ref().ok_or(Error::Proposal)?;
    let policy = body.next_recovery_policy.as_ref().ok_or(Error::FreshKey)?;
    if policy.threshold != 1 || policy.guardians.len() != 1 {
        return Err(Error::FreshKey);
    }
    let guardian = &policy.guardians[0];
    let key = guardian.key.as_ref().ok_or(Error::FreshKey)?;
    if body.format_version != 1
        || body.owner_id.len() != 32
        || body.previous_state_hash.len() != 32
        || body.sequence == 0
        || body.kind != api::OwnerKeyTransitionKind::Recover as i32
        || body.nonce.len() != 32
        || body.valid_from_unix_seconds <= 0
        || body.previous_key_valid_until_unix_seconds != 0
        || next.algorithm != 1
        || next.public_key.len() != 32
        || guardian.kind != api::RecoveryGuardianKind::Weft as i32
        || key.algorithm != 1
        || key.public_key.len() != 32
        || policy.window_secs.unwrap_or(604800) == 0
    {
        return Err(Error::Proposal);
    }
    fn counted(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
        let len = u32::try_from(bytes.len()).map_err(|_| Error::Proposal)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
        Ok(())
    }
    let mut out = Vec::new();
    out.extend_from_slice(&body.format_version.to_be_bytes());
    counted(&mut out, &body.owner_id)?;
    counted(&mut out, &body.previous_state_hash)?;
    out.extend_from_slice(&body.sequence.to_be_bytes());
    out.extend_from_slice(&body.kind.to_be_bytes());
    out.extend_from_slice(&next.algorithm.to_be_bytes());
    counted(&mut out, &next.public_key)?;
    out.extend_from_slice(&policy.threshold.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&guardian.kind.to_be_bytes());
    out.extend_from_slice(&key.algorithm.to_be_bytes());
    counted(&mut out, &key.public_key)?;
    out.extend_from_slice(&policy.window_secs.unwrap_or(604800).to_be_bytes());
    out.extend_from_slice(&body.valid_from_unix_seconds.to_be_bytes());
    out.extend_from_slice(&0i64.to_be_bytes());
    counted(&mut out, &body.nonce)?;
    Ok(out)
}

pub fn proposal_signing_digest(
    proposal: &api::CustodialRecoverProposal,
) -> Result<[u8; 32], Error> {
    let body = proposal
        .recover
        .as_ref()
        .and_then(|r| r.transition.as_ref())
        .ok_or(Error::Proposal)?;
    let canonical = canonical_recover(body)?;
    let mut hash = Sha256::new();
    hash.update(b"heddle-owner-key-transition-v1");
    hash.update(&canonical);
    let digest: [u8; 32] = hash.finalize().into();
    if proposal.canonical_transition != canonical || proposal.signing_digest.as_slice() != digest {
        return Err(Error::Proposal);
    }
    Ok(digest)
}

/// Structural gates against the persisted attempt/proposal and independently
/// resolved old guardian. Hosts MUST also enforce current tip, email, consent,
/// request PoP and apply_transition_with_timelock in the completion transaction.
pub fn validate_submission(
    attempt: &api::RecoveryAttempt,
    proposal: &api::CustodialRecoverProposal,
    request: &api::SubmitCustodialRecoverRequest,
    old_guardian: &api::AuthorizationVerificationKey,
    now: i64,
) -> Result<(), Error> {
    let details = attempt.custodial.as_ref().ok_or(Error::Binding)?;
    if attempt.vetoed
        || attempt.completed
        || details.state != api::CustodialRecoveryState::Prepared as i32
    {
        return Err(Error::State);
    }
    let binding = details.binding.as_ref().ok_or(Error::Binding)?;
    canonical_email_binding(binding)?;
    let reference = attempt.r#ref.as_ref().ok_or(Error::Binding)?;
    if reference.spool.is_some()
        || reference.id.is_empty()
        || request.recovery.as_ref() != Some(reference)
        || now < 0
    {
        return Err(Error::Binding);
    }
    if attempt.version.len() != 32 || request.expected_version != attempt.version {
        return Err(Error::Version);
    }
    let seconds = |time: Option<&prost_types::Timestamp>| -> Result<i64, Error> {
        time.filter(|t| t.nanos == 0 && t.seconds > 0)
            .map(|t| t.seconds)
            .ok_or(Error::Binding)
    };
    let start = seconds(details.started_at.as_ref())?;
    let eligible = seconds(attempt.eligible_at.as_ref())?;
    let expiry = seconds(details.expires_at.as_ref())?;
    let window = i64::try_from(details.effective_window_secs).map_err(|_| Error::Binding)?;
    if window <= 0
        || start.checked_add(window) != Some(eligible)
        || eligible.checked_add(86400) != Some(expiry)
    {
        return Err(Error::Binding);
    }
    if now < eligible {
        return Err(Error::Early);
    }
    if now >= expiry {
        return Err(Error::Expired);
    }
    let prepared = proposal.recover.as_ref().ok_or(Error::Proposal)?;
    proposal_signing_digest(proposal)?;
    let signed = request.recover.as_ref().ok_or(Error::Proposal)?;
    let body = signed.transition.as_ref().ok_or(Error::Proposal)?;
    let next_root = body.next_authority_key.as_ref().ok_or(Error::Proposal)?;
    let policy = body.next_recovery_policy.as_ref().ok_or(Error::FreshKey)?;
    if policy.threshold != 1 || policy.guardians.len() != 1 {
        return Err(Error::FreshKey);
    }
    let guardian = &policy.guardians[0];
    let fresh = guardian.key.as_ref().ok_or(Error::FreshKey)?;
    if guardian.kind != api::RecoveryGuardianKind::Weft as i32
        || fresh.algorithm != 1
        || fresh.public_key.len() != 32
        || fresh == old_guardian
        || fresh == next_root
        || signed.next_recovery_key_proofs.len() != 1
        || !signature_shape(&signed.next_recovery_key_proofs[0], fresh)
    {
        return Err(Error::FreshKey);
    }
    if body.format_version != 1
        || body.kind != api::OwnerKeyTransitionKind::Recover as i32
        || body.previous_state_hash.len() != 32
        || body.previous_state_hash != details.owner_state_hash
        || body.valid_from_unix_seconds != eligible
        || body.previous_key_valid_until_unix_seconds != 0
        || next_root.algorithm != 1
        || next_root.public_key != binding.proposed_root_public_key
        || policy.window_secs.unwrap_or(604800) != details.effective_window_secs
        || proposal.recovery.as_ref() != Some(attempt)
        || proposal.ownership.as_ref().map(|o| &o.version) != Some(&details.owner_state_hash)
        || prepared.next_authority_key_proof.is_some()
        || signed.transition != prepared.transition
        || signed.authorizations != prepared.authorizations
        || signed.next_recovery_key_proofs != prepared.next_recovery_key_proofs
        || signed.authorizations.len() != 1
        || !signature_shape(&signed.authorizations[0], old_guardian)
        || !signed
            .next_authority_key_proof
            .as_ref()
            .is_some_and(|p| signature_shape(p, next_root))
    {
        return Err(Error::Proposal);
    }
    Ok(())
}

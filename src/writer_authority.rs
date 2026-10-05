//! Portable writer binding and retained device checks. Owner-history/Biscuit
//! verification remains the native verifier's responsibility. Expected issuer
//! facts and admission inventories MUST come from independently verified state.
use crate::heddle::api::{common as host, v1alpha2 as api};
use crate::hybrid_codec::{Reject, counted, hash, key_id, strict_decode, verify, width};

pub fn decode_authority(envelope: &[u8]) -> Result<api::ThreadControlAuthority, Reject> {
    let authority: api::ThreadControlAuthority = strict_decode(envelope, 65536)?;
    if authority.format != 1 {
        return Err(Reject::Version);
    }
    Ok(authority)
}
/// Bind the actor's OWN root account; preserve exact owner identity when the
/// actor is the Spool owner. This does not authenticate a carried owner history.
pub fn verify_account_binding(
    authority: &api::ThreadControlAuthority,
    actor_account: &[u8],
    spool_account: &[u8],
    spool_owner_id: &[u8],
) -> Result<(), Reject> {
    width(actor_account, 16)?;
    if actor_account.iter().all(|b| *b == 0) {
        return Err(Reject::Canonical);
    }
    width(spool_account, 16)?;
    width(spool_owner_id, 32)?;
    let root = authority
        .owner
        .as_ref()
        .and_then(|h| h.root.as_ref())
        .and_then(|s| s.root.as_ref())
        .ok_or(Reject::Root)?;
    width(&root.account_uuid, 16)?;
    width(&root.owner_id, 32)?;
    if root.account_uuid != actor_account {
        return Err(Reject::GenesisBinding);
    }
    if actor_account == spool_account && root.owner_id != spool_owner_id {
        return Err(Reject::Root);
    }
    Ok(())
}
/// Owner-signed Spool policy cuts apply to the actor's publisher AND mint root,
/// including writers whose accounts differ from the Spool governance owner.
pub fn check_writer_keys(
    authority: &api::ThreadControlAuthority,
    publisher_key_id: &[u8],
    revoked_key_ids: &[Vec<u8>],
) -> Result<(), Reject> {
    width(publisher_key_id, 32)?;
    width(&authority.mint_root_public_key, 32)?;
    if revoked_key_ids
        .iter()
        .any(|id| id == publisher_key_id || *id == key_id(&authority.mint_root_public_key))
    {
        return Err(Reject::Revoked);
    }
    Ok(())
}
/// The carrier only locates these facts. Authenticate the Spool policy and
/// selected owner history separately before durable admission.
pub(crate) fn check_witness_writer(
    statement: &host::HostedWitnessStatementV1,
    envelope: &[u8],
    histories: &[api::OwnerHistory],
    policies: &[api::SignedSpoolPolicyRecord],
) -> Result<(), Reject> {
    crate::import_authority::require_policy_history(
        policies,
        &statement.spool_uuid,
        statement.policy_sequence,
        &statement.policy_state_hash,
    )?;
    let revoked = policies
        .iter()
        .filter_map(|p| p.body.as_ref())
        .find(|p| {
            p.spool_uuid == statement.spool_uuid
                && p.sequence == statement.policy_sequence
                && p.policy_state_hash == statement.policy_state_hash
        })
        .and_then(|p| p.policy.as_ref())
        .map(|p| p.revoked_key_ids.as_slice())
        .unwrap_or(&[]);
    if revoked.contains(&statement.publisher_key_id) {
        return Err(Reject::Revoked);
    }
    if envelope.is_empty() {
        if statement.purpose != 1 {
            return Err(Reject::Bounds);
        }
        return Ok(()); // LocalKey genesis: no account envelope or mint root.
    }
    let authority = decode_authority(envelope)?;
    let spool = histories
        .iter()
        .filter(|h| h.state_hash == statement.owner_state_hash)
        .filter_map(|h| h.root.as_ref()?.root.as_ref())
        .find(|r| r.owner_id == statement.owner_id)
        .ok_or(Reject::Root)?;
    let actor = authority
        .owner
        .as_ref()
        .and_then(|h| h.root.as_ref())
        .and_then(|s| s.root.as_ref())
        .ok_or(Reject::Root)?;
    verify_account_binding(
        &authority,
        &actor.account_uuid,
        &spool.account_uuid,
        &statement.owner_id,
    )?;
    check_writer_keys(&authority, &statement.publisher_key_id, revoked)
}

/// Issuer facts come from the actor's verified owner history. Recover clears
/// retained_mint_authority for every prior issuer; Rotate preserves it.
pub struct RetainedMintRootExpectation<'a> {
    pub account_uuid: &'a [u8],
    pub mint_root_public_key: &'a [u8],
    pub issuer_state_hash: &'a [u8],
    pub issuer_sequence: u64,
    pub issuer_public_key: &'a [u8],
    pub issuer_retained_mint_authority: bool,
    /// Issuance: durable host inventory. Receiver: exact attachments extracted
    /// from authenticated P1/P2/P4 payloads after witness and payload checks.
    pub admitted_attachments: &'a [api::SignedOwnerMintRootAttachment],
    pub now_unix_seconds: i64,
}
/// No historical certificate establishes its own prior admission. In particular
/// a valid old-owner signature on a newly forged certificate is insufficient.
pub fn verify_retained_owner_mint_root_attachment(
    signed: &api::SignedOwnerMintRootAttachment,
    expected: &RetainedMintRootExpectation<'_>,
) -> Result<(), Reject> {
    if !expected.issuer_retained_mint_authority || !expected.admitted_attachments.contains(signed) {
        return Err(Reject::Root);
    }
    let a = signed.attachment.as_ref().ok_or(Reject::Canonical)?;
    let owner = a.owner_key.as_ref().ok_or(Reject::Canonical)?;
    let mint = a.mint_root_key.as_ref().ok_or(Reject::Canonical)?;
    if a.account_uuid != expected.account_uuid
        || a.owner_state_hash != expected.issuer_state_hash
        || a.owner_sequence != expected.issuer_sequence
        || owner.public_key != expected.issuer_public_key
        || mint.public_key != expected.mint_root_public_key
    {
        return Err(Reject::Root);
    }
    if a.format_version != 1
        || owner.algorithm != 1
        || mint.algorithm != 1
        || a.account_uuid.iter().all(|b| *b == 0)
        || a.not_before_unix_seconds < 0
        || a.expires_at_unix_seconds <= a.not_before_unix_seconds
    {
        return Err(Reject::Canonical);
    }
    width(&a.account_uuid, 16)?;
    for bytes in [
        &a.owner_state_hash,
        &a.nonce,
        &owner.public_key,
        &mint.public_key,
    ] {
        width(bytes, 32)?;
    }
    if expected.now_unix_seconds < a.not_before_unix_seconds
        || expected.now_unix_seconds >= a.expires_at_unix_seconds
    {
        return Err(Reject::Expired);
    }
    let mut body = a.format_version.to_be_bytes().to_vec();
    counted(&mut body, &a.account_uuid)?;
    counted(&mut body, &a.owner_state_hash)?;
    body.extend_from_slice(&a.owner_sequence.to_be_bytes());
    for k in [owner, mint] {
        body.extend_from_slice(&(k.algorithm as u32).to_be_bytes());
        counted(&mut body, &k.public_key)?;
    }
    body.extend_from_slice(&a.not_before_unix_seconds.to_be_bytes());
    body.extend_from_slice(&a.expires_at_unix_seconds.to_be_bytes());
    counted(&mut body, &a.nonce)?;
    let signature = signed.owner_signature.as_ref().ok_or(Reject::Signature)?;
    if signature.signer_key_id != key_id(&owner.public_key) {
        return Err(Reject::Signature);
    }
    verify(
        expected.issuer_public_key,
        &hash(&[b"heddle-mint-root-attachment-v1", &body]),
        &signature.signature,
    )
}

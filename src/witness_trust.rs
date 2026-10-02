//! Authenticated complete witness history. Root selection is the existing
//! descriptor_trust caller's responsibility; endpoint keys never create trust.
use crate::heddle::api::common::*;
pub use crate::hybrid_codec::Reject;
use crate::hybrid_codec::{canonical, field, hash, record, verify, width};

pub const SET_DOMAIN: &str = "heddle-hosted-witness-set-v1\0";
pub const MAX_SET_BYTES: usize = 1024 * 1024;
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_PROOF_BYTES: usize = 4096;
pub const MAX_SIBLINGS: usize = 64;
record!(HostedWitnessEntryV1, executor_id:b, public_key:b, role:e, state:e, purposes:p,
    active_from_unix_millis:u, active_until_unix_millis:u, archive_root:b,
    archive_leaf_count:u, revoked_at_unix_millis:u);
record!(HostedWitnessSetV1, format_version:u, deployment_authority:s, descriptor_root_id:s,
    generation:u, issued_at_unix_millis:u, valid_until_unix_millis:u, current_executor_id:b, entries:l);
record!(HostedWitnessStatementV1, format_version:u, executor_id:b, purpose:e, spool_uuid:b,
    spool_genesis_digest:b, owner_id:b, owner_state_hash:b, ownership_transfer_sequence:u,
    policy_state_hash:b, policy_sequence:u, basis:e, publisher_key_id:b, authority_digest:b,
    original_signatures_digest:b, host_transaction_id:b, admission_order:u,
    observed_at_unix_millis:u, canonical_payload:b);

pub fn witness_id(public_key: &[u8]) -> Vec<u8> {
    hash(&[b"heddle-hosted-witness-key-v1\0", public_key])
}
pub fn set_signing_bytes(value: &HostedWitnessSetV1) -> Result<Vec<u8>, Reject> {
    let mut bytes = SET_DOMAIN.as_bytes().to_vec();
    bytes.extend_from_slice(&canonical(value)?);
    if bytes.len() + 96 > MAX_SET_BYTES {
        return Err(Reject::Bounds);
    }
    Ok(bytes)
}
pub fn purpose_domain(purpose: i32) -> Result<&'static str, Reject> {
    match purpose {
        1 => Ok("heddle-import-genesis-first-admission-witness-v1"),
        2 => Ok("heddle-import-authority-first-admission-witness-v1"),
        3 => Ok("heddle-import-publication-witness-v1"),
        4 => Ok("heddle-hosted-landing-witness-v1"),
        _ => Err(Reject::Version),
    }
}
pub fn statement_signing_digest(value: &HostedWitnessStatementV1) -> Result<Vec<u8>, Reject> {
    crate::hybrid_codec::signing_digest(purpose_domain(value.purpose)?, value)
}
pub fn leaf_digest(purpose: i32, canonical: &[u8], signature: &[u8]) -> Result<Vec<u8>, Reject> {
    purpose_domain(purpose)?;
    width(signature, 64)?;
    if canonical.is_empty() || canonical.len() > 128 * 1024 {
        return Err(Reject::Bounds);
    }
    Ok(hash(&[
        &[0],
        &(purpose as u32).to_be_bytes(),
        &(canonical.len() as u64).to_be_bytes(),
        canonical,
        signature,
    ]))
}

/// Receiver-owned inputs, serialized with durable mutation. Known job keys
/// include retained associations across expiry, renewal and deletion.
#[derive(Clone, Copy)]
pub struct SetExpectation<'a> {
    pub authority: &'a str,
    pub root_id: &'a str,
    pub root_public_key: &'a [u8],
    pub root_epoch: u64,
    pub now_unix_millis: i64,
    pub clock_floor_unix_millis: i64,
    pub known_job_keys: &'a [Vec<u8>],
}

/// Rebuild ONLY the receiver's previously accepted, durable history snapshot.
/// Its old freshness window is not a new-work permission. Persist the original
/// signed bytes and clock floor; callers must separately authenticate a fresh
/// set at their actual clock with this returned high-water as `previous`.
pub fn restore_history_snapshot(
    signed: &SignedHostedWitnessSetV1,
    selected: &SetExpectation<'_>,
) -> Result<VerifiedWitnessSet, Reject> {
    let body = signed.body.as_ref().ok_or(Reject::Canonical)?;
    let mut historical = *selected;
    historical.now_unix_millis = body.issued_at_unix_millis;
    historical.clock_floor_unix_millis = 0;
    verify_set(signed, &historical, None)
}
/// Cannot be constructed by callers. Retain its full body as the durable
/// previous snapshot; no isolated entry is sufficient trust.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedWitnessSet {
    body: HostedWitnessSetV1,
    digest: Vec<u8>,
    root_epoch: u64,
}
impl VerifiedWitnessSet {
    pub fn body(&self) -> &HostedWitnessSetV1 {
        &self.body
    }
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
    pub fn root_epoch(&self) -> u64 {
        self.root_epoch
    }
}

pub fn verify_set(
    signed: &SignedHostedWitnessSetV1,
    expected: &SetExpectation<'_>,
    previous: Option<&VerifiedWitnessSet>,
) -> Result<VerifiedWitnessSet, Reject> {
    use prost::Message;
    if signed.encoded_len() > MAX_SET_BYTES {
        return Err(Reject::Bounds);
    }
    let body = signed.body.as_ref().ok_or(Reject::Canonical)?;
    if body.format_version != 1 {
        return Err(Reject::Version);
    }
    if body.deployment_authority != expected.authority
        || body.descriptor_root_id != expected.root_id
    {
        return Err(Reject::Root);
    }
    let input = set_signing_bytes(body)?;
    verify(expected.root_public_key, &input, &signed.root_signature)?;
    let digest = hash(&[&input]);
    if digest != signed.body_digest {
        return Err(Reject::Canonical);
    }
    if body.generation == 0 || body.entries.is_empty() || body.entries.len() > MAX_ENTRIES {
        return Err(Reject::Semantic);
    }
    if expected.now_unix_millis < expected.clock_floor_unix_millis {
        return Err(Reject::StaleContext);
    }
    if body.issued_at_unix_millis < 0
        || body.valid_until_unix_millis <= body.issued_at_unix_millis
        || body.valid_until_unix_millis - body.issued_at_unix_millis > 300_000
    {
        return Err(Reject::Semantic);
    }
    if expected.now_unix_millis < body.issued_at_unix_millis
        || expected.now_unix_millis >= body.valid_until_unix_millis
    {
        return Err(Reject::Expired);
    }
    crate::import_authority::canonical_https(&body.deployment_authority, true)?;
    if body.descriptor_root_id.is_empty() || body.descriptor_root_id.len() > 256 {
        return Err(Reject::Bounds);
    }
    width(&body.current_executor_id, 32)?;
    let mut current = 0;
    for (i, entry) in body.entries.iter().enumerate() {
        width(&entry.public_key, 32)?;
        width(&entry.executor_id, 32)?;
        if entry.executor_id != witness_id(&entry.public_key)
            || (i > 0 && body.entries[i - 1].executor_id >= entry.executor_id)
            || body.entries[..i]
                .iter()
                .any(|old| old.public_key == entry.public_key)
            || entry.public_key == expected.root_public_key
        {
            return Err(Reject::Semantic);
        }
        if entry.role != 1 || expected.known_job_keys.contains(&entry.public_key) {
            return Err(Reject::JobAsWitness);
        }
        if entry.purposes.is_empty()
            || entry.purposes.iter().any(|p| !(1..=4).contains(p))
            || entry.purposes.windows(2).any(|p| p[0] >= p[1])
            || entry.active_from_unix_millis < 0
            || entry.active_until_unix_millis <= entry.active_from_unix_millis
        {
            return Err(Reject::Semantic);
        }
        match entry.state {
            1 => {
                current += 1;
                if entry.executor_id != body.current_executor_id
                    || entry.active_from_unix_millis > body.issued_at_unix_millis
                    || entry.active_until_unix_millis < body.valid_until_unix_millis
                    || !entry.archive_root.is_empty()
                    || entry.archive_leaf_count != 0
                    || entry.revoked_at_unix_millis != 0
                {
                    return Err(Reject::Semantic);
                }
            }
            2 => {
                width(&entry.archive_root, 32)?;
                if entry.active_until_unix_millis > body.issued_at_unix_millis
                    || entry.revoked_at_unix_millis != 0
                    || (entry.archive_leaf_count == 0 && entry.archive_root != hash(&[b""]))
                {
                    return Err(Reject::Semantic);
                }
            }
            3 => {
                if entry.revoked_at_unix_millis <= 0
                    || entry.revoked_at_unix_millis > body.issued_at_unix_millis
                    || (!entry.archive_root.is_empty() && entry.archive_root.len() != 32)
                    || (entry.archive_root.is_empty() && entry.archive_leaf_count != 0)
                {
                    return Err(Reject::Semantic);
                }
            }
            _ => return Err(Reject::Semantic),
        }
    }
    if current != 1 {
        return Err(Reject::Semantic);
    }
    if let Some(old) = previous {
        if old.root_epoch != expected.root_epoch {
            return Err(Reject::StaleContext);
        }
        if body.generation < old.body.generation
            || (body.generation == old.body.generation && digest != old.digest)
        {
            return Err(Reject::HighWater);
        }
        for before in &old.body.entries {
            let after = body
                .entries
                .iter()
                .find(|e| e.executor_id == before.executor_id)
                .ok_or(Reject::Transition)?;
            if before.public_key != after.public_key
                || before.role != after.role
                || before.purposes != after.purposes
                || before.active_from_unix_millis != after.active_from_unix_millis
                || (before.state != 1
                    && (before.active_until_unix_millis != after.active_until_unix_millis
                        || before.archive_root != after.archive_root
                        || before.archive_leaf_count != after.archive_leaf_count))
                || (before.state == 2 && after.state == 1)
                || (before.state == 3
                    && (after.state != 3
                        || after.revoked_at_unix_millis != before.revoked_at_unix_millis))
                || (before.state == 1
                    && after.state != 1
                    && after.active_until_unix_millis < old.body.valid_until_unix_millis)
            {
                return Err(Reject::Transition);
            }
        }
    }
    Ok(VerifiedWitnessSet {
        body: body.clone(),
        digest,
        root_epoch: expected.root_epoch,
    })
}

fn split(count: u64) -> u64 {
    1_u64 << (63 - (count - 1).leading_zeros())
}
pub fn merkle_root(sorted_leaves: &[Vec<u8>]) -> Result<Vec<u8>, Reject> {
    if sorted_leaves.iter().any(|x| x.len() != 32) || sorted_leaves.windows(2).any(|x| x[0] >= x[1])
    {
        return Err(Reject::Canonical);
    }
    fn tree(leaves: &[Vec<u8>]) -> Vec<u8> {
        match leaves.len() {
            0 => hash(&[b""]),
            1 => leaves[0].clone(),
            n => {
                let k = split(n as u64) as usize;
                hash(&[&[1], &tree(&leaves[..k]), &tree(&leaves[k..])])
            }
        }
    }
    Ok(tree(sorted_leaves))
}
pub fn verify_inclusion(
    leaf: &[u8],
    proof: &HostedWitnessHistoryProofV1,
    entry: &HostedWitnessEntryV1,
) -> Result<(), Reject> {
    use prost::Message;
    if proof.encoded_len() > MAX_PROOF_BYTES || proof.siblings.len() > MAX_SIBLINGS {
        return Err(Reject::Bounds);
    }
    if leaf.len() != 32
        || proof.executor_id != entry.executor_id
        || proof.leaf_count != entry.archive_leaf_count
        || proof.leaf_count == 0
        || proof.leaf_index >= proof.leaf_count
        || proof.siblings.iter().any(|s| s.len() != 32)
    {
        return Err(Reject::Proof);
    }
    fn path(index: u64, count: u64, directions: &mut Vec<bool>) {
        if count == 1 {
            return;
        }
        let k = split(count);
        if index < k {
            path(index, k, directions);
            directions.push(false);
        } else {
            path(index - k, count - k, directions);
            directions.push(true);
        }
    }
    let mut directions = Vec::new();
    path(proof.leaf_index, proof.leaf_count, &mut directions);
    if directions.len() != proof.siblings.len() {
        return Err(Reject::Proof);
    }
    let mut root = leaf.to_vec();
    for (right, sibling) in directions.iter().zip(&proof.siblings) {
        root = if *right {
            hash(&[&[1], sibling, &root])
        } else {
            hash(&[&[1], &root, sibling])
        };
    }
    if root != entry.archive_root {
        return Err(Reject::Proof);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedWitnessStatement {
    statement_digest: Vec<u8>,
    set_digest: Vec<u8>,
    generation: u64,
    root_epoch: u64,
}
pub fn resolve_statement(
    set: &VerifiedWitnessSet,
    signed: &SignedHostedWitnessStatementV1,
    proof: Option<&HostedWitnessHistoryProofV1>,
    new_work: bool,
    now_ms: i64,
) -> Result<ResolvedWitnessStatement, Reject> {
    if now_ms < set.body.issued_at_unix_millis || now_ms >= set.body.valid_until_unix_millis {
        return Err(Reject::Expired);
    }
    let s = signed.body.as_ref().ok_or(Reject::Canonical)?;
    if s.format_version != 1 {
        return Err(Reject::Version);
    }
    for v in [
        &s.executor_id,
        &s.spool_genesis_digest,
        &s.owner_id,
        &s.owner_state_hash,
        &s.policy_state_hash,
        &s.publisher_key_id,
        &s.authority_digest,
        &s.original_signatures_digest,
    ] {
        width(v, 32)?;
    }
    width(&s.spool_uuid, 16)?;
    width(&s.host_transaction_id, 16)?;
    if s.canonical_payload.is_empty() || s.canonical_payload.len() > 64 * 1024 {
        return Err(Reject::Bounds);
    }
    if ![1, 2].contains(&s.basis) || s.admission_order == 0 {
        return Err(Reject::Semantic);
    }
    let entry = set
        .body
        .entries
        .iter()
        .find(|e| e.executor_id == s.executor_id)
        .ok_or(Reject::Root)?;
    if entry.state == 3 {
        return Err(Reject::Revoked);
    }
    if !entry.purposes.contains(&s.purpose) {
        return Err(Reject::Scope);
    }
    if s.observed_at_unix_millis < entry.active_from_unix_millis
        || s.observed_at_unix_millis >= entry.active_until_unix_millis
        || (new_work && (entry.state != 1 || s.observed_at_unix_millis != now_ms))
    {
        return Err(Reject::Expired);
    }
    verify(
        &entry.public_key,
        &statement_signing_digest(s)?,
        &signed.signature,
    )?;
    let digest = leaf_digest(s.purpose, &canonical(s)?, &signed.signature)?;
    if entry.state == 2 {
        let proof = proof.ok_or(Reject::Proof)?;
        if proof.purpose != s.purpose {
            return Err(Reject::Proof);
        }
        verify_inclusion(&digest, proof, entry)?;
    }
    Ok(ResolvedWitnessStatement {
        statement_digest: digest,
        set_digest: set.digest.clone(),
        generation: set.body.generation,
        root_epoch: set.root_epoch,
    })
}
/// Called under the receiver's trust/mutation lock; an earlier resolved value
/// never authorizes mutation after freshness, root or generation changes.
pub fn recheck_context(
    context: &ResolvedWitnessStatement,
    newest: &VerifiedWitnessSet,
    signed: &SignedHostedWitnessStatementV1,
    now_ms: i64,
) -> Result<(), Reject> {
    let s = signed.body.as_ref().ok_or(Reject::Canonical)?;
    if context.root_epoch != newest.root_epoch
        || context.generation != newest.body.generation
        || context.set_digest != newest.digest
        || context.statement_digest != leaf_digest(s.purpose, &canonical(s)?, &signed.signature)?
    {
        return Err(Reject::StaleContext);
    }
    if now_ms < newest.body.issued_at_unix_millis || now_ms >= newest.body.valid_until_unix_millis {
        return Err(Reject::Expired);
    }
    Ok(())
}
pub fn validate_lookup(
    request: &crate::heddle::api::v1alpha2::GetHostedWitnessHistoryProofRequest,
) -> Result<(), Reject> {
    width(&request.executor_id, 32)?;
    width(&request.statement_leaf_digest, 32)
}

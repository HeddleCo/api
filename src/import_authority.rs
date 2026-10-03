//! HYBRID canonical import authority. The existing heddle capability verifier
//! supplies independently selected owner history/current permission. This
//! module verifies the NEW typed parent grant and its bounded job child;
//! it neither enrolls incoming roots nor substitutes for owner verification.
use crate::heddle::api::v1alpha2::*;
pub use crate::hybrid_codec::{Reject, strict_decode};
use crate::hybrid_codec::{canonical, field, hash, key_id, record, signing_digest, verify, width};

pub const PERMISSION_DOMAIN: &str = "heddle-import-member-permission-v1";
pub const GENESIS_DOMAIN: &str = "heddle-import-genesis-authority-v1";
pub const DELEGATION_DOMAIN: &str = "heddle-import-job-delegation-v1";
pub const RENEWAL_DOMAIN: &str = "heddle-import-job-renewal-v1";
pub const OPERATION_DOMAIN: &str = "heddle-delegated-import-operation-v1";
pub const MANIFEST_DOMAIN: &str = "heddle-import-result-manifest-v1";
pub const PUBLICATION_DOMAIN: &str = "heddle-import-publication-payload-v1";
pub const MAX_BRANCHES: usize = 256;
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
pub const MAX_RESULT_BYTES: u64 = 1 << 30;
pub const CANCELLATION_NAMESPACE: &str = "heddle-import-cancel-v1";

record!(AuthorizationSignature, signer_key_id:b, signature:b);
record!(RecordSignature, public_key:b, signature:b);
record!(SignedRecord, format:s, canonical_record:b, signatures:l);
record!(ImportFrontierV1, format_version:u, thread_id:b, operation_ids:h);
record!(ImportContentV1, format_version:u, canonical_capture:b);
record!(ImportBoundaryAcceptanceV1, binding:m, signed_acceptance:m, originals_manifest:b, publication_intent:b, original_receipts:l);
record!(ImportGenesisWitnessV1, format_version:u, binding:m, original_genesis:m, creator_authority_envelope:b, boundary_acceptance:o);
record!(ImportAuthorityWitnessV1, format_version:u, kind:e, original:m, dependencies:l, authority_envelope:b, boundary_acceptances:l);
record!(HostedLandingRequestProofV1, format_version:u, signing_identity:s, method_path:s, timestamp_millis:u, nonce:b, request_body:b, signature:m);
record!(HostedLandingWitnessV1, format_version:u, execution:m, request:m, source_operation:m, review_evidence:l, authority_envelope:b);
record!(ImportJobCasStateV1, format_version:u, logical_job_id:b, retry_lineage_id:b, active_predecessor:m, authority_epoch:u, committed_manifest:m);
record!(ImportIdentityV1, spool_uuid:b, spool_genesis_digest:b, owner_id:b,
    owner_account_uuid:b, owner_state_hash:b, ownership_transfer_sequence:u);
record!(ImportOwnerChainV1, spool_genesis_digest:b, owner_state_hashes:q, transfer_audit_hashes:q);
record!(ImportBranchLimitV1, ref_name:s, hash_algorithm:e, ref_mode:e, pinned_commit_oid:b,
    genesis_digest:b, target_thread_id:b, expected_frontier_digest:b, slot_id:u, max_result_bytes:u);
record!(ImportPermissionScopeV1, provider:s, source_url:s, branches:l, destination_version:b,
    options_digest:b, converter_version:s, max_operations:u, max_result_bytes:u);
record!(ImportMemberPermissionV1, format_version:u, identity:m, logical_job_id:b,
    retry_lineage_id:b, subject_public_key:b, purpose:e, scope:m, not_before_unix_seconds:u,
    expires_at_unix_seconds:u, cancellation_id:b, owner_chain_digest:b, nonce:b);
record!(SignedImportMemberPermissionV1, body:m, owner_signature:m);
record!(ImportGenesisAuthorityV1, format_version:u, identity:m, genesis_digest:b,
    original_creator_signature:b, creator_public_key:b, creator_authority_envelope_digest:b,
    parent_permission_digest:b, owner_chain_digest:b);
record!(SignedImportGenesisAuthorityV1, body:m, creator_signature:m);
record!(ImportBranchManifestV1, limit:m, genesis_authority_digest:b);
record!(ImportJobDelegationV1, format_version:u, identity:m, delegation_id:b, logical_job_id:b,
    retry_lineage_id:b, job_public_key:b, job_key_id:b, delegating_public_key:b,
    parent_permission_digest:b, owner_chain_digest:b, purpose:e, scope:m, branch_manifest:l,
    not_before_unix_seconds:u, expires_at_unix_seconds:u, cancellation_id:b, predecessor_delegation_digest:b);
record!(SignedImportJobDelegationV1, body:m, delegating_signature:m);
record!(ImportCommittedSlotV1, ref_name:s, slot_id:u, signed_operation_digest:b,
    resulting_frontier_digest:b, result_bytes:u);
record!(ImportResultManifestV1, format_version:u, logical_job_id:b, retry_lineage_id:b, slots:l);
record!(ImportJobRenewalV1, format_version:u, predecessor_delegation_digest:b,
    expected_authority_epoch:u, committed_manifest_digest:b, replacement:m);
record!(SignedImportJobRenewalV1, body:m, delegating_signature:m);
record!(DelegatedImportOperationV1, format_version:u, spool_uuid:b, spool_genesis_digest:b,
    logical_job_id:b, retry_lineage_id:b, physical_operation_id:b, delegation_digest:b,
    ref_name:s, slot_id:u, hash_algorithm:e, observed_commit_oid:b, genesis_digest:b,
    target_thread_id:b, expected_frontier_digest:b, resulting_frontier_digest:b,
    resulting_content_digest:b, result_bytes:u, options_digest:b, converter_version:s);
record!(SignedDelegatedImportOperationV1, body:m, job_signature:m);
record!(ImportPublicationWitnessV1, format_version:u, signed_operation_digest:b, delegation_digest:b,
    logical_job_id:b, retry_lineage_id:b, physical_operation_id:b, ref_name:s, slot_id:u,
    hash_algorithm:e, observed_commit_oid:b, expected_frontier_digest:b, resulting_frontier_digest:b,
    terminal_manifest_digest:b);

pub fn signed_permission_digest(v: &SignedImportMemberPermissionV1) -> Result<Vec<u8>, Reject> {
    signing_digest("heddle-signed-import-member-permission-v1", v)
}
pub fn owner_chain_digest(v: &ImportOwnerChainV1) -> Result<Vec<u8>, Reject> {
    width(&v.spool_genesis_digest, 32)?;
    if v.owner_state_hashes.is_empty()
        || v.owner_state_hashes.len() > 64
        || v.transfer_audit_hashes.len() > 64
    {
        return Err(Reject::Bounds);
    }
    for h in v.owner_state_hashes.iter().chain(&v.transfer_audit_hashes) {
        width(h, 32)?;
    }
    if v.owner_state_hashes.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Reject::Canonical);
    }
    signing_digest("heddle-import-owner-chain-v1", v)
}
pub fn signed_genesis_digest(v: &SignedImportGenesisAuthorityV1) -> Result<Vec<u8>, Reject> {
    signing_digest("heddle-signed-import-genesis-authority-v1", v)
}
pub fn signed_delegation_digest(v: &SignedImportJobDelegationV1) -> Result<Vec<u8>, Reject> {
    signing_digest("heddle-signed-import-job-delegation-v1", v)
}
pub fn signed_operation_digest(v: &SignedDelegatedImportOperationV1) -> Result<Vec<u8>, Reject> {
    signing_digest("heddle-signed-delegated-import-operation-v1", v)
}
pub fn manifest_digest(v: &ImportResultManifestV1) -> Result<Vec<u8>, Reject> {
    signing_digest(MANIFEST_DOMAIN, v)
}
pub fn verify_authorization_signature(
    key: &[u8],
    domain: &str,
    body: &impl crate::hybrid_codec::Canonical,
    signature: &AuthorizationSignature,
) -> Result<(), Reject> {
    if signature.signer_key_id != key_id(key) {
        return Err(Reject::Signature);
    }
    let bytes = canonical(body)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Reject::Bounds);
    }
    verify(
        key,
        &hash(&[domain.as_bytes(), &bytes]),
        &signature.signature,
    )
}

/// Conservative canonical URL grammar for v1: lowercase DNS HTTPS host, no
/// userinfo/query/fragment/port/escapes, ASCII unreserved path segments. No
/// implicit URL normalization is performed by a signing implementation.
pub fn canonical_https(value: &str, origin: bool) -> Result<(), Reject> {
    if value.len() > 2048 {
        return Err(Reject::Bounds);
    }
    let rest = value.strip_prefix("https://").ok_or(Reject::Canonical)?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    if host.is_empty()
        || host.len() > 253
        || host.split('.').any(|part| {
            part.is_empty()
                || part.len() > 63
                || part.starts_with('-')
                || part.ends_with('-')
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        || (origin && rest != host)
        || (!origin && path.is_empty())
        || path.split('/').any(|p| {
            p.is_empty() && !origin
                || p == "."
                || p == ".."
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        })
    {
        return Err(Reject::Canonical);
    }
    Ok(())
}
fn identity(value: &ImportIdentityV1) -> Result<(), Reject> {
    for v in [&value.spool_uuid, &value.owner_account_uuid] {
        width(v, 16)?;
        if v.iter().all(|b| *b == 0) {
            return Err(Reject::Canonical);
        }
    }
    for v in [
        &value.spool_genesis_digest,
        &value.owner_id,
        &value.owner_state_hash,
    ] {
        width(v, 32)?;
    }
    Ok(())
}
fn interval(start: i64, end: i64, now: i64) -> Result<(), Reject> {
    if start < 0 || end <= start {
        return Err(Reject::Semantic);
    }
    if now < start || now >= end {
        return Err(Reject::Expired);
    }
    Ok(())
}
fn branch(value: &ImportBranchLimitV1) -> Result<(), Reject> {
    if !value.ref_name.starts_with("refs/heads/")
        || value.ref_name.len() > 1024
        || value.ref_name.ends_with('/')
        || value.ref_name.ends_with('.')
        || value.ref_name.contains("..")
        || value.ref_name.contains("//")
        || value.ref_name.contains("@{")
        || value
            .ref_name
            .split('/')
            .any(|p| p.starts_with('.') || p.ends_with(".lock"))
        || !value
            .ref_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
    {
        return Err(Reject::Canonical);
    }
    let size = match value.hash_algorithm {
        1 => 20,
        2 => 32,
        _ => return Err(Reject::Version),
    };
    match value.ref_mode {
        1 => width(&value.pinned_commit_oid, size)?,
        2 if value.pinned_commit_oid.is_empty() => (),
        _ => return Err(Reject::Semantic),
    }
    for v in [
        &value.genesis_digest,
        &value.target_thread_id,
        &value.expected_frontier_digest,
    ] {
        width(v, 32)?;
    }
    if value.max_result_bytes == 0 || value.max_result_bytes > MAX_RESULT_BYTES {
        return Err(Reject::Bounds);
    }
    Ok(())
}
pub fn validate_scope(value: &ImportPermissionScopeV1) -> Result<(), Reject> {
    canonical_https(&value.source_url, false)?;
    if value.provider.is_empty()
        || value.provider.len() > 64
        || !value
            .provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || value.converter_version.is_empty()
        || value.converter_version.len() > 128
        || !value.converter_version.is_ascii()
    {
        return Err(Reject::Canonical);
    }
    width(&value.destination_version, 32)?;
    width(&value.options_digest, 32)?;
    if value.branches.is_empty()
        || value.branches.len() > MAX_BRANCHES
        || value.max_operations == 0
        || value.max_operations as usize > MAX_BRANCHES
        || value.max_result_bytes == 0
        || value.max_result_bytes > MAX_RESULT_BYTES
    {
        return Err(Reject::Bounds);
    }
    if (value.max_operations as usize) < value.branches.len() {
        return Err(Reject::Scope);
    }
    let mut total = 0_u64;
    for (i, b) in value.branches.iter().enumerate() {
        branch(b)?;
        if i > 0 && value.branches[i - 1].ref_name.as_bytes() >= b.ref_name.as_bytes() {
            return Err(Reject::Canonical);
        }
        total = total
            .checked_add(b.max_result_bytes)
            .ok_or(Reject::Bounds)?;
    }
    if total > value.max_result_bytes {
        return Err(Reject::Scope);
    }
    Ok(())
}
fn scope_subset(child: &ImportPermissionScopeV1, parent: &ImportPermissionScopeV1) -> bool {
    child.provider == parent.provider
        && child.source_url == parent.source_url
        && child.destination_version == parent.destination_version
        && child.options_digest == parent.options_digest
        && child.converter_version == parent.converter_version
        && child.max_operations <= parent.max_operations
        && child.max_result_bytes <= parent.max_result_bytes
        && child.branches.iter().all(|c| {
            parent.branches.iter().any(|p| {
                let mut limit = c.clone();
                limit.max_result_bytes = p.max_result_bytes;
                limit == *p && c.max_result_bytes <= p.max_result_bytes
            })
        })
}

/// Public context from the existing owner/keyring verifier, not from fields in
/// the incoming bundle. now is receiver/host time for new work or independently
/// verified witness observation time for retained history, NEVER author time.
pub struct ImportOwnerExpectation<'a> {
    pub identity: &'a ImportIdentityV1,
    pub owner_public_key: &'a [u8],
    pub owner_chain_digest: &'a [u8],
    pub authority_expires_at_seconds: i64,
    pub now_unix_seconds: i64,
    pub forbidden_job_keys: &'a [Vec<u8>], // Every user/root/witness key, including tombstones.
    pub known_job_associations: &'a [(Vec<u8>, Vec<u8>)], // key -> logical job.
}
pub fn verify_member_permission(
    signed: &SignedImportMemberPermissionV1,
    expected: &ImportOwnerExpectation<'_>,
) -> Result<(), Reject> {
    let p = signed.body.as_ref().ok_or(Reject::ImportPermission)?;
    if p.format_version != 1 || p.purpose != 1 {
        return Err(Reject::ImportPermission);
    }
    identity(p.identity.as_ref().ok_or(Reject::Canonical)?)?;
    if p.identity.as_ref() != Some(expected.identity)
        || p.owner_chain_digest != expected.owner_chain_digest
    {
        return Err(Reject::Root);
    }
    width(&p.logical_job_id, 16)?;
    width(&p.retry_lineage_id, 16)?;
    width(&p.subject_public_key, 32)?;
    width(&p.cancellation_id, 32)?;
    width(&p.nonce, 32)?;
    width(&p.owner_chain_digest, 32)?;
    validate_scope(p.scope.as_ref().ok_or(Reject::Canonical)?)?;
    interval(
        p.not_before_unix_seconds,
        p.expires_at_unix_seconds,
        expected.now_unix_seconds,
    )?;
    if p.expires_at_unix_seconds > expected.authority_expires_at_seconds {
        return Err(Reject::Scope);
    }
    verify_authorization_signature(
        expected.owner_public_key,
        PERMISSION_DOMAIN,
        p,
        signed.owner_signature.as_ref().ok_or(Reject::Signature)?,
    )
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedImportDelegation {
    body: ImportJobDelegationV1,
    digest: Vec<u8>,
}
impl VerifiedImportDelegation {
    pub fn body(&self) -> &ImportJobDelegationV1 {
        &self.body
    }
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}
pub fn verify_delegation(
    signed: &SignedImportJobDelegationV1,
    member: Option<&SignedImportMemberPermissionV1>,
    expected: &ImportOwnerExpectation<'_>,
) -> Result<VerifiedImportDelegation, Reject> {
    let d = signed.body.as_ref().ok_or(Reject::Canonical)?;
    if d.format_version != 1 || d.purpose != 1 {
        return Err(Reject::Version);
    }
    identity(d.identity.as_ref().ok_or(Reject::Canonical)?)?;
    if d.identity.as_ref() != Some(expected.identity)
        || d.owner_chain_digest != expected.owner_chain_digest
    {
        return Err(Reject::Root);
    }
    for v in [&d.delegation_id, &d.logical_job_id, &d.retry_lineage_id] {
        width(v, 16)?;
        if v.iter().all(|b| *b == 0) {
            return Err(Reject::Canonical);
        }
    }
    for v in [
        &d.job_public_key,
        &d.job_key_id,
        &d.delegating_public_key,
        &d.parent_permission_digest,
        &d.owner_chain_digest,
        &d.cancellation_id,
        &d.predecessor_delegation_digest,
    ] {
        width(v, 32)?;
    }
    if d.job_key_id != key_id(&d.job_public_key) {
        return Err(Reject::Canonical);
    }
    if d.job_public_key == d.delegating_public_key
        || d.job_public_key == expected.owner_public_key
        || expected.forbidden_job_keys.contains(&d.job_public_key)
    {
        return Err(Reject::KeyRole);
    }
    if expected
        .known_job_associations
        .iter()
        .any(|(k, j)| k == &d.job_public_key && j != &d.logical_job_id)
    {
        return Err(Reject::Scope);
    }
    let scope = d.scope.as_ref().ok_or(Reject::Canonical)?;
    validate_scope(scope)?;
    if d.branch_manifest.len() != scope.branches.len() {
        return Err(Reject::Scope);
    }
    for (m, b) in d.branch_manifest.iter().zip(&scope.branches) {
        width(&m.genesis_authority_digest, 32)?;
        if m.limit.as_ref() != Some(b) {
            return Err(Reject::Scope);
        }
    }
    interval(
        d.not_before_unix_seconds,
        d.expires_at_unix_seconds,
        expected.now_unix_seconds,
    )?;
    if d.expires_at_unix_seconds > expected.authority_expires_at_seconds {
        return Err(Reject::Scope);
    }
    if d.delegating_public_key == expected.owner_public_key {
        if member.is_some() || d.parent_permission_digest != vec![0; 32] {
            return Err(Reject::ImportPermission);
        }
    } else {
        let member = member.ok_or(Reject::ImportPermission)?;
        verify_member_permission(member, expected)?;
        let p = member.body.as_ref().ok_or(Reject::ImportPermission)?;
        if d.parent_permission_digest != signed_permission_digest(member)?
            || d.delegating_public_key != p.subject_public_key
            || d.logical_job_id != p.logical_job_id
            || d.retry_lineage_id != p.retry_lineage_id
            || d.not_before_unix_seconds < p.not_before_unix_seconds
            || d.expires_at_unix_seconds > p.expires_at_unix_seconds
            || !scope_subset(scope, p.scope.as_ref().ok_or(Reject::Canonical)?)
        {
            return Err(Reject::Scope);
        }
    }
    verify_authorization_signature(
        &d.delegating_public_key,
        DELEGATION_DOMAIN,
        d,
        signed
            .delegating_signature
            .as_ref()
            .ok_or(Reject::Signature)?,
    )?;
    Ok(VerifiedImportDelegation {
        body: d.clone(),
        digest: signed_delegation_digest(signed)?,
    })
}
pub fn verify_genesis_authority(
    signed: &SignedImportGenesisAuthorityV1,
    delegation: &VerifiedImportDelegation,
    original_genesis_digest: &[u8],
    original_signature: &[u8],
    envelope_digest: &[u8],
) -> Result<(), Reject> {
    let g = signed.body.as_ref().ok_or(Reject::Canonical)?;
    let d = &delegation.body;
    if g.format_version != 1 {
        return Err(Reject::Version);
    }
    width(&g.original_creator_signature, 64)?;
    for v in [
        &g.genesis_digest,
        &g.creator_public_key,
        &g.creator_authority_envelope_digest,
        &g.parent_permission_digest,
        &g.owner_chain_digest,
    ] {
        width(v, 32)?;
    }
    if g.identity != d.identity
        || g.creator_public_key != d.delegating_public_key
        || g.parent_permission_digest != d.parent_permission_digest
        || g.owner_chain_digest != d.owner_chain_digest
        || g.genesis_digest != original_genesis_digest
        || g.original_creator_signature != original_signature
        || g.creator_authority_envelope_digest != envelope_digest
        || !d.branch_manifest.iter().any(|m| {
            m.limit
                .as_ref()
                .is_some_and(|b| b.genesis_digest == g.genesis_digest)
                && signed_genesis_digest(signed).is_ok_and(|h| h == m.genesis_authority_digest)
        })
    {
        return Err(Reject::Scope);
    }
    verify_authorization_signature(
        &g.creator_public_key,
        GENESIS_DOMAIN,
        g,
        signed.creator_signature.as_ref().ok_or(Reject::Signature)?,
    )
}
/// Structural signature + scoped operation only. This does not establish
/// publication, current policy, cancellation, leases or conversion correctness.
pub fn verify_operation(
    signed: &SignedDelegatedImportOperationV1,
    delegation: &VerifiedImportDelegation,
) -> Result<(), Reject> {
    let o = signed.body.as_ref().ok_or(Reject::Canonical)?;
    let d = &delegation.body;
    if o.format_version != 1 {
        return Err(Reject::Version);
    }
    let id = d.identity.as_ref().ok_or(Reject::Canonical)?;
    width(&o.physical_operation_id, 16)?;
    for v in [
        &o.spool_genesis_digest,
        &o.delegation_digest,
        &o.genesis_digest,
        &o.target_thread_id,
        &o.expected_frontier_digest,
        &o.resulting_frontier_digest,
        &o.resulting_content_digest,
        &o.options_digest,
    ] {
        width(v, 32)?;
    }
    width(&o.spool_uuid, 16)?;
    width(&o.logical_job_id, 16)?;
    width(&o.retry_lineage_id, 16)?;
    let scope = d.scope.as_ref().ok_or(Reject::Canonical)?;
    let b = scope
        .branches
        .iter()
        .find(|b| b.ref_name == o.ref_name && b.slot_id == o.slot_id)
        .ok_or(Reject::Scope)?;
    let oid_len = match o.hash_algorithm {
        1 => 20,
        2 => 32,
        _ => return Err(Reject::Version),
    };
    width(&o.observed_commit_oid, oid_len)?;
    if o.spool_uuid != id.spool_uuid
        || o.spool_genesis_digest != id.spool_genesis_digest
        || o.logical_job_id != d.logical_job_id
        || o.retry_lineage_id != d.retry_lineage_id
        || o.delegation_digest != delegation.digest
        || o.hash_algorithm != b.hash_algorithm
        || (b.ref_mode == 1 && o.observed_commit_oid != b.pinned_commit_oid)
        || o.genesis_digest != b.genesis_digest
        || o.target_thread_id != b.target_thread_id
        || o.expected_frontier_digest != b.expected_frontier_digest
        || o.result_bytes > b.max_result_bytes
        || o.result_bytes == 0
        || o.options_digest != scope.options_digest
        || o.converter_version != scope.converter_version
    {
        return Err(Reject::Scope);
    }
    verify_authorization_signature(
        &d.job_public_key,
        OPERATION_DOMAIN,
        o,
        signed.job_signature.as_ref().ok_or(Reject::Signature)?,
    )
}
pub fn verify_new_operation(
    signed: &SignedDelegatedImportOperationV1,
    delegation: &VerifiedImportDelegation,
    now_seconds: i64,
) -> Result<(), Reject> {
    interval(
        delegation.body.not_before_unix_seconds,
        delegation.body.expires_at_unix_seconds,
        now_seconds,
    )?;
    verify_operation(signed, delegation)
}
pub fn validate_manifest(m: &ImportResultManifestV1) -> Result<(), Reject> {
    if m.format_version != 1 {
        return Err(Reject::Version);
    }
    width(&m.logical_job_id, 16)?;
    width(&m.retry_lineage_id, 16)?;
    if m.slots.len() > MAX_BRANCHES {
        return Err(Reject::Bounds);
    }
    for (i, s) in m.slots.iter().enumerate() {
        width(&s.signed_operation_digest, 32)?;
        width(&s.resulting_frontier_digest, 32)?;
        if !s.ref_name.starts_with("refs/heads/") || !s.ref_name.is_ascii() {
            return Err(Reject::Canonical);
        }
        if s.ref_name.len() > 1024 || s.result_bytes == 0 || s.result_bytes > MAX_RESULT_BYTES {
            return Err(Reject::Bounds);
        }
        if i > 0 && (&m.slots[i - 1].ref_name, m.slots[i - 1].slot_id) >= (&s.ref_name, s.slot_id) {
            return Err(Reject::Canonical);
        }
    }
    Ok(())
}
/// CAS state MUST be receiver-owned and held under the publication/renewal
/// transaction fence. Returns replacement only after all remaining-slot checks.
pub fn verify_renewal(
    signed: &SignedImportJobRenewalV1,
    previous: &VerifiedImportDelegation,
    committed: &ImportResultManifestV1,
    authority_epoch: u64,
    member: Option<&SignedImportMemberPermissionV1>,
    expected: &ImportOwnerExpectation<'_>,
) -> Result<VerifiedImportDelegation, Reject> {
    let r = signed.body.as_ref().ok_or(Reject::Canonical)?;
    if r.format_version != 1 {
        return Err(Reject::Version);
    }
    validate_manifest(committed)?;
    if r.expected_authority_epoch != authority_epoch {
        return Err(Reject::StaleContext);
    }
    if r.predecessor_delegation_digest != previous.digest {
        return Err(Reject::RenewalFork);
    }
    if r.committed_manifest_digest != manifest_digest(committed)? {
        return Err(Reject::StaleManifest);
    }
    let signed_next = r.replacement.as_ref().ok_or(Reject::Canonical)?;
    let next = verify_delegation(signed_next, member, expected)?;
    let before = &previous.body;
    let after = &next.body;
    let before_id = before.identity.as_ref().ok_or(Reject::Canonical)?;
    let after_id = after.identity.as_ref().ok_or(Reject::Canonical)?;
    if after.logical_job_id != before.logical_job_id
        || after.retry_lineage_id != before.retry_lineage_id
        || committed.logical_job_id != before.logical_job_id
        || committed.retry_lineage_id != before.retry_lineage_id
        || after_id.spool_uuid != before_id.spool_uuid
        || after_id.spool_genesis_digest != before_id.spool_genesis_digest
        || after.predecessor_delegation_digest != previous.digest
        || after.job_public_key == before.job_public_key
        || after.delegation_id == before.delegation_id
    {
        return Err(Reject::RenewalFork);
    }
    let old_scope = before.scope.as_ref().ok_or(Reject::Canonical)?;
    let new_scope = after.scope.as_ref().ok_or(Reject::Canonical)?;
    if !scope_subset(new_scope, old_scope) {
        return Err(Reject::RenewalFork);
    }
    let old_slots = &old_scope.branches;
    let mut consumed = 0_u64;
    for slot in &committed.slots {
        // Old certificates may already omit previously committed slots. Only
        // charge all committed slots against the original logical-job budgets;
        // the host's initial manifest/limits remain durable across renewals.
        if let Some(b) = old_slots
            .iter()
            .find(|b| b.ref_name == slot.ref_name && b.slot_id == slot.slot_id)
        {
            if slot.result_bytes > b.max_result_bytes {
                return Err(Reject::RenewalFork);
            }
            consumed = consumed
                .checked_add(slot.result_bytes)
                .ok_or(Reject::Bounds)?;
        }
        if new_scope
            .branches
            .iter()
            .any(|b| b.ref_name == slot.ref_name && b.slot_id == slot.slot_id)
        {
            return Err(Reject::CommittedSlot);
        }
    }
    let removed = old_slots
        .iter()
        .filter(|b| {
            committed
                .slots
                .iter()
                .any(|s| s.ref_name == b.ref_name && s.slot_id == b.slot_id)
        })
        .count();
    if new_scope.max_operations as usize > old_scope.max_operations as usize - removed
        || new_scope.max_result_bytes
            > old_scope
                .max_result_bytes
                .checked_sub(consumed)
                .ok_or(Reject::RenewalFork)?
        || after.branch_manifest.iter().any(|m| {
            !before.branch_manifest.iter().any(|old| {
                old.genesis_authority_digest == m.genesis_authority_digest
                    && old
                        .limit
                        .as_ref()
                        .zip(m.limit.as_ref())
                        .is_some_and(|(a, b)| {
                            a.ref_name == b.ref_name && a.genesis_digest == b.genesis_digest
                        })
            })
        })
    {
        return Err(Reject::RenewalFork);
    }
    verify_authorization_signature(
        &after.delegating_public_key,
        RENEWAL_DOMAIN,
        r,
        signed
            .delegating_signature
            .as_ref()
            .ok_or(Reject::Signature)?,
    )?;
    Ok(next)
}
/// Persistent unique slot identity: logical job/ref/slot. Exact replay returns
/// the old receipt/manifest, never another publication or fresh witness.
pub fn check_slot_replay(
    committed: &ImportResultManifestV1,
    signed: &SignedDelegatedImportOperationV1,
) -> Result<bool, Reject> {
    validate_manifest(committed)?;
    let o = signed.body.as_ref().ok_or(Reject::Canonical)?;
    if committed.logical_job_id != o.logical_job_id
        || committed.retry_lineage_id != o.retry_lineage_id
    {
        return Err(Reject::Scope);
    }
    match committed
        .slots
        .iter()
        .find(|s| s.ref_name == o.ref_name && s.slot_id == o.slot_id)
    {
        Some(s)
            if s.signed_operation_digest == signed_operation_digest(signed)?
                && s.resulting_frontier_digest == o.resulting_frontier_digest
                && s.result_bytes == o.result_bytes =>
        {
            Ok(true)
        }
        Some(_) => Err(Reject::SlotConflict),
        None => Ok(false),
    }
}
/// Verify exact committed publication in addition to job signature/scope. The
/// owner/keyring verifier must resolve the statement's accepted state/order;
/// witness signature alone cannot establish that user authority or disclosure.
pub fn verify_publication(
    operation: &SignedDelegatedImportOperationV1,
    delegation: &VerifiedImportDelegation,
    manifest: &ImportResultManifestV1,
    statement: &crate::heddle::api::common::SignedHostedWitnessStatementV1,
    set: &crate::witness_trust::VerifiedWitnessSet,
    proof: Option<&crate::heddle::api::common::HostedWitnessHistoryProofV1>,
    now_ms: i64,
) -> Result<crate::witness_trust::ResolvedWitnessStatement, Reject> {
    validate_statement_boundary(statement.body.as_ref().ok_or(Reject::Canonical)?)?;
    verify_operation(operation, delegation)?;
    if !check_slot_replay(manifest, operation)? {
        return Err(Reject::Scope);
    }
    let o = operation.body.as_ref().ok_or(Reject::Canonical)?;
    let d = &delegation.body;
    let id = d.identity.as_ref().ok_or(Reject::Canonical)?;
    let s = statement.body.as_ref().ok_or(Reject::Canonical)?;
    let payload = ImportPublicationWitnessV1 {
        format_version: 1,
        signed_operation_digest: signed_operation_digest(operation)?,
        delegation_digest: delegation.digest.clone(),
        logical_job_id: o.logical_job_id.clone(),
        retry_lineage_id: o.retry_lineage_id.clone(),
        physical_operation_id: o.physical_operation_id.clone(),
        ref_name: o.ref_name.clone(),
        slot_id: o.slot_id,
        hash_algorithm: o.hash_algorithm,
        observed_commit_oid: o.observed_commit_oid.clone(),
        expected_frontier_digest: o.expected_frontier_digest.clone(),
        resulting_frontier_digest: o.resulting_frontier_digest.clone(),
        terminal_manifest_digest: manifest_digest(manifest)?,
    };
    if s.purpose != 3
        || s.spool_uuid != id.spool_uuid
        || s.spool_genesis_digest != id.spool_genesis_digest
        || s.owner_id != id.owner_id
        || s.owner_state_hash != id.owner_state_hash
        || s.ownership_transfer_sequence != id.ownership_transfer_sequence
        || s.authority_digest != delegation.digest
        || s.original_signatures_digest
            != hash(&[&operation
                .job_signature
                .as_ref()
                .ok_or(Reject::Signature)?
                .signature])
        || s.canonical_payload != canonical(&payload)?
        || s.basis != 1
    {
        return Err(Reject::Scope);
    }
    interval(
        d.not_before_unix_seconds,
        d.expires_at_unix_seconds,
        s.observed_at_unix_millis / 1000,
    )?;
    crate::witness_trust::resolve_statement(set, statement, proof, false, now_ms)
}
pub fn require_hybrid_peer(
    protocol: Option<&crate::heddle::api::common::ProtocolCompatibility>,
) -> Result<(), Reject> {
    let protocol = protocol.ok_or(Reject::Protocol)?;
    if protocol.protocol_version != 2 || protocol.mandatory_features != [1] {
        return Err(Reject::Protocol);
    }
    Ok(())
}

/// Producer-owned logical-job/lease fence for RetryImportSource and final
/// publication. The physical retry row never supplies a new logical identity.
pub fn check_job_fence(
    logical_job_id: &[u8],
    active_delegation_digest: &[u8],
    expected_epoch: u64,
    active: &VerifiedImportDelegation,
    durable_epoch: u64,
) -> Result<(), Reject> {
    if logical_job_id != active.body.logical_job_id {
        return Err(Reject::Scope);
    }
    if expected_epoch != durable_epoch || active_delegation_digest != active.digest {
        return Err(Reject::StaleContext);
    }
    Ok(())
}
pub fn validate_public_bundle(bundle: &ImportPublicProofBundleV1) -> Result<(), Reject> {
    use prost::Message;
    if bundle.format_version != 1 {
        return Err(Reject::Version);
    }
    if bundle.encoded_len() > MAX_BUNDLE_BYTES
        || bundle.owner_histories.len() > 64
        || bundle.ownership_transfers.len() > 64
        || bundle.genesis_authorities.len() > MAX_BRANCHES
        || bundle.delegations.len() > 64
        || bundle.renewals.len() > 63
        || bundle.operations.len() > MAX_BRANCHES
        || bundle.statements.len() > 1024
        || bundle.history_proofs.len() > 1024
        || bundle.policies.len() > 256
        || bundle.original_geneses.len() > MAX_BRANCHES
        || bundle.creator_authority_envelopes.len() > MAX_BRANCHES
        || bundle.member_permissions.len() > 64
        || bundle.manifests.len() > 320
        || bundle.genesis_witnesses.len() > 256
        || bundle.authority_witnesses.len() > 256
        || bundle.landing_witnesses.len() > 256
    {
        return Err(Reject::Bounds);
    }
    validate_bundle_history(bundle)
}

/// Typed adapter boundary: an authentic unrelated capability/online role must
/// never be selected as the parent of an import certificate.
pub enum ImportPermissionEvidence<'a> {
    Import(&'a SignedImportMemberPermissionV1),
    OwnerCapability(&'a SignedOwnerCapability),
    OnlineRole(&'a str),
}
pub fn select_import_permission(
    evidence: ImportPermissionEvidence<'_>,
) -> Result<&SignedImportMemberPermissionV1, Reject> {
    match evidence {
        ImportPermissionEvidence::Import(p) => Ok(p),
        ImportPermissionEvidence::OwnerCapability(_) | ImportPermissionEvidence::OnlineRole(_) => {
            Err(Reject::ImportPermission)
        }
    }
}
/// Hybrid dispatch has no legacy execution arm, even for an authentic witness.
pub fn require_import_operation_format(format: &str) -> Result<(), Reject> {
    if format != OPERATION_DOMAIN {
        return Err(Reject::Protocol);
    }
    Ok(())
}
pub fn frontier_digest(frontier: &ImportFrontierV1) -> Result<Vec<u8>, Reject> {
    if frontier.format_version != 1 {
        return Err(Reject::Version);
    }
    width(&frontier.thread_id, 32)?;
    if frontier.operation_ids.len() > 128 {
        return Err(Reject::Bounds);
    }
    for id in &frontier.operation_ids {
        width(id, 32)?;
    }
    if frontier.operation_ids.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Reject::Canonical);
    }
    signing_digest("heddle-import-frontier-v1", frontier)
}
pub fn content_digest(content: &ImportContentV1) -> Result<Vec<u8>, Reject> {
    if content.format_version != 1 {
        return Err(Reject::Version);
    }
    if content.canonical_capture.is_empty()
        || content.canonical_capture.len() > MAX_RESULT_BYTES as usize
    {
        return Err(Reject::Bounds);
    }
    signing_digest("heddle-import-content-v1", content)
}
pub fn signed_native_digest(record: &SignedRecord) -> Result<Vec<u8>, Reject> {
    signing_digest("heddle-signed-native-record-v1", record)
}
fn verify_native(record: &SignedRecord, format: &str) -> Result<(), Reject> {
    if record.format != format {
        return Err(Reject::Version);
    }
    if record.canonical_record.is_empty()
        || record.canonical_record.len() > MAX_RECORD_BYTES
        || record.signatures.is_empty()
        || record.signatures.len() > 16
    {
        return Err(Reject::Bounds);
    }
    let mut previous: Option<&[u8]> = None;
    let input = [format.as_bytes(), b"\0", &record.canonical_record].concat();
    for s in &record.signatures {
        if previous.is_some_and(|p| p >= s.public_key.as_slice()) {
            return Err(Reject::Canonical);
        }
        verify(&s.public_key, &input, &s.signature)?;
        previous = Some(&s.public_key);
    }
    Ok(())
}
/// Recompute transport commitments from exact native evidence. The caller's
/// native verifier additionally authenticates manifest membership, receipt
/// subjects/bases, accepting authority and canonical native encoding.
pub fn verify_boundary_acceptance(e: &ImportBoundaryAcceptanceV1) -> Result<(), Reject> {
    let binding = e.binding.as_ref().ok_or(Reject::BoundaryAcceptance)?;
    validate_boundary_binding(binding)?;
    let acceptance = e
        .signed_acceptance
        .as_ref()
        .ok_or(Reject::BoundaryAcceptance)?;
    verify_native(acceptance, "heddle-original-boundary-acceptance-v1")?;
    if acceptance.signatures.len() != 1 {
        return Err(Reject::Signature);
    }
    if e.originals_manifest.is_empty()
        || e.publication_intent.is_empty()
        || e.originals_manifest.len() > MAX_RECORD_BYTES
        || e.publication_intent.len() > MAX_RECORD_BYTES
        || e.original_receipts.is_empty()
        || e.original_receipts.len() > 128
    {
        return Err(Reject::Bounds);
    }
    if binding.acceptance_id != native_id(acceptance)
        || binding.signed_acceptance_digest != signed_native_digest(acceptance)?
        || binding.originals_manifest_digest
            != boundary_octets_digest(
                "heddle-boundary-originals-manifest-v1",
                &e.originals_manifest,
            )
        || binding.publication_intent_digest
            != boundary_octets_digest(
                "heddle-boundary-publication-intent-v1",
                &e.publication_intent,
            )
    {
        return Err(Reject::BoundaryAcceptance);
    }
    let native: NativeBoundarySelection =
        rmp_serde::from_slice(&acceptance.canonical_record).map_err(|_| Reject::Canonical)?;
    if native.originals_manifest.as_slice()
        != native_octets_id(
            "heddle-original-publication-manifest-v1",
            &e.originals_manifest,
        )
        || native.publication_intent.as_slice()
            != native_octets_id(
                "heddle-original-publication-intent-v1",
                &e.publication_intent,
            )
    {
        return Err(Reject::BoundaryAcceptance);
    }
    let mut digests = Vec::new();
    for receipt in &e.original_receipts {
        if ![
            "heddle-thread-genesis-admission-v2",
            "heddle-thread-authority-admission-v3",
        ]
        .contains(&receipt.format.as_str())
        {
            return Err(Reject::Version);
        }
        verify_native(receipt, &receipt.format)?;
        if receipt.signatures.len() != 1 {
            return Err(Reject::Signature);
        }
        let native: NativeBoundaryReceipt =
            rmp_serde::from_slice(&receipt.canonical_record).map_err(|_| Reject::Canonical)?;
        if native.basis
            != (NativeBoundaryBasis::BoundaryAcceptance {
                acceptance: binding
                    .acceptance_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| Reject::Canonical)?,
            })
        {
            return Err(Reject::BoundaryAcceptance);
        }
        digests.push(signed_native_digest(receipt)?);
    }
    if digests != binding.original_receipt_digests {
        return Err(Reject::BoundaryAcceptance);
    }
    Ok(())
}
// These readers extract only the native commitment selectors. Full native
// canonicality, model validity, membership and authority remain the native gate.
#[derive(serde::Deserialize)]
struct NativeBoundarySelection {
    originals_manifest: [u8; 32],
    publication_intent: [u8; 32],
}
#[derive(serde::Deserialize, PartialEq)]
enum NativeBoundaryBasis {
    OriginalAuthority,
    BoundaryAcceptance { acceptance: [u8; 32] },
}
#[derive(serde::Deserialize)]
struct NativeBoundaryReceipt {
    basis: NativeBoundaryBasis,
    thread: [u8; 32],
    subject: Option<NativeBoundarySubject>,
}
#[derive(serde::Deserialize)]
enum NativeBoundarySubject {
    Operation([u8; 32]),
    OwnershipClaim([u8; 32]),
    OwnershipResolution([u8; 32]),
}
fn native_octets_id(format: &str, bytes: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(format.as_bytes());
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(b"\0");
    h.update(bytes);
    h.finalize().as_bytes().to_vec()
}
fn boundary_original(
    e: &ImportBoundaryAcceptanceV1,
    original: &SignedRecord,
) -> Result<(), Reject> {
    let id = native_id(original);
    for receipt in &e.original_receipts {
        let value: NativeBoundaryReceipt =
            rmp_serde::from_slice(&receipt.canonical_record).map_err(|_| Reject::Canonical)?;
        let (format, subject) = match value.subject {
            None if receipt.format == "heddle-thread-genesis-admission-v2" => {
                ("heddle-thread-genesis-v1", value.thread)
            }
            Some(NativeBoundarySubject::Operation(id)) => ("heddle-thread-operation-v1", id),
            Some(NativeBoundarySubject::OwnershipClaim(id)) => {
                ("heddle-thread-ownership-claim-v1", id)
            }
            Some(NativeBoundarySubject::OwnershipResolution(id)) => {
                ("heddle-thread-ownership-resolution-v1", id)
            }
            _ => return Err(Reject::BoundaryAcceptance),
        };
        if original.format == format && id == subject {
            return Ok(());
        }
    }
    Err(Reject::BoundaryAcceptance)
}
pub fn boundary_octets_digest(domain: &str, bytes: &[u8]) -> Vec<u8> {
    hash(&[
        domain.as_bytes(),
        &(bytes.len() as u32).to_be_bytes(),
        bytes,
    ])
}
pub fn validate_boundary_binding(
    b: &crate::heddle::api::common::HostedWitnessBoundaryAcceptanceV1,
) -> Result<(), Reject> {
    if b.format_version != 1 {
        return Err(Reject::Version);
    }
    for digest in [
        &b.acceptance_id,
        &b.signed_acceptance_digest,
        &b.originals_manifest_digest,
        &b.publication_intent_digest,
    ] {
        width(digest, 32)?;
    }
    if b.original_receipt_digests.is_empty() || b.original_receipt_digests.len() > 128 {
        return Err(Reject::Bounds);
    }
    for digest in &b.original_receipt_digests {
        width(digest, 32)?;
    }
    if b.original_receipt_digests.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Reject::Canonical);
    }
    Ok(())
}
pub fn validate_statement_boundary(
    s: &crate::heddle::api::common::HostedWitnessStatementV1,
) -> Result<(), Reject> {
    match (s.basis, s.boundary_acceptance.as_ref()) {
        (1, None) => Ok(()),
        (2, Some(b)) if s.purpose == 1 || s.purpose == 2 => validate_boundary_binding(b),
        _ => Err(Reject::BoundaryAcceptance),
    }
}
fn match_boundary(
    s: &crate::heddle::api::common::HostedWitnessStatementV1,
    evidence: &[ImportBoundaryAcceptanceV1],
) -> Result<(), Reject> {
    validate_statement_boundary(s)?;
    let mut previous = None;
    for e in evidence {
        verify_boundary_acceptance(e)?;
        let b = e.binding.as_ref().ok_or(Reject::BoundaryAcceptance)?;
        if previous.is_some_and(|p: &[u8]| p >= b.acceptance_id.as_slice()) {
            return Err(Reject::Canonical);
        }
        previous = Some(b.acceptance_id.as_slice());
    }
    if let Some(binding) = &s.boundary_acceptance
        && !evidence.iter().any(|e| e.binding.as_ref() == Some(binding))
    {
        return Err(Reject::BoundaryAcceptance);
    }
    Ok(())
}
fn native_dependencies(
    records: &[SignedRecord],
    evidence: &[ImportBoundaryAcceptanceV1],
) -> Result<(), Reject> {
    if records.len() > 128 {
        return Err(Reject::Bounds);
    }
    let mut previous = None;
    for record in records {
        match record.format.as_str() {
            "heddle-thread-genesis-v1"
            | "heddle-thread-operation-v1"
            | "heddle-thread-ownership-claim-v1"
            | "heddle-thread-ownership-resolution-v1" => (),
            "heddle-original-boundary-acceptance-v1"
            | "heddle-thread-genesis-admission-v2"
            | "heddle-thread-authority-admission-v3" => {
                if !evidence.iter().any(|e| {
                    e.signed_acceptance.as_ref() == Some(record)
                        || e.original_receipts.contains(record)
                }) {
                    return Err(Reject::BoundaryAcceptance);
                }
            }
            _ => return Err(Reject::Version),
        }
        verify_native(record, &record.format)?;
        let digest = signed_native_digest(record)?;
        if previous.as_ref().is_some_and(|p| p >= &digest) {
            return Err(Reject::Canonical);
        }
        previous = Some(digest);
    }
    Ok(())
}
fn original_signatures(
    records: &[&SignedRecord],
    extra: &[RecordSignature],
) -> Result<Vec<u8>, Reject> {
    let signatures = records
        .iter()
        .flat_map(|r| r.signatures.iter())
        .chain(extra.iter())
        .collect::<Vec<_>>();
    let mut out = (signatures.len() as u32).to_be_bytes().to_vec();
    for s in signatures {
        s.write(&mut out)?;
    }
    Ok(hash(&[b"heddle-hosted-original-signatures-v1", &out]))
}
use crate::hybrid_codec::Canonical;
/// Caller constructs this from independently verified native originals and
/// accepted owner/policy/landing context. This matching layer verifies original
/// signatures and exact payload commitments separately from witness trust; it
/// does not replace native causal, authority or landing-model verification.
pub enum WitnessPayload<'a> {
    Genesis(&'a ImportGenesisWitnessV1),
    Authority(&'a ImportAuthorityWitnessV1),
    Landing(&'a HostedLandingWitnessV1),
}
pub fn verify_witness_payload(
    statement: &crate::heddle::api::common::HostedWitnessStatementV1,
    payload: WitnessPayload<'_>,
) -> Result<(), Reject> {
    let (purpose, bytes, authority, signatures, publisher) = match payload {
        WitnessPayload::Genesis(p) => {
            if p.format_version != 1 {
                return Err(Reject::Version);
            }
            let original = p.original_genesis.as_ref().ok_or(Reject::Canonical)?;
            let binding = p.binding.as_ref().ok_or(Reject::Canonical)?;
            let b = binding.body.as_ref().ok_or(Reject::Canonical)?;
            match_boundary(
                statement,
                &p.boundary_acceptance.iter().cloned().collect::<Vec<_>>(),
            )?;
            if let Some(e) = &p.boundary_acceptance {
                boundary_original(e, original)?;
            }
            if (statement.basis == 2) != p.boundary_acceptance.is_some() {
                return Err(Reject::BoundaryAcceptance);
            }
            verify_native(original, "heddle-thread-genesis-v1")?;
            if native_id(original) != b.genesis_digest {
                return Err(Reject::Scope);
            }
            if let Some(id) = &b.identity {
                if statement.spool_uuid != id.spool_uuid
                    || statement.spool_genesis_digest != id.spool_genesis_digest
                    || statement.owner_id != id.owner_id
                    || statement.owner_state_hash != id.owner_state_hash
                    || statement.ownership_transfer_sequence != id.ownership_transfer_sequence
                {
                    return Err(Reject::Scope);
                }
            } else {
                return Err(Reject::Canonical);
            }
            let creator = original
                .signatures
                .iter()
                .find(|s| s.public_key == b.creator_public_key)
                .ok_or(Reject::Signature)?;
            if b.original_creator_signature != creator.signature
                || b.creator_authority_envelope_digest != hash(&[&p.creator_authority_envelope])
            {
                return Err(Reject::Scope);
            }
            verify_authorization_signature(
                &b.creator_public_key,
                GENESIS_DOMAIN,
                b,
                binding
                    .creator_signature
                    .as_ref()
                    .ok_or(Reject::Signature)?,
            )?;
            (
                1,
                canonical(p)?,
                signed_genesis_digest(binding)?,
                original_signatures(&[original], &[])?,
                key_id(&b.creator_public_key),
            )
        }
        WitnessPayload::Authority(p) => {
            if p.format_version != 1 {
                return Err(Reject::Version);
            }
            let original = p.original.as_ref().ok_or(Reject::Canonical)?;
            let format = match p.kind {
                1 => "heddle-thread-operation-v1",
                2 => "heddle-thread-ownership-claim-v1",
                3 => "heddle-thread-ownership-resolution-v1",
                _ => return Err(Reject::Version),
            };
            verify_native(original, format)?;
            if (p.kind == 2 || p.kind == 3) && original.signatures.len() != 2 {
                return Err(Reject::Signature);
            }
            if !original
                .signatures
                .iter()
                .any(|s| key_id(&s.public_key) == statement.publisher_key_id)
            {
                return Err(Reject::Signature);
            }
            if p.authority_envelope.is_empty() || p.authority_envelope.len() > MAX_RECORD_BYTES {
                return Err(Reject::Bounds);
            }
            match_boundary(statement, &p.boundary_acceptances)?;
            if let Some(b) = &statement.boundary_acceptance {
                let e = p
                    .boundary_acceptances
                    .iter()
                    .find(|e| e.binding.as_ref() == Some(b))
                    .ok_or(Reject::BoundaryAcceptance)?;
                boundary_original(e, original)?;
            }
            native_dependencies(&p.dependencies, &p.boundary_acceptances)?;
            let records = std::iter::once(original)
                .chain(p.dependencies.iter())
                .collect::<Vec<_>>();
            (
                2,
                canonical(p)?,
                hash(&[
                    b"heddle-hosted-authority-envelope-v1",
                    &(p.authority_envelope.len() as u32).to_be_bytes(),
                    &p.authority_envelope,
                ]),
                original_signatures(&records, &[])?,
                statement.publisher_key_id.clone(),
            )
        }
        WitnessPayload::Landing(p) => {
            if p.format_version != 1 {
                return Err(Reject::Version);
            }
            let execution = p.execution.as_ref().ok_or(Reject::Canonical)?;
            let source = p.source_operation.as_ref().ok_or(Reject::Canonical)?;
            let request = p.request.as_ref().ok_or(Reject::Canonical)?;
            if request.format_version != 1
                || request.method_path != "/heddle.api.v1alpha2.ThreadService/LandThread"
            {
                return Err(Reject::Version);
            }
            verify_native(execution, "heddle-thread-operation-v1")?;
            verify_native(source, "heddle-thread-operation-v1")?;
            match_boundary(statement, &[])?;
            native_dependencies(&p.review_evidence, &[])?;
            let signature = request.signature.as_ref().ok_or(Reject::Signature)?;
            if request.signing_identity
                != format!(
                    "principal:device-key:{}",
                    hex::encode(&signature.public_key)
                )
            {
                return Err(Reject::Signature);
            }
            width(&request.nonce, 16)?;
            if request.timestamp_millis <= 0
                || request.request_body.is_empty()
                || request.request_body.len() > MAX_RECORD_BYTES
                || p.authority_envelope.is_empty()
                || p.authority_envelope.len() > MAX_RECORD_BYTES
            {
                return Err(Reject::Bounds);
            }
            let input = crate::signing::unary_bytes(
                &request.signing_identity,
                &request.method_path,
                request.timestamp_millis,
                &request.nonce,
                &request.request_body,
            );
            verify(&signature.public_key, &input, &signature.signature)?;
            let records = [execution, source]
                .into_iter()
                .chain(p.review_evidence.iter())
                .collect::<Vec<_>>();
            (
                4,
                canonical(p)?,
                hash(&[
                    b"heddle-hosted-authority-envelope-v1",
                    &(p.authority_envelope.len() as u32).to_be_bytes(),
                    &p.authority_envelope,
                ]),
                original_signatures(&records, std::slice::from_ref(signature))?,
                key_id(&signature.public_key),
            )
        }
    };
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Reject::Bounds);
    }
    if statement.purpose != purpose
        || statement.canonical_payload != bytes
        || statement.authority_digest != authority
        || statement.original_signatures_digest != signatures
        || statement.publisher_key_id != publisher
    {
        return Err(Reject::Scope);
    }
    Ok(())
}

pub fn resolve_bundle_permission<'a>(
    bundle: &'a ImportPublicProofBundleV1,
    digest: &[u8],
) -> Result<Option<&'a SignedImportMemberPermissionV1>, Reject> {
    width(digest, 32)?;
    if digest == [0; 32] {
        return Ok(None);
    }
    bundle
        .member_permissions
        .iter()
        .find(|p| signed_permission_digest(p).is_ok_and(|d| d == digest))
        .map(Some)
        .ok_or(Reject::ImportPermission)
}
pub fn resolve_bundle_manifest<'a>(
    bundle: &'a ImportPublicProofBundleV1,
    digest: &[u8],
) -> Result<&'a ImportResultManifestV1, Reject> {
    width(digest, 32)?;
    bundle
        .manifests
        .iter()
        .find(|m| manifest_digest(m).is_ok_and(|d| d == digest))
        .ok_or(Reject::StaleManifest)
}
pub fn publication_payload(
    operation: &SignedDelegatedImportOperationV1,
    manifest: &ImportResultManifestV1,
) -> Result<ImportPublicationWitnessV1, Reject> {
    let o = operation.body.as_ref().ok_or(Reject::Canonical)?;
    Ok(ImportPublicationWitnessV1 {
        format_version: 1,
        signed_operation_digest: signed_operation_digest(operation)?,
        delegation_digest: o.delegation_digest.clone(),
        logical_job_id: o.logical_job_id.clone(),
        retry_lineage_id: o.retry_lineage_id.clone(),
        physical_operation_id: o.physical_operation_id.clone(),
        ref_name: o.ref_name.clone(),
        slot_id: o.slot_id,
        hash_algorithm: o.hash_algorithm,
        observed_commit_oid: o.observed_commit_oid.clone(),
        expected_frontier_digest: o.expected_frontier_digest.clone(),
        resulting_frontier_digest: o.resulting_frontier_digest.clone(),
        terminal_manifest_digest: manifest_digest(manifest)?,
    })
}
/// Completeness and digest addressing only. Trust/signature verification still
/// uses independently selected owner contexts at each witnessed historical time.
fn validate_bundle_history(bundle: &ImportPublicProofBundleV1) -> Result<(), Reject> {
    fn sorted<T>(
        values: &[T],
        digest: impl Fn(&T) -> Result<Vec<u8>, Reject>,
    ) -> Result<(), Reject> {
        let mut previous = None;
        for value in values {
            let d = digest(value)?;
            if previous.as_ref().is_some_and(|p| p >= &d) {
                return Err(Reject::Canonical);
            }
            previous = Some(d);
        }
        Ok(())
    }
    for statement in &bundle.statements {
        let s = statement.body.as_ref().ok_or(Reject::Canonical)?;
        validate_statement_boundary(s)?;
        require_policy_history(
            bundle,
            &s.spool_uuid,
            s.policy_sequence,
            &s.policy_state_hash,
        )?;
    }
    sorted(&bundle.member_permissions, signed_permission_digest)?;
    sorted(&bundle.manifests, manifest_digest)?;
    if let Some(p) = &bundle.member_permission
        && resolve_bundle_permission(bundle, &signed_permission_digest(p)?)? != Some(p)
    {
        return Err(Reject::ImportPermission);
    }
    let terminal = bundle.terminal_manifest.as_ref().ok_or(Reject::Canonical)?;
    if resolve_bundle_manifest(bundle, &manifest_digest(terminal)?)? != terminal {
        return Err(Reject::Canonical);
    }
    if bundle.delegations.is_empty() || bundle.renewals.len() + 1 != bundle.delegations.len() {
        return Err(Reject::Canonical);
    }
    for (i, d) in bundle.delegations.iter().enumerate() {
        let body = d.body.as_ref().ok_or(Reject::Canonical)?;
        resolve_bundle_permission(bundle, &body.parent_permission_digest)?;
        if i == 0 {
            if body.predecessor_delegation_digest != [0; 32] {
                return Err(Reject::RenewalFork);
            }
        } else {
            let r = bundle.renewals[i - 1]
                .body
                .as_ref()
                .ok_or(Reject::Canonical)?;
            if r.replacement.as_ref() != Some(d)
                || r.predecessor_delegation_digest
                    != signed_delegation_digest(&bundle.delegations[i - 1])?
                || body.predecessor_delegation_digest != r.predecessor_delegation_digest
                || r.expected_authority_epoch != i as u64
            {
                return Err(Reject::RenewalFork);
            }
            resolve_bundle_manifest(bundle, &r.committed_manifest_digest)?;
        }
        for branch in &body.branch_manifest {
            let g = bundle
                .genesis_authorities
                .iter()
                .find(|g| {
                    signed_genesis_digest(g).is_ok_and(|h| h == branch.genesis_authority_digest)
                })
                .ok_or(Reject::Scope)?;
            let b = g.body.as_ref().ok_or(Reject::Canonical)?;
            resolve_bundle_permission(bundle, &b.parent_permission_digest)?;
            if !bundle
                .original_geneses
                .iter()
                .any(|o| native_id(o) == b.genesis_digest)
                || !bundle
                    .creator_authority_envelopes
                    .iter()
                    .any(|e| hash(&[e]) == b.creator_authority_envelope_digest)
            {
                return Err(Reject::Scope);
            }
            // Every branch needs its original admission, not merely its
            // binding. Proof-only retirement lookup cannot recover a payload.
            if !bundle.genesis_witnesses.iter().any(|payload| {
                payload.binding.as_ref() == Some(g)
                    && payload.original_genesis.as_ref().is_some_and(|o| {
                        native_id(o) == b.genesis_digest && bundle.original_geneses.contains(o)
                    })
                    && hash(&[&payload.creator_authority_envelope])
                        == b.creator_authority_envelope_digest
                    && canonical(payload).is_ok_and(|bytes| {
                        bundle.statements.iter().any(|s| {
                            s.body
                                .as_ref()
                                .is_some_and(|s| s.purpose == 1 && s.canonical_payload == bytes)
                        })
                    })
            }) {
                return Err(Reject::Scope);
            }
        }
    }
    for manifest in &bundle.manifests {
        validate_manifest(manifest)?;
        if manifest.logical_job_id != terminal.logical_job_id
            || manifest.retry_lineage_id != terminal.retry_lineage_id
        {
            return Err(Reject::Scope);
        }
        for slot in &manifest.slots {
            let operation = bundle
                .operations
                .iter()
                .find(|o| {
                    signed_operation_digest(o).is_ok_and(|d| d == slot.signed_operation_digest)
                })
                .ok_or(Reject::Scope)?;
            if !check_slot_replay(manifest, operation)? || !check_slot_replay(terminal, operation)?
            {
                return Err(Reject::Scope);
            }
        }
    }
    for operation in &bundle.operations {
        let o = operation.body.as_ref().ok_or(Reject::Canonical)?;
        if !bundle
            .delegations
            .iter()
            .any(|d| signed_delegation_digest(d).is_ok_and(|h| h == o.delegation_digest))
            || !check_slot_replay(terminal, operation)?
        {
            return Err(Reject::Scope);
        }
        if !bundle.manifests.iter().any(|m| {
            check_slot_replay(m, operation) == Ok(true)
                && publication_payload(operation, m)
                    .and_then(|p| canonical(&p))
                    .is_ok_and(|p| {
                        bundle.statements.iter().any(|s| {
                            s.body
                                .as_ref()
                                .is_some_and(|s| s.purpose == 3 && s.canonical_payload == p)
                        })
                    })
        }) {
            return Err(Reject::Scope);
        }
    }
    for statement in &bundle.statements {
        let s = statement.body.as_ref().ok_or(Reject::Canonical)?;
        let found = match s.purpose {
            1 => bundle
                .genesis_witnesses
                .iter()
                .any(|p| canonical(p).is_ok_and(|p| p == s.canonical_payload)),
            2 => bundle
                .authority_witnesses
                .iter()
                .any(|p| canonical(p).is_ok_and(|p| p == s.canonical_payload)),
            3 => bundle.operations.iter().any(|o| {
                bundle.manifests.iter().any(|m| {
                    publication_payload(o, m)
                        .and_then(|p| canonical(&p))
                        .is_ok_and(|p| p == s.canonical_payload)
                })
            }),
            4 => bundle
                .landing_witnesses
                .iter()
                .any(|p| canonical(p).is_ok_and(|p| p == s.canonical_payload)),
            _ => return Err(Reject::Version),
        };
        if !found {
            return Err(Reject::Scope);
        }
    }
    Ok(())
}
/// Reference completeness only. Native verification must authenticate every
/// selected policy, its owner context and the receipt before using its time.
fn require_policy_history(
    bundle: &ImportPublicProofBundleV1,
    spool: &[u8],
    mut sequence: u64,
    state_hash: &[u8],
) -> Result<(), Reject> {
    let mut state_hash = state_hash.to_vec();
    for _ in 0..=bundle.policies.len() {
        width(&state_hash, 32)?;
        if sequence == 0 {
            return if state_hash == [0; 32] {
                Ok(())
            } else {
                Err(Reject::Scope)
            };
        }
        let mut matches = bundle
            .policies
            .iter()
            .filter_map(|p| p.body.as_ref())
            .filter(|p| {
                p.spool_uuid == spool && p.sequence == sequence && p.policy_state_hash == state_hash
            });
        let policy = matches.next().ok_or(Reject::Scope)?;
        if matches.next().is_some() {
            return Err(Reject::Canonical);
        }
        let head = policy.expected_head.as_ref().ok_or(Reject::Canonical)?;
        if head.sequence.checked_add(1) != Some(sequence) {
            return Err(Reject::Scope);
        }
        sequence = head.sequence;
        state_hash = head.state_hash.clone();
    }
    Err(Reject::Scope)
}
fn native_id(record: &SignedRecord) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(record.format.as_bytes());
    h.update(&(record.canonical_record.len() as u64).to_le_bytes());
    h.update(b"\0");
    h.update(&record.canonical_record);
    h.finalize().as_bytes().to_vec()
}
/// Prepare response is a coherent proposal, never authority. Caller must compare
/// the IDs, predecessor and manifest before asking its device to sign renewal.
pub fn validate_renewal_preparation(response: &PrepareImportJobResponse) -> Result<(), Reject> {
    let state = response.renewal_state.as_ref().ok_or(Reject::Canonical)?;
    let proposal = response.proposal.as_ref().ok_or(Reject::Canonical)?;
    let previous = state.active_predecessor.as_ref().ok_or(Reject::Canonical)?;
    let p = previous.body.as_ref().ok_or(Reject::Canonical)?;
    let manifest = state.committed_manifest.as_ref().ok_or(Reject::Canonical)?;
    validate_manifest(manifest)?;
    if state.format_version != 1
        || state.authority_epoch == 0
        || state.logical_job_id != p.logical_job_id
        || state.retry_lineage_id != p.retry_lineage_id
        || proposal.logical_job_id != state.logical_job_id
        || proposal.retry_lineage_id != state.retry_lineage_id
        || manifest.logical_job_id != state.logical_job_id
        || manifest.retry_lineage_id != state.retry_lineage_id
        || proposal.predecessor_delegation_digest != signed_delegation_digest(previous)?
    {
        return Err(Reject::StaleContext);
    }
    Ok(())
}

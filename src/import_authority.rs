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
pub const OPERATION_DOMAIN: &str = "heddle-delegated-import-operation-v1";
pub const MANIFEST_DOMAIN: &str = "heddle-import-result-manifest-v1";
pub const PUBLICATION_DOMAIN: &str = "heddle-import-publication-payload-v1";
pub const MAX_BRANCHES: usize = 256;
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
pub const MAX_DELEGATION_WINDOW_SECONDS: u64 = 7 * 24 * 60 * 60;
pub const MAX_COMMIT_REQUEST_BYTES: usize = 2 * MAX_BUNDLE_BYTES;
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
record!(ImportIdentityV1, spool_uuid:b, spool_genesis_digest:b, owner_id:b,
    owner_account_uuid:b, owner_state_hash:b, ownership_transfer_sequence:u);
record!(ImportOwnerChainV1, spool_genesis_digest:b, owner_state_hashes:q, transfer_audit_hashes:q);
record!(ImportBranchLimitV1, ref_name:s, hash_algorithm:e, ref_mode:e, pinned_commit_oid:b,
    genesis_digest:b, target_thread_id:b, expected_frontier_digest:b, slot_id:u, ref_disclosure:e);
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
    not_before_unix_seconds:u, expires_at_unix_seconds:u, cancellation_id:b);
record!(ImportJobPreparationV1, format_version:u, identity:m, delegation_id:b, logical_job_id:b,
    retry_lineage_id:b, job_public_key:b, job_key_id:b, owner_chain_digest:b, purpose:e,
    scope:m, cancellation_id:b);
record!(SignedImportJobDelegationV1, body:m, delegating_signature:m);
record!(ImportCommittedSlotV1, ref_name:s, slot_id:u, signed_operation_digest:b,
    resulting_frontier_digest:b, result_bytes:u);
record!(ImportResultManifestV1, format_version:u, logical_job_id:b, retry_lineage_id:b, slots:l);
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
// Structural validation never substitutes a synthetic historical clock.
fn validity(start: i64, end: i64, now: i64, current: bool) -> Result<(), Reject> {
    if start < 0 || end <= start {
        return Err(Reject::Semantic);
    }
    if current {
        interval(start, end, now)?;
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
        1 => {
            width(&value.pinned_commit_oid, size)?;
            if value.ref_disclosure != 0 {
                return Err(Reject::RefDisclosure);
            }
        }
        2 if value.pinned_commit_oid.is_empty() => {
            if value.ref_disclosure != 1 {
                return Err(Reject::RefDisclosure);
            }
        }
        _ => return Err(Reject::Semantic),
    }
    for v in [
        &value.genesis_digest,
        &value.target_thread_id,
        &value.expected_frontier_digest,
    ] {
        width(v, 32)?;
    }
    Ok(())
}

/// Check independently observed OID knowledge before signing/preparation.
/// Empty/unknown is None, never an implicit observe-mode selection or consent.
pub fn validate_ref_selection(
    value: &ImportBranchLimitV1,
    known_commit_oid: Option<&[u8]>,
) -> Result<(), Reject> {
    branch(value)?;
    if let Some(oid) = known_commit_oid {
        width(oid, if value.hash_algorithm == 1 { 20 } else { 32 })?;
        if value.ref_mode != 1 || value.pinned_commit_oid != oid {
            return Err(Reject::RefPinning);
        }
    }
    Ok(())
}

/// Converter option octets are selected verbatim from authenticated discovery.
pub fn conversion_options_digest(version: &str, options: &[u8]) -> Result<Vec<u8>, Reject> {
    if version.is_empty() || version.len() > 128 || !version.is_ascii() {
        return Err(Reject::Canonical);
    }
    if options.len() > 4096 {
        return Err(Reject::Bounds);
    }
    let mut bytes = Vec::new();
    crate::hybrid_codec::counted(&mut bytes, version.as_bytes())?;
    crate::hybrid_codec::counted(&mut bytes, options)?;
    Ok(hash(&[b"heddle-import-conversion-options-v1", &bytes]))
}

/// Resolve explicit custody using a CURRENT authenticated connection provider.
/// Public URLs never select an adapter by domain. Network/grant checks remain host gates.
pub fn resolve_import_provider(
    source: &ProviderRepository,
    connection_provider: Option<&str>,
) -> Result<&'static str, Reject> {
    canonical_https(&source.clone_url, false)?;
    if source.provider_repository_id.len() > 4096 || source.name.len() > 4096 {
        return Err(Reject::Bounds);
    }
    if let Some(connection) = &source.connection {
        let positive = |v: &str| {
            !v.is_empty()
                && v.bytes().all(|b| b.is_ascii_digit())
                && v.parse::<u64>().is_ok_and(|id| id > 0)
        };
        if connection_provider != Some("github")
            || connection.spool.is_some()
            || connection.id.is_empty()
            || !positive(&source.provider_repository_id)
            || !positive(&source.installation_id)
        {
            return Err(Reject::SourceSelection);
        }
        let path = source
            .clone_url
            .strip_prefix("https://github.com/")
            .ok_or(Reject::SourceSelection)?;
        let parts: Vec<_> = path.split('/').collect();
        if parts.len() != 2
            || parts[0].is_empty()
            || parts[1].strip_suffix(".git").is_none_or(str::is_empty)
        {
            return Err(Reject::SourceSelection);
        }
        Ok("github")
    } else {
        if connection_provider.is_some()
            || source.private
            || !source.installation_id.is_empty()
            || (!source.provider_repository_id.is_empty()
                && source.provider_repository_id != source.clone_url)
        {
            return Err(Reject::SourceSelection);
        }
        Ok("public-git")
    }
}

/// Advisory Git size in KiB. UNKNOWN is explicit and must carry zero.
pub fn validate_repository_size_estimate(source: &ProviderRepository) -> Result<(), Reject> {
    match source.size_estimate_state {
        0 if source.git_size_kib == 0 => Ok(()),
        1 if source.connection.is_some() => Ok(()),
        _ => Err(Reject::Canonical),
    }
}

/// Preserve selected identity exactly. Redirect/SSRF and current grants are host gates.
pub fn validate_resolve_import_source_response(
    request: &ResolveImportSourceRequest,
    response: &ResolveImportSourceResponse,
    connection_provider: Option<&str>,
) -> Result<(), Reject> {
    use prost::Message;
    if response.encoded_len() > MAX_BUNDLE_BYTES {
        return Err(Reject::Bounds);
    }
    let selected = request.source.as_ref().ok_or(Reject::SourceSelection)?;
    let resolved = response.source.as_ref().ok_or(Reject::SourceSelection)?;
    let provider = resolve_import_provider(selected, connection_provider)?;
    if resolve_import_provider(resolved, connection_provider)? != provider
        || selected.clone_url != resolved.clone_url
        || selected.connection != resolved.connection
        || selected.installation_id != resolved.installation_id
        || selected.private != resolved.private
        || (selected.provider_repository_id != resolved.provider_repository_id
            && (selected.connection.is_some() || !selected.provider_repository_id.is_empty()))
        || (resolved.connection.is_none() && resolved.provider_repository_id != selected.clone_url)
    {
        return Err(Reject::SourceSelection);
    }
    validate_repository_size_estimate(resolved)?;
    validate_repository_hash_algorithm(resolved, false)
}

/// Structural binding to signed provider/URL; durable custody association is a host invariant.
fn validate_retained_import_source(
    selector: &ImportSourceSelectionV1,
    scope: &ImportPermissionScopeV1,
) -> Result<(), Reject> {
    let source = ProviderRepository {
        connection: selector.connection.clone(),
        provider_repository_id: selector.provider_repository_id.clone(),
        installation_id: selector.installation_id.clone(),
        private: selector.private,
        clone_url: scope.source_url.clone(),
        ..Default::default()
    };
    let provider =
        resolve_import_provider(&source, selector.connection.as_ref().map(|_| "github"))?;
    if scope.provider != provider
        || (selector.connection.is_none() && selector.provider_repository_id != scope.source_url)
    {
        return Err(Reject::SourceSelection);
    }
    Ok(())
}

/// Discovery may report unknown. Preparing/signing requires known=true; no SHA-1 fallback.
pub fn validate_repository_hash_algorithm(
    source: &ProviderRepository,
    known: bool,
) -> Result<(), Reject> {
    let size = match source.hash_algorithm {
        1 => Some(40),
        2 => Some(64),
        0 if !known => None,
        _ => return Err(Reject::Version),
    };
    if source.refs.len() > 512 {
        return Err(Reject::Bounds);
    }
    for (i, r) in source.refs.iter().enumerate() {
        if r.hash_algorithm != source.hash_algorithm {
            return Err(Reject::SourceSelection);
        }
        if i > 0 && source.refs[i - 1].name >= r.name {
            return Err(Reject::Canonical);
        }
        if !r.head_oid.is_empty() {
            let size = size.ok_or(Reject::Version)?;
            if r.head_oid.len() != size {
                return Err(Reject::SourceSelection);
            }
            if !r
                .head_oid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Reject::Canonical);
            }
        }
    }
    Ok(())
}

/// Compare independent repository discovery before signing, including known-OID pinning.
pub fn validate_discovered_import_scope(
    scope: &ImportPermissionScopeV1,
    source: &ProviderRepository,
) -> Result<(), Reject> {
    validate_discovered_import_scope_inner(scope, source)
}

fn validate_discovered_import_scope_inner(
    scope: &ImportPermissionScopeV1,
    source: &ProviderRepository,
) -> Result<(), Reject> {
    validate_repository_hash_algorithm(source, true)?;
    if scope.source_url != source.clone_url {
        return Err(Reject::SourceSelection);
    }
    for b in &scope.branches {
        if b.hash_algorithm != source.hash_algorithm {
            return Err(Reject::SourceSelection);
        }
        let oid = source
            .refs
            .iter()
            .find(|r| r.name == b.ref_name)
            .filter(|r| !r.head_oid.is_empty())
            .map(|r| hex::decode(&r.head_oid).map_err(|_| Reject::Canonical))
            .transpose()?;
        validate_ref_selection(b, oid.as_deref())?;
    }
    Ok(())
}

/// Host resolves the selector anew and checks current grants and selected-commit
/// availability before issuing a reservation, for a new job. Source state
/// MUST come from an authenticated job-state read or receiver-owned durable state;
/// the current source resolver binds independently verified discovery to the proposal.
pub fn prepare_import_source_scope(
    request: &PrepareImportJobRequest,
    current_source: &ProviderRepository,
    connection_provider: Option<&str>,
    configuration: &GetImportConfigurationResponse,
    current_destination_version: &[u8],
) -> Result<ImportPermissionScopeV1, Reject> {
    let selector = request.source.as_ref().ok_or(Reject::SourceSelection)?;
    if selector.connection != current_source.connection
        || (selector.provider_repository_id != current_source.provider_repository_id
            && (selector.connection.is_some() || !selector.provider_repository_id.is_empty()))
        || selector.installation_id != current_source.installation_id
        || selector.private != current_source.private
    {
        return Err(Reject::SourceSelection);
    }
    let scope = request.proposed_scope.as_ref().ok_or(Reject::Canonical)?;
    let provider = resolve_import_provider(current_source, connection_provider)?;
    if scope.provider != provider {
        return Err(Reject::SourceSelection);
    }
    validate_discovered_import_scope(scope, current_source)?;
    validate_import_configuration(configuration)?;
    prepare_scope(scope, configuration, current_destination_version)
}

fn validate_provider_support(
    provider: &str,
    configuration: &GetImportConfigurationResponse,
) -> Result<(), Reject> {
    if !configuration
        .providers
        .iter()
        .any(|p| p.provider == provider)
    {
        return Err(Reject::SourceSelection);
    }
    Ok(())
}

pub fn validate_import_configuration(v: &GetImportConfigurationResponse) -> Result<(), Reject> {
    use prost::Message;
    if v.encoded_len() > MAX_BUNDLE_BYTES || v.converters.is_empty() || v.converters.len() > 32 {
        return Err(Reject::Bounds);
    }
    for (i, c) in v.converters.iter().enumerate() {
        for text in [&c.converter_version, &c.options_encoding] {
            if text.is_empty() || text.len() > 128 || !text.is_ascii() {
                return Err(Reject::Canonical);
            }
        }
        if i > 0 && v.converters[i - 1].converter_version >= c.converter_version {
            return Err(Reject::Canonical);
        }
        if c.canonical_options.is_empty()
            || c.canonical_options.len() > 64
            || c.canonical_options.iter().any(|o| o.len() > 4096)
        {
            return Err(Reject::Bounds);
        }
        if c.canonical_options.windows(2).any(|w| w[0] >= w[1])
            || !c.canonical_options.contains(&c.default_options)
        {
            return Err(Reject::Canonical);
        }
    }
    if v.providers.is_empty() || v.providers.len() > 2 {
        return Err(Reject::Bounds);
    }
    for (i, p) in v.providers.iter().enumerate() {
        if i > 0 && v.providers[i - 1].provider >= p.provider {
            return Err(Reject::Canonical);
        }
        let mode = match p.provider.as_str() {
            "github" => 1,
            "public-git" => 2,
            _ => return Err(Reject::SourceSelection),
        };
        if p.source_modes != [mode] {
            return Err(Reject::SourceSelection);
        }
    }
    if let Some(default) = &v.default_converter_version
        && !v.converters.iter().any(|c| &c.converter_version == default)
    {
        return Err(Reject::Canonical);
    }
    let l = v.limits.as_ref().ok_or(Reject::Canonical)?;
    if l.max_branches == 0
        || l.max_branches as usize > MAX_BRANCHES
        || l.max_operations == 0
        || l.max_operations as usize > MAX_BRANCHES
        || l.max_result_bytes == 0
    {
        return Err(Reject::Bounds);
    }
    Ok(())
}

/// Host-side negotiation with a CURRENT authenticated configuration and CAS.
/// Only an empty destination token is filled; all other choices survive exactly.
pub fn prepare_scope(
    proposed: &ImportPermissionScopeV1,
    configuration: &GetImportConfigurationResponse,
    current_destination_version: &[u8],
) -> Result<ImportPermissionScopeV1, Reject> {
    use ImportPreparationRefusalReason as Reason;
    validate_import_configuration(configuration)?;
    width(current_destination_version, 32)?;
    if !proposed.destination_version.is_empty() && proposed.destination_version.len() != 32 {
        return Err(Reject::PreparationRefused(Reason::InvalidScope));
    }
    if !proposed.destination_version.is_empty()
        && proposed.destination_version != current_destination_version
    {
        return Err(Reject::PreparationRefused(Reason::DestinationConflict));
    }
    let mut selected = proposed.clone();
    selected.destination_version = current_destination_version.to_vec();
    validate_scope(&selected).map_err(|_| Reject::PreparationRefused(Reason::InvalidScope))?;
    validate_provider_support(&selected.provider, configuration)
        .map_err(|_| Reject::PreparationRefused(Reason::InvalidScope))?;
    let converter = configuration
        .converters
        .iter()
        .find(|c| c.converter_version == selected.converter_version)
        .ok_or(Reject::PreparationRefused(Reason::UnsupportedConverter))?;
    let supported = converter
        .canonical_options
        .iter()
        .try_fold(false, |found, o| {
            Ok::<_, Reject>(
                found
                    || conversion_options_digest(&converter.converter_version, o)?
                        == selected.options_digest,
            )
        })?;
    if !supported {
        return Err(Reject::PreparationRefused(Reason::UnsupportedOptions));
    }
    let limits = configuration.limits.as_ref().ok_or(Reject::Canonical)?;
    if selected.branches.len() > limits.max_branches as usize
        || selected.max_operations > limits.max_operations
        || selected.max_result_bytes > limits.max_result_bytes
    {
        return Err(Reject::PreparationRefused(Reason::BudgetExceeded));
    }
    Ok(selected)
}

/// Independently retained refs/slots for one non-terminal logical job. Include
/// Prepared jobs and all original refs until logical termination, not just the
/// current certificate's remaining scope. Hosts provide the complete inventory
/// under the same transaction that reserves/activates; this helper stores nothing.
pub struct ImportSpoolReservation<'a> {
    pub spool_uuid: &'a [u8],
    pub logical_job_id: &'a [u8],
    pub branches: &'a [ImportBranchLimitV1],
}

/// Per-spool full refs and (full ref, slot_id) keys are exclusive across jobs,
/// regardless of provider/source. Same-job checks retain exact branch identity.
/// Run after scope negotiation and before atomically reserving every ref/slot.
pub fn check_import_spool_reservations(
    spool_uuid: &[u8],
    logical_job_id: &[u8],
    scope: &ImportPermissionScopeV1,
    reservations: &[ImportSpoolReservation<'_>],
) -> Result<(), Reject> {
    initial_operation_id(spool_uuid, false)?;
    initial_operation_id(logical_job_id, false)?;
    validate_scope(scope)?;
    for reservation in reservations {
        initial_operation_id(reservation.spool_uuid, false)?;
        initial_operation_id(reservation.logical_job_id, false)?;
        if reservation.spool_uuid != spool_uuid {
            continue;
        }
        let same_job = reservation.logical_job_id == logical_job_id;
        for selected in &scope.branches {
            let conflict = if same_job {
                !reservation.branches.contains(selected)
            } else {
                reservation.branches.iter().any(|held| {
                    held.ref_name == selected.ref_name
                        || held.target_thread_id == selected.target_thread_id
                        || held.genesis_digest == selected.genesis_digest
                })
            };
            if conflict {
                return Err(Reject::PreparationRefused(
                    ImportPreparationRefusalReason::DestinationConflict,
                ));
            }
        }
    }
    Ok(())
}

/// Commit-only wire mapping for reservation conflicts and stale destination CAS.
/// These admission failures destroy prepared custody and do not freeze a receipt.
pub fn import_commit_conflict_failure(
    rejection: &Reject,
) -> Option<crate::heddle::api::common::CallFailure> {
    use crate::heddle::api::common::{CallFailure, CallFailureCode, ErrorDetail, ErrorReason};
    let (code, reason) = match rejection {
        Reject::PreparationRefused(ImportPreparationRefusalReason::DestinationConflict) => (
            CallFailureCode::AlreadyExists,
            ErrorReason::ImportDestinationConflict,
        ),
        Reject::StaleContext => (CallFailureCode::Aborted, ErrorReason::VersionConflict),
        _ => return None,
    };
    Some(CallFailure {
        code: code as i32,
        message: String::new(),
        error: Some(ErrorDetail {
            reason: reason as i32,
            ..Default::default()
        }),
    })
}

/// Current destination configuration/ownership/policy CAS at activation. Other
/// imports do not advance this token. Exact stored replay is resolved first.
pub fn check_import_destination_version(
    scope: &ImportPermissionScopeV1,
    current_destination_version: &[u8],
) -> Result<(), Reject> {
    width(&scope.destination_version, 32)?;
    width(current_destination_version, 32)?;
    if scope.destination_version != current_destination_version {
        return Err(Reject::StaleContext);
    }
    Ok(())
}

/// Browser-side comparison before signing. A host cannot silently negotiate.
pub fn validate_preparation_response(
    request: &PrepareImportJobRequest,
    response: &PrepareImportJobResponse,
) -> Result<(), Reject> {
    if let Some(refusal) = &response.refusal {
        let reason = ImportPreparationRefusalReason::try_from(refusal.reason)
            .map_err(|_| Reject::Version)?;
        if reason == ImportPreparationRefusalReason::Unspecified
            || refusal.field.len() > 256
            || !refusal.field.is_ascii()
            || response.proposal.is_some()
            || response.reservation_expires_at_unix_seconds != 0
            || response.prepared_at_unix_seconds != 0
            || response.max_validity_duration_seconds != 0
            || response.clock_skew_allowance_seconds != 0
        {
            return Err(Reject::Canonical);
        }
        return Err(Reject::PreparationRefused(reason));
    }
    let p = response.proposal.as_ref().ok_or(Reject::Canonical)?;
    let returned = p.scope.as_ref().ok_or(Reject::Canonical)?;
    let mut requested = request.proposed_scope.clone().ok_or(Reject::Canonical)?;
    if requested.destination_version.is_empty() {
        requested.destination_version = returned.destination_version.clone();
    }
    if canonical(&requested)? != canonical(returned)?
        || p.identity != request.identity
        || p.retry_lineage_id != request.retry_lineage_id
    {
        return Err(Reject::PreparedFields);
    }
    validate_scope(returned)?;
    Ok(())
}

/// Enforce inclusive decoded protobuf sizes before semantic admission.
/// Transport must also bound the whole uncompressed payload before decoding.
pub fn validate_commit_request_bounds(request: &CommitImportJobRequest) -> Result<(), Reject> {
    use prost::Message;
    if request.encoded_len() > MAX_COMMIT_REQUEST_BYTES
        || request
            .proof
            .as_ref()
            .ok_or(Reject::Canonical)?
            .encoded_len()
            > MAX_BUNDLE_BYTES
    {
        return Err(Reject::Bounds);
    }
    Ok(())
}

/// Source association/provider comes from the host's authenticated resolver,
/// never a projection hint. Native base decoding/identity and current grants
/// remain host gates; this validates carrier, bounds and exact originals.
pub fn validate_commit_request(
    request: &CommitImportJobRequest,
    resolved_provider: &str,
    current_source: &ProviderRepository,
    configuration: &GetImportConfigurationResponse,
) -> Result<(), Reject> {
    use prost::Message;
    validate_commit_request_bounds(request)?;
    let source = request.source.as_ref().ok_or(Reject::SourceSelection)?;
    let proof = request.proof.as_ref().ok_or(Reject::Canonical)?;
    if request.client_operation_id.is_empty()
        || request.client_operation_id.len() > 128
        || request.destination.as_ref().is_none_or(|d| d.id.is_empty())
    {
        return Err(Reject::Canonical);
    }
    if request.initial_base_state.len() > 4096 || proof.encoded_len() > MAX_BUNDLE_BYTES {
        return Err(Reject::Bounds);
    }
    if proof.format_version != 1
        || proof.delegations.len() != 1
        || !proof.operations.is_empty()
        || proof.terminal_manifest.is_some()
        || !proof.manifests.is_empty()
    {
        return Err(Reject::Canonical);
    }
    let d = proof.delegations[0]
        .body
        .as_ref()
        .ok_or(Reject::Canonical)?;
    let scope = d.scope.as_ref().ok_or(Reject::Canonical)?;
    validate_scope(scope)?;
    let id = d.identity.as_ref().ok_or(Reject::Canonical)?;
    identity(id)?;
    let uuid = hex::encode(&id.spool_uuid);
    let destination_id = format!(
        "{}-{}-{}-{}-{}",
        &uuid[..8],
        &uuid[8..12],
        &uuid[12..16],
        &uuid[16..20],
        &uuid[20..]
    );
    if request
        .destination
        .as_ref()
        .is_none_or(|s| s.id != destination_id)
    {
        return Err(Reject::Scope);
    }
    if source.clone_url != scope.source_url
        || resolved_provider != scope.provider
        || source.provider_repository_id.len() > 4096
        || source.name.len() > 4096
    {
        return Err(Reject::SourceSelection);
    }
    if source.connection != current_source.connection
        || (source.provider_repository_id != current_source.provider_repository_id
            && (source.connection.is_some() || !source.provider_repository_id.is_empty()))
        || source.clone_url != current_source.clone_url
        || source.installation_id != current_source.installation_id
        || source.private != current_source.private
    {
        return Err(Reject::SourceSelection);
    }
    let provider = resolve_import_provider(
        current_source,
        current_source
            .connection
            .as_ref()
            .map(|_| resolved_provider),
    )?;
    if provider != resolved_provider {
        return Err(Reject::SourceSelection);
    }
    validate_import_configuration(configuration)?;
    validate_provider_support(provider, configuration)?;
    validate_repository_hash_algorithm(current_source, true)?;
    if source.hash_algorithm != current_source.hash_algorithm {
        return Err(Reject::SourceSelection);
    }
    // A frozen pin names the selected commit, even if the branch head moves.
    // OBSERVE still cannot hide a currently known selected OID by clearing hints.
    for b in &scope.branches {
        if b.hash_algorithm != current_source.hash_algorithm {
            return Err(Reject::SourceSelection);
        }
        if b.ref_mode == 2
            && current_source
                .refs
                .iter()
                .any(|r| r.name == b.ref_name && !r.head_oid.is_empty())
        {
            return Err(Reject::RefPinning);
        }
    }
    // Current converter/options/budget support is also rechecked at activation.
    prepare_scope(scope, configuration, &scope.destination_version)?;
    if proof.original_geneses.len() != scope.branches.len()
        || proof.creator_authority_envelopes.len() != scope.branches.len()
        || proof.genesis_authorities.len() != scope.branches.len()
        || d.branch_manifest.len() != scope.branches.len()
    {
        return Err(Reject::GenesisBinding);
    }
    // Arrays are ordered exactly like the signed branch manifest, no second
    // association-by-name payload and no incoming regenerated branch originals.
    for (i, b) in scope.branches.iter().enumerate() {
        let original = &proof.original_geneses[i];
        let binding = &proof.genesis_authorities[i];
        let g = binding.body.as_ref().ok_or(Reject::GenesisBinding)?;
        let m = &d.branch_manifest[i];
        if native_id(original) != b.genesis_digest
            || g.genesis_digest != b.genesis_digest
            || m.limit.as_ref() != Some(b)
            || m.genesis_authority_digest != signed_genesis_digest(binding)?
            || g.creator_authority_envelope_digest != hash(&[&proof.creator_authority_envelopes[i]])
            || proof.creator_authority_envelopes[i].is_empty()
            || proof.creator_authority_envelopes[i].len() > MAX_RECORD_BYTES
            || !original.signatures.iter().any(|s| {
                s.public_key == g.creator_public_key && s.signature == g.original_creator_signature
            })
        {
            return Err(Reject::GenesisBinding);
        }
        verify_native(original, "heddle-thread-genesis-v1")?;
    }
    Ok(())
}

/// This closed route has no initial-submission or authority-attachment role.
pub fn validate_import_source(_: &ImportSourceRequest) -> Result<(), Reject> {
    Err(Reject::ImportSourceRequiresCommit)
}

/// Complete initial validation, excluding native model/owner history, live
/// source access and transaction checks owned by the hosted implementation.
pub fn verify_commit_submission(
    request: &CommitImportJobRequest,
    prepared: &PrepareImportJobResponse,
    resolved_provider: &str,
    current_source: &ProviderRepository,
    configuration: &GetImportConfigurationResponse,
    expected: &ImportOwnerExpectation<'_>,
) -> Result<VerifiedImportDelegation, Reject> {
    validate_commit_request(request, resolved_provider, current_source, configuration)?;
    let proof = request.proof.as_ref().ok_or(Reject::Canonical)?;
    let member = proof.member_permission.as_ref();
    verify_prepared_delegation(
        prepared,
        &proof.delegations[0],
        member,
        &proof.genesis_authorities,
        expected,
    )
}

pub fn validate_commit_response(
    request: &CommitImportJobRequest,
    response: &MutationResponse,
) -> Result<(), Reject> {
    let receipt = response.receipt.as_ref().ok_or(Reject::PendingOperation)?;
    let Some(mutation_receipt::Outcome::PendingOperation(operation)) = &receipt.outcome else {
        return Err(Reject::PendingOperation);
    };
    if request.client_operation_id.is_empty()
        || receipt.client_operation_id != request.client_operation_id
        || request.destination.is_none()
        || operation.spool != request.destination
        || operation.id
            != initial_operation_id(
                &request
                    .proof
                    .as_ref()
                    .ok_or(Reject::PendingOperation)?
                    .delegations
                    .first()
                    .and_then(|d| d.body.as_ref())
                    .ok_or(Reject::PendingOperation)?
                    .retry_lineage_id,
                false,
            )?
    {
        return Err(Reject::PendingOperation);
    }
    Ok(())
}

/// Use a durable caller-scoped idempotency row BEFORE rechecking expired job
/// authority. Host stores the original request/receipt atomically with activation.
/// Changed inputs refuse OperationIdReused only for an ID with an accepted receipt.
pub fn check_commit_replay(
    request: &CommitImportJobRequest,
    stored: &CommitImportJobRequest,
    response: &MutationResponse,
) -> Result<(), Reject> {
    if request != stored {
        return Err(Reject::OperationIdReused);
    }
    validate_commit_response(request, response)
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
    {
        return Err(Reject::Bounds);
    }
    if (value.max_operations as usize) < value.branches.len() {
        return Err(Reject::Scope);
    }
    for (i, b) in value.branches.iter().enumerate() {
        branch(b)?;
        if value.branches[..i].iter().any(|other| {
            other.target_thread_id == b.target_thread_id || other.genesis_digest == b.genesis_digest
        }) {
            return Err(Reject::Scope);
        }
        if i > 0 && value.branches[i - 1].ref_name.as_bytes() >= b.ref_name.as_bytes() {
            return Err(Reject::Canonical);
        }
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
        && child.branches.iter().all(|c| parent.branches.contains(c))
}

/// Public context from the existing owner/keyring verifier, not from fields in
/// the incoming bundle. now is receiver/host time for new work or independently
/// verified witness observation time for retained history, NEVER author time.
pub struct ImportOwnerExpectation<'a> {
    pub identity: &'a ImportIdentityV1,
    pub owner_public_key: &'a [u8],
    pub owner_chain_digest: &'a [u8],
    /// From the independently verified EFFECTIVE owner state at `now`, not
    /// the immutable root. Accepted claim/deferral clearing is unbounded.
    pub authority_expires_at_seconds: i64,
    pub now_unix_seconds: i64,
    pub forbidden_job_keys: &'a [Vec<u8>], // Every user/root/witness key, including tombstones.
    pub known_job_associations: &'a [(Vec<u8>, Vec<u8>)], // key -> logical job.
}
/// Independently verified owner facts for retained bundle verification. Historical
/// check times are selected internally from authenticated receipts, never callers.
#[derive(Clone, Copy)]
pub struct ImportBundleOwnerExpectation<'a> {
    pub identity: &'a ImportIdentityV1,
    pub owner_public_key: &'a [u8],
    pub owner_chain_digest: &'a [u8],
    pub authority_expires_at_seconds: i64,
    /// Effective interval of these independently authenticated owner facts.
    pub effective_from_unix_seconds: i64,
    pub effective_until_unix_seconds: Option<i64>,
    pub forbidden_job_keys: &'a [Vec<u8>],
    pub forbidden_landing_keys: &'a [Vec<u8>],
    pub known_job_associations: &'a [(Vec<u8>, Vec<u8>)],
}
impl<'a> ImportBundleOwnerExpectation<'a> {
    fn at(self, time: i64, associations: &'a [(Vec<u8>, Vec<u8>)]) -> ImportOwnerExpectation<'a> {
        ImportOwnerExpectation {
            identity: self.identity,
            owner_public_key: self.owner_public_key,
            owner_chain_digest: self.owner_chain_digest,
            authority_expires_at_seconds: self.authority_expires_at_seconds,
            now_unix_seconds: time,
            forbidden_job_keys: self.forbidden_job_keys,
            known_job_associations: associations,
        }
    }
}
/// Inputs MUST come from the selected, independently verified effective state.
/// Historical verification selects the state at its authenticated observation.
pub fn effective_owner_authority_expiry(
    deferred_human: bool,
    claimable_until: i64,
) -> Result<i64, Reject> {
    if deferred_human {
        if claimable_until <= 0 {
            return Err(Reject::Scope);
        }
        Ok(claimable_until)
    } else {
        Ok(i64::MAX)
    }
}
pub fn verify_member_permission(
    signed: &SignedImportMemberPermissionV1,
    expected: &ImportOwnerExpectation<'_>,
) -> Result<(), Reject> {
    verify_member_permission_inner(signed, expected, true)
}
fn verify_member_permission_inner(
    signed: &SignedImportMemberPermissionV1,
    expected: &ImportOwnerExpectation<'_>,
    current: bool,
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
    validity(
        p.not_before_unix_seconds,
        p.expires_at_unix_seconds,
        expected.now_unix_seconds,
        current,
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
    member: Option<SignedImportMemberPermissionV1>,
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
    verify_delegation_inner(signed, member, expected, true)
}
fn verify_delegation_inner(
    signed: &SignedImportJobDelegationV1,
    member: Option<&SignedImportMemberPermissionV1>,
    expected: &ImportOwnerExpectation<'_>,
    current: bool,
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
    if i128::from(d.expires_at_unix_seconds) - i128::from(d.not_before_unix_seconds)
        > i128::from(MAX_DELEGATION_WINDOW_SECONDS)
    {
        return Err(Reject::ValidityBounds);
    }
    validity(
        d.not_before_unix_seconds,
        d.expires_at_unix_seconds,
        expected.now_unix_seconds,
        current,
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
        verify_member_permission_inner(member, expected, current)?;
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
        member: member.cloned(),
    })
}
/// Frozen canonical projection. The browser completes only the fields absent
/// here; it cannot normalize or reduce even an otherwise authorized scope.
pub fn delegation_preparation(d: &ImportJobDelegationV1) -> ImportJobPreparationV1 {
    ImportJobPreparationV1 {
        format_version: d.format_version,
        identity: d.identity.clone(),
        delegation_id: d.delegation_id.clone(),
        logical_job_id: d.logical_job_id.clone(),
        retry_lineage_id: d.retry_lineage_id.clone(),
        job_public_key: d.job_public_key.clone(),
        job_key_id: d.job_key_id.clone(),
        owner_chain_digest: d.owner_chain_digest.clone(),
        purpose: d.purpose,
        scope: d.scope.clone(),
        cancellation_id: d.cancellation_id.clone(),
    }
}

/// Validate Commit against the HOST-STORED preparation and independently
/// selected current authority. Native genesis/envelope verification, online
/// revocation, custody uniqueness and transactional activation remain host gates.
pub fn verify_prepared_delegation(
    prepared: &PrepareImportJobResponse,
    signed: &SignedImportJobDelegationV1,
    member: Option<&SignedImportMemberPermissionV1>,
    geneses: &[SignedImportGenesisAuthorityV1],
    expected: &ImportOwnerExpectation<'_>,
) -> Result<VerifiedImportDelegation, Reject> {
    verify_prepared_inner(prepared, signed, member, geneses, expected, false)
}
/// Browser signing preflight only: no execution or admission token is returned.
pub fn preflight_prepared_delegation(
    prepared: &PrepareImportJobResponse,
    signed: &SignedImportJobDelegationV1,
    member: Option<&SignedImportMemberPermissionV1>,
    geneses: &[SignedImportGenesisAuthorityV1],
    expected: &ImportOwnerExpectation<'_>,
) -> Result<(), Reject> {
    verify_prepared_inner(prepared, signed, member, geneses, expected, true).map(|_| ())
}
fn verify_prepared_inner(
    prepared: &PrepareImportJobResponse,
    signed: &SignedImportJobDelegationV1,
    member: Option<&SignedImportMemberPermissionV1>,
    geneses: &[SignedImportGenesisAuthorityV1],
    expected: &ImportOwnerExpectation<'_>,
    browser: bool,
) -> Result<VerifiedImportDelegation, Reject> {
    let proposal = prepared.proposal.as_ref().ok_or(Reject::Canonical)?;
    let d = signed.body.as_ref().ok_or(Reject::Canonical)?;
    if canonical(proposal)? != canonical(&delegation_preparation(d))? {
        return Err(Reject::PreparedFields);
    }
    let scope = proposal.scope.as_ref().ok_or(Reject::Canonical)?;
    if d.branch_manifest.len() != scope.branches.len() {
        return Err(Reject::PreparedFields);
    }
    for (m, b) in d.branch_manifest.iter().zip(&scope.branches) {
        let limit = m.limit.as_ref().ok_or(Reject::PreparedFields)?;
        if canonical(limit)? != canonical(b)? {
            return Err(Reject::PreparedFields);
        }
    }
    // Use i128 for host arithmetic so extreme advertised uint64 bounds cannot
    // wrap. Skew permits a future not-before, never grace after expiry.
    let now = i128::from(expected.now_unix_seconds);
    let start = i128::from(d.not_before_unix_seconds);
    let end = i128::from(d.expires_at_unix_seconds);
    let at = i128::from(prepared.prepared_at_unix_seconds);
    let skew = i128::from(prepared.clock_skew_allowance_seconds);
    if at < 0
        || now < 0
        || if browser { now + skew < at } else { now < at }
        || i128::from(prepared.reservation_expires_at_unix_seconds) != at + 3600
        || now >= i128::from(prepared.reservation_expires_at_unix_seconds)
    {
        return Err(Reject::Expired);
    }
    if prepared.max_validity_duration_seconds == 0
        || prepared.max_validity_duration_seconds > MAX_DELEGATION_WINDOW_SECONDS
        || start < 0
        || start < at - skew
        || start > now + skew
        || end <= start
        || end <= now
        || end - start > i128::from(prepared.max_validity_duration_seconds)
    {
        return Err(Reject::ValidityBounds);
    }
    if let Some(parent) = member {
        if browser {
            let p = parent.body.as_ref().ok_or(Reject::ImportPermission)?;
            verify_member_permission_inner(parent, expected, false)?;
            if i128::from(p.not_before_unix_seconds) > now + skew
                || i128::from(p.expires_at_unix_seconds) <= now
            {
                return Err(Reject::Expired);
            }
        } else {
            verify_member_permission(parent, expected)?;
        }
    }
    // Future not-before within skew can be committed, but verify_new_operation
    // still refuses execution until that exact signed time. Parent/owner expiry
    // and containment are checked without extending them by skew.
    let at_start = ImportOwnerExpectation {
        now_unix_seconds: expected.now_unix_seconds.max(d.not_before_unix_seconds),
        ..*expected
    };
    let verified = verify_delegation_inner(
        signed,
        member,
        if browser { expected } else { &at_start },
        !browser,
    )?;
    if geneses.len() != d.branch_manifest.len() {
        return Err(Reject::GenesisBinding);
    }
    for m in &d.branch_manifest {
        let branch = m.limit.as_ref().ok_or(Reject::Canonical)?;
        let g = geneses
            .iter()
            .find(|g| signed_genesis_digest(g).is_ok_and(|h| h == m.genesis_authority_digest))
            .ok_or(Reject::GenesisBinding)?;
        let body = g.body.as_ref().ok_or(Reject::GenesisBinding)?;
        if body.genesis_digest != branch.genesis_digest {
            return Err(Reject::GenesisBinding);
        }
        {
            verify_genesis_authority(
                g,
                &verified,
                &branch.genesis_digest,
                &body.original_creator_signature,
                &body.creator_authority_envelope_digest,
            )?;
        }
    }
    Ok(verified)
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
        || o.result_bytes > scope.max_result_bytes
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
    committed_before: &ImportResultManifestV1,
) -> Result<(), Reject> {
    interval(
        delegation.body.not_before_unix_seconds,
        delegation.body.expires_at_unix_seconds,
        now_seconds,
    )?;
    check_import_publication_budget(signed, delegation, committed_before)
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
        if s.ref_name.len() > 1024 || s.result_bytes == 0 {
            return Err(Reject::Bounds);
        }
        if i > 0 && (&m.slots[i - 1].ref_name, m.slots[i - 1].slot_id) >= (&s.ref_name, s.slot_id) {
            return Err(Reject::Canonical);
        }
    }
    Ok(())
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
    let mut before = manifest.clone();
    let o = operation.body.as_ref().ok_or(Reject::Canonical)?;
    before
        .slots
        .retain(|slot| slot.ref_name != o.ref_name || slot.slot_id != o.slot_id);
    check_import_publication_budget(operation, delegation, &before)?;
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
    validate_bundle_bounds(bundle)?;
    validate_bundle_history(bundle, true)
}
fn validate_bundle_bounds(bundle: &ImportPublicProofBundleV1) -> Result<(), Reject> {
    crate::writer_authority::validate_owner_histories(&bundle.owner_histories)?;
    use prost::Message;
    if bundle.format_version != 1 {
        return Err(Reject::Version);
    }
    if bundle.encoded_len() > MAX_BUNDLE_BYTES
        || bundle.owner_histories.len() > 64
        || bundle.ownership_transfers.len() > 64
        || bundle.genesis_authorities.len() > MAX_BRANCHES
        || bundle.delegations.len() != 1
        || bundle.operations.len() > MAX_BRANCHES
        || bundle.statements.len() > 1024
        || bundle.history_proofs.len() > 1024
        || bundle.policies.len() > 256
        || bundle.original_geneses.len() > MAX_BRANCHES
        || bundle.creator_authority_envelopes.len() > MAX_BRANCHES
        || bundle.manifests.len() > MAX_BRANCHES
        || bundle.genesis_witnesses.len() > 256
        || bundle.authority_witnesses.len() > 256
        || bundle.landing_witnesses.len() > 256
    {
        return Err(Reject::Bounds);
    }
    Ok(())
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
    if content.canonical_capture.is_empty() {
        return Err(Reject::Bounds);
    }
    signing_digest("heddle-import-content-v1", content)
}
pub fn signed_native_digest(record: &SignedRecord) -> Result<Vec<u8>, Reject> {
    signing_digest("heddle-signed-native-record-v1", record)
}
pub(crate) fn verify_native(record: &SignedRecord, format: &str) -> Result<(), Reject> {
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
pub(crate) fn boundary_original(
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
pub(crate) fn match_boundary(
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
    reviews_only: bool,
) -> Result<(), Reject> {
    if records.len() > 128 {
        return Err(Reject::Bounds);
    }
    let mut previous = None;
    for record in records {
        if reviews_only {
            require_review_operation(record)?;
        }
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
#[derive(serde::Deserialize)]
struct ReviewOperation {
    body: ReviewBody,
}
#[derive(serde::Deserialize)]
struct ReviewBody {
    kind: String,
    canonical: Vec<u8>,
}
#[derive(serde::Deserialize)]
struct ReviewControl {
    control: ReviewKind,
}
#[derive(serde::Deserialize)]
struct ReviewKind {
    kind: String,
}
fn require_review_operation(record: &SignedRecord) -> Result<(), Reject> {
    if record.format != "heddle-thread-operation-v1" {
        return Err(Reject::Semantic);
    }
    let operation: ReviewOperation =
        rmp_serde::from_slice(&record.canonical_record).map_err(|_| Reject::Semantic)?;
    if operation.body.kind != "metadata" {
        return Err(Reject::Semantic);
    }
    let control: ReviewControl =
        rmp_serde::from_slice(&operation.body.canonical).map_err(|_| Reject::Semantic)?;
    if control.control.kind != "review" {
        return Err(Reject::Semantic);
    }
    Ok(())
}
pub(crate) fn original_signatures(
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
/// Portable request-role refusal. Receiver facts include known job and forbidden request keys.
pub fn verify_landing_key_roles(
    payload: &HostedLandingWitnessV1,
    known_job_keys: &[Vec<u8>],
    forbidden_keys: &[Vec<u8>],
) -> Result<(), Reject> {
    let key = &payload
        .request
        .as_ref()
        .and_then(|r| r.signature.as_ref())
        .ok_or(Reject::Signature)?
        .public_key;
    if known_job_keys.contains(key) || forbidden_keys.contains(key) {
        return Err(Reject::KeyRole);
    }
    Ok(())
}

/// Exact matching and original signatures do not replace native causal/authority/landing checks.
#[derive(Clone, Copy)]
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
            native_dependencies(&p.dependencies, &p.boundary_acceptances, false)?;
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
            native_dependencies(&p.review_evidence, &[], true)?;
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
        .member_permission
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
fn validate_bundle_history(
    bundle: &ImportPublicProofBundleV1,
    require_admissions: bool,
) -> Result<(), Reject> {
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
    let mut foreign = crate::foreign_dependencies::References::new(
        &bundle.foreign_dependencies,
        ForeignDependencyOrigin::Import,
    )?;
    for p in &bundle.authority_witnesses {
        let subject_thread =
            crate::foreign_dependencies::thread(p.original.as_ref().ok_or(Reject::Canonical)?)?;
        if !bundle.genesis_witnesses.iter().any(|g| {
            g.original_genesis
                .as_ref()
                .is_some_and(|g| native_id(g) == subject_thread)
        }) {
            return Err(Reject::Scope);
        }
    }
    let job_keys = bundle
        .delegations
        .iter()
        .filter_map(|d| d.body.as_ref().map(|d| d.job_public_key.clone()))
        .collect::<Vec<_>>();
    for p in &bundle.landing_witnesses {
        verify_landing_key_roles(p, &job_keys, &[])?;
        let execution = p.execution.as_ref().ok_or(Reject::Canonical)?;
        let thread = crate::foreign_dependencies::thread(execution)?;
        if !bundle.genesis_witnesses.iter().any(|p| {
            p.original_genesis
                .as_ref()
                .is_some_and(|g| native_id(g) == thread)
        }) {
            return Err(Reject::Scope);
        }
    }
    // In-carrier genesis witnesses establish origin membership, never permission.
    for original in bundle
        .authority_witnesses
        .iter()
        .flat_map(|p| p.original.iter().chain(p.dependencies.iter()))
        .chain(bundle.landing_witnesses.iter().flat_map(|p| {
            p.execution
                .iter()
                .chain(p.source_operation.iter())
                .chain(p.review_evidence.iter())
        }))
    {
        if [
            "heddle-original-boundary-acceptance-v1",
            "heddle-thread-genesis-admission-v2",
            "heddle-thread-authority-admission-v3",
        ]
        .contains(&original.format.as_str())
        {
            continue;
        }
        let thread = crate::foreign_dependencies::thread(original)?;
        if !bundle.genesis_witnesses.iter().any(|p| {
            p.original_genesis
                .as_ref()
                .is_some_and(|g| native_id(g) == thread)
        }) {
            foreign.require(original)?;
        } else if original.format == "heddle-thread-genesis-v1"
            && !bundle
                .genesis_witnesses
                .iter()
                .any(|p| p.original_genesis.as_ref() == Some(original))
        {
            return Err(Reject::Scope);
        }
    }
    foreign.finish()?;
    for operation in &bundle.operations {
        if operation.body.is_none() {
            return Err(Reject::Canonical);
        }
    }
    for statement in &bundle.statements {
        let s = statement.body.as_ref().ok_or(Reject::Canonical)?;
        validate_statement_boundary(s)?;
        require_policy_history(
            &bundle.policies,
            &s.spool_uuid,
            s.policy_sequence,
            &s.policy_state_hash,
        )?;
        let envelope = match s.purpose {
            2 => Some(
                bundle
                    .authority_witnesses
                    .iter()
                    .find(|p| canonical(*p).is_ok_and(|bytes| bytes == s.canonical_payload))
                    .ok_or(Reject::Scope)?
                    .authority_envelope
                    .as_slice(),
            ),
            4 => Some(
                bundle
                    .landing_witnesses
                    .iter()
                    .find(|p| canonical(*p).is_ok_and(|bytes| bytes == s.canonical_payload))
                    .ok_or(Reject::Scope)?
                    .authority_envelope
                    .as_slice(),
            ),
            _ => None,
        };
        if let Some(envelope) = envelope {
            crate::writer_authority::check_witness_writer(
                s,
                envelope,
                &bundle.owner_histories,
                &bundle.policies,
                crate::writer_authority::spool_account_for_statement(
                    s,
                    bundle
                        .delegations
                        .iter()
                        .filter_map(|d| d.body.as_ref()?.identity.as_ref())
                        .chain(
                            bundle
                                .genesis_authorities
                                .iter()
                                .filter_map(|g| g.body.as_ref()?.identity.as_ref()),
                        ),
                    &bundle.ownership_transfers,
                )?,
                bundle
                    .authority_witnesses
                    .iter()
                    .find(|p| {
                        (p.kind == 2 || p.kind == 3)
                            && canonical(*p).is_ok_and(|v| v == s.canonical_payload)
                    })
                    .and_then(|p| p.original.as_ref())
                    .map(|r| r.signatures.as_slice())
                    .unwrap_or(&[]),
            )?;
        }
    }
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
    if bundle.delegations.len() != 1 {
        return Err(Reject::Canonical);
    }
    for d in &bundle.delegations {
        let body = d.body.as_ref().ok_or(Reject::Canonical)?;
        resolve_bundle_permission(bundle, &body.parent_permission_digest)?;
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
            // Every published branch needs its original admission, not merely its
            // binding. Proof-only retirement lookup cannot recover a payload.
            if require_admissions
                && bundle.operations.iter().any(|o| {
                    o.body
                        .as_ref()
                        .is_some_and(|o| o.genesis_digest == b.genesis_digest)
                })
                && !bundle.genesis_witnesses.iter().any(|payload| {
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
                })
            {
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
/// Authenticate policy contents against their committed hashes and enforce the
/// governance contract's grow-only revocations. Native verification still
/// authenticates owner signatures/context and the receipt observation time.
pub(crate) fn require_policy_history(
    policies: &[SignedSpoolPolicyRecord],
    spool: &[u8],
    mut sequence: u64,
    state_hash: &[u8],
) -> Result<(), Reject> {
    let mut previous: Option<(&[u8], u64)> = None;
    for signed in policies {
        let p = signed.body.as_ref().ok_or(Reject::Canonical)?;
        let current = (p.spool_uuid.as_slice(), p.sequence);
        if previous.is_some_and(|prev| prev >= current) {
            return Err(Reject::Canonical);
        }
        previous = Some(current);
    }
    let mut state_hash = state_hash.to_vec();
    let mut successor_revoked: Option<&[Vec<u8>]> = None;
    for _ in 0..=policies.len() {
        width(&state_hash, 32)?;
        if sequence == 0 {
            return if state_hash == [0; 32] {
                Ok(())
            } else {
                Err(Reject::Scope)
            };
        }
        let mut matches = policies.iter().filter_map(|p| p.body.as_ref()).filter(|p| {
            p.spool_uuid == spool && p.sequence == sequence && p.policy_state_hash == state_hash
        });
        let policy = matches.next().ok_or(Reject::Scope)?;
        let digest = policy_state_digest(policy)?;
        if digest != policy.policy_state_hash {
            return Err(Reject::Canonical);
        }
        // policy_state_digest above already requires an authenticated body.
        let revoked = policy
            .policy
            .as_ref()
            .map(|p| p.revoked_key_ids.as_slice())
            .unwrap_or(&[]);
        if successor_revoked.is_some_and(|next| revoked.iter().any(|id| !next.contains(id))) {
            return Err(Reject::Scope);
        }
        successor_revoked = Some(revoked);
        let head = policy.expected_head.as_ref().ok_or(Reject::Canonical)?;
        if head.sequence.checked_add(1) != Some(sequence) {
            return Err(Reject::Scope);
        }
        sequence = head.sequence;
        state_hash = head.state_hash.clone();
    }
    Err(Reject::Scope)
}
/// Canonical SignedPolicyBody fields 1–10; protobuf is never the signed encoding.
pub fn policy_state_digest(p: &SignedPolicyBody) -> Result<Vec<u8>, Reject> {
    use crate::hybrid_codec::counted;
    if p.format_version != 1 || !p.merge_parent_state_hashes.is_empty() {
        return Err(Reject::Version);
    }
    width(&p.spool_uuid, 16)?;
    width(&p.owner_id, 32)?;
    width(&p.owner_state_hash, 32)?;
    let head = p.expected_head.as_ref().ok_or(Reject::Canonical)?;
    width(&head.state_hash, 32)?;
    let policy = p.policy.as_ref().ok_or(Reject::Canonical)?;
    if p.merge_policies.len() != 2
        || p.merge_policies[0].setting_key != "max_audience"
        || p.merge_policies[0].semantics != 1
        || p.merge_policies[1].setting_key != "revoked_key_ids"
        || p.merge_policies[1].semantics != 2
    {
        return Err(Reject::Canonical);
    }
    let mut out = p.format_version.to_be_bytes().to_vec();
    counted(&mut out, &p.spool_uuid)?;
    counted(&mut out, &head.state_hash)?;
    out.extend_from_slice(&head.sequence.to_be_bytes());
    out.extend_from_slice(&p.sequence.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(policy.revoked_key_ids.len() as u32).to_be_bytes());
    for (i, id) in policy.revoked_key_ids.iter().enumerate() {
        width(id, 32)?;
        if i > 0 && policy.revoked_key_ids[i - 1] >= *id {
            return Err(Reject::Canonical);
        }
        counted(&mut out, id)?;
    }
    out.push(u8::from(policy.max_audience.is_some()));
    if let Some(audience) = policy.max_audience {
        if !(1..=3).contains(&audience) {
            return Err(Reject::Canonical);
        }
        out.extend_from_slice(&(audience as u32).to_be_bytes());
    }
    out.extend_from_slice(&2u32.to_be_bytes());
    for rule in &p.merge_policies {
        counted(&mut out, rule.setting_key.as_bytes())?;
        out.extend_from_slice(&(rule.semantics as u32).to_be_bytes());
    }
    counted(&mut out, &p.owner_id)?;
    counted(&mut out, &p.owner_state_hash)?;
    out.extend_from_slice(&p.ownership_transfer_sequence.to_be_bytes());
    Ok(hash(&[b"heddle-spool-signed-policy-v2", &out]))
}
pub(crate) fn native_id(record: &SignedRecord) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(record.format.as_bytes());
    h.update(&(record.canonical_record.len() as u64).to_le_bytes());
    h.update(b"\0");
    h.update(&record.canonical_record);
    h.finalize().as_bytes().to_vec()
}

/// Caller-generated non-nil UUID, reserved as the first physical operation ID.
/// Occupancy is checked under the host's reservation/activation transaction.
pub fn initial_operation_id(lineage: &[u8], occupied: bool) -> Result<String, Reject> {
    width(lineage, 16)?;
    if lineage.iter().all(|b| *b == 0) {
        return Err(Reject::Canonical);
    }
    if occupied {
        return Err(Reject::OperationIdReused);
    }
    let h = hex::encode(lineage);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

/// Evaluate inside the cancellation transaction, after caller-scoped replay lookup.
/// The selector names only the ACTIVE delegation. Parent revocation is independent.
pub fn check_cancel_request(
    request: &CancelImportJobRequest,
    active: &SignedImportJobDelegationV1,
    durable_epoch: u64,
    cancelled: bool,
) -> Result<(), Reject> {
    let d = active.body.as_ref().ok_or(Reject::Canonical)?;
    width(&request.logical_job_id, 16)?;
    width(&request.cancellation_id, 32)?;
    let id = d.identity.as_ref().ok_or(Reject::Canonical)?;
    if request.client_operation_id.is_empty()
        || request.destination.as_ref().is_none_or(|s| {
            initial_operation_id(&id.spool_uuid, false).map_or(true, |uuid| s.id != uuid)
        })
        || request.logical_job_id != d.logical_job_id
    {
        return Err(Reject::Scope);
    }
    if durable_epoch == 0 || request.expected_authority_epoch != durable_epoch {
        return Err(Reject::StaleContext);
    }
    if request.cancellation_id != d.cancellation_id {
        return Err(Reject::Scope);
    }
    if cancelled {
        return Err(Reject::Revoked);
    }
    Ok(())
}
/// Exact replay acknowledges the stored cancellation without advancing the epoch.
pub fn check_cancel_replay(
    request: &CancelImportJobRequest,
    stored: &CancelImportJobRequest,
) -> Result<(), Reject> {
    if request != stored {
        return Err(Reject::OperationIdReused);
    }
    Ok(())
}
/// Check both independent revocation selectors, regardless of Cancel's selector.
pub fn check_import_revocations(
    delegation: &SignedImportJobDelegationV1,
    member: Option<&SignedImportMemberPermissionV1>,
    revoked: &[Vec<u8>],
) -> Result<(), Reject> {
    let d = delegation.body.as_ref().ok_or(Reject::Canonical)?;
    width(&d.cancellation_id, 32)?;
    if revoked.contains(&d.cancellation_id) {
        return Err(Reject::Revoked);
    }
    if let Some(parent) = member {
        let p = parent.body.as_ref().ok_or(Reject::ImportPermission)?;
        width(&p.cancellation_id, 32)?;
        if revoked.contains(&p.cancellation_id) {
            return Err(Reject::Revoked);
        }
    }
    Ok(())
}

/// Compute the exact remaining total and slots from an authenticated manifest.
/// An empty result is completed work and cannot pass new-scope validation.
pub fn remaining_import_scope(
    scope: &ImportPermissionScopeV1,
    committed: &ImportResultManifestV1,
) -> Result<ImportPermissionScopeV1, Reject> {
    validate_scope(scope)?;
    validate_manifest(committed)?;
    let mut remaining = scope.clone();
    for slot in &committed.slots {
        if !scope
            .branches
            .iter()
            .any(|b| b.ref_name == slot.ref_name && b.slot_id == slot.slot_id)
        {
            return Err(Reject::Scope);
        }
        {
            remaining.max_result_bytes = remaining
                .max_result_bytes
                .checked_sub(slot.result_bytes)
                .ok_or(Reject::Scope)?;
            remaining.max_operations = remaining
                .max_operations
                .checked_sub(1)
                .ok_or(Reject::Scope)?;
        }
    }
    remaining.branches.retain(|b| {
        !committed
            .slots
            .iter()
            .any(|s| s.ref_name == b.ref_name && s.slot_id == b.slot_id)
    });
    Ok(remaining)
}

/// Validate discovery metadata only; a well-shaped selector grants no authority.
pub fn validate_hybrid_import_job_selector(
    selector: &HybridImportJobSelector,
) -> Result<(), Reject> {
    width(&selector.logical_job_id, 16)?;
    if selector.logical_job_id.iter().all(|byte| *byte == 0) {
        return Err(Reject::Canonical);
    }
    Ok(())
}

/// Project a visible operation's durable HYBRID association into the existing
/// writer-only state read. Missing/unknown subject or selector is unavailable.
/// Malformed present metadata is rejected; never substitute an attempt ID.
/// This validates shape, not operation visibility, writer access or signatures.
pub fn import_job_state_request_from_operation(
    operation: &OperationRecord,
) -> Result<Option<GetImportJobStateRequest>, Reject> {
    let Some(operation_subject::Subject::Import(subject)) = operation
        .subject
        .as_ref()
        .and_then(|subject| subject.subject.as_ref())
    else {
        return Ok(None);
    };
    let Some(selector) = subject.hybrid_job.as_ref() else {
        return Ok(None);
    };
    validate_hybrid_import_job_selector(selector)?;
    let request = GetImportJobStateRequest {
        destination: operation
            .r#ref
            .as_ref()
            .and_then(|record| record.spool.clone()),
        logical_job_id: selector.logical_job_id.clone(),
    };
    validate_job_state_request(&request)?;
    Ok(Some(request))
}

/// Finite destination-writer read; transport authentication/authorization belongs
/// to the generated RPC contract. Validate before any storage lookup.
pub fn validate_job_state_request(request: &GetImportJobStateRequest) -> Result<(), Reject> {
    use prost::Message;
    if request.encoded_len() > 4096 {
        return Err(Reject::Bounds);
    }
    initial_operation_id(&request.logical_job_id, false)?;
    let destination = request.destination.as_ref().ok_or(Reject::Scope)?;
    let compact = destination.id.replace('-', "");
    let raw = hex::decode(&compact).map_err(|_| Reject::Scope)?;
    if initial_operation_id(&raw, false).map_or(true, |id| id != destination.id) {
        return Err(Reject::Scope);
    }
    Ok(())
}

/// Supply the authenticated read, never an incoming untrusted state assertion.
pub fn validate_job_state_response(
    request: &GetImportJobStateRequest,
    response: &GetImportJobStateResponse,
) -> Result<(), Reject> {
    use prost::Message;
    validate_job_state_request(request)?;
    if response.encoded_len() > 4096 {
        return Err(Reject::Bounds);
    }
    if !(1..=5).contains(&response.status) || response.authority_epoch == 0 {
        return Err(Reject::Canonical);
    }
    width(&response.active_cancellation_id, 32)?;
    width(&response.active_delegation_digest, 32)?;
    validate_retry_availability(response, request.destination.as_ref().ok_or(Reject::Scope)?)
}

/// Independently installed descriptor pin; never learned from a response.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportWitnessRootPin {
    pub authority: String,
    pub root_id: String,
    pub public_key: Vec<u8>,
    pub epoch: u64,
}
/// Receiver-owned durable data, committed atomically with accepted history.
/// Do not deserialize this from the incoming proof or lower its clock floor.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportWitnessSnapshot {
    pub root: ImportWitnessRootPin,
    pub witness_set: crate::heddle::api::common::SignedHostedWitnessSetV1,
    pub clock_floor_unix_millis: i64,
    pub job_associations: Vec<(Vec<u8>, Vec<u8>)>,
    pub accepted_history: Vec<ImportPublicProofBundleV1>,
}
/// Witnessed requires an authenticated observation for every accepted delegation.
/// Recovery can retain witnessed history but grants no admission for the active tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportBundleEvidence {
    Recovery,
    Witnessed,
}
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedImportBundleWitnesses {
    pub evidence: ImportBundleEvidence,
    pub accepted_history: ImportResultManifestV1,
    pub snapshot: Option<ImportWitnessSnapshot>,
    pub snapshot_advanced: bool,
    pub owner_check_time_unix_seconds: Option<i64>,
}
/// Check the host's signed same-transaction assertion for a P1 and its consumed P3.
/// Receivers verify consistency; only the issuing host can ensure atomic visibility.
pub fn check_import_genesis_publication_pair(
    delegation: &VerifiedImportDelegation,
    admission: &crate::heddle::api::common::HostedWitnessStatementV1,
    publication: &crate::heddle::api::common::HostedWitnessStatementV1,
) -> Result<(), Reject> {
    validity(
        delegation.body.not_before_unix_seconds,
        delegation.body.expires_at_unix_seconds,
        admission.observed_at_unix_millis / 1000,
        true,
    )?;
    if admission.purpose != 1
        || publication.purpose != 3
        || admission.observed_at_unix_millis != publication.observed_at_unix_millis
        || admission.host_transaction_id != publication.host_transaction_id
        || admission.executor_id != publication.executor_id
        || admission.admission_order >= publication.admission_order
    {
        return Err(Reject::Transition);
    }
    Ok(())
}

/// Verify public Fetch/export evidence. Owner contexts
/// are resolved independently at each authenticated time. The verifier derives times
/// from the first authenticated publication of the sole delegation.
/// Unwitnessed certificates are time-free recovery only.
/// The mandatory hook verifies the selected policy chain and owner/native context
/// at each authenticated statement time (heddle capability-verifier / WASM).
/// With no statements it receives None and verifies time-free policy closure.
/// No result is returned on failure. Recovery without a witnessed prefix or new
/// authenticated set returns the input snapshot unchanged. A witnessed prefix
/// extends rollback protection; recovery cannot persist job history. A new set
/// can additionally advance set trust and clock. None remains None when no
/// set is carried and no input exists. Persist under the trust lock; inspect
/// snapshot_advanced for actual durable change, independently of evidence.
pub fn verify_import_bundle_witnesses<'a>(
    bundle: &ImportPublicProofBundleV1,
    pin: &ImportWitnessRootPin,
    snapshot: Option<&ImportWitnessSnapshot>,
    now_ms: i64,
    mut owner_at: impl FnMut(Option<i64>) -> Result<ImportBundleOwnerExpectation<'a>, Reject>,
    mut verify_policy: impl FnMut(
        &ImportPublicProofBundleV1,
        Option<&crate::heddle::api::common::HostedWitnessStatementV1>,
    ) -> Result<(), Reject>,
) -> Result<VerifiedImportBundleWitnesses, Reject> {
    use crate::witness_trust as trust;
    width(&pin.public_key, 32)?;
    if pin.epoch == 0 {
        return Err(Reject::StaleContext);
    }
    validate_bundle_bounds(bundle)?;
    let terminal = bundle.terminal_manifest.as_ref().ok_or(Reject::Canonical)?;
    validate_bundle_history(bundle, !terminal.slots.is_empty())?;
    let mut associations = snapshot.map_or_else(Vec::new, |s| s.job_associations.clone());
    for d in &bundle.delegations {
        let b = d.body.as_ref().ok_or(Reject::Canonical)?;
        if associations
            .iter()
            .any(|(key, job)| *key == b.job_public_key && *job != b.logical_job_id)
        {
            return Err(Reject::KeyRole);
        }
        if !associations.iter().any(|(key, _)| *key == b.job_public_key) {
            associations.push((b.job_public_key.clone(), b.logical_job_id.clone()));
        }
    }
    let job_keys = associations
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    fn expectation<'a>(
        root: &'a ImportWitnessRootPin,
        floor: i64,
        now: i64,
        keys: &'a [Vec<u8>],
    ) -> trust::SetExpectation<'a> {
        trust::SetExpectation {
            authority: &root.authority,
            root_id: &root.root_id,
            root_public_key: &root.public_key,
            root_epoch: root.epoch,
            now_unix_millis: now,
            clock_floor_unix_millis: floor,
            known_job_keys: keys,
        }
    }
    let previous = if let Some(s) = snapshot {
        if s.root.authority != pin.authority {
            return Err(Reject::Root);
        }
        let restored = trust::restore_history_snapshot(
            &s.witness_set,
            &expectation(&s.root, 0, now_ms, &job_keys),
        )?;
        Some(restored)
    } else {
        None
    };
    let carried = bundle.witness_set.as_ref();
    if carried.is_none() && !bundle.statements.is_empty() {
        return Err(Reject::Canonical);
    }
    let new_set =
        carried.is_some_and(|c| snapshot.is_none_or(|s| s.root != *pin || s.witness_set != *c));
    let selected = expectation(
        pin,
        snapshot.map_or(0, |s| s.clock_floor_unix_millis),
        now_ms,
        &job_keys,
    );
    let set = carried
        .map(|carried| {
            if snapshot.is_some_and(|s| s.root != *pin) {
                trust::verify_set_after_root_replacement(
                    carried,
                    &selected,
                    previous.as_ref().ok_or(Reject::StaleContext)?,
                )
            } else {
                trust::verify_set(carried, &selected, previous.as_ref())
            }
        })
        .transpose()?;
    // Authenticate statements before using their observation times or policies.
    let mut resolved = Vec::new();
    for signed in &bundle.statements {
        let s = signed.body.as_ref().ok_or(Reject::Canonical)?;
        let set = set.as_ref().ok_or(Reject::Canonical)?;
        let entry = set
            .body()
            .entries
            .iter()
            .find(|e| e.executor_id == s.executor_id)
            .ok_or(Reject::Root)?;
        let proof = if entry.state == 2 {
            let leaf = trust::leaf_digest(s.purpose, &canonical(s)?, &signed.signature)?;
            bundle.history_proofs.iter().find(|p| {
                p.purpose == s.purpose && trust::verify_inclusion(&leaf, p, entry).is_ok()
            })
        } else {
            None
        };
        let context = trust::resolve_statement(set, signed, proof, false, now_ms)?;
        verify_policy(bundle, Some(s))?;
        resolved.push((context, proof));
    }
    if bundle.statements.is_empty() {
        // Time-free policy/owner/native closure; this asserts no admission event.
        verify_policy(bundle, None)?;
    }
    // Derive owner-selection times only from authenticated receipts. Prefer the
    // first publication for each delegation; initial admissions stand alone too.
    // Select precisely the P3 each progressive prefix consumes, independent of
    // statement array order. Every carried P3 must be consumed exactly once.
    let mut prefix = ImportResultManifestV1 {
        slots: vec![],
        ..terminal.clone()
    };
    let mut selected_publications = Vec::new();
    for operation in &bundle.operations {
        let digest = signed_operation_digest(operation)?;
        let slot = terminal
            .slots
            .iter()
            .find(|slot| slot.signed_operation_digest == digest)
            .ok_or(Reject::Scope)?;
        prefix.slots.push(slot.clone());
        prefix
            .slots
            .sort_by(|a, b| (&a.ref_name, a.slot_id).cmp(&(&b.ref_name, b.slot_id)));
        let payload = canonical(&publication_payload(operation, &prefix)?)?;
        let matches = bundle
            .statements
            .iter()
            .filter(|signed| {
                signed
                    .body
                    .as_ref()
                    .is_some_and(|s| s.purpose == 3 && s.canonical_payload == payload)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(Reject::Transition);
        }
        selected_publications.push(matches[0]);
    }
    if bundle.statements.iter().any(|signed| {
        signed
            .body
            .as_ref()
            .is_some_and(|s| s.purpose == 3 && !selected_publications.contains(&signed))
    }) {
        return Err(Reject::Transition);
    }
    let mut admitted_geneses = std::collections::BTreeSet::<Vec<u8>>::new();
    let mut times = vec![None; bundle.delegations.len()];
    let mut publications = Vec::new();
    for signed in &bundle.statements {
        let statement = signed.body.as_ref().ok_or(Reject::Canonical)?;
        if statement.purpose != 3 {
            continue;
        }
        let (operation, manifest) = bundle
            .operations
            .iter()
            .flat_map(|o| bundle.manifests.iter().map(move |m| (o, m)))
            .find(|(o, m)| {
                publication_payload(o, m)
                    .and_then(|p| canonical(&p))
                    .is_ok_and(|b| b == statement.canonical_payload)
            })
            .ok_or(Reject::Scope)?;
        let digest = &operation
            .body
            .as_ref()
            .ok_or(Reject::Canonical)?
            .delegation_digest;
        let index = bundle
            .delegations
            .iter()
            .position(|d| signed_delegation_digest(d).is_ok_and(|h| h == *digest))
            .ok_or(Reject::Scope)?;
        let time = statement.observed_at_unix_millis / 1000;
        // First means accepted publication order, independent of array order.
        if times[index].is_none_or(|(order, _)| statement.admission_order < order) {
            times[index] = Some((statement.admission_order, time));
        }
        publications.push((signed, operation, manifest, index));
    }
    // Resolve only after authentication. Facts must cover the selected time;
    // current claimed state cannot stand in for an earlier deferred state.
    let mut resolve_owner = |time: Option<i64>| {
        let facts = owner_at(time)?;
        if facts.effective_from_unix_seconds < 0
            || facts
                .effective_until_unix_seconds
                .is_some_and(|end| end <= facts.effective_from_unix_seconds)
            || time.is_some_and(|t| {
                t < facts.effective_from_unix_seconds
                    || facts
                        .effective_until_unix_seconds
                        .is_some_and(|end| t >= end)
            })
        {
            return Err(Reject::Scope);
        }
        for (key, job) in facts.known_job_associations {
            if associations.iter().any(|(k, j)| k == key && j != job) {
                return Err(Reject::KeyRole);
            }
            if !associations.iter().any(|(k, _)| k == key) {
                associations.push((key.clone(), job.clone()));
            }
        }
        if facts
            .forbidden_job_keys
            .iter()
            .any(|key| associations.iter().any(|(known, _)| known == key))
        {
            return Err(Reject::KeyRole);
        }
        // Also keep newly supplied known job keys disjoint from witness roles.
        if set.as_ref().is_some_and(|set| {
            facts.known_job_associations.iter().any(|(key, _)| {
                *key == pin.public_key || set.body().entries.iter().any(|e| e.public_key == *key)
            })
        }) {
            return Err(Reject::KeyRole);
        }
        Ok((facts, associations.clone()))
    };
    let mut verified = Vec::new();
    for (i, d) in bundle.delegations.iter().enumerate() {
        let body = d.body.as_ref().ok_or(Reject::Canonical)?;
        let parent = resolve_bundle_permission(bundle, &body.parent_permission_digest)?;
        let time = times[i].map(|(_, time)| time);
        let (facts, selected_associations) = resolve_owner(time)?;
        let owner = facts.at(time.unwrap_or(0), &selected_associations);
        let token = verify_delegation_inner(d, parent, &owner, times[i].is_some())?;
        verified.push(token);
    }
    let initial = verified.first().ok_or(Reject::Canonical)?;
    for branch in &initial.body.branch_manifest {
        let limit = branch.limit.as_ref().ok_or(Reject::Canonical)?;
        let binding = bundle
            .genesis_authorities
            .iter()
            .find(|g| signed_genesis_digest(g).is_ok_and(|h| h == branch.genesis_authority_digest))
            .ok_or(Reject::Scope)?;
        let original = bundle
            .original_geneses
            .iter()
            .find(|o| native_id(o) == limit.genesis_digest)
            .ok_or(Reject::Scope)?;
        let g = binding.body.as_ref().ok_or(Reject::Canonical)?;
        let envelope = bundle
            .creator_authority_envelopes
            .iter()
            .find(|e| hash(&[e]) == g.creator_authority_envelope_digest)
            .ok_or(Reject::Scope)?;
        verify_native(original, "heddle-thread-genesis-v1")?;
        let signature = original
            .signatures
            .iter()
            .find(|s| s.public_key == g.creator_public_key)
            .ok_or(Reject::Scope)?;
        verify_genesis_authority(
            binding,
            initial,
            &limit.genesis_digest,
            &signature.signature,
            &hash(&[envelope]),
        )?;
    }
    for ((context, proof), signed) in resolved.iter().zip(&bundle.statements) {
        let s = signed.body.as_ref().ok_or(Reject::Canonical)?;
        if !verified.iter().any(|d| {
            d.body.identity.as_ref().is_some_and(|id| {
                s.spool_uuid == id.spool_uuid
                    && s.spool_genesis_digest == id.spool_genesis_digest
                    && s.owner_id == id.owner_id
                    && s.owner_state_hash == id.owner_state_hash
                    && s.ownership_transfer_sequence == id.ownership_transfer_sequence
            })
        }) {
            return Err(Reject::Scope);
        }
        match s.purpose {
            1 => {
                // Every original admission must independently satisfy [N,E).
                let time = s.observed_at_unix_millis / 1000;
                let (facts, selected_associations) = resolve_owner(Some(time))?;
                let owner = facts.at(time, &selected_associations);
                verify_delegation(
                    &bundle.delegations[0],
                    resolve_bundle_permission(bundle, &initial.body.parent_permission_digest)?,
                    &owner,
                )?;
                let payload = bundle
                    .genesis_witnesses
                    .iter()
                    .find(|p| canonical(*p).is_ok_and(|b| b == s.canonical_payload))
                    .ok_or(Reject::Scope)?;
                let genesis = &payload
                    .binding
                    .as_ref()
                    .and_then(|g| g.body.as_ref())
                    .ok_or(Reject::Canonical)?
                    .genesis_digest;
                if !admitted_geneses.insert(genesis.clone()) {
                    return Err(Reject::Transition);
                }
                let publication = bundle
                    .operations
                    .iter()
                    .zip(&selected_publications)
                    .find(|(o, _)| {
                        o.body
                            .as_ref()
                            .is_some_and(|o| &o.genesis_digest == genesis)
                    })
                    .and_then(|(_, s)| s.body.as_ref())
                    .ok_or(Reject::Transition)?;
                check_import_genesis_publication_pair(initial, s, publication)?;
                verify_witness_payload(
                    s,
                    WitnessPayload::Genesis(
                        bundle
                            .genesis_witnesses
                            .iter()
                            .find(|p| canonical(*p).is_ok_and(|b| b == s.canonical_payload))
                            .ok_or(Reject::Scope)?,
                    ),
                )?;
            }
            2 => verify_witness_payload(
                s,
                WitnessPayload::Authority(
                    bundle
                        .authority_witnesses
                        .iter()
                        .find(|p| canonical(*p).is_ok_and(|b| b == s.canonical_payload))
                        .ok_or(Reject::Scope)?,
                ),
            )?,
            4 => {
                let payload = bundle
                    .landing_witnesses
                    .iter()
                    .find(|p| canonical(*p).is_ok_and(|b| b == s.canonical_payload))
                    .ok_or(Reject::Scope)?;
                let (facts, selected_associations) =
                    resolve_owner(Some(s.observed_at_unix_millis / 1000))?;
                let known = selected_associations
                    .iter()
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                verify_landing_key_roles(payload, &known, facts.forbidden_landing_keys)?;
                verify_witness_payload(s, WitnessPayload::Landing(payload))?;
            }
            3 => {
                let (_, operation, manifest, index) = publications
                    .iter()
                    .find(|(statement, _, _, _)| *statement == signed)
                    .ok_or(Reject::Scope)?;
                let d = &bundle.delegations[*index];
                let body = d.body.as_ref().ok_or(Reject::Canonical)?;
                let time = s.observed_at_unix_millis / 1000;
                let (facts, selected_associations) = resolve_owner(Some(time))?;
                let owner = facts.at(time, &selected_associations);
                let delegation = verify_delegation(
                    d,
                    resolve_bundle_permission(bundle, &body.parent_permission_digest)?,
                    &owner,
                )?;
                verify_publication(
                    operation,
                    &delegation,
                    manifest,
                    signed,
                    set.as_ref().ok_or(Reject::Canonical)?,
                    *proof,
                    now_ms,
                )?;
            }
            _ => return Err(Reject::Version),
        }
        trust::recheck_context(
            context,
            set.as_ref().ok_or(Reject::Canonical)?,
            signed,
            now_ms,
        )?;
    }
    // Operations are accepted publication order, while manifest slots are sorted.
    let mut progressive = ImportResultManifestV1 {
        slots: vec![],
        ..terminal.clone()
    };
    let mut order = 0;
    let mut observed = 0;
    let mut consumed = std::collections::BTreeMap::<(Vec<u8>, Vec<u8>), (u32, u64)>::new();
    let mut total_bytes = 0_u64;
    for o in &bundle.operations {
        let digest = signed_operation_digest(o)?;
        let slot = terminal
            .slots
            .iter()
            .find(|s| s.signed_operation_digest == digest)
            .ok_or(Reject::Scope)?;
        progressive.slots.push(slot.clone());
        progressive
            .slots
            .sort_by(|a, b| (&a.ref_name, a.slot_id).cmp(&(&b.ref_name, b.slot_id)));
        let payload = canonical(&publication_payload(o, &progressive)?)?;
        let s = bundle
            .statements
            .iter()
            .filter_map(|s| s.body.as_ref())
            .find(|s| s.purpose == 3 && s.canonical_payload == payload)
            .ok_or(Reject::Transition)?;
        if s.admission_order <= order || s.observed_at_unix_millis < observed {
            return Err(Reject::Transition);
        }
        order = s.admission_order;
        observed = s.observed_at_unix_millis;
        let digest = &o.body.as_ref().ok_or(Reject::Canonical)?.delegation_digest;
        let index = verified
            .iter()
            .position(|d| d.digest == *digest)
            .ok_or(Reject::Scope)?;
        let result_bytes = o.body.as_ref().ok_or(Reject::Canonical)?.result_bytes;
        total_bytes = total_bytes
            .checked_add(result_bytes)
            .ok_or(Reject::Bounds)?;
        let original_scope = initial.body.scope.as_ref().ok_or(Reject::Canonical)?;
        if total_bytes > original_scope.max_result_bytes
            || progressive.slots.len() > original_scope.max_operations as usize
        {
            return Err(Reject::Scope);
        }
        let delegation = &verified[index];
        let mut committed_before = progressive.clone();
        let operation_digest = signed_operation_digest(o)?;
        committed_before
            .slots
            .retain(|s| s.signed_operation_digest != operation_digest);
        check_import_publication_budget(o, delegation, &committed_before)?;
        let scope = delegation.body.scope.as_ref().ok_or(Reject::Canonical)?;
        let mut budgets = vec![(&delegation.digest, scope)];
        if let Some(parent) = &delegation.member {
            budgets.push((
                &delegation.body.parent_permission_digest,
                parent
                    .body
                    .as_ref()
                    .and_then(|p| p.scope.as_ref())
                    .ok_or(Reject::Canonical)?,
            ));
        }
        for (digest, scope) in budgets {
            let (operations, bytes) = consumed
                .entry((digest.clone(), delegation.body.logical_job_id.clone()))
                .or_default();
            *operations = operations.checked_add(1).ok_or(Reject::Bounds)?;
            *bytes = bytes.checked_add(result_bytes).ok_or(Reject::Bounds)?;
            if *operations > scope.max_operations || *bytes > scope.max_result_bytes {
                return Err(Reject::Scope);
            }
        }
    }
    if progressive != *terminal {
        return Err(Reject::Scope);
    }
    let mut history = snapshot.map_or_else(Vec::new, |s| s.accepted_history.clone());
    if let Some(old) = history.iter_mut().find(|b| {
        b.terminal_manifest
            .as_ref()
            .is_some_and(|m| m.logical_job_id == terminal.logical_job_id)
            && b.delegations
                .first()
                .and_then(|d| d.body.as_ref())
                .and_then(|d| d.identity.as_ref())
                .map(|id| &id.spool_uuid)
                == bundle
                    .delegations
                    .first()
                    .and_then(|d| d.body.as_ref())
                    .and_then(|d| d.identity.as_ref())
                    .map(|id| &id.spool_uuid)
    }) {
        if !bundle.delegations.starts_with(&old.delegations)
            || !bundle.operations.starts_with(&old.operations)
            || bundle.owner_genesis != old.owner_genesis
            || !bundle
                .ownership_transfers
                .starts_with(&old.ownership_transfers)
            || !old
                .owner_histories
                .iter()
                .all(|v| bundle.owner_histories.contains(v))
            || bundle.member_permission != old.member_permission
            || !old
                .genesis_authorities
                .iter()
                .all(|v| bundle.genesis_authorities.contains(v))
            || !old
                .original_geneses
                .iter()
                .all(|v| bundle.original_geneses.contains(v))
            || !old
                .creator_authority_envelopes
                .iter()
                .all(|v| bundle.creator_authority_envelopes.contains(v))
            || !old.manifests.iter().all(|v| bundle.manifests.contains(v))
            || !old.statements.iter().all(|v| bundle.statements.contains(v))
            || !old.policies.iter().all(|v| bundle.policies.contains(v))
            || !old
                .genesis_witnesses
                .iter()
                .all(|v| bundle.genesis_witnesses.contains(v))
            || !old
                .authority_witnesses
                .iter()
                .all(|v| bundle.authority_witnesses.contains(v))
            || !old
                .landing_witnesses
                .iter()
                .all(|v| bundle.landing_witnesses.contains(v))
            || !old
                .foreign_dependencies
                .iter()
                .all(|v| bundle.foreign_dependencies.contains(v))
        {
            return Err(Reject::HighWater);
        }
        *old = bundle.clone();
    } else {
        history.push(bundle.clone());
    }
    let witnessed = times[0].is_some();
    let witnessed_prefix = usize::from(witnessed);
    let mut persisted = snapshot.cloned();
    if witnessed_prefix > 0 || new_set {
        let mut persisted_associations =
            snapshot.map_or_else(Vec::new, |s| s.job_associations.clone());
        if witnessed_prefix > 0 {
            for d in &bundle.delegations[..witnessed_prefix] {
                let b = d.body.as_ref().ok_or(Reject::Canonical)?;
                if !persisted_associations
                    .iter()
                    .any(|(key, _)| *key == b.job_public_key)
                {
                    persisted_associations
                        .push((b.job_public_key.clone(), b.logical_job_id.clone()));
                }
            }
        }
        persisted = Some(ImportWitnessSnapshot {
            root: pin.clone(),
            witness_set: carried.ok_or(Reject::Canonical)?.clone(),
            clock_floor_unix_millis: now_ms,
            job_associations: persisted_associations,
            accepted_history: if witnessed_prefix > 0 {
                history
            } else {
                snapshot.map_or_else(Vec::new, |s| s.accepted_history.clone())
            },
        });
    }
    Ok(VerifiedImportBundleWitnesses {
        evidence: if witnessed {
            ImportBundleEvidence::Witnessed
        } else {
            ImportBundleEvidence::Recovery
        },
        snapshot_advanced: persisted.as_ref() != snapshot,
        owner_check_time_unix_seconds: times[0].map(|(_, time)| time),
        accepted_history: terminal.clone(),
        snapshot: persisted,
    })
}

/// Independently authenticated current caller facts for source custody checks.
pub struct ImportControlCaller<'a> {
    pub authenticated_pop: bool,
    pub destination_writer: bool,
    pub caller_account: &'a str,
    pub connection_owner_account: Option<&'a str>,
    pub authorized_source: Option<&'a ImportSourceSelectionV1>,
    pub exact_grants_current: bool,
    pub selected_commits_available: bool,
}
#[derive(Clone, Copy)]
pub enum ImportControlAction {
    Cancel,
    Retry,
}

/// Destination control is independent of source custody. Cancel never fetches.
/// Run at Retry admission after checking signed authority.
pub fn check_import_control_caller(
    action: ImportControlAction,
    retained: &ImportSourceSelectionV1,
    scope: &ImportPermissionScopeV1,
    caller: &ImportControlCaller<'_>,
) -> Result<(), Reject> {
    if !caller.authenticated_pop || !caller.destination_writer || caller.caller_account.is_empty() {
        return Err(Reject::Scope);
    }
    if matches!(action, ImportControlAction::Cancel) {
        return Ok(());
    }
    validate_retained_import_source(retained, scope)?;
    if retained.connection.is_some()
        && (caller.connection_owner_account != Some(caller.caller_account)
            || caller.authorized_source != Some(retained)
            || !caller.exact_grants_current)
    {
        return Err(Reject::SourceSelection);
    }
    if !caller.selected_commits_available {
        return Err(Reject::SourceSelection);
    }
    Ok(())
}

fn validate_retry_availability(
    response: &GetImportJobStateResponse,
    destination: &SpoolRef,
) -> Result<(), Reject> {
    use get_import_job_state_response::RetryAvailability;
    match response
        .retry_availability
        .as_ref()
        .ok_or(Reject::Canonical)?
    {
        RetryAvailability::EligibleRetryTarget(target) => {
            if response.status != 1 {
                return Err(Reject::Canonical);
            }
            let operation = target.operation_ref.as_ref().ok_or(Reject::Canonical)?;
            let raw = hex::decode(operation.id.replace('-', "")).map_err(|_| Reject::Canonical)?;
            if initial_operation_id(&raw, false)? != operation.id {
                return Err(Reject::Canonical);
            }
            if operation.spool.as_ref() != Some(destination) {
                return Err(Reject::Scope);
            }
            if target.operation_version.is_empty() || target.operation_version.len() > 256 {
                return Err(Reject::Bounds);
            }
        }
        RetryAvailability::RetryUnavailable(reason) => {
            if !matches!(
                (response.status, *reason),
                (1, 1 | 2 | 6) | (2, 3) | (3, 4) | (4, 5) | (5, 7)
            ) {
                return Err(Reject::Canonical);
            }
        }
    }
    Ok(())
}

/// Validate the minimal writer snapshot and its retry target.
pub fn validate_retry_state_response(
    request: &GetImportJobStateRequest,
    response: &GetImportJobStateResponse,
) -> Result<(), Reject> {
    validate_job_state_response(request, response)?;
    validate_retry_availability(response, request.destination.as_ref().ok_or(Reject::Scope)?)
}

/// Receiver-owned facts locked together with job/authority/source state. The
/// operation-lineage association is durable host state, not an ID inference.
pub struct ImportRetryAdmission<'a> {
    pub read: &'a GetImportJobStateResponse,
    pub original: &'a OperationRecord,
    pub retry_lineage_id: &'a [u8],
    pub logical_job_terminal: bool,
    pub retained_source: &'a ImportSourceSelectionV1,
    pub committed_manifest: &'a ImportResultManifestV1,
    pub now_unix_seconds: i64,
}

/// Run after caller-scoped frozen replay lookup, under ONE admission transaction.
/// Full owner/policy/revocation/lease checks and allocation remain host gates.
pub fn check_retry_admission(
    request: &RetryImportSourceRequest,
    context: &ImportRetryAdmission<'_>,
    active: &VerifiedImportDelegation,
    caller: &ImportControlCaller<'_>,
) -> Result<(), Reject> {
    use get_import_job_state_response::RetryAvailability;
    let destination = request
        .original_operation
        .as_ref()
        .and_then(|r| r.spool.clone());
    let read_request = GetImportJobStateRequest {
        destination,
        logical_job_id: request.logical_job_id.clone(),
    };
    validate_retry_state_response(&read_request, context.read)?;
    if request.client_operation_id.is_empty() || request.client_operation_id.len() > 128 {
        return Err(Reject::Canonical);
    }
    if context.logical_job_terminal || context.read.status != 1 {
        return Err(Reject::Revoked);
    }
    let Some(RetryAvailability::EligibleRetryTarget(target)) = &context.read.retry_availability
    else {
        return Err(Reject::StaleContext);
    };
    let target_ref = target.operation_ref.as_ref().ok_or(Reject::Canonical)?;
    let original_ref = context.original.r#ref.as_ref().ok_or(Reject::Scope)?;
    if request.original_operation.as_ref() != Some(original_ref)
        || original_ref.spool != target_ref.spool
        || original_ref.id != target_ref.id
        || context.retry_lineage_id != active.body.retry_lineage_id
        || import_job_state_request_from_operation(context.original)?.as_ref()
            != Some(&read_request)
    {
        return Err(Reject::Scope);
    }
    if request.expected_operation_version != target.operation_version
        || context.original.version != target.operation_version
        || context.original.superseded_by.is_some()
        || !matches!(context.original.state, 4 | 5)
    {
        return Err(Reject::StaleContext);
    }
    let state = context.read;
    if state.active_delegation_digest != active.digest
        || state.active_cancellation_id != active.body.cancellation_id
    {
        return Err(Reject::StaleContext);
    }
    check_job_fence(
        &request.logical_job_id,
        &request.active_delegation_digest,
        request.expected_authority_epoch,
        active,
        state.authority_epoch,
    )?;
    interval(
        active.body.not_before_unix_seconds,
        active.body.expires_at_unix_seconds,
        context.now_unix_seconds,
    )?;
    let manifest = context.committed_manifest;
    validate_manifest(manifest)?;
    if manifest.logical_job_id != active.body.logical_job_id
        || manifest.retry_lineage_id != active.body.retry_lineage_id
    {
        return Err(Reject::Scope);
    }
    let scope = active.body.scope.as_ref().ok_or(Reject::Canonical)?;
    if !scope.branches.iter().any(|b| {
        !manifest
            .slots
            .iter()
            .any(|s| s.ref_name == b.ref_name && s.slot_id == b.slot_id)
    }) {
        return Err(Reject::StaleContext);
    }
    check_import_control_caller(
        ImportControlAction::Retry,
        context.retained_source,
        scope,
        caller,
    )
}

/// Check a host-generated UUID against the COMPLETE durable attempt set, including
/// the first lineage UUID. Persist the allocation, both direct links and receipt
/// atomically; do not generate a UUID from the request idempotency key.
pub fn validate_retry_response(
    request: &RetryImportSourceRequest,
    response: &MutationResponse,
    prior_attempt_ids: &[String],
) -> Result<(), Reject> {
    let receipt = response.receipt.as_ref().ok_or(Reject::PendingOperation)?;
    let Some(mutation_receipt::Outcome::PendingOperation(operation)) = &receipt.outcome else {
        return Err(Reject::PendingOperation);
    };
    let original = request
        .original_operation
        .as_ref()
        .ok_or(Reject::PendingOperation)?;
    let raw = hex::decode(operation.id.replace('-', "")).map_err(|_| Reject::PendingOperation)?;
    if initial_operation_id(&raw, false).map_or(true, |id| id != operation.id)
        || request.client_operation_id.is_empty()
        || receipt.client_operation_id != request.client_operation_id
        || original.spool.is_none()
        || operation.spool != original.spool
        || operation.id == original.id
        || operation.id == request.client_operation_id
        || prior_attempt_ids.contains(&operation.id)
    {
        return Err(Reject::PendingOperation);
    }
    Ok(())
}

/// Exact frozen Retry replay returns the stored receipt without allocating.
pub fn check_retry_replay(request_bytes: &[u8], stored_bytes: &[u8]) -> Result<(), Reject> {
    if request_bytes.len() > 2 * MAX_BUNDLE_BYTES {
        return Err(Reject::Bounds);
    }
    if request_bytes != stored_bytes {
        return Err(Reject::OperationIdReused);
    }
    Ok(())
}

/// Under the publication transaction, use the complete cumulative manifest of
/// this logical job. All operations consume the same single delegation total.
pub fn check_import_publication_budget(
    signed: &SignedDelegatedImportOperationV1,
    active: &VerifiedImportDelegation,
    committed_before: &ImportResultManifestV1,
) -> Result<(), Reject> {
    verify_operation(signed, active)?;
    let scope = active.body.scope.as_ref().ok_or(Reject::Canonical)?;
    if committed_before.logical_job_id != active.body.logical_job_id
        || committed_before.retry_lineage_id != active.body.retry_lineage_id
    {
        return Err(Reject::Scope);
    }
    let remaining = remaining_import_scope(scope, committed_before)?;
    if check_slot_replay(committed_before, signed)? {
        return Ok(());
    }
    let o = signed.body.as_ref().ok_or(Reject::Canonical)?;
    if remaining.max_operations == 0 || o.result_bytes > remaining.max_result_bytes {
        return Err(Reject::Scope);
    }
    Ok(())
}

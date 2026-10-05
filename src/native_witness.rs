//! Job-free native witness closure. This layer checks transport commitments and
//! signatures; callers still verify native models, independently selected owner
//! authority, policy, causal closure and boundary intent before durable mutation.
use crate::foreign_dependencies::thread;
use crate::heddle::api::{common as host, v1alpha2 as api};
use crate::hybrid_codec::{Reject, canonical, field, hash, key_id, record, signing_digest, width};
use crate::import_authority as import;
use prost::Message;

pub const GENESIS_DOMAIN: &str = "heddle-native-genesis-authority-v1";
pub const SIGNED_GENESIS_DOMAIN: &str = "heddle-signed-native-genesis-authority-v1";
record!(api::NativeGenesisAuthorityV1, format_version:u, identity:m, owner_kind:e,
    genesis_digest:b, original_signatures_digest:b, creator_public_key:b,
    creator_authority_envelope_digest:b, owner_chain_digest:b, publisher_key_id:b);
record!(api::SignedNativeGenesisAuthorityV1, body:m, creator_signature:m);
record!(api::NativeGenesisWitnessV1, format_version:u, kind:e, binding:m,
    original_genesis:m, creator_authority_envelope:b, boundary_acceptance:o);

pub fn signed_genesis_digest(v: &api::SignedNativeGenesisAuthorityV1) -> Result<Vec<u8>, Reject> {
    signing_digest(SIGNED_GENESIS_DOMAIN, v)
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum NativeOwner {
    Account(Vec<u8>),
    LocalKey([u8; 32]),
}
#[derive(serde::Deserialize)]
struct GenesisSelectors {
    version: u16,
    spool: String,
    creator: [u8; 32],
    owner: NativeOwner,
}
fn spool_uuid(text: &str) -> Result<Vec<u8>, Reject> {
    if text.len() != 36
        || [8, 13, 18, 23].iter().any(|&i| text.as_bytes()[i] != b'-')
        || text.bytes().enumerate().any(|(i, b)| {
            ![8, 13, 18, 23].contains(&i) && !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b)
        })
    {
        return Err(Reject::Canonical);
    }
    hex::decode(text.replace('-', "")).map_err(|_| Reject::Canonical)
}
/// Exact creator signature, original signature, immutable owner variant and
/// envelope match. Verify the returned binding against separately selected
/// native authority using StartThread's method; no import permission is read.
pub fn verify_genesis_authority(
    signed: &api::SignedNativeGenesisAuthorityV1,
    original: &api::SignedRecord,
    envelope: &[u8],
) -> Result<(), Reject> {
    let b = signed.body.as_ref().ok_or(Reject::GenesisBinding)?;
    if b.format_version != 1 {
        return Err(Reject::Version);
    }
    let id = b.identity.as_ref().ok_or(Reject::Canonical)?;
    for v in [&id.spool_uuid, &id.owner_account_uuid] {
        width(v, 16)?;
        if v.iter().all(|v| *v == 0) {
            return Err(Reject::Canonical);
        }
    }
    for v in [
        &id.spool_genesis_digest,
        &id.owner_id,
        &id.owner_state_hash,
        &b.genesis_digest,
        &b.original_signatures_digest,
        &b.creator_public_key,
        &b.creator_authority_envelope_digest,
        &b.owner_chain_digest,
        &b.publisher_key_id,
    ] {
        width(v, 32)?;
    }
    if envelope.len() > import::MAX_RECORD_BYTES {
        return Err(Reject::Bounds);
    }
    import::verify_native(original, "heddle-thread-genesis-v1")?;
    let g: GenesisSelectors =
        rmp_serde::from_slice(&original.canonical_record).map_err(|_| Reject::Canonical)?;
    if g.version != 1
        || spool_uuid(&g.spool)? != id.spool_uuid
        || g.creator.as_slice() != b.creator_public_key
        || original.signatures.len() != 1
        || original.signatures[0].public_key != b.creator_public_key
        || import::native_id(original) != b.genesis_digest
        || import::original_signatures(&[original], &[])? != b.original_signatures_digest
        || hash(&[envelope]) != b.creator_authority_envelope_digest
        || key_id(&b.creator_public_key) != b.publisher_key_id
    {
        return Err(Reject::GenesisBinding);
    }
    match (&g.owner, b.owner_kind) {
        (NativeOwner::Account(account), 1) if !envelope.is_empty() => {
            let authority = crate::writer_authority::decode_authority(envelope)?;
            crate::writer_authority::verify_account_binding(
                &authority,
                account,
                &id.owner_account_uuid,
                &id.owner_id,
            )?;
        }
        (NativeOwner::LocalKey(key), 2) if key == &g.creator && envelope.is_empty() => (),
        _ => return Err(Reject::GenesisBinding),
    }
    import::verify_authorization_signature(
        &b.creator_public_key,
        GENESIS_DOMAIN,
        b,
        signed.creator_signature.as_ref().ok_or(Reject::Signature)?,
    )
}
pub fn verify_genesis_payload(
    s: &host::HostedWitnessStatementV1,
    p: &api::NativeGenesisWitnessV1,
) -> Result<(), Reject> {
    if p.format_version != 1 || p.kind != 2 {
        return Err(Reject::Version);
    }
    let binding = p.binding.as_ref().ok_or(Reject::GenesisBinding)?;
    let original = p.original_genesis.as_ref().ok_or(Reject::Canonical)?;
    verify_genesis_authority(binding, original, &p.creator_authority_envelope)?;
    let b = binding.body.as_ref().ok_or(Reject::GenesisBinding)?;
    let id = b.identity.as_ref().ok_or(Reject::Canonical)?;
    import::match_boundary(
        s,
        &p.boundary_acceptance.iter().cloned().collect::<Vec<_>>(),
    )?;
    if (s.basis == 2) != p.boundary_acceptance.is_some() {
        return Err(Reject::BoundaryAcceptance);
    }
    if let Some(e) = &p.boundary_acceptance {
        import::boundary_original(e, original)?;
    }
    if s.purpose != 1
        || s.spool_uuid != id.spool_uuid
        || s.spool_genesis_digest != id.spool_genesis_digest
        || (s.basis == 1
            && (s.owner_id != id.owner_id
                || s.owner_state_hash != id.owner_state_hash
                || s.ownership_transfer_sequence != id.ownership_transfer_sequence))
        || s.canonical_payload != canonical(p)?
        || s.authority_digest != signed_genesis_digest(binding)?
        || s.original_signatures_digest != b.original_signatures_digest
        || s.publisher_key_id != b.publisher_key_id
    {
        return Err(Reject::Scope);
    }
    if s.canonical_payload.len() > import::MAX_RECORD_BYTES {
        return Err(Reject::Bounds);
    }
    Ok(())
}
fn sorted<T>(values: &[T], digest: impl Fn(&T) -> Result<Vec<u8>, Reject>) -> Result<(), Reject> {
    let mut previous = None;
    for v in values {
        let h = digest(v)?;
        if previous.as_ref().is_some_and(|p| p >= &h) {
            return Err(Reject::Canonical);
        }
        previous = Some(h);
    }
    Ok(())
}
fn authority_payload_digest(p: &api::ImportAuthorityWitnessV1) -> Result<Vec<u8>, Reject> {
    signing_digest("heddle-import-authority-witness-payload-v1", p)
}
/// Reference completeness, including a statement for every sidecar, a witnessed
/// genesis for every original/dependency and an explicit claim for LocalKey.
/// Presence is never permission. Call verify_bundle_witnesses with a
/// separately authenticated fresh set, then native owner/model verification.
pub fn validate_public_bundle(b: &api::NativePublicProofBundleV1) -> Result<(), Reject> {
    if b.format_version != 1 {
        return Err(Reject::Version);
    }
    if b.encoded_len() > import::MAX_BUNDLE_BYTES
        || b.owner_histories.len() > 64
        || b.ownership_transfers.len() > 64
        || b.owner_chains.is_empty()
        || b.owner_chains.len() > 64
        || b.policies.len() > 256
        || b.genesis_witnesses.is_empty()
        || b.genesis_witnesses.len() > 256
        || b.authority_witnesses.len() > 256
        || b.landing_witnesses.len() > 256
        || b.statements.len() > 1024
        || b.history_proofs.len() > 1024
    {
        return Err(Reject::Bounds);
    }
    let mut foreign = crate::foreign_dependencies::References::new(
        &b.foreign_dependencies,
        api::ForeignDependencyOrigin::Native,
    )?;
    let owner = b
        .owner_genesis
        .as_ref()
        .and_then(|o| o.genesis.as_ref())
        .ok_or(Reject::Canonical)?;
    sorted(&b.owner_chains, import::owner_chain_digest)?;
    let chain = b.owner_chains.first().ok_or(Reject::Canonical)?;
    b.witness_set.as_ref().ok_or(Reject::Canonical)?;
    for retained in &b.owner_chains {
        if retained.spool_genesis_digest != chain.spool_genesis_digest
            || retained
                .owner_state_hashes
                .iter()
                .any(|h| !b.owner_histories.iter().any(|o| o.state_hash == *h))
            || retained.transfer_audit_hashes.iter().any(|h| {
                !b.ownership_transfers
                    .iter()
                    .any(|t| t.audit_record_hash == *h)
            })
        {
            return Err(Reject::Scope);
        }
    }
    sorted(&b.genesis_witnesses, |p| {
        signed_genesis_digest(p.binding.as_ref().ok_or(Reject::GenesisBinding)?)
    })?;
    sorted(&b.authority_witnesses, authority_payload_digest)?;
    sorted(&b.landing_witnesses, |p| {
        signing_digest("heddle-hosted-landing-witness-payload-v1", p)
    })?;
    sorted(&b.statements, |s| {
        crate::witness_trust::statement_signing_digest(s.body.as_ref().ok_or(Reject::Canonical)?)
    })?;
    for p in &b.genesis_witnesses {
        let binding = p.binding.as_ref().ok_or(Reject::GenesisBinding)?;
        let g = binding.body.as_ref().ok_or(Reject::GenesisBinding)?;
        let id = g.identity.as_ref().ok_or(Reject::Canonical)?;
        verify_genesis_authority(
            binding,
            p.original_genesis.as_ref().ok_or(Reject::Canonical)?,
            &p.creator_authority_envelope,
        )?;
        if id.spool_uuid != owner.spool_uuid
            || id.spool_genesis_digest != chain.spool_genesis_digest
            || !b
                .owner_chains
                .iter()
                .any(|c| import::owner_chain_digest(c).is_ok_and(|h| h == g.owner_chain_digest))
            || !b.owner_histories.iter().any(|h| {
                h.state_hash == id.owner_state_hash
                    && h.root
                        .as_ref()
                        .and_then(|r| r.root.as_ref())
                        .is_some_and(|r| {
                            r.owner_id == id.owner_id && r.account_uuid == id.owner_account_uuid
                        })
            })
        {
            return Err(Reject::Scope);
        }
        if g.owner_kind == 2
            && !b.authority_witnesses.iter().any(|a| {
                a.kind == 2
                    && a.original
                        .as_ref()
                        .is_some_and(|o| thread(o).is_ok_and(|t| t == g.genesis_digest))
            })
        {
            return Err(Reject::Scope);
        }
        require_statement(b, 1, &canonical(p)?)?;
    }
    for p in &b.authority_witnesses {
        require_statement(b, 2, &canonical(p)?)?;
        if !requires_authority(p.original.as_ref().ok_or(Reject::Canonical)?)? {
            return Err(Reject::Scope);
        }
        let subject_thread = thread(p.original.as_ref().ok_or(Reject::Canonical)?)?;
        if !b.genesis_witnesses.iter().any(|g| {
            g.original_genesis
                .as_ref()
                .is_some_and(|g| import::native_id(g) == subject_thread)
        }) {
            return Err(Reject::Scope);
        }
        for original in p.original.iter().chain(p.dependencies.iter()) {
            if [
                "heddle-thread-genesis-v1",
                "heddle-thread-operation-v1",
                "heddle-thread-ownership-claim-v1",
                "heddle-thread-ownership-resolution-v1",
            ]
            .contains(&original.format.as_str())
            {
                let t = thread(original)?;
                if !b.genesis_witnesses.iter().any(|g| {
                    g.original_genesis
                        .as_ref()
                        .is_some_and(|o| import::native_id(o) == t)
                }) {
                    foreign.require(original)?;
                    continue;
                }
                if original.format == "heddle-thread-genesis-v1"
                    && !b
                        .genesis_witnesses
                        .iter()
                        .any(|g| g.original_genesis.as_ref() == Some(original))
                {
                    return Err(Reject::Scope);
                }
                if original.format != "heddle-thread-genesis-v1"
                    && p.original.as_ref() != Some(original)
                {
                    require_native_dependency(b, original, &mut foreign)?;
                }
            } else if ![
                "heddle-original-boundary-acceptance-v1",
                "heddle-thread-genesis-admission-v2",
                "heddle-thread-authority-admission-v3",
            ]
            .contains(&original.format.as_str())
            {
                return Err(Reject::Version);
            }
        }
    }
    for p in &b.landing_witnesses {
        require_statement(b, 4, &canonical(p)?)?;
        let execution = p.execution.as_ref().ok_or(Reject::Canonical)?;
        let op: OperationSelectors =
            rmp_serde::from_slice(&execution.canonical_record).map_err(|_| Reject::Canonical)?;
        if execution.format != "heddle-thread-operation-v1" || op.body.kind != "integration" {
            return Err(Reject::Scope);
        }
        if !b.genesis_witnesses.iter().any(|g| {
            g.original_genesis
                .as_ref()
                .is_some_and(|o| thread(execution).is_ok_and(|t| import::native_id(o) == t))
        }) {
            return Err(Reject::Scope);
        }
        for original in p.source_operation.iter().chain(p.review_evidence.iter()) {
            require_native_dependency(b, original, &mut foreign)?;
        }
    }
    for signed in &b.statements {
        let s = signed.body.as_ref().ok_or(Reject::Canonical)?;
        if s.spool_uuid != owner.spool_uuid
            || s.spool_genesis_digest != chain.spool_genesis_digest
            || !b.owner_histories.iter().any(|h| {
                h.state_hash == s.owner_state_hash
                    && h.root
                        .as_ref()
                        .and_then(|r| r.root.as_ref())
                        .is_some_and(|r| r.owner_id == s.owner_id)
            })
        {
            return Err(Reject::Scope);
        }
        // Reuse the unchanged policy chain completeness contract.
        import::require_policy_history(
            &b.policies,
            &s.spool_uuid,
            s.policy_sequence,
            &s.policy_state_hash,
        )?;
        match s.purpose {
            1 => {
                let p = b
                    .genesis_witnesses
                    .iter()
                    .find(|p| canonical(*p).is_ok_and(|v| v == s.canonical_payload))
                    .ok_or(Reject::Scope)?;
                verify_genesis_payload(s, p)?;
                crate::writer_authority::check_witness_writer(
                    s,
                    &p.creator_authority_envelope,
                    &b.owner_histories,
                    &b.policies,
                )?;
            }
            2 => {
                let p = b
                    .authority_witnesses
                    .iter()
                    .find(|p| canonical(*p).is_ok_and(|v| v == s.canonical_payload))
                    .ok_or(Reject::Scope)?;
                import::verify_witness_payload(s, import::WitnessPayload::Authority(p))?;
                crate::writer_authority::check_witness_writer(
                    s,
                    &p.authority_envelope,
                    &b.owner_histories,
                    &b.policies,
                )?;
            }
            4 => {
                let p = b
                    .landing_witnesses
                    .iter()
                    .find(|p| canonical(*p).is_ok_and(|v| v == s.canonical_payload))
                    .ok_or(Reject::Scope)?;
                import::verify_witness_payload(s, import::WitnessPayload::Landing(p))?;
                crate::writer_authority::check_witness_writer(
                    s,
                    &p.authority_envelope,
                    &b.owner_histories,
                    &b.policies,
                )?;
            }
            _ => return Err(Reject::Version),
        }
    }
    foreign.finish()
}
#[derive(serde::Deserialize)]
struct OperationSelectors {
    body: OperationBodySelectors,
}
#[derive(serde::Deserialize)]
struct OperationBodySelectors {
    kind: String,
}
#[derive(serde::Deserialize)]
struct CaptureOperationSelectors {
    body: CaptureBodySelectors,
}
#[derive(serde::Deserialize)]
struct CaptureBodySelectors {
    canonical: CaptureSelectors,
}
#[derive(serde::Deserialize)]
struct CaptureSelectors {
    author: OperationBodySelectors,
}
#[derive(serde::Deserialize)]
struct LocalIntegrationOperationSelectors {
    body: LocalIntegrationBodySelectors,
}
#[derive(serde::Deserialize)]
struct LocalIntegrationBodySelectors {
    canonical: Vec<u8>,
}
fn requires_authority(record: &api::SignedRecord) -> Result<bool, Reject> {
    if record.format != "heddle-thread-operation-v1" {
        return Ok(true);
    }
    let op: OperationSelectors =
        rmp_serde::from_slice(&record.canonical_record).map_err(|_| Reject::Canonical)?;
    if op.body.kind == "integration" {
        return Ok(false);
    }
    match op.body.kind.as_str() {
        "capture" => {
            let op: CaptureOperationSelectors =
                rmp_serde::from_slice(&record.canonical_record).map_err(|_| Reject::Canonical)?;
            Ok(op.body.canonical.author.kind != "local_key")
        }
        "local_integration" => {
            let op: LocalIntegrationOperationSelectors =
                rmp_serde::from_slice(&record.canonical_record).map_err(|_| Reject::Canonical)?;
            let integration: CaptureSelectors =
                rmp_serde::from_slice(&op.body.canonical).map_err(|_| Reject::Canonical)?;
            Ok(integration.author.kind != "local_key")
        }
        _ => Ok(true),
    }
}
fn require_native_dependency(
    b: &api::NativePublicProofBundleV1,
    original: &api::SignedRecord,
    foreign: &mut crate::foreign_dependencies::References<'_>,
) -> Result<(), Reject> {
    let t = thread(original)?;
    if !b.genesis_witnesses.iter().any(|g| {
        g.original_genesis
            .as_ref()
            .is_some_and(|o| import::native_id(o) == t)
    }) {
        return foreign.require(original);
    }
    if requires_authority(original)? {
        let p = b
            .authority_witnesses
            .iter()
            .find(|p| p.original.as_ref() == Some(original))
            .ok_or(Reject::Scope)?;
        return require_statement(b, 2, &canonical(p)?);
    }
    let op: OperationSelectors =
        rmp_serde::from_slice(&original.canonical_record).map_err(|_| Reject::Canonical)?;
    if op.body.kind == "integration" {
        let p = b
            .landing_witnesses
            .iter()
            .find(|p| p.execution.as_ref() == Some(original))
            .ok_or(Reject::Scope)?;
        return require_statement(b, 4, &canonical(p)?);
    }
    // Local captures and LocalKey integrations retain native proof and the
    // thread's exact hosted ownership claim, never an authority/landing receipt.
    // This establishes reference closure only. Native authorization must bind
    // publisher to genesis.owner.local_key and enforce the selected signed cutoff.
    import::verify_native(original, "heddle-thread-operation-v1")?;
    let t = thread(original)?;
    let claim = b
        .authority_witnesses
        .iter()
        .find(|p| {
            p.kind == 2
                && p.original
                    .as_ref()
                    .is_some_and(|o| thread(o).is_ok_and(|id| id == t))
        })
        .ok_or(Reject::Scope)?;
    require_statement(b, 2, &canonical(claim)?)
}
fn require_statement(
    b: &api::NativePublicProofBundleV1,
    purpose: i32,
    payload: &[u8],
) -> Result<(), Reject> {
    if b.statements
        .iter()
        .filter(|s| {
            s.body
                .as_ref()
                .is_some_and(|s| s.purpose == purpose && s.canonical_payload == payload)
        })
        .count()
        != 1
    {
        return Err(Reject::Scope);
    }
    Ok(())
}
/// Authenticate every exact statement against a separately selected fresh set.
/// RETIRED statements require exact proofs; carrier sets cannot select roots.
pub fn verify_bundle_witnesses(
    b: &api::NativePublicProofBundleV1,
    set: &crate::witness_trust::VerifiedWitnessSet,
    now_ms: i64,
    forbidden_landing_keys: &[Vec<u8>],
) -> Result<(), Reject> {
    validate_public_bundle(b)?;
    for p in &b.landing_witnesses {
        import::verify_landing_key_roles(p, set.known_job_keys(), forbidden_landing_keys)?;
    }
    let carried = b.witness_set.as_ref().ok_or(Reject::Canonical)?;
    if carried.body.as_ref() != Some(set.body()) || carried.body_digest != set.digest() {
        return Err(Reject::StaleContext);
    }
    for signed in &b.statements {
        match crate::witness_trust::resolve_statement(set, signed, None, false, now_ms) {
            Ok(_) => continue,
            Err(Reject::Proof) => (),
            Err(e) => return Err(e),
        }
        let statement = signed.body.as_ref().ok_or(Reject::Canonical)?;
        let entry = set
            .body()
            .entries
            .iter()
            .find(|e| e.executor_id == statement.executor_id)
            .ok_or(Reject::Root)?;
        let leaf = crate::witness_trust::leaf_digest(
            statement.purpose,
            &canonical(statement)?,
            &signed.signature,
        )?;
        // Search exact Merkle paths without repeating signature verification
        // for every candidate. Only the matching proof is resolved finally.
        let proof = b
            .history_proofs
            .iter()
            .find(|p| {
                p.purpose == statement.purpose
                    && crate::witness_trust::verify_inclusion(&leaf, p, entry).is_ok()
            })
            .ok_or(Reject::Proof)?;
        crate::witness_trust::resolve_statement(set, signed, Some(proof), false, now_ms)?;
    }
    Ok(())
}
/// Select a LocalKey original's own-origin proof cutoff from an independently
/// verified native carrier. Native causal/owner verification remains required.
/// The caller supplies the dependent statement's authenticated admission order.
/// Later admissions are ignored for both conflict selection and the maximum.
pub fn local_work_cutoff(
    b: &api::NativePublicProofBundleV1,
    original: &api::SignedRecord,
    dependent_admission_order: u64,
) -> Result<u64, Reject> {
    let subject = thread(original)?;
    let mut genesis_count = 0;
    let mut orders = Vec::new();
    let mut claims = Vec::new();
    let mut resolutions = Vec::new();
    for signed in &b.statements {
        let s = signed.body.as_ref().ok_or(Reject::Canonical)?;
        if s.admission_order > dependent_admission_order {
            continue;
        }
        if s.purpose == 1 {
            for p in &b.genesis_witnesses {
                let binding = p
                    .binding
                    .as_ref()
                    .and_then(|v| v.body.as_ref())
                    .ok_or(Reject::Canonical)?;
                if binding.genesis_digest == subject && s.canonical_payload == canonical(p)? {
                    if binding.owner_kind != 2 {
                        return Err(Reject::Scope);
                    }
                    genesis_count += 1;
                    orders.push(s.admission_order);
                }
            }
        } else if s.purpose == 2 {
            for p in &b.authority_witnesses {
                if ![2, 3].contains(&p.kind) || s.canonical_payload != canonical(p)? {
                    continue;
                }
                let r = p.original.as_ref().ok_or(Reject::Canonical)?;
                if thread(r)? != subject {
                    continue;
                }
                orders.push(s.admission_order);
                if p.kind == 2 {
                    claims.push(import::native_id(r));
                } else {
                    resolutions.push(r);
                }
            }
        }
    }
    if genesis_count != 1 {
        return Err(Reject::Scope);
    }
    match resolutions.as_slice() {
        [] if claims.len() == 1 => (),
        [r] => {
            #[derive(serde::Deserialize)]
            struct Resolution {
                winning_claim: Vec<u8>,
                conflicting_claims: Vec<Vec<u8>>,
            }
            let r: Resolution =
                rmp_serde::from_slice(&r.canonical_record).map_err(|_| Reject::Canonical)?;
            claims.sort();
            if claims != r.conflicting_claims || !claims.contains(&r.winning_claim) {
                return Err(Reject::Scope);
            }
        }
        _ => return Err(Reject::Scope),
    }
    orders
        .into_iter()
        .max()
        .filter(|v| *v > 0)
        .ok_or(Reject::Scope)
}
/// Transport dispatch is explicit and rejects dual arms before staging. Missing
/// import delegation remains an import rejection, never native fallback.
pub fn validate_carriers(
    imported: Option<&api::ImportPublicProofBundleV1>,
    native: Option<&api::NativePublicProofBundleV1>,
) -> Result<(), Reject> {
    match (imported, native) {
        (Some(_), Some(_)) => Err(Reject::Protocol),
        (Some(b), None) => import::validate_public_bundle(b),
        (None, Some(b)) => validate_public_bundle(b),
        (None, None) => Ok(()), // Purely local; hosted mandatory gate is a caller gate.
    }
}

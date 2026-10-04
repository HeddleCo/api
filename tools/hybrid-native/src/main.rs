//! Maintenance codec and fixed-vector native gate. No expected bytes are
//! generated during verification. All codecs come from the newest compatible published pair.
use anyhow::{Context, Result, bail, ensure};
use contract::{
    heddle::api::{common as host, v1alpha2 as wire},
    hybrid_codec as codec, import_authority as import, witness_trust as witness,
};
use crypto::thread_operation::SignedGenesis;
use objects::object::{
    ContentHash, State,
    original_boundary_acceptance::{
        OriginalBoundaryAcceptance, OriginalPublicationManifest, PublicationIntent,
    },
    thread_authority_admission::ThreadAuthorityAdmission,
    thread_genesis_admission::ThreadGenesisAdmission,
    thread_replication::{
        Capture, ThreadGenesis, ThreadOperation, integration::HostedIntegration,
        local_integration::LocalIntegration, metadata::ThreadControl,
        ownership_claim::ThreadOwnershipClaim, ownership_resolution::ThreadOwnershipResolution,
    },
};
use prost::Message;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;

fn hex_field(value: &Value) -> Result<Vec<u8>> {
    Ok(hex::decode(value.as_str().context("hex string required")?)?)
}
fn record<T: Message + Default>(fixture: &Value, name: &str) -> Result<T> {
    let value = fixture["wire_vectors"]
        .get(name)
        .or_else(|| fixture["signed_vectors"].get(name))
        .or_else(|| fixture["commitment_vectors"].get(name))
        .with_context(|| format!("missing vector {name}"))?;
    Ok(codec::strict_decode(
        &hex_field(&value["wire_hex"])?,
        import::MAX_BUNDLE_BYTES,
    )?)
}
fn read_json(path: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
fn native_wire(record: &wire::SignedRecord) -> Result<thread_api::contract::SignedRecord> {
    Ok(Message::decode(record.encode_to_vec().as_slice())?)
}
fn signature(record: &wire::SignedRecord, key: &[u8]) -> Result<Vec<u8>> {
    Ok(record
        .signatures
        .iter()
        .find(|s| s.public_key == key)
        .context("missing native signing role")?
        .signature
        .clone())
}
fn genesis(record: &wire::SignedRecord) -> Result<ThreadGenesis> {
    ensure!(
        record.format == "heddle-thread-genesis-v1",
        "native genesis format"
    );
    let body = ThreadGenesis::decode(&record.canonical_record)?;
    Ok(SignedGenesis {
        canonical: record.canonical_record.clone(),
        signature: signature(record, &body.creator)?,
    }
    .verify()?)
}
fn operation(record: &wire::SignedRecord) -> Result<ThreadOperation> {
    Ok(thread_api::replication::decode_record(native_wire(record)?)?.verify()?)
}
fn verify_old_capture(value: &Value) -> Result<()> {
    let g = SignedGenesis {
        canonical: hex_field(&value["genesis_canonical_hex"])?,
        signature: hex_field(&value["genesis_signature_hex"])?,
    }
    .verify()?;
    let signed = wire::SignedRecord::decode(hex_field(&value["capture"])?.as_slice())?;
    let op = operation(&signed)?;
    op.validate_parents(&g, &[])
        .context("native capture ancestry")?;
    Ok(())
}

fn set(f: &Value, b: &wire::ImportPublicProofBundleV1) -> Result<witness::VerifiedWitnessSet> {
    let root = hex_field(&f["keys"]["root"]["public_key_hex"])?;
    let jobs: Vec<_> = b
        .delegations
        .iter()
        .map(|d| {
            d.body
                .as_ref()
                .map(|d| d.job_public_key.clone())
                .context("delegation body")
        })
        .collect::<Result<_>>()?;
    Ok(witness::verify_set(
        b.witness_set.as_ref().context("exported witness set")?,
        &witness::SetExpectation {
            authority: "https://weft.example.test",
            root_id: "descriptor-root-1",
            root_public_key: &root,
            root_epoch: 1,
            now_unix_millis: 1_350_000,
            clock_floor_unix_millis: 1_000_000,
            known_job_keys: &jobs,
        },
        None,
    )?)
}

fn authenticate(
    f: &Value,
    set: &witness::VerifiedWitnessSet,
    s: &host::SignedHostedWitnessStatementV1,
) -> Result<i64> {
    // Candidate proofs are checked against the root-authenticated archive.
    for (name, value) in f["wire_vectors"].as_object().context("wire vectors")? {
        if value["schema"] == "heddle.api.common.HostedWitnessHistoryProofV1" {
            let proof: host::HostedWitnessHistoryProofV1 = record(f, name)?;
            if witness::resolve_statement(set, s, Some(&proof), false, 1_350_000).is_ok() {
                return Ok(s
                    .body
                    .as_ref()
                    .context("authenticated receipt")?
                    .observed_at_unix_millis
                    / 1000);
            }
        }
    }
    bail!("receipt signature/retirement binding rejected")
}

// Existing owner-record policy v2 preimage (owner_records.proto, fields 1-10,
// then field 11 for the signature). The native owner verifier resolves its key.
fn policy_canonical(body: &wire::SignedPolicyBody, include_hash: bool) -> Result<Vec<u8>> {
    let mut out = body.format_version.to_be_bytes().to_vec();
    codec::counted(&mut out, &body.spool_uuid)?;
    let head = body.expected_head.as_ref().context("policy predecessor")?;
    codec::counted(&mut out, &head.state_hash)?;
    out.extend_from_slice(&head.sequence.to_be_bytes());
    out.extend_from_slice(&body.sequence.to_be_bytes());
    ensure!(
        body.merge_parent_state_hashes.is_empty(),
        "policy format 1 has no merge parents"
    );
    out.extend_from_slice(&0_u32.to_be_bytes());
    let policy = body.policy.as_ref().context("policy body")?;
    ensure!(
        policy.revoked_key_ids.windows(2).all(|p| p[0] < p[1]),
        "policy revocations sorted unique"
    );
    out.extend_from_slice(&u32::try_from(policy.revoked_key_ids.len())?.to_be_bytes());
    for id in &policy.revoked_key_ids {
        codec::width(id, 32)?;
        codec::counted(&mut out, id)?;
    }
    match policy.max_audience {
        None => out.push(0),
        Some(a) => {
            ensure!((1..=3).contains(&a), "policy audience");
            out.push(1);
            out.extend_from_slice(&a.to_be_bytes());
        }
    }
    ensure!(
        body.merge_policies.len() == 2
            && body.merge_policies[0].setting_key == "max_audience"
            && body.merge_policies[0].semantics == 1
            && body.merge_policies[1].setting_key == "revoked_key_ids"
            && body.merge_policies[1].semantics == 2,
        "existing policy merge semantics"
    );
    out.extend_from_slice(&u32::try_from(body.merge_policies.len())?.to_be_bytes());
    for rule in &body.merge_policies {
        codec::counted(&mut out, rule.setting_key.as_bytes())?;
        out.extend_from_slice(&rule.semantics.to_be_bytes());
    }
    codec::counted(&mut out, &body.owner_id)?;
    codec::counted(&mut out, &body.owner_state_hash)?;
    out.extend_from_slice(&body.ownership_transfer_sequence.to_be_bytes());
    if include_hash {
        codec::counted(&mut out, &body.policy_state_hash)?;
    }
    Ok(out)
}

fn verify_export(f: &Value, b: &wire::ImportPublicProofBundleV1) -> Result<()> {
    import::validate_public_bundle(b).context("historical export reference closure")?;
    let set = set(f, b)?;
    let history = b
        .owner_histories
        .first()
        .context("exported owner history")?;
    ensure!(
        history.accepted_transitions.is_empty() && b.ownership_transfers.is_empty(),
        "fixed root-only history"
    );
    let native_root = capability_verifier::wire::SignedOwnerRoot::decode(
        history
            .root
            .as_ref()
            .context("owner root")?
            .encode_to_vec()
            .as_slice(),
    )?;
    let owner = capability_verifier::verify_owner_root(&native_root)?;
    let selected_owner = hex_field(&f["keys"]["owner"]["public_key_hex"])?;
    ensure!(
        owner.authority_key().public_key == selected_owner
            && history.state_hash == owner.state_hash(),
        "independent owner root"
    );
    let spool = b.owner_genesis.as_ref().context("Spool genesis")?;
    let native_spool = capability_verifier::wire::SignedSpoolOwnerGenesis::decode(
        spool.encode_to_vec().as_slice(),
    )?;
    capability_verifier::verify_spool_owner_genesis(&native_spool)?;
    let spool_body = spool.genesis.as_ref().context("Spool body")?;
    let spool_key = spool_body
        .owner_public_key
        .as_ref()
        .context("Spool owner key")?;
    ensure!(
        spool_key.algorithm == owner.authority_key().algorithm
            && spool_key.public_key == selected_owner,
        "Spool rooted in selected owner"
    );
    let chain = b.owner_chain.as_ref().context("owner chain")?;
    let spool_digest = capability_verifier::creation::spool_genesis_digest(
        native_spool.genesis.as_ref().context("native Spool")?,
    )?;
    ensure!(
        chain.spool_genesis_digest == spool_digest
            && chain.owner_state_hashes == [owner.state_hash().to_vec()]
            && chain.transfer_audit_hashes.is_empty(),
        "authenticated owner chain"
    );
    let identity = b
        .delegations
        .first()
        .context("initial delegation")?
        .body
        .as_ref()
        .context("delegation")?
        .identity
        .as_ref()
        .context("identity")?;
    ensure!(
        identity.owner_id == owner.owner_id()
            && identity.owner_state_hash == owner.state_hash()
            && identity.spool_uuid == spool_body.spool_uuid
            && identity.spool_genesis_digest == spool_digest
            && identity.owner_account_uuid
                == native_root.root.as_ref().context("root")?.account_uuid
            && identity.ownership_transfer_sequence == 0,
        "verified import identity"
    );
    let chain_digest = import::owner_chain_digest(chain)?;
    let mut forbidden = vec![
        selected_owner.clone(),
        hex_field(&f["keys"]["root"]["public_key_hex"])?,
    ];
    forbidden.extend(
        b.original_geneses
            .iter()
            .flat_map(|g| g.signatures.iter().map(|s| s.public_key.clone())),
    );
    forbidden.extend(set.body().entries.iter().map(|e| e.public_key.clone()));
    let context = |now| import::ImportOwnerExpectation {
        identity,
        owner_public_key: &selected_owner,
        owner_chain_digest: &chain_digest,
        // This verified owner root has no expiry; signed permissions and job
        // certificates provide their own historical validity bounds.
        authority_expires_at_seconds: i64::MAX,
        now_unix_seconds: now,
        forbidden_job_keys: &forbidden,
        known_job_associations: &[],
    };
    for p in &b.policies {
        let body = p.body.as_ref().context("selected policy")?;
        ensure!(
            body.format_version == 1
                && body.spool_uuid == spool_body.spool_uuid
                && body.owner_id == owner.owner_id()
                && body.owner_state_hash == owner.state_hash()
                && body.ownership_transfer_sequence == 0,
            "policy authenticated owner context"
        );
        ensure!(
            body.policy_state_hash
                == codec::hash(&[
                    b"heddle-spool-signed-policy-v2",
                    &policy_canonical(body, false)?
                ]),
            "policy state preimage"
        );
        let signature = p
            .owner_signature
            .as_ref()
            .context("policy owner signature")?;
        ensure!(
            signature.signer_key_id == codec::key_id(&selected_owner),
            "policy signing role"
        );
        codec::verify(
            &selected_owner,
            &codec::hash(&[
                b"heddle-spool-signed-policy-signature-v2",
                &policy_canonical(body, true)?,
            ]),
            &signature.signature,
        )?;
        ensure!(
            !body
                .policy
                .as_ref()
                .context("policy")?
                .revoked_key_ids
                .contains(&signature.signer_key_id),
            "policy cannot revoke its owner"
        );
    }
    let mut times = BTreeMap::new();
    for s in &b.statements {
        let time = authenticate(f, &set, s)?;
        let body = s.body.as_ref().context("authenticated statement")?;
        ensure!(
            body.spool_uuid == identity.spool_uuid
                && body.spool_genesis_digest == identity.spool_genesis_digest
                && body.owner_id == identity.owner_id
                && body.owner_state_hash == identity.owner_state_hash
                && body.ownership_transfer_sequence == 0,
            "receipt owner context"
        );
        times.insert(body.canonical_payload.clone(), time);
    }
    let mut active = Vec::new();
    for (i, d) in b.delegations.iter().enumerate() {
        let body = d.body.as_ref().context("delegation")?;
        let op = b
            .operations
            .iter()
            .find(|o| {
                o.body.as_ref().is_some_and(|o| {
                    import::signed_delegation_digest(d).is_ok_and(|h| h == o.delegation_digest)
                })
            })
            .context("original publication for delegation")?;
        let (manifest, statement) = publication(b, op)?;
        let time = *times
            .get(
                &statement
                    .body
                    .as_ref()
                    .context("receipt")?
                    .canonical_payload,
            )
            .context("authenticated time")?;
        let parent = import::resolve_bundle_permission(b, &body.parent_permission_digest)?;
        let verified = if i == 0 {
            import::verify_delegation(d, parent, &context(time))?
        } else {
            let r = &b.renewals[i - 1];
            let committed = import::resolve_bundle_manifest(
                b,
                &r.body
                    .as_ref()
                    .context("renewal")?
                    .committed_manifest_digest,
            )?;
            import::verify_renewal(
                r,
                &active[i - 1],
                committed,
                i as u64,
                parent,
                &context(time),
            )?
        };
        // verify_publication authenticates the statement and uses its witnessed
        // time for the exact signed operation; no caller-supplied historical time.
        let proof = matching_proof(f, &set, statement)?;
        import::verify_publication(
            op,
            &verified,
            manifest,
            statement,
            &set,
            Some(&proof),
            1_350_000,
        )?;
        active.push(verified);
    }
    for payload in &b.genesis_witnesses {
        let canonical = codec::canonical(payload)?;
        let time = *times
            .get(&canonical)
            .context("every genesis admission authenticated")?;
        let s = b
            .statements
            .iter()
            .find(|s| {
                s.body
                    .as_ref()
                    .is_some_and(|s| s.purpose == 1 && s.canonical_payload == canonical)
            })
            .context("genesis receipt")?;
        import::verify_witness_payload(
            s.body.as_ref().context("receipt")?,
            import::WitnessPayload::Genesis(payload),
        )?;
        let binding = payload.binding.as_ref().context("binding")?;
        let g = genesis(
            payload
                .original_genesis
                .as_ref()
                .context("original genesis")?,
        )?;
        let old = &b.delegations[0];
        let d = import::verify_delegation(
            old,
            import::resolve_bundle_permission(
                b,
                &binding
                    .body
                    .as_ref()
                    .context("binding body")?
                    .parent_permission_digest,
            )?,
            &context(time),
        )?;
        let body = binding.body.as_ref().context("binding body")?;
        import::verify_genesis_authority(
            binding,
            &d,
            g.id()?.as_bytes(),
            &body.original_creator_signature,
            &codec::hash(&[&payload.creator_authority_envelope]),
        )?;
        objects::object::thread_replication::hosted_import::initial_base_state(
            &g,
            &objects::object::thread_replication::hosted_import::synthetic_initial_base()?
                .encode_current_msgpack()?,
        )?;
    }
    println!(
        "B PASS: signed policy history, both genesis admissions, receipt-derived times, both historical publications"
    );
    Ok(())
}

fn matching_proof(
    f: &Value,
    set: &witness::VerifiedWitnessSet,
    s: &host::SignedHostedWitnessStatementV1,
) -> Result<host::HostedWitnessHistoryProofV1> {
    for (name, value) in f["wire_vectors"].as_object().context("wire vectors")? {
        if value["schema"] == "heddle.api.common.HostedWitnessHistoryProofV1" {
            let proof = record(f, name)?;
            if witness::resolve_statement(set, s, Some(&proof), false, 1_350_000).is_ok() {
                return Ok(proof);
            }
        }
    }
    bail!("missing authenticated retirement path")
}
fn publication<'a>(
    b: &'a wire::ImportPublicProofBundleV1,
    op: &wire::SignedDelegatedImportOperationV1,
) -> Result<(
    &'a wire::ImportResultManifestV1,
    &'a host::SignedHostedWitnessStatementV1,
)> {
    for m in &b.manifests {
        let payload = codec::canonical(&import::publication_payload(op, m)?)?;
        if let Some(s) = b.statements.iter().find(|s| {
            s.body
                .as_ref()
                .is_some_and(|s| s.purpose == 3 && s.canonical_payload == payload)
        }) {
            return Ok((m, s));
        }
    }
    bail!("missing original publication receipt/manifest")
}

fn input() -> Result<Vec<u8>> {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text)?;
    Ok(hex::decode(text.trim())?)
}

fn encode(format: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(match format {
        "heddle-thread-genesis-v1" => rmp_serde::from_slice::<ThreadGenesis>(bytes)?.encode()?,
        "heddle-thread-operation-v1" => {
            rmp_serde::from_slice::<ThreadOperation>(bytes)?.encode()?
        }
        "heddle-thread-ownership-claim-v1" => {
            rmp_serde::from_slice::<ThreadOwnershipClaim>(bytes)?.encode()?
        }
        "heddle-thread-ownership-resolution-v1" => {
            rmp_serde::from_slice::<ThreadOwnershipResolution>(bytes)?.encode()?
        }
        "heddle-thread-control-v1" => rmp_serde::from_slice::<ThreadControl>(bytes)?.encode()?,
        "heddle-hosted-integration-v1" => {
            rmp_serde::from_slice::<HostedIntegration>(bytes)?.encode()?
        }
        "heddle-local-integration-v1" => {
            rmp_serde::from_slice::<LocalIntegration>(bytes)?.encode()?
        }
        "heddle-original-boundary-acceptance-v1" => {
            rmp_serde::from_slice::<OriginalBoundaryAcceptance>(bytes)?.encode()?
        }
        "heddle-original-publication-manifest-v1" => {
            rmp_serde::from_slice::<OriginalPublicationManifest>(bytes)?.encode()?
        }
        "heddle-original-publication-intent-v1" => {
            let intent: PublicationIntent = rmp_serde::from_slice(bytes)?;
            intent.id()?;
            rmp_serde::to_vec_named(&intent)?
        }
        "heddle-thread-genesis-admission-v2" => {
            rmp_serde::from_slice::<ThreadGenesisAdmission>(bytes)?.encode()?
        }
        "heddle-thread-authority-admission-v3" => {
            rmp_serde::from_slice::<ThreadAuthorityAdmission>(bytes)?.encode()?
        }
        "capture" => {
            let capture: Capture = rmp_serde::from_slice(bytes)?;
            capture.validated_state()?;
            rmp_serde::to_vec_named(&capture)?
        }
        _ => bail!("unsupported native format {format}"),
    })
}

fn verify_native(f: &Value) -> Result<()> {
    let b: wire::ImportPublicProofBundleV1 = record(f, "complete_renewed_export")?;
    let set = set(f, &b)?;
    let mut originals = b.original_geneses.clone();
    for name in ["converted_dev", "converted_main"] {
        originals.push(record(f, name)?);
    }
    for name in [
        "authority_admission_payload",
        "ownership_admission_payload",
        "resolution_admission_payload",
    ] {
        let payload: wire::ImportAuthorityWitnessV1 = record(f, name)?;
        originals.push(payload.original.context("original authority")?);
        originals.extend(payload.dependencies);
    }
    let landing: wire::HostedLandingWitnessV1 = record(f, "landing_payload")?;
    originals.push(
        landing
            .execution
            .as_ref()
            .context("landing execution")?
            .clone(),
    );
    originals.push(
        landing
            .source_operation
            .as_ref()
            .context("landing source")?
            .clone(),
    );
    originals.extend(landing.review_evidence.clone());
    let mut geneses = BTreeMap::new();
    let mut operations = BTreeMap::new();
    let mut claims = BTreeMap::new();
    for r in &originals {
        match r.format.as_str() {
            "heddle-thread-genesis-v1" => {
                let g = genesis(r)?;
                geneses.insert(g.id()?, g);
            }
            "heddle-thread-operation-v1" => {
                let op = operation(r)?;
                operations.insert(op.id()?, op);
            }
            "heddle-thread-ownership-claim-v1" => {
                let body = ThreadOwnershipClaim::decode(&r.canonical_record)?;
                let signed = crypto::thread_ownership_claim::SignedOwnershipClaim {
                    canonical: r.canonical_record.clone(),
                    local_signature: signature(r, &body.prior_local_key)?,
                    acceptance_signature: signature(r, &body.accepting_publisher)?,
                };
                let verified = signed.verify()?;
                let mut encoded = thread_api::thread_ownership::encode(&signed)?;
                encoded
                    .signatures
                    .sort_by(|a, b| a.public_key.cmp(&b.public_key));
                ensure!(
                    encoded.encode_to_vec() == r.encode_to_vec(),
                    "native claim re-encode"
                );
                claims.insert(verified.id()?, verified);
            }
            "heddle-thread-ownership-resolution-v1" => {
                ThreadOwnershipResolution::decode(&r.canonical_record)?;
            }
            _ => bail!("unexpected positive native format"),
        }
    }
    for op in operations.values() {
        let g = geneses
            .get(&op.thread)
            .context("native operation genesis closure")?;
        let parents = op
            .parents
            .iter()
            .map(|id| {
                operations
                    .get(id)
                    .cloned()
                    .context("native causal dependency")
            })
            .collect::<Result<Vec<_>>>()?;
        op.validate_parents(g, &parents)
            .context("native capture/control/integration ancestry")?;
    }
    for c in claims.values() {
        c.validate_genesis(geneses.get(&c.thread).context("claim genesis")?)?;
        for id in &c.source_frontier {
            ensure!(
                operations.get(id).is_some_and(|o| o.thread == c.thread),
                "claim source frontier"
            );
        }
    }
    for r in &originals {
        if r.format == "heddle-thread-ownership-resolution-v1" {
            let value = ThreadOwnershipResolution::decode(&r.canonical_record)?;
            value.validate_genesis(geneses.get(&value.thread).context("resolution genesis")?)?;
            for id in &value.conflicting_claims {
                ensure!(
                    claims.get(id).is_some_and(|c| c.thread == value.thread),
                    "resolution claims closure"
                );
            }
            for id in &value.frontier {
                ensure!(
                    operations.get(id).is_some_and(|o| o.thread == value.thread),
                    "resolution source frontier"
                );
            }
            let signed = crypto::thread_ownership_resolution::SignedOwnershipResolution {
                canonical: r.canonical_record.clone(),
                local_signature: signature(r, &value.local_owner)?,
                acceptance_signature: signature(r, &value.accepting_publisher)?,
            };
            signed.verify(claims.get(&value.winning_claim).context("winning claim")?)?;
            let mut encoded = thread_api::thread_ownership::encode_resolution(&signed)?;
            encoded
                .signatures
                .sort_by(|a, b| a.public_key.cmp(&b.public_key));
            ensure!(
                encoded.encode_to_vec() == r.encode_to_vec(),
                "native resolution re-encode"
            );
        }
    }
    // Native authority is evaluated at the authenticated admission time.
    let history = b.owner_histories.first().context("owner history")?;
    let root = capability_verifier::wire::SignedOwnerRoot::decode(
        history
            .root
            .as_ref()
            .context("owner root")?
            .encode_to_vec()
            .as_slice(),
    )?;
    let owner = capability_verifier::verify_owner_root(&root)?;
    for (name, statement_name) in [
        ("authority_admission_payload", "authority_admission"),
        ("ownership_admission_payload", "ownership_admission"),
        ("resolution_admission_payload", "resolution_admission"),
    ] {
        let payload: wire::ImportAuthorityWitnessV1 = record(f, name)?;
        let signed = record(f, statement_name)?;
        let time = authenticate(f, &set, &signed)?;
        import::verify_witness_payload(
            signed.body.as_ref().context("receipt")?,
            import::WitnessPayload::Authority(&payload),
        )?;
        let original = payload.original.as_ref().context("original")?;
        let (publisher, actor, method) = match payload.kind {
            1 => {
                let op = operation(original)?;
                let objects::object::thread_replication::ThreadOperationBody::Metadata(bytes) =
                    op.body
                else {
                    bail!("control required")
                };
                let control = ThreadControl::decode(&bytes)?;
                let method = control.authorization_method();
                (op.publisher, control.actor, method)
            }
            2 => {
                let claim = ThreadOwnershipClaim::decode(&original.canonical_record)?;
                let objects::object::thread_replication::SourceAuthor::Account { actor, .. } =
                    claim.acceptance
                else {
                    bail!("account acceptance")
                };
                (
                    claim.accepting_publisher,
                    actor,
                    "/heddle.api.v1alpha2.ThreadService/ClaimThreadOwnership",
                )
            }
            3 => {
                let resolution = ThreadOwnershipResolution::decode(&original.canonical_record)?;
                let objects::object::thread_replication::SourceAuthor::Account { actor, .. } =
                    resolution.acceptance
                else {
                    bail!("account resolution")
                };
                (
                    resolution.accepting_publisher,
                    actor,
                    "/heddle.api.v1alpha2.ThreadService/ResolveOwnershipConflict",
                )
            }
            _ => bail!("authority discriminator"),
        };
        verify_authority(
            &payload.authority_envelope,
            &owner,
            &publisher,
            &actor,
            method,
            time,
        )?;
    }
    let signed: host::SignedHostedWitnessStatementV1 = record(f, "landing_statement")?;
    let time = authenticate(f, &set, &signed)?;
    import::verify_witness_payload(
        signed.body.as_ref().context("landing receipt")?,
        import::WitnessPayload::Landing(&landing),
    )?;
    let execution = operation(landing.execution.as_ref().context("execution")?)?;
    let objects::object::thread_replication::ThreadOperationBody::Integration(bytes) =
        execution.body
    else {
        bail!("native integration")
    };
    let integration = HostedIntegration::decode(&bytes)?;
    let source = operation(landing.source_operation.as_ref().context("source")?)?;
    integration.validate_source(&source)?;
    let objects::object::thread_replication::ThreadOperationBody::Capture(capture) = &source.body
    else {
        bail!("original source capture")
    };
    let objects::object::thread_replication::SourceAuthor::Account {
        actor, authority, ..
    } = &capture.author
    else {
        bail!("account source")
    };
    verify_authority(
        authority,
        &owner,
        &source.publisher,
        actor,
        "/heddle.api.v1alpha2.SyncService/PublishContent",
        time,
    )?;
    let request = landing.request.as_ref().context("request")?;
    request_binding(request, &integration)?;
    let unary = native_api::signing::unary_bytes(
        &request.signing_identity,
        &request.method_path,
        request.timestamp_millis,
        &request.nonce,
        &request.request_body,
    );
    let original_signature = &request
        .signature
        .as_ref()
        .context("original request signature")?
        .signature;
    let preimage = [unary.as_slice(), original_signature.as_slice()].concat();
    let fixed = &f["native_request_proof"];
    ensure!(
        fixed["domain"] == "weft-hosted-landing-request-proof-v1"
            && hex_field(&fixed["unary_input_hex"])? == unary
            && hex_field(&fixed["original_signature_hex"])? == *original_signature
            && hex_field(&fixed["canonical_hex"])? == preimage
            && hex_field(&fixed["id_hex"])? == integration.initiating_request_proof.as_bytes(),
        "frozen native request preimage"
    );
    let request_body = native_api::heddle::api::v1alpha2::LandThreadRequest::decode(
        request.request_body.as_slice(),
    )?;
    let target_base = geneses
        .get(&integration.target_thread)
        .context("target genesis")?
        .base;
    let spool_id = integration.spool.to_string();
    ensure!(
        request_body
            .thread
            .as_ref()
            .and_then(|t| t.spool.as_ref())
            .is_some_and(|s| s.id == spool_id)
            && request_body
                .target
                .as_ref()
                .and_then(|t| t.spool.as_ref())
                .is_some_and(|s| s.id == spool_id)
            && request_body
                .source
                .as_ref()
                .and_then(|r| r.spool.as_ref())
                .is_some_and(|s| s.id == spool_id)
            && request_body
                .expected_target
                .as_ref()
                .and_then(|r| r.spool.as_ref())
                .is_some_and(|s| s.id == spool_id),
        "request exact Spool"
    );
    ensure!(
        request_body
            .thread
            .as_ref()
            .and_then(|t| t.id.as_ref())
            .is_some_and(|id| id.value == integration.source_thread.as_bytes())
            && request_body
                .target
                .as_ref()
                .and_then(|t| t.id.as_ref())
                .is_some_and(|id| id.value == integration.target_thread.as_bytes())
            && request_body.expected_policy_version == integration.review_policy_version.as_bytes(),
        "landing request exact source/target/policy"
    );
    use native_api::heddle::api::v1alpha2::revision_ref::Revision;
    ensure!(request_body.source.as_ref().and_then(|r| r.revision.as_ref()).is_some_and(|r| matches!(r, Revision::State(id) if id.value == integration.source_revision.as_bytes()))
        && request_body.expected_target.as_ref().and_then(|r| r.revision.as_ref()).is_some_and(|r| matches!(r, Revision::State(id) if id.value == target_base.as_bytes())), "request selected native revisions");
    ensure!(
        integration.executed_at_ms / 1000 == time
            && witness::witness_id(&integration.executor)
                == signed.body.as_ref().context("receipt")?.executor_id
            && integration.spool_genesis.as_bytes()
                == signed
                    .body
                    .as_ref()
                    .context("receipt")?
                    .spool_genesis_digest
                    .as_slice()
            && integration.review_policy_version.as_bytes()
                == signed
                    .body
                    .as_ref()
                    .context("receipt")?
                    .policy_state_hash
                    .as_slice(),
        "landing receipt binding"
    );
    for review in &landing.review_evidence {
        let op = operation(review)?;
        ensure!(
            integration.review_evidence.contains(&op.id()?)
                && op.thread == integration.source_thread,
            "selected native review"
        );
        let objects::object::thread_replication::ThreadOperationBody::Metadata(bytes) = op.body
        else {
            bail!("review metadata")
        };
        let control = ThreadControl::decode(&bytes)?;
        verify_authority(
            &control.authority_envelope,
            &owner,
            &op.publisher,
            &control.actor,
            control.authorization_method(),
            time,
        )?;
        let objects::object::thread_replication::metadata::Control::Review(review) =
            control.control
        else {
            bail!("approval")
        };
        ensure!(
            review.source == integration.source_revision
                && review.target == target_base
                && review.policy_version == integration.review_policy_version,
            "review exact source/target/policy"
        );
    }
    let content: wire::ImportContentV1 = record(f, "content")?;
    let capture: Capture = rmp_serde::from_slice(&content.canonical_capture)?;
    ensure!(
        rmp_serde::to_vec_named(&capture)? == content.canonical_capture,
        "native content canonical Capture"
    );
    capture.validated_state()?;
    println!(
        "A PASS: native parse/re-encode, original signatures, child-State ancestry, causal closure, authority and request binding"
    );
    Ok(())
}

fn verify_boundary_native(
    f: &Value,
    statement_name: &str,
    payload_name: &str,
    kind: &str,
) -> Result<()> {
    use objects::object::{
        original_boundary_acceptance::{ManifestSubject, OriginalManifestEntry},
        thread_replication::{SourceAuthor, integration::TrustedHostedExecutor},
    };
    let bundle: wire::ImportPublicProofBundleV1 = record(f, "complete_renewed_export")?;
    let set = set(f, &bundle)?;
    let signed: host::SignedHostedWitnessStatementV1 = record(f, statement_name)?;
    let time = authenticate(f, &set, &signed)?;
    let statement = signed.body.as_ref().context("boundary witness")?;
    let (evidence, original, envelope, dependencies) = if kind == "genesis" {
        let payload: wire::ImportGenesisWitnessV1 = record(f, payload_name)?;
        import::verify_witness_payload(statement, import::WitnessPayload::Genesis(&payload))?;
        (
            vec![payload.boundary_acceptance.context("boundary evidence")?],
            payload.original_genesis.context("original genesis")?,
            payload.creator_authority_envelope,
            Vec::new(),
        )
    } else {
        let payload: wire::ImportAuthorityWitnessV1 = record(f, payload_name)?;
        import::verify_witness_payload(statement, import::WitnessPayload::Authority(&payload))?;
        (
            payload.boundary_acceptances,
            payload.original.context("source original")?,
            payload.authority_envelope,
            payload.dependencies,
        )
    };
    let enclosing = evidence
        .iter()
        .find(|e| e.binding.as_ref() == statement.boundary_acceptance.as_ref())
        .context("exact enclosing acceptance binding")?;
    let enclosing_id = enclosing
        .binding
        .as_ref()
        .context("acceptance binding")?
        .acceptance_id
        .clone();
    let descriptor = if kind == "genesis" {
        OriginalManifestEntry::from_genesis(&genesis(&original)?, &envelope)?
    } else {
        OriginalManifestEntry::from_operation(&operation(&original)?)?
    };
    // Resolve immutable subjects from the existing native fixture originals, never
    // from a receipt's claims. Every candidate's original signature is checked.
    let native_authority: wire::ImportAuthorityWitnessV1 =
        record(f, "authority_admission_payload")?;
    let candidates = bundle
        .genesis_witnesses
        .iter()
        .map(|p| -> Result<_> {
            Ok((
                p.original_genesis
                    .clone()
                    .context("exported original genesis")?,
                p.creator_authority_envelope.clone(),
            ))
        })
        .chain(std::iter::once(Ok((
            original,
            if kind == "genesis" {
                envelope
            } else {
                Vec::new()
            },
        ))))
        .chain(
            dependencies
                .into_iter()
                .chain(native_authority.dependencies)
                .filter(|r| r.format == "heddle-thread-operation-v1")
                .map(|r| Ok((r, Vec::new()))),
        );
    let mut originals = BTreeMap::new();
    for candidate in candidates {
        let (original, envelope) = candidate?;
        let entry = if original.format == "heddle-thread-genesis-v1" {
            OriginalManifestEntry::from_genesis(&genesis(&original)?, &envelope)?
        } else {
            OriginalManifestEntry::from_operation(&operation(&original)?)?
        };
        let value = (entry.clone(), original, envelope);
        if let Some(previous) = originals.insert(entry.subject, value.clone()) {
            ensure!(previous == value, "conflicting original subject evidence");
        }
    }
    let issuer = set
        .body()
        .entries
        .iter()
        .find(|e| e.executor_id == statement.executor_id)
        .context("authenticated witness issuer")?;
    let root: wire::OwnerHistory = record(f, "owner_history")?;
    let native_root = capability_verifier::wire::SignedOwnerRoot::decode(
        root.root.context("root")?.encode_to_vec().as_slice(),
    )?;
    let owner = capability_verifier::verify_owner_root(&native_root)?;
    ensure!(
        owner.authority_key().public_key == hex_field(&f["keys"]["owner"]["public_key_hex"])?,
        "independently selected owner"
    );
    for evidence in &evidence {
        let a = evidence.signed_acceptance.as_ref().context("acceptance")?;
        let acceptance = crypto::original_boundary_acceptance::SignedBoundaryAcceptance {
            canonical: a.canonical_record.clone(),
            signature: signature(
                a,
                &OriginalBoundaryAcceptance::decode(&a.canonical_record)?.accepting_publisher,
            )?,
        }
        .verify_signature()?;
        let manifest = OriginalPublicationManifest::decode(&evidence.originals_manifest)?;
        let intent: PublicationIntent = rmp_serde::from_slice(&evidence.publication_intent)?;
        ensure!(
            rmp_serde::to_vec_named(&intent)? == evidence.publication_intent,
            "canonical native intent"
        );
        let selected = acceptance.selected(&intent, &manifest)?;
        if evidence
            .binding
            .as_ref()
            .context("acceptance binding")?
            .acceptance_id
            == enclosing_id
        {
            ensure!(
                selected.contains(&&descriptor),
                "exact original selected by signed manifest"
            );
        }
        ensure!(
            selected.len() == evidence.original_receipts.len(),
            "complete per-original receipt selection"
        );
        let trust = TrustedHostedExecutor {
            spool: intent.spool,
            spool_genesis: intent.spool_genesis,
            executor: issuer.public_key.as_slice().try_into()?,
        };
        let mut seen = std::collections::BTreeSet::new();
        for r in &evidence.original_receipts {
            ensure!(
                r.signatures.len() == 1 && r.signatures[0].public_key == issuer.public_key,
                "independent per-original receipt signer"
            );
            let subject = match r.format.as_str() {
                "heddle-thread-genesis-admission-v2" => ManifestSubject::Genesis(
                    ThreadGenesisAdmission::decode(&r.canonical_record)?.thread,
                ),
                "heddle-thread-authority-admission-v3" => {
                    use objects::object::thread_authority_admission::OriginalAuthoritySubject;
                    match ThreadAuthorityAdmission::decode(&r.canonical_record)?.subject {
                        OriginalAuthoritySubject::Operation(id) => ManifestSubject::Source(id),
                        _ => bail!("fixture receipt original kind"),
                    }
                }
                _ => bail!("fixture receipt format"),
            };
            let selected_entry = selected
                .iter()
                .find(|e| e.subject == subject)
                .context("receipt subject outside selected originals")?;
            ensure!(seen.insert(subject.clone()), "duplicate receipt subject");
            let (entry, original, envelope) = originals
                .get(&subject)
                .context("selected original/envelope missing")?;
            ensure!(
                *selected_entry == entry,
                "selected descriptor differs from immutable original"
            );
            match subject {
                ManifestSubject::Genesis(_) => {
                    let receipt = crypto::thread_genesis_admission::SignedGenesisAdmission {
                        canonical: r.canonical_record.clone(),
                        signature: signature(r, &issuer.public_key)?,
                        boundary_acceptance: None,
                    }
                    .verify_signature()?;
                    receipt.authorize_with_acceptance(
                        &genesis(original)?,
                        envelope,
                        &trust,
                        Some(&acceptance),
                    )?;
                }
                ManifestSubject::Source(_) => {
                    let receipt = crypto::thread_authority_admission::SignedAuthorityAdmission {
                        canonical: r.canonical_record.clone(),
                        signature: signature(r, &issuer.public_key)?,
                        boundary_acceptance: None,
                    }
                    .verify_signature()?;
                    receipt.authorize_with_acceptance(
                        &operation(original)?,
                        &trust,
                        Some(&acceptance),
                    )?;
                }
                _ => bail!("fixture original kind"),
            }
        }
        ensure!(
            selected.iter().all(|e| seen.contains(&e.subject)),
            "selected original receipt omitted"
        );
        let SourceAuthor::Account {
            actor, authority, ..
        } = &acceptance.accepting_author
        else {
            bail!("account acceptance required")
        };
        for entry in selected {
            let (subject_kind, method) = match entry.subject {
                ManifestSubject::Genesis(_) => (
                    capability_verifier::boundary_authority::BoundarySubjectKind::AccountGenesis,
                    "/heddle.api.v1alpha2.ThreadService/StartThread",
                ),
                ManifestSubject::Source(_) => (
                    capability_verifier::boundary_authority::BoundarySubjectKind::Source,
                    "/heddle.api.v1alpha2.SyncService/PublishContent",
                ),
                _ => bail!("fixture original kind"),
            };
            capability_verifier::boundary_authority::verify_accepting_authority(
                authority,
                capability_verifier::thread_control_authority::Context {
                    owner: &owner,
                    account_uuid: actor.principal_id.as_bytes(),
                    publisher: &acceptance.accepting_publisher,
                    agent_id: actor.agent_id.as_deref(),
                    method,
                    spool_path: "example",
                    now: time,
                },
                capability_verifier::boundary_authority::OriginalSubjectScope {
                    kind: subject_kind,
                    account: acceptance.original_account.as_bytes(),
                    thread: entry.thread.as_bytes(),
                    subject: entry.subject.id().as_bytes(),
                    publisher: &entry.publisher,
                    agent_id: entry
                        .authority
                        .as_ref()
                        .and_then(|a| a.actor.agent_id.as_deref()),
                },
                &[],
                |_| false,
            )?;
        }
    }
    println!(
        "BOUNDARY NATIVE PASS {statement_name}: selected original, exact acceptance basis, receipt signatures, current accepting authority"
    );
    Ok(())
}
fn verify_boundaries(f: &Value) -> Result<()> {
    for v in f["boundary_vectors"]["passing"]
        .as_array()
        .context("boundary passing vectors")?
    {
        verify_boundary_native(
            f,
            v["statement"].as_str().context("statement")?,
            v["payload"].as_str().context("payload")?,
            v["kind"].as_str().context("kind")?,
        )?;
    }
    Ok(())
}

fn verify_authority(
    bytes: &[u8],
    owner: &capability_verifier::VerifiedOwnerState,
    publisher: &[u8; 32],
    actor: &objects::object::CollaborationActor,
    method: &str,
    now: i64,
) -> Result<()> {
    capability_verifier::thread_control_authority::verify(
        bytes,
        capability_verifier::thread_control_authority::Context {
            owner,
            account_uuid: actor.principal_id.as_bytes(),
            publisher,
            agent_id: actor.agent_id.as_deref(),
            method,
            spool_path: "example",
            now,
        },
        |_| false,
    )?;
    Ok(())
}
fn request_binding(
    request: &wire::HostedLandingRequestProofV1,
    integration: &HostedIntegration,
) -> Result<()> {
    use native_api::{
        heddle::api::{
            common::{CallContext, RequestProof},
            v1alpha2::LandThreadRequest,
        },
        v2::client::Rpc,
    };
    let body = LandThreadRequest::decode(request.request_body.as_slice())?;
    let signature = request
        .signature
        .as_ref()
        .context("original request signature")?;
    let key: [u8; 32] = signature.public_key.as_slice().try_into()?;
    ensure!(
        request.format_version == 1
            && request.method_path == thread_api::rpc::ThreadServiceLandThread::METHOD.path,
        "exact original landing method"
    );
    thread_api::request_proof::verify(
        &CallContext {
            client_operation_id: body.client_operation_id,
            request_proof: Some(RequestProof {
                algorithm: "ed25519".into(),
                signing_identity: request.signing_identity.clone(),
                timestamp_millis: request.timestamp_millis,
                nonce: request.nonce.clone(),
                signature: signature.signature.clone(),
            }),
            ..Default::default()
        },
        thread_api::rpc::ThreadServiceLandThread::METHOD,
        &request.request_body,
        &key,
        integration.executed_at_ms,
    )?;
    let mut preimage = native_api::signing::unary_bytes(
        &request.signing_identity,
        &request.method_path,
        request.timestamp_millis,
        &request.nonce,
        &request.request_body,
    );
    preimage.extend_from_slice(&signature.signature);
    ensure!(
        integration.initiating_request_proof
            == ContentHash::compute_typed("weft-hosted-landing-request-proof-v1", &preimage),
        "existing hosted initiating-request preimage"
    );
    Ok(())
}

// alpha.28 contract verification uses the unchanged published native codecs.
fn verify_native_witness_fixture() -> Result<()> {
    use objects::object::{
        CollaborationActor,
        thread_replication::{GenesisOwner, SourceAuthor, ThreadOperationBody},
    };
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/native-host-witness-v1.json"
    ))?;
    let reference: wire::NativePublicProofBundleV1 = record(&f, "local_adopt_push")?;
    let claim = ThreadOwnershipClaim::decode(
        &reference.authority_witnesses[0]
            .original
            .as_ref()
            .context("claim")?
            .canonical_record,
    )?;
    let SourceAuthor::Account { actor, .. } = claim.acceptance else {
        bail!("account claim")
    };
    let history = reference.owner_histories.first().context("owner history")?;
    let root = capability_verifier::wire::SignedOwnerRoot::decode(
        history
            .root
            .as_ref()
            .context("owner root")?
            .encode_to_vec()
            .as_slice(),
    )?;
    let owner = capability_verifier::verify_owner_root(&root)?;
    ensure!(
        owner.authority_key().public_key == hex_field(&f["keys"]["owner"]["public_key_hex"])?
            && history.state_hash == owner.state_hash(),
        "independent owner pin"
    );
    let spool = capability_verifier::wire::SignedSpoolOwnerGenesis::decode(
        reference
            .owner_genesis
            .as_ref()
            .context("spool")?
            .encode_to_vec()
            .as_slice(),
    )?;
    capability_verifier::verify_spool_owner_genesis(&spool)?;
    for name in f["positive"].as_array().context("positive cases")? {
        let name = name.as_str().context("case")?;
        let b: wire::NativePublicProofBundleV1 = record(&f, name)?;
        let now = b
            .witness_set
            .as_ref()
            .and_then(|s| s.body.as_ref())
            .context("set body")?
            .issued_at_unix_millis
            + 1;
        let root_key = hex_field(&f["keys"]["root"]["public_key_hex"])?;
        let set = witness::verify_set(
            b.witness_set.as_ref().context("set")?,
            &witness::SetExpectation {
                authority: "https://weft.example.test",
                root_id: "descriptor-root-1",
                root_public_key: &root_key,
                root_epoch: 1,
                now_unix_millis: now,
                clock_floor_unix_millis: 1_000_000,
                known_job_keys: &[],
            },
            None,
        )?;
        contract::native_witness::verify_bundle_witnesses(&b, &set, now)?;
        let mut geneses = BTreeMap::new();
        for p in &b.genesis_witnesses {
            let g = genesis(p.original_genesis.as_ref().context("original")?)?;
            let id = g.id()?;
            if matches!(g.owner, GenesisOwner::Account(_)) && p.boundary_acceptance.is_none() {
                verify_authority(
                    &p.creator_authority_envelope,
                    &owner,
                    &g.creator,
                    &actor,
                    "/heddle.api.v1alpha2.ThreadService/StartThread",
                    1100,
                )?;
            }
            if let Some(e) = &p.boundary_acceptance {
                verify_native_genesis_boundary(
                    &g,
                    &p.creator_authority_envelope,
                    e,
                    &owner,
                    &set,
                    &hex_field(&f["keys"]["witness"]["public_key_hex"])?,
                )?;
            }
            geneses.insert(id, g);
        }
        let mut claims = BTreeMap::new();
        let mut operations = BTreeMap::new();
        for p in &b.authority_witnesses {
            for r in p.original.iter().chain(p.dependencies.iter()) {
                match r.format.as_str() {
                    "heddle-thread-operation-v1" => {
                        let op = operation(r)?;
                        operations.insert(op.id()?, op);
                    }
                    "heddle-thread-ownership-claim-v1" => {
                        let value = ThreadOwnershipClaim::decode(&r.canonical_record)?;
                        let signed = crypto::thread_ownership_claim::SignedOwnershipClaim {
                            canonical: r.canonical_record.clone(),
                            local_signature: signature(r, &value.prior_local_key)?,
                            acceptance_signature: signature(r, &value.accepting_publisher)?,
                        };
                        let value = signed.verify()?;
                        value.validate_genesis(
                            geneses.get(&value.thread).context("claim genesis")?,
                        )?;
                        claims.insert(value.id()?, value);
                    }
                    "heddle-thread-genesis-v1" | "heddle-thread-ownership-resolution-v1" => (),
                    _ => bail!("unexpected native original"),
                }
            }
        }
        for p in &b.landing_witnesses {
            for r in p
                .execution
                .iter()
                .chain(p.source_operation.iter())
                .chain(p.review_evidence.iter())
            {
                let op = operation(r)?;
                operations.insert(op.id()?, op);
            }
        }
        for op in operations.values() {
            let parents = op
                .parents
                .iter()
                .map(|id| operations.get(id).cloned().context("causal parent"))
                .collect::<Result<Vec<_>>>()?;
            op.validate_parents(
                geneses.get(&op.thread).context("operation genesis")?,
                &parents,
            )?;
            if let ThreadOperationBody::LocalIntegration(bytes) = &op.body {
                let integration = LocalIntegration::decode(bytes)?;
                integration.validate_source(
                    operations
                        .get(&integration.source_operation)
                        .context("local integration source closure")?,
                )?;
            }
        }
        for p in &b.authority_witnesses {
            let r = p.original.as_ref().context("authority original")?;
            let (publisher, actor, method): ([u8; 32], CollaborationActor, &str) = match p.kind {
                1 => {
                    let op = operation(r)?;
                    match op.body {
                        ThreadOperationBody::Capture(c) => {
                            let SourceAuthor::Account {
                                actor, authority, ..
                            } = c.author
                            else {
                                bail!("account source")
                            };
                            ensure!(authority == p.authority_envelope, "exact source authority");
                            (
                                op.publisher,
                                actor,
                                "/heddle.api.v1alpha2.SyncService/PublishContent",
                            )
                        }
                        ThreadOperationBody::Metadata(bytes) => {
                            let control = ThreadControl::decode(&bytes)?;
                            ensure!(
                                control.authority_envelope == p.authority_envelope,
                                "exact metadata authority"
                            );
                            (
                                op.publisher,
                                control.actor.clone(),
                                control.authorization_method(),
                            )
                        }
                        _ => bail!("native source/control operation"),
                    }
                }
                2 => {
                    let c = ThreadOwnershipClaim::decode(&r.canonical_record)?;
                    for id in &c.source_frontier {
                        ensure!(
                            operations.get(id).is_some_and(|o| o.thread == c.thread),
                            "claim frontier closure"
                        );
                    }
                    let SourceAuthor::Account {
                        actor, authority, ..
                    } = c.acceptance
                    else {
                        bail!("account claim")
                    };
                    ensure!(authority == p.authority_envelope, "exact claim authority");
                    (
                        c.accepting_publisher,
                        actor,
                        "/heddle.api.v1alpha2.ThreadService/ClaimThreadOwnership",
                    )
                }
                3 => {
                    let v = ThreadOwnershipResolution::decode(&r.canonical_record)?;
                    v.validate_genesis(geneses.get(&v.thread).context("resolution genesis")?)?;
                    for id in &v.conflicting_claims {
                        ensure!(
                            claims.get(id).is_some_and(|c| c.thread == v.thread),
                            "conflict closure"
                        );
                    }
                    for id in &v.frontier {
                        ensure!(
                            operations.get(id).is_some_and(|o| o.thread == v.thread),
                            "resolution frontier"
                        );
                    }
                    crypto::thread_ownership_resolution::SignedOwnershipResolution {
                        canonical: r.canonical_record.clone(),
                        local_signature: signature(r, &v.local_owner)?,
                        acceptance_signature: signature(r, &v.accepting_publisher)?,
                    }
                    .verify(claims.get(&v.winning_claim).context("winner")?)?;
                    let SourceAuthor::Account {
                        actor, authority, ..
                    } = v.acceptance
                    else {
                        bail!("account resolution")
                    };
                    ensure!(
                        authority == p.authority_envelope,
                        "exact resolution authority"
                    );
                    (
                        v.accepting_publisher,
                        actor,
                        "/heddle.api.v1alpha2.ThreadService/ResolveOwnershipConflict",
                    )
                }
                _ => bail!("native authority kind"),
            };
            verify_authority(
                &p.authority_envelope,
                &owner,
                &publisher,
                &actor,
                method,
                1100,
            )?;
        }
        println!(
            "NATIVE MODEL PASS {name}: original signatures, StartThread/ownership/source authority, causal and acceptance closure"
        );
    }
    Ok(())
}
fn verify_native_genesis_boundary(
    g: &ThreadGenesis,
    envelope: &[u8],
    e: &wire::ImportBoundaryAcceptanceV1,
    owner: &capability_verifier::VerifiedOwnerState,
    set: &witness::VerifiedWitnessSet,
    issuer_key: &[u8],
) -> Result<()> {
    use objects::object::{
        original_boundary_acceptance::OriginalManifestEntry,
        thread_replication::{SourceAuthor, integration::TrustedHostedExecutor},
    };
    let a = e.signed_acceptance.as_ref().context("acceptance")?;
    let acceptance = crypto::original_boundary_acceptance::SignedBoundaryAcceptance {
        canonical: a.canonical_record.clone(),
        signature: signature(
            a,
            &OriginalBoundaryAcceptance::decode(&a.canonical_record)?.accepting_publisher,
        )?,
    }
    .verify_signature()?;
    let manifest = OriginalPublicationManifest::decode(&e.originals_manifest)?;
    let intent: PublicationIntent = rmp_serde::from_slice(&e.publication_intent)?;
    ensure!(
        rmp_serde::to_vec_named(&intent)? == e.publication_intent,
        "native canonical intent"
    );
    let descriptor = OriginalManifestEntry::from_genesis(g, envelope)?;
    let selected = acceptance.selected(&intent, &manifest)?;
    ensure!(
        selected.len() == 1 && selected.contains(&&descriptor),
        "exact native genesis selected"
    );
    let issuer = set
        .body()
        .entries
        .iter()
        .find(|i| i.public_key == issuer_key)
        .context("witness issuer")?;
    let trust = TrustedHostedExecutor {
        spool: intent.spool,
        spool_genesis: intent.spool_genesis,
        executor: issuer.public_key.as_slice().try_into()?,
    };
    let receipt = e.original_receipts.first().context("receipt")?;
    crypto::thread_genesis_admission::SignedGenesisAdmission {
        canonical: receipt.canonical_record.clone(),
        signature: signature(receipt, &trust.executor)?,
        boundary_acceptance: None,
    }
    .verify_signature()?
    .authorize_with_acceptance(g, envelope, &trust, Some(&acceptance))?;
    let SourceAuthor::Account {
        actor, authority, ..
    } = &acceptance.accepting_author
    else {
        bail!("account accepting authority")
    };
    capability_verifier::boundary_authority::verify_accepting_authority(
        authority,
        capability_verifier::thread_control_authority::Context {
            owner,
            account_uuid: actor.principal_id.as_bytes(),
            publisher: &acceptance.accepting_publisher,
            agent_id: actor.agent_id.as_deref(),
            method: "/heddle.api.v1alpha2.ThreadService/StartThread",
            spool_path: "example",
            now: 1100,
        },
        capability_verifier::boundary_authority::OriginalSubjectScope {
            kind: capability_verifier::boundary_authority::BoundarySubjectKind::AccountGenesis,
            account: acceptance.original_account.as_bytes(),
            thread: descriptor.thread.as_bytes(),
            subject: descriptor.subject.id().as_bytes(),
            publisher: &descriptor.publisher,
            agent_id: None,
        },
        &[],
        |_| false,
    )?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("merge-state") => {
            let states: Vec<Vec<u8>> = rmp_serde::from_slice(&input()?)?;
            ensure!(states.len() == 2, "source and target States required");
            let source = State::decode_current_msgpack(&states[0])?;
            let mut target = State::decode_current_msgpack(&states[1])?;
            let mut parents = vec![source.id(), target.id()];
            parents.sort();
            parents.dedup();
            target.parents = parents;
            println!(
                "{}",
                serde_json::json!({
                    "source_id_hex": hex::encode(source.id().as_bytes()),
                    "id_hex": hex::encode(target.id().as_bytes()),
                    "state_hex": hex::encode(target.encode_current_msgpack()?),
                })
            );
        }
        Some("child-state" | "descendant-state") => {
            let mut state = State::decode_current_msgpack(&input()?)?;
            ensure!(
                args[1] == "descendant-state" || state.parents.is_empty(),
                "fixture base must be an initial State"
            );
            let base = state.id();
            state.parents = vec![base];
            state.intent = Some("Native hybrid child capture".into());
            println!(
                "{}",
                serde_json::json!({
                    "base_id_hex": hex::encode(base.as_bytes()),
                    "id_hex": hex::encode(state.id().as_bytes()),
                    "state_hex": hex::encode(state.encode_current_msgpack()?),
                })
            );
        }
        Some("encode") => {
            let format = args.get(2).context("native format required")?;
            println!("{}", hex::encode(encode(format, &input()?)?));
        }
        Some("verify") => {
            let f = read_json(args.get(2).context("fixture path")?)?;
            verify_native(&f)?;
            verify_boundaries(&f)?;
            verify_export(&f, &record(&f, "complete_renewed_export")?)?;
        }
        Some("verify-native-witness") => verify_native_witness_fixture()?,
        Some("verify-capture") => {
            verify_old_capture(&read_json(args.get(2).context("old vector path")?)?)?
        }
        Some("verify-export") => {
            let f = read_json(args.get(2).context("fixture path")?)?;
            let mut bundle: wire::ImportPublicProofBundleV1 =
                record(&f, "complete_renewed_export")?;
            if let Some(option) = args.get(3) {
                ensure!(
                    option == "--without-admission",
                    "unknown export probe option"
                );
                let name = args.get(4).context("branch name")?;
                let payload = bundle
                    .genesis_witnesses
                    .iter()
                    .find(|p| {
                        p.original_genesis
                            .as_ref()
                            .is_some_and(|g| genesis(g).is_ok_and(|g| g.name == *name))
                    })
                    .context("original branch genesis")?;
                let canonical = codec::canonical(payload)?;
                bundle.statements.retain(|s| {
                    s.body
                        .as_ref()
                        .is_none_or(|s| s.canonical_payload != canonical)
                });
            }
            import::validate_public_bundle(&bundle)?;
            println!("export closure accepted");
        }
        _ => bail!(
            "usage: hybrid-native-conformance child-state | descendant-state | encode FORMAT | verify FIXTURE | verify-native-witness | verify-capture OLD_VECTOR | verify-export FIXTURE"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../../tests/fixtures/import-authority-host-witness-v1.json"
        ))
        .expect("fixed vectors")
    }
    #[test]
    fn native_witness_originals_and_start_thread_authority() {
        verify_native_witness_fixture().expect("native model and owner authority");
    }
    #[test]
    fn prepared_commit_matches_native_original_branches() {
        let f = fixture();
        let prepared: wire::PrepareImportJobResponse =
            record(&f, "commit_preparation").expect("preparation");
        let identity = record(&f, "identity").expect("identity");
        let owner = hex_field(&f["keys"]["owner"]["public_key_hex"]).expect("owner");
        let chain = hex_field(&f["context"]["owner_chain_digest_hex"]).expect("chain");
        let expectation = import::ImportOwnerExpectation {
            identity: &identity,
            owner_public_key: &owner,
            owner_chain_digest: &chain,
            authority_expires_at_seconds: 2000,
            now_unix_seconds: 1100,
            forbidden_job_keys: &[],
            known_job_associations: &[],
        };
        let geneses = [
            record(&f, "genesis_dev").expect("dev"),
            record(&f, "genesis_main").expect("main"),
        ];
        let verified = import::verify_prepared_delegation(
            &prepared,
            &record(&f, "delegation").expect("delegation"),
            Some(&record(&f, "permission").expect("parent")),
            &geneses,
            &expectation,
        )
        .expect("completed signed commit");
        let submission: wire::CommitImportJobRequest =
            record(&f, "commit_request").expect("initial submission");
        import::verify_commit_submission(
            &submission,
            &prepared,
            "github",
            &record(&f, "source_connected").expect("current source"),
            &record(&f, "import_configuration").expect("configuration"),
            &expectation,
        )
        .expect("source and signed complete submission");
        for name in ["genesis_dev_payload", "genesis_payload"] {
            let payload: wire::ImportGenesisWitnessV1 = record(&f, name).expect("original payload");
            let original = payload.original_genesis.as_ref().expect("native original");
            let g = genesis(original).expect("published native parse and creator signature");
            let base = objects::object::thread_replication::hosted_import::initial_base_state(
                &g,
                &submission.initial_base_state,
            )
            .expect("same exact canonical empty base for both branches");
            assert!(
                base.parents.is_empty(),
                "initial base cannot carry a nonempty closure"
            );
            let binding = payload.binding.as_ref().expect("binding");
            let signature = signature(original, &g.creator).expect("original creator signature");
            import::verify_genesis_authority(
                binding,
                &verified,
                g.id().expect("native genesis ID").as_bytes(),
                &signature,
                &codec::hash(&[&payload.creator_authority_envelope]),
            )
            .expect("exact prepared branch, original signature and envelope");
        }
        println!(
            "COMMIT NATIVE PASS: prepared branches, original creator signatures and envelopes"
        );
    }
    #[test]
    fn published_harness_pair_is_0287_alpha19() {
        for manifest in [
            include_str!("../Cargo.toml"),
            include_str!("../../../tests/custodial-verifier/Cargo.toml"),
        ] {
            assert!(
                manifest.contains("version = \"=0.31.0-alpha.19\""),
                "published API pin must be alpha.19"
            );
            assert!(
                manifest.contains("\"=0.28.7\""),
                "published heddle pin must be 0.28.7"
            );
            assert!(!manifest.contains("0.28.6") && !manifest.contains("alpha.18"));
        }
        for lock in [
            include_str!("../Cargo.lock"),
            include_str!("../../../tests/custodial-verifier/Cargo.lock"),
        ] {
            assert!(
                lock.contains("version = \"0.28.7\""),
                "locked published heddle must be 0.28.7"
            );
            assert!(
                !lock.contains("version = \"0.28.6\"")
                    && !lock.contains("version = \"0.31.0-alpha.18\"")
            );
        }
    }
    #[test]
    fn boundary_complete_two_and_three_originals() {
        let f = fixture();
        for size in [2, 3] {
            verify_boundary_native(
                &f,
                &format!("boundary_complete_{size}_statement"),
                &format!("boundary_complete_{size}_payload"),
                "genesis",
            )
            .expect("complete distinct subjects must pass");
        }
    }
    #[test]
    fn boundary_duplicate_subject_cannot_cover_missing_original() {
        let f = fixture();
        let error = verify_boundary_native(
            &f,
            "boundary_duplicate_2_statement",
            "boundary_duplicate_2_payload",
            "genesis",
        )
        .expect_err("two distinct signed receipts for main cannot cover dev");
        assert!(
            format!("{error:#}").contains("duplicate receipt subject"),
            "{error:#}"
        );
    }
    #[test]
    fn boundary_enclosing_acceptance_uses_exact_binding() {
        let f = fixture();
        let p: wire::ImportAuthorityWitnessV1 =
            record(&f, "boundary_enclosing_not_first_payload").expect("payload");
        let s: host::SignedHostedWitnessStatementV1 =
            record(&f, "boundary_enclosing_not_first_statement").expect("statement");
        assert_ne!(
            p.boundary_acceptances[0].binding,
            s.body.expect("body").boundary_acceptance,
            "control must select an acceptance beyond the first"
        );
        verify_boundary_native(
            &f,
            "boundary_enclosing_not_first_statement",
            "boundary_enclosing_not_first_payload",
            "authority",
        )
        .expect("exact source acceptance after dependency acceptance");
    }
    #[test]
    fn boundary_all_dependency_acceptances_are_verified() {
        let f = fixture();
        verify_boundary_native(
            &f,
            "boundary_multiple_dependencies_statement",
            "boundary_multiple_dependencies_payload",
            "authority",
        )
        .expect("resolve enclosing acceptance by exact binding");
        let error = verify_boundary_native(
            &f,
            "boundary_invalid_dependency_acceptance_statement",
            "boundary_invalid_dependency_acceptance_payload",
            "authority",
        )
        .expect_err("every dependency acceptance must be verified");
        assert!(
            format!("{error:#}").contains("duplicate receipt subject"),
            "{error:#}"
        );
    }
    #[test]
    fn boundary_receipt_collection_negatives() {
        let f = fixture();
        for v in f["boundary_vectors"]["native_negative"]
            .as_array()
            .expect("native negatives")
        {
            let name = v["name"].as_str().expect("name");
            let error = verify_boundary_native(
                &f,
                v["statement"].as_str().expect("statement"),
                v["payload"].as_str().expect("payload"),
                v["kind"].as_str().expect("kind"),
            )
            .expect_err("incomplete subject coverage");
            assert!(
                format!("{error:#}").contains(v["error"].as_str().expect("expected error")),
                "{name}: {error:#}"
            );
            println!("BOUNDARY NATIVE REJECT {name}: {error:#}");
        }
    }
    #[test]
    fn boundary_substitutions_fail_then_exact_native_control_passes() {
        let f = fixture();
        for v in f["boundary_vectors"]["negative"]
            .as_array()
            .expect("negatives")
        {
            let name = v["name"].as_str().expect("name");
            let s: host::SignedHostedWitnessStatementV1 =
                record(&f, v["statement"].as_str().expect("statement")).expect("statement bytes");
            let p: wire::ImportGenesisWitnessV1 =
                record(&f, v["payload"].as_str().expect("payload")).expect("payload bytes");
            let e = p.boundary_acceptance.as_ref().expect("evidence");
            let a = e.signed_acceptance.as_ref().expect("acceptance");
            let acceptance = crypto::original_boundary_acceptance::SignedBoundaryAcceptance {
                canonical: a.canonical_record.clone(),
                signature: a.signatures[0].signature.clone(),
            }
            .verify_signature()
            .expect("authentic native acceptance");
            let manifest = OriginalPublicationManifest::decode(&e.originals_manifest)
                .expect("canonical complete manifest");
            let intent: PublicationIntent =
                rmp_serde::from_slice(&e.publication_intent).expect("native intent");
            assert_eq!(
                rmp_serde::to_vec_named(&intent).expect("intent bytes"),
                e.publication_intent
            );
            let original = p.original_genesis.as_ref().expect("original");
            let g = genesis(original).expect("original native creator signature");
            let receipt = ThreadGenesisAdmission::decode(&e.original_receipts[0].canonical_record)
                .expect("canonical native receipt");
            match name {
                "acceptance_swapped_between_originals" => {
                    let descriptor = objects::object::original_boundary_acceptance::OriginalManifestEntry::from_genesis(&g, &p.creator_authority_envelope).expect("original descriptor");
                    assert!(
                        !acceptance
                            .selected(&intent, &manifest)
                            .expect("valid other selection")
                            .contains(&&descriptor)
                    );
                }
                "manifest_mismatch" | "intent_mismatch" => assert!(
                    acceptance.selected(&intent, &manifest).is_err(),
                    "signed native selection rejects {name}"
                ),
                "receipt_from_another_acceptance" => {
                    use objects::object::original_boundary_acceptance::BoundaryOriginalKind;
                    assert!(
                        receipt
                            .basis
                            .authorize_evidence(
                                Some(&acceptance),
                                receipt.spool,
                                receipt.owner,
                                Some(BoundaryOriginalKind::AccountGenesis)
                            )
                            .is_err(),
                        "exact native acceptance ID rejects"
                    );
                }
                "missing_binding" => assert_eq!(
                    import::validate_statement_boundary(s.body.as_ref().expect("body")),
                    Err(codec::Reject::BoundaryAcceptance)
                ),
                _ => panic!("unknown boundary control {name}"),
            }
            assert_eq!(
                import::verify_witness_payload(
                    s.body.as_ref().expect("body"),
                    import::WitnessPayload::Genesis(&p)
                ),
                Err(codec::Reject::BoundaryAcceptance)
            );
            println!(
                "BOUNDARY NATIVE REJECT {name}: {}",
                v["first_failing_check"].as_str().expect("intended check")
            );
            verify_boundary_native(
                &f,
                "boundary_genesis_statement",
                "boundary_genesis_payload",
                "genesis",
            )
            .expect("exact native control");
        }
    }
    #[test]
    fn boundary_native_published_codec_vectors() {
        verify_boundaries(&fixture()).expect("native boundary basis, membership and authority");
    }
    #[test]
    fn fixed_native_vectors_and_complete_historical_export() {
        let f = fixture();
        verify_native(&f).expect("native gate");
        verify_export(&f, &record(&f, "complete_renewed_export").expect("export"))
            .expect("historical gate");
    }
    #[test]
    fn old_parentless_capture_is_rejected_by_native_ancestry() {
        let old: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/hybrid-native-old-parentless-v1.json"
        ))
        .expect("old bytes");
        let error = verify_old_capture(&old).expect_err("old capture must fail");
        assert!(
            format!("{error:#}").contains("capture source ancestry differs from causal parents"),
            "{error:#}"
        );
        println!("A REJECT old parentless capture: {error:#}");
    }
    #[test]
    fn old_controls_and_old_export_are_rejected() {
        let old: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/hybrid-native-old-parentless-v1.json"
        ))
        .expect("old bytes");
        for name in ["old_control_wire_hex", "old_review_wire_hex"] {
            let record = wire::SignedRecord::decode(hex_field(&old[name]).expect("hex").as_slice())
                .expect("old record");
            let error = operation(&record).expect_err("old native Vec encoding must fail");
            assert!(
                format!("{error:#}").contains("non-canonical Thread control"),
                "{error:#}"
            );
            println!("A REJECT {name}: {error:#}");
        }
        let bundle = wire::ImportPublicProofBundleV1::decode(
            hex_field(&old["old_export_wire_hex"])
                .expect("hex")
                .as_slice(),
        )
        .expect("old export");
        assert!(bundle.policies.is_empty());
        assert_eq!(
            import::validate_public_bundle(&bundle),
            Err(codec::Reject::Scope)
        );
        println!("B REJECT verbatim acf67659 zero-policy export: Scope");
    }
    #[test]
    fn export_requires_selected_policy_and_each_genesis_original() {
        let f = fixture();
        let b: wire::ImportPublicProofBundleV1 =
            record(&f, "complete_renewed_export").expect("bundle");
        let mut old = b.clone();
        old.policies.clear();
        assert_eq!(
            import::validate_public_bundle(&old),
            Err(codec::Reject::Scope)
        );
        println!("B REJECT old zero-policy export: Scope");
        for i in 0..b.genesis_witnesses.len() {
            let name = genesis(
                b.genesis_witnesses[i]
                    .original_genesis
                    .as_ref()
                    .expect("original"),
            )
            .expect("native genesis")
            .name;
            for part in ["admission", "payload", "genesis", "envelope"] {
                let mut missing = b.clone();
                let payload = &b.genesis_witnesses[i];
                match part {
                    "admission" => missing.statements.retain(|s| {
                        s.body.as_ref().is_none_or(|s| {
                            s.canonical_payload != codec::canonical(payload).expect("payload")
                        })
                    }),
                    "payload" => {
                        missing.genesis_witnesses.remove(i);
                    }
                    "genesis" => missing
                        .original_geneses
                        .retain(|g| Some(g) != payload.original_genesis.as_ref()),
                    "envelope" => missing
                        .creator_authority_envelopes
                        .retain(|e| *e != payload.creator_authority_envelope),
                    _ => unreachable!("fixed parts"),
                }
                assert_eq!(
                    import::validate_public_bundle(&missing),
                    Err(codec::Reject::Scope),
                    "branch {i} {part}"
                );
                println!("B REJECT missing {name} genesis {part}: Scope");
            }
        }
    }
    #[test]
    fn historical_policy_requires_authentic_preimage_and_owner_signature() {
        let f = fixture();
        let b: wire::ImportPublicProofBundleV1 =
            record(&f, "complete_renewed_export").expect("bundle");
        let mut changed = b.clone();
        changed.policies[0]
            .body
            .as_mut()
            .expect("body")
            .policy
            .as_mut()
            .expect("policy")
            .max_audience = Some(1);
        let error = verify_export(&f, &changed).expect_err("policy body mutation");
        assert!(
            error.to_string().contains("policy state preimage"),
            "{error:#}"
        );
        let mut changed = b;
        changed.policies[0]
            .owner_signature
            .as_mut()
            .expect("signature")
            .signature[0] ^= 1;
        let error = verify_export(&f, &changed).expect_err("policy signature mutation");
        assert!(error.to_string().contains("invalid signature"), "{error:#}");
        println!("B REJECT changed policy preimage and original owner signature");
    }
    #[test]
    fn request_binding_rejects_the_old_preimage_and_changed_signature() {
        let f = fixture();
        let landing: wire::HostedLandingWitnessV1 = record(&f, "landing_payload").expect("landing");
        let execution =
            operation(landing.execution.as_ref().expect("execution")).expect("native operation");
        let objects::object::thread_replication::ThreadOperationBody::Integration(bytes) =
            execution.body
        else {
            panic!("integration")
        };
        let mut integration = HostedIntegration::decode(&bytes).expect("integration");
        let request = landing.request.as_ref().expect("request");
        request_binding(request, &integration).expect("passing request control");
        let input = native_api::signing::unary_bytes(
            &request.signing_identity,
            &request.method_path,
            request.timestamp_millis,
            &request.nonce,
            &request.request_body,
        );
        integration.initiating_request_proof =
            ContentHash::compute_typed("heddle-hosted-initiating-request-proof-v1", &input);
        let error = request_binding(request, &integration)
            .expect_err("old domain and missing original signature");
        assert!(
            error
                .to_string()
                .contains("existing hosted initiating-request preimage")
        );
        println!("A REJECT old request preimage: {error}");
        let mut changed = request.clone();
        changed.signature.as_mut().expect("signature").signature[0] ^= 1;
        assert!(request_binding(&changed, &integration).is_err());
    }
}

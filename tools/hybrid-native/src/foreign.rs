//! Fixed-vector staged receiver model. This is API conformance, not repository storage.
use super::*;
use objects::object::thread_replication::{SourceAuthor, ThreadOperationBody};

fn selected_set(f: &Value) -> Result<witness::VerifiedWitnessSet> {
    let root = hex_field(&f["keys"]["root"]["public_key_hex"])?;
    let job = hex_field(&f["keys"]["job"]["public_key_hex"])?;
    Ok(witness::verify_set(
        &record(f, "mixed_set")?,
        &witness::SetExpectation {
            authority: "https://weft.example.test",
            root_id: "descriptor-root-1",
            root_public_key: &root,
            root_epoch: 1,
            now_unix_millis: 1_200_001,
            clock_floor_unix_millis: 1_000_000,
            known_job_keys: &[job],
        },
        None,
    )?)
}
fn import_stage(f: &Value, b: &wire::ImportPublicProofBundleV1) -> Result<()> {
    let owner_key = hex_field(&f["keys"]["owner"]["public_key_hex"])?;
    let root_key = hex_field(&f["keys"]["root"]["public_key_hex"])?;
    let owner = verify_owner_history(b.owner_histories.first().context("owner")?, 1200)?;
    ensure!(
        owner.authority_key().public_key == owner_key,
        "independent owner pin"
    );
    let spool = capability_verifier::wire::SignedSpoolOwnerGenesis::decode(
        b.owner_genesis
            .as_ref()
            .context("spool")?
            .encode_to_vec()
            .as_slice(),
    )?;
    capability_verifier::verify_spool_owner_genesis(&spool)?;
    let id = b
        .delegations
        .first()
        .and_then(|d| d.body.as_ref())
        .and_then(|d| d.identity.as_ref())
        .context("identity")?;
    let chain = b.owner_chain.as_ref().context("chain")?;
    let chain_digest = import::owner_chain_digest(chain)?;
    ensure!(
        id.owner_id == owner.owner_id()
            && id.owner_state_hash == owner.state_hash()
            && chain.owner_state_hashes == [owner.state_hash().to_vec()]
            && chain.spool_genesis_digest
                == capability_verifier::creation::spool_genesis_digest(
                    spool.genesis.as_ref().context("spool genesis")?
                )?,
        "independent lineage"
    );
    let pin = import::ImportWitnessRootPin {
        authority: "https://weft.example.test".into(),
        root_id: "descriptor-root-1".into(),
        public_key: root_key,
        epoch: 1,
    };
    let result = import::verify_import_bundle_witnesses(
        b,
        &pin,
        None,
        1_200_001,
        |_| {
            Ok(import::ImportBundleOwnerExpectation {
                identity: id,
                owner_public_key: &owner_key,
                owner_chain_digest: &chain_digest,
                authority_expires_at_seconds: 2000,
                effective_from_unix_seconds: 0,
                effective_until_unix_seconds: None,
                forbidden_job_keys: &[],
                known_job_associations: &[],
            })
        },
        |bundle, _| {
            for p in &bundle.policies {
                let body = p.body.as_ref().ok_or(codec::Reject::Canonical)?;
                if body.owner_id != owner.owner_id() || body.owner_state_hash != owner.state_hash()
                {
                    return Err(codec::Reject::Scope);
                }
                let canonical =
                    policy_canonical(body, false).map_err(|_| codec::Reject::Canonical)?;
                if body.policy_state_hash
                    != codec::hash(&[b"heddle-spool-signed-policy-v2", &canonical])
                {
                    return Err(codec::Reject::Canonical);
                }
                let canonical =
                    policy_canonical(body, true).map_err(|_| codec::Reject::Canonical)?;
                let signature = p.owner_signature.as_ref().ok_or(codec::Reject::Signature)?;
                codec::verify(
                    &owner_key,
                    &codec::hash(&[b"heddle-spool-signed-policy-signature-v2", &canonical]),
                    &signature.signature,
                )?;
            }
            Ok(())
        },
    )?;
    ensure!(
        result.evidence == import::ImportBundleEvidence::Witnessed,
        "P3-bound stage"
    );
    Ok(())
}

struct InstalledOriginal {
    origin: i32,
    record: wire::SignedRecord,
    job: Option<Vec<u8>>,
}

#[derive(Default)]
struct Receiver {
    // Only stage installation writes these rows. No caller-supplied resolver.
    rows: BTreeMap<Vec<u8>, InstalledOriginal>,
    installed: BTreeSet<String>,
    targets: BTreeSet<String>,
}
impl Receiver {
    fn stage(&mut self, f: &Value, name: &str) -> Result<()> {
        let descriptor = f["stages"]
            .as_array()
            .context("stages")?
            .iter()
            .find(|s| s["id"] == name)
            .context("stage descriptor")?;
        let origin = descriptor["origin"].as_i64().context("origin")? as i32;
        let imported: wire::ImportPublicProofBundleV1 = record(f, "import_stage")?;
        if origin == 1 {
            import_stage(f, &imported)?;
        } else {
            // Native model/owner verification uses the published native verifier.
            let mut context = serde_json::from_str::<Value>(include_str!(
                "../../../tests/fixtures/native-host-witness-v1.json"
            ))?;
            context["wire_vectors"][name] = f["wire_vectors"][name].clone();
            context["positive"] = serde_json::json!([name]);
            verify_native_witness_vectors(&context)?;
        }
        let mut pending = Vec::new();
        for name in descriptor["originals"].as_array().context("originals")? {
            let r: wire::SignedRecord = record(f, name.as_str().context("original name")?)?;
            let op = operation(&r)?;
            let job = if origin == 1 && !matches!(op.source_author()?, Some(SourceAuthor::LocalKey))
            {
                let sidecar = imported
                    .authority_witnesses
                    .iter()
                    .find(|p| p.original.as_ref() == Some(&r))
                    .context("import continuation P2")?;
                let ThreadOperationBody::Metadata(bytes) = &op.body else {
                    bail!("review metadata")
                };
                let control = ThreadControl::decode(bytes)?;
                let owner =
                    verify_owner_history(imported.owner_histories.first().context("owner")?, 1200)?;
                verify_authority(
                    &sidecar.authority_envelope,
                    &owner,
                    &op.publisher,
                    &control.actor,
                    control.authorization_method(),
                    1100,
                )?;
                None
            } else if origin == 1 {
                let d = imported.delegations[0]
                    .body
                    .as_ref()
                    .context("delegation")?;
                ensure!(
                    op.publisher.as_slice() == d.job_public_key,
                    "exact bound job publisher"
                );
                let frontier = import::frontier_digest(&wire::ImportFrontierV1 {
                    format_version: 1,
                    thread_id: op.thread.as_bytes().to_vec(),
                    operation_ids: vec![op.id()?.as_bytes().to_vec()],
                })?;
                let ThreadOperationBody::Capture(capture) = &op.body else {
                    bail!("import capture")
                };
                let content = import::content_digest(&wire::ImportContentV1 {
                    format_version: 1,
                    canonical_capture: rmp_serde::to_vec_named(&capture.result)?,
                })?;
                ensure!(
                    imported
                        .operations
                        .iter()
                        .any(|p| p
                            .body
                            .as_ref()
                            .is_some_and(|p| p.genesis_digest == op.thread.as_bytes()
                                && p.resulting_frontier_digest == frontier
                                && p.resulting_content_digest == content)),
                    "exact P3 frontier/content binding"
                );
                let original_genesis = imported
                    .original_geneses
                    .iter()
                    .find_map(|r| {
                        genesis(r)
                            .ok()
                            .filter(|g| g.id().is_ok_and(|id| id == op.thread))
                    })
                    .context("import genesis")?;
                ensure!(
                    op.validate_parents(&original_genesis, &[]).is_err(),
                    "converted Git root must still reject through the standalone native rule"
                );
                Some(d.job_public_key.clone())
            } else {
                None
            };
            pending.push((
                import::signed_native_digest(&r)?,
                InstalledOriginal {
                    origin,
                    record: r,
                    job,
                },
            ));
        }
        self.rows.extend(pending);
        self.installed.insert(name.into());
        Ok(())
    }
    fn install(&mut self, f: &Value, name: &str, carrier: &str) -> Result<()> {
        let native: wire::NativePublicProofBundleV1 = if carrier == "native" {
            record(f, name)?
        } else {
            record(f, "native_child_stage")?
        };
        let imported: wire::ImportPublicProofBundleV1 = if carrier == "import" {
            record(f, name)?
        } else {
            record(f, "import_stage")?
        };
        let (references, landings) = if carrier == "native" {
            contract::native_witness::verify_bundle_witnesses(
                &native,
                &selected_set(f)?,
                1_200_001,
            )?;
            (&native.foreign_dependencies, &native.landing_witnesses)
        } else {
            import_stage(f, &imported)?;
            (&imported.foreign_dependencies, &imported.landing_witnesses)
        };
        // Recheck receiver-owned origin proofs before any target mutation.
        for stage in &self.installed {
            if stage == "import_stage" {
                import_stage(f, &record(f, stage)?)?;
            } else {
                contract::native_witness::verify_bundle_witnesses(
                    &record(f, stage)?,
                    &selected_set(f)?,
                    1_200_001,
                )?;
            }
        }
        for reference in references {
            let installed = self
                .rows
                .get(&reference.signed_native_digest)
                .ok_or(codec::Reject::Scope)?;
            if installed.origin != reference.origin
                || reference.thread_genesis_digest
                    != operation(&installed.record)?.thread.as_bytes()
            {
                return Err(codec::Reject::Scope.into());
            }
        }
        let job_key = hex_field(&f["keys"]["job"]["public_key_hex"])?;
        let owner = verify_owner_history(native.owner_histories.first().context("owner")?, 1200)?;
        let mut originals: BTreeMap<ContentHash, ThreadOperation> = self
            .rows
            .values()
            .map(|installed| {
                let op = operation(&installed.record)?;
                Ok((op.id()?, op))
            })
            .collect::<Result<_>>()?;
        if carrier == "import" {
            let mut own = Receiver::default();
            own.stage(f, "import_stage")?;
            for installed in own.rows.values() {
                let op = operation(&installed.record)?;
                originals.insert(op.id()?, op);
            }
        }
        for p in &native.authority_witnesses {
            if let Some(r) = &p.original {
                let op = operation(r)?;
                originals.insert(op.id()?, op);
            }
        }
        let genesis_records: Vec<_> = if carrier == "native" {
            native
                .genesis_witnesses
                .iter()
                .filter_map(|p| p.original_genesis.as_ref())
                .collect()
        } else {
            imported
                .genesis_witnesses
                .iter()
                .filter_map(|p| p.original_genesis.as_ref())
                .collect()
        };
        for p in landings {
            let request = p.request.as_ref().context("request")?;
            let request_key = &request
                .signature
                .as_ref()
                .context("request signature")?
                .public_key;
            if *request_key == job_key {
                return Err(codec::Reject::KeyRole.into());
            }
            let source_record = p.source_operation.as_ref().context("source")?;
            let source = operation(source_record)?;
            match source.source_author()? {
                Some(SourceAuthor::LocalKey) => {
                    let digest = import::signed_native_digest(source_record)?;
                    let installed = self
                        .rows
                        .get(&digest)
                        .ok_or(codec::Reject::ImportPermission)?;
                    if installed
                        .job
                        .as_ref()
                        .is_none_or(|job| job.as_slice() != source.publisher)
                    {
                        return Err(codec::Reject::ImportPermission.into());
                    }
                }
                Some(SourceAuthor::Account {
                    actor, authority, ..
                }) => verify_authority(
                    &authority,
                    &owner,
                    &source.publisher,
                    &actor,
                    "/heddle.api.v1alpha2.SyncService/PublishContent",
                    1100,
                )?,
                None => {
                    ensure!(
                        matches!(source.body, ThreadOperationBody::Integration(_)),
                        "hosted integration source"
                    );
                    ensure!(
                        native
                            .landing_witnesses
                            .iter()
                            .any(|p| p.execution.as_ref() == Some(source_record))
                            || imported
                                .landing_witnesses
                                .iter()
                                .any(|p| p.execution.as_ref() == Some(source_record)),
                        "source P4 required"
                    );
                }
            }
            let execution = operation(p.execution.as_ref().context("execution")?)?;
            let ThreadOperationBody::Integration(bytes) = &execution.body else {
                bail!("hosted integration")
            };
            let integration = HostedIntegration::decode(bytes)?;
            integration.validate_source(&source)?;
            let review_ids = p
                .review_evidence
                .iter()
                .map(|r| Ok(operation(r)?.id()?))
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                review_ids.len() == integration.review_evidence.len()
                    && review_ids
                        .iter()
                        .all(|id| integration.review_evidence.contains(id)),
                "exact native review closure"
            );
            request_binding(request, &integration)?;
            let g = genesis_records
                .iter()
                .find_map(|r| {
                    genesis(r)
                        .ok()
                        .filter(|g| g.id().is_ok_and(|id| id == execution.thread))
                })
                .context("target genesis")?;
            let parents = execution
                .parents
                .iter()
                .map(|id| originals.get(id).cloned().context("target parent"))
                .collect::<Result<Vec<_>>>()?;
            execution.validate_parents(&g, &parents)?;
        }
        self.targets.insert(name.into());
        Ok(())
    }
}
pub(super) fn verify() -> Result<()> {
    let f = serde_json::from_str::<Value>(include_str!(
        "../../../tests/fixtures/foreign-dependencies-alpha34.json"
    ))?;
    for v in f["positive"].as_array().context("positives")? {
        let mut receiver = Receiver::default();
        let stage = v["stage"].as_str().context("stage")?;
        receiver.stage(&f, stage)?;
        receiver.install(
            &f,
            v["id"].as_str().context("name")?,
            v["carrier"].as_str().context("carrier")?,
        )?;
        println!("STAGED PASS {}", v["id"]);
    }
    for v in f["receiver_negative"].as_array().context("negatives")? {
        let control = v["control"].as_str().context("control")?;
        let descriptor = f["positive"]
            .as_array()
            .context("positives")?
            .iter()
            .find(|p| p["id"] == control)
            .context("control")?;
        let stage = descriptor["stage"].as_str().context("stage")?;
        let carrier = descriptor["carrier"].as_str().context("carrier")?;
        let mut receiver = Receiver::default();
        if v["omit_stage"] != true {
            receiver.stage(&f, stage)?;
        }
        if v["unbind"] == true {
            for installed in receiver.rows.values_mut() {
                installed.job = None;
            }
        }
        let counts = (
            receiver.rows.len(),
            receiver.installed.len(),
            receiver.targets.len(),
        );
        let id = v["id"].as_str().context("id")?;
        let result = receiver.install(
            &f,
            if id == "job_signed_landing" {
                id
            } else {
                control
            },
            carrier,
        );
        let error = match result {
            Err(error) => error,
            Ok(()) => bail!("receiver must reject"),
        };
        ensure!(
            format!(
                "{:?}",
                error
                    .downcast_ref::<codec::Reject>()
                    .context("typed reject")?
            ) == v["expected"].as_str().context("reason")?,
            "{id}: {error}"
        );
        ensure!(
            counts
                == (
                    receiver.rows.len(),
                    receiver.installed.len(),
                    receiver.targets.len()
                ),
            "no state change"
        );
        receiver.stage(&f, stage)?;
        receiver.install(&f, control, carrier)?;
        println!("STAGED REJECT {id}: {error}; unchanged state; PASS exact control");
    }
    Ok(())
}

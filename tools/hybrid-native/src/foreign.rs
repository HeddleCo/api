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
                forbidden_landing_keys: &[],
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
    admission_order: u64,
    admission_purpose: i32,
    stage: String,
    spool: Vec<u8>,
    thread: Vec<u8>,
    authority: String,
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
        let imported: wire::ImportPublicProofBundleV1 = record(
            f,
            if origin == wire::ForeignDependencyOrigin::Import as i32 {
                name
            } else {
                "import_stage"
            },
        )?;
        if origin == wire::ForeignDependencyOrigin::Import as i32 {
            import_stage(f, &imported)?;
        } else {
            // Native model/owner verification uses the published native verifier.
            let mut context = serde_json::from_str::<Value>(include_str!(
                "../../../tests/fixtures/native-host-witness-v1.json"
            ))?;
            context["wire_vectors"][name] = f["wire_vectors"][name].clone();
            context["positive"] = serde_json::json!([name]);
            let native: wire::NativePublicProofBundleV1 = record(f, name)?;
            contract::native_witness::verify_bundle_witnesses(
                &native,
                &selected_set(f)?,
                1_200_001,
                &[],
            )?;
            if native.foreign_dependencies.is_empty() && native.landing_witnesses.is_empty() {
                verify_native_witness_vectors(&context)?;
            }
        }
        let mut pending = Vec::new();
        for record_name in descriptor["originals"].as_array().context("originals")? {
            let r: wire::SignedRecord = record(f, record_name.as_str().context("original name")?)?;
            let op = operation(&r)?;
            let job = if matches!(op.body, ThreadOperationBody::Integration(_)) {
                None
            } else if origin == wire::ForeignDependencyOrigin::Import as i32
                && !matches!(op.source_author()?, Some(SourceAuthor::LocalKey))
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
            } else if origin == wire::ForeignDependencyOrigin::Import as i32 {
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
            let native: wire::NativePublicProofBundleV1 = record(
                f,
                if origin == wire::ForeignDependencyOrigin::Native as i32 {
                    name
                } else {
                    "native_child_stage"
                },
            )?;
            let (statements, p2, p4, spool, set) =
                if origin == wire::ForeignDependencyOrigin::Import as i32 {
                    (
                        &imported.statements,
                        &imported.authority_witnesses,
                        &imported.landing_witnesses,
                        &imported.owner_genesis,
                        &imported.witness_set,
                    )
                } else {
                    if let Some(SourceAuthor::Account {
                        actor, authority, ..
                    }) = op.source_author()?
                    {
                        let owner = verify_owner_history(
                            native.owner_histories.first().context("owner")?,
                            1200,
                        )?;
                        verify_authority(
                            &authority,
                            &owner,
                            &op.publisher,
                            &actor,
                            "/heddle.api.v1alpha2.SyncService/PublishContent",
                            1100,
                        )?;
                    }
                    (
                        &native.statements,
                        &native.authority_witnesses,
                        &native.landing_witnesses,
                        &native.owner_genesis,
                        &native.witness_set,
                    )
                };
            let spool = spool
                .as_ref()
                .and_then(|g| g.genesis.as_ref())
                .context("spool")?
                .spool_uuid
                .clone();
            let authority = set
                .as_ref()
                .and_then(|s| s.body.as_ref())
                .context("set")?
                .deployment_authority
                .clone();
            let admission = statements
                .iter()
                .filter_map(|s| s.body.as_ref())
                .find(|s| match s.purpose {
                    2 => p2.iter().any(|p| {
                        p.original.as_ref() == Some(&r)
                            && codec::canonical(p).is_ok_and(|v| v == s.canonical_payload)
                    }),
                    4 => p4.iter().any(|p| {
                        p.execution.as_ref() == Some(&r)
                            && codec::canonical(p).is_ok_and(|v| v == s.canonical_payload)
                    }),
                    3 if job.is_some() => imported.operations.iter().any(|o| {
                        o.body
                            .as_ref()
                            .is_some_and(|o| o.genesis_digest == op.thread.as_bytes())
                            && imported.manifests.iter().any(|m| {
                                import::publication_payload(o, m)
                                    .and_then(|p| codec::canonical(&p))
                                    .is_ok_and(|v| v == s.canonical_payload)
                            })
                    }),
                    _ => false,
                })
                .context("exact original admission")?;
            pending.push((
                import::signed_native_digest(&r)?,
                InstalledOriginal {
                    origin,
                    record: r,
                    job,
                    admission_order: admission.admission_order,
                    admission_purpose: admission.purpose,
                    stage: name.into(),
                    spool,
                    thread: op.thread.as_bytes().to_vec(),
                    authority,
                },
            ));
        }
        self.rows.extend(pending);
        self.installed.insert(name.into());
        Ok(())
    }
    fn install_prefix(
        &mut self,
        f: &Value,
        name: &str,
        catalog: &[Value],
        visiting: &mut Vec<String>,
    ) -> Result<()> {
        if self.installed.contains(name) {
            return Ok(());
        }
        let prefix = catalog
            .iter()
            .find(|p| p["id"] == name)
            .ok_or(codec::Reject::Scope)?;
        let key = format!(
            "{}:{}:{}:{}",
            prefix["carrier"],
            prefix["thread_genesis_digest"],
            prefix["signed_native_digest"],
            prefix["cutoff"]
        );
        if visiting.contains(&key) {
            return Err(codec::Reject::Scope.into());
        }
        if visiting.len() > catalog.len() {
            return Err(codec::Reject::Bounds.into());
        }
        visiting.push(key.clone());
        let carrier = prefix["carrier"].as_str().context("carrier")?;
        let references = if carrier == "native" {
            record::<wire::NativePublicProofBundleV1>(f, name)?.foreign_dependencies
        } else {
            record::<wire::ImportPublicProofBundleV1>(f, name)?.foreign_dependencies
        };
        for reference in references {
            let foreign = catalog
                .iter()
                .find(|p| {
                    p["thread_genesis_digest"].as_str()
                        == Some(&hex::encode(&reference.thread_genesis_digest))
                        && p["cutoff"].as_str().and_then(|c| c.parse::<u64>().ok())
                            == Some(reference.prefix_admission_order)
                        && p["signed_native_digest"].as_str()
                            == Some(&hex::encode(&reference.signed_native_digest))
                })
                .ok_or(codec::Reject::Scope)?;
            self.install_prefix(
                f,
                foreign["id"].as_str().context("prefix id")?,
                catalog,
                visiting,
            )?;
        }
        self.install(f, name, carrier)?;
        self.stage(f, name)?;
        visiting.pop();
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
                &[],
            )?;
            (&native.foreign_dependencies, &native.landing_witnesses)
        } else {
            import_stage(f, &imported)?;
            (&imported.foreign_dependencies, &imported.landing_witnesses)
        };
        // Recheck receiver-owned origin proofs before any target mutation.
        for stage in &self.installed {
            if f["stages"].as_array().context("stages")?.iter().any(|p| {
                p["id"] == *stage
                    && p["origin"].as_i64() == Some(wire::ForeignDependencyOrigin::Import as i64)
            }) {
                import_stage(f, &record(f, stage)?)?;
            } else {
                contract::native_witness::verify_bundle_witnesses(
                    &record(f, stage)?,
                    &selected_set(f)?,
                    1_200_001,
                &[],
                )?;
            }
        }
        let (spool, authority) = if carrier == "native" {
            (
                native
                    .owner_genesis
                    .as_ref()
                    .and_then(|g| g.genesis.as_ref())
                    .context("spool")?
                    .spool_uuid
                    .as_slice(),
                native
                    .witness_set
                    .as_ref()
                    .and_then(|s| s.body.as_ref())
                    .context("set")?
                    .deployment_authority
                    .as_str(),
            )
        } else {
            (
                imported
                    .owner_genesis
                    .as_ref()
                    .and_then(|g| g.genesis.as_ref())
                    .context("spool")?
                    .spool_uuid
                    .as_slice(),
                imported
                    .witness_set
                    .as_ref()
                    .and_then(|s| s.body.as_ref())
                    .context("set")?
                    .deployment_authority
                    .as_str(),
            )
        };
        for reference in references {
            let installed = self
                .rows
                .get(&reference.signed_native_digest)
                .ok_or(codec::Reject::Scope)?;
            if installed.origin != reference.origin
                || installed.admission_order != reference.prefix_admission_order
                || installed.spool != spool
                || installed.authority != authority
                || reference.thread_genesis_digest != installed.thread
            {
                return Err(codec::Reject::Scope.into());
            }
        }
        let records = if carrier == "native" {
            (&native.authority_witnesses, &native.landing_witnesses)
        } else {
            (&imported.authority_witnesses, &imported.landing_witnesses)
        };
        for reference in references {
            let installed = self
                .rows
                .get(&reference.signed_native_digest)
                .ok_or(codec::Reject::Scope)?;
            let referenced = records
                .0
                .iter()
                .flat_map(|p| p.dependencies.iter())
                .chain(
                    records
                        .1
                        .iter()
                        .flat_map(|p| p.source_operation.iter().chain(p.review_evidence.iter())),
                )
                .find(|r| {
                    import::signed_native_digest(r)
                        .is_ok_and(|d| d == reference.signed_native_digest)
                })
                .ok_or(codec::Reject::Scope)?;
            if referenced != &installed.record {
                return Err(codec::Reject::Scope.into());
            }
            operation(&installed.record)?;
        }

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
                }) => {
                    let digest = import::signed_native_digest(source_record)?;
                    let installed = self.rows.get(&digest).ok_or(codec::Reject::Scope)?;
                    if installed.admission_purpose != 2 {
                        return Err(codec::Reject::Scope.into());
                    }
                    verify_authority(
                        &authority,
                        &owner,
                        &source.publisher,
                        &actor,
                        "/heddle.api.v1alpha2.SyncService/PublishContent",
                        1100,
                    )?;
                }
                None => {
                    ensure!(
                        matches!(source.body, ThreadOperationBody::Integration(_)),
                        "hosted integration source"
                    );
                    let digest = import::signed_native_digest(source_record)?;
                    let installed = self.rows.get(&digest).ok_or(codec::Reject::Scope)?;
                    if installed.admission_purpose != 4 {
                        return Err(codec::Reject::Scope.into());
                    }
                    let stage_name = &installed.stage;
                    let admitted =
                        if installed.origin == wire::ForeignDependencyOrigin::Import as i32 {
                            record::<wire::ImportPublicProofBundleV1>(f, stage_name)?
                                .landing_witnesses
                                .iter()
                                .any(|p| p.execution.as_ref() == Some(source_record))
                        } else {
                            record::<wire::NativePublicProofBundleV1>(f, stage_name)?
                                .landing_witnesses
                                .iter()
                                .any(|p| p.execution.as_ref() == Some(source_record))
                        };
                    if !admitted {
                        return Err(codec::Reject::Scope.into());
                    }
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
            .chain(f["prefixes"].as_array().context("prefixes")?)
            .find(|p| p["id"] == control)
            .context("control")?;
        let stage = v["prefix_setup"]
            .as_str()
            .or_else(|| descriptor["stage"].as_str())
            .context("stage")?;
        let carrier = descriptor["carrier"].as_str().context("carrier")?;
        let mut receiver = Receiver::default();
        if v["prefix_setup"].is_string() {
            receiver.install_prefix(
                &f,
                stage,
                f["prefixes"].as_array().context("prefixes")?,
                &mut Vec::new(),
            )?;
        } else if v["omit_stage"] != true {
            receiver.stage(&f, stage)?;
        }
        for installed in receiver.rows.values_mut() {
            if v["unbind"] == true {
                installed.job = None;
            }
            if v["unadmit"].as_i64() == Some(installed.admission_purpose as i64) {
                installed.admission_purpose = 0;
            }
            match v["row_mismatch"].as_str() {
                Some("origin") => installed.origin = wire::ForeignDependencyOrigin::Native as i32,
                Some("thread") => installed.thread = vec![0; 32],
                Some("spool") => installed.spool = vec![0; 16],
                Some("authority") => installed.authority = "https://other.example.test".into(),
                Some("order") => installed.admission_order += 1,
                Some("bytes") => installed.record.signatures[0].signature[0] ^= 1,
                _ => (),
            }
        }
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
        receiver.stage(&f, stage)?;
        receiver.install(&f, control, carrier)?;
        println!("STAGED REJECT {id}: {error}; PASS exact control");
    }
    let catalog = f["prefixes"].as_array().context("prefixes")?;
    let mut receiver = Receiver::default();
    for name in f["fresh_receiver"]["roots"].as_array().context("roots")? {
        receiver.install_prefix(&f, name.as_str().context("root")?, catalog, &mut Vec::new())?;
    }
    ensure!(
        receiver.installed.len()
            == f["fresh_receiver"]["expected_prefixes"]
                .as_array()
                .context("expected")?
                .len(),
        "all prefixes installed"
    );
    println!("PREFIX PASS bidirectional fresh receiver");
    let cycle_catalog = catalog
        .iter()
        .filter(|p| {
            f["cycle_negative"]["prefixes"]
                .as_array()
                .is_some_and(|ids| ids.contains(&p["id"]))
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut receiver = Receiver::default();
    let error = receiver.install_prefix(
        &f,
        f["cycle_negative"]["root"].as_str().context("cycle root")?,
        &cycle_catalog,
        &mut Vec::new(),
    );
    let error = match error {
        Err(error) => error,
        Ok(()) => bail!("genuine cycle must reject"),
    };
    ensure!(
        error.downcast_ref::<codec::Reject>() == Some(&codec::Reject::Scope),
        "cycle Scope"
    );
    receiver.install_prefix(
        &f,
        f["cycle_negative"]["control"]
            .as_str()
            .context("cycle control")?,
        catalog,
        &mut Vec::new(),
    )?;
    println!("PREFIX REJECT genuine cycle; PASS exact control");
    Ok(())
}

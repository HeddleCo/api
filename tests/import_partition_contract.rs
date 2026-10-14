use ed25519_dalek::{Signer, SigningKey};
use heddle_api::heddle::api::v1alpha2 as api;
use heddle_api::{hybrid_codec as codec, import_authority as import};
use prost::Message;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/import-partition-alpha49.json")).expect("goldens")
}
fn base() -> Value {
    serde_json::from_str(heddle_api::IMPORT_AUTHORITY_HOST_WITNESS_V1_FIXTURE_JSON)
        .expect("frozen alpha.27 flow")
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex")).expect("bytes")
}
fn vector<T: Message + Default>(f: &Value, name: &str) -> T {
    let v = if f["signed_vectors"][name].is_null() {
        &f["wire_vectors"][name]
    } else {
        &f["signed_vectors"][name]
    };
    T::decode(bytes(&v["wire_hex"]).as_slice()).expect("frozen vector")
}
fn key(f: &Value, name: &str) -> SigningKey {
    SigningKey::from_bytes(
        &bytes(&f["keys"][name]["seed_hex"])
            .try_into()
            .expect("seed"),
    )
}
fn auth(
    body: &impl codec::Canonical,
    key: &SigningKey,
    domain: &str,
) -> api::AuthorizationSignature {
    api::AuthorizationSignature {
        signer_key_id: codec::key_id(&key.verifying_key().to_bytes()),
        signature: key
            .sign(&codec::signing_digest(domain, body).expect("canonical body"))
            .to_bytes()
            .to_vec(),
    }
}
fn materials(f: &Value) -> Vec<(api::ImportBranchLimitV1, api::SignedRecord)> {
    f["selection"]
        .as_array()
        .expect("selection")
        .iter()
        .map(|m| {
            (
                api::ImportBranchLimitV1::decode(bytes(&m["limit_wire_hex"]).as_slice())
                    .expect("limit"),
                api::SignedRecord::decode(bytes(&m["original_wire_hex"]).as_slice())
                    .expect("original"),
            )
        })
        .collect()
}
fn build_job(
    branches: &[api::ImportBranchLimitV1],
    materials: &[(api::ImportBranchLimitV1, api::SignedRecord)],
) -> Result<api::ImportPublicProofBundleV1, codec::Reject> {
    let f = base();
    let mut scope: api::ImportPermissionScopeV1 = vector(&f, "scope");
    scope.branches = branches.to_vec();
    scope.max_operations = 256;
    scope.max_result_bytes = u64::MAX;
    scope.source_url = format!(
        "https://example.test/{}",
        "a".repeat(2048 - "https://example.test/".len())
    );
    scope.provider = "public-git".into();
    scope.converter_version = "c".repeat(128);
    scope.options_digest = import::conversion_options_digest(
        &scope.converter_version,
        &vector::<api::GetImportConfigurationResponse>(&f, "import_configuration").converters[0]
            .canonical_options[0],
    )?;
    let seed = codec::hash(&[b"partition-job\0", &branches[0].genesis_digest]);
    let job_key = SigningKey::from_bytes(&seed.as_slice().try_into().expect("hash width"));
    let mut parent = vector::<api::SignedImportMemberPermissionV1>(&f, "permission")
        .body
        .expect("body");
    parent.scope = Some(scope.clone());
    parent.logical_job_id = seed[..16].to_vec();
    parent.retry_lineage_id = seed[16..].to_vec();
    let permission = api::SignedImportMemberPermissionV1 {
        owner_signature: Some(auth(&parent, &key(&f, "owner"), import::PERMISSION_DOMAIN)),
        body: Some(parent.clone()),
    };
    let envelope = [
        b"heddle-signed-import-member-permission-v1\0".as_slice(),
        &codec::canonical(&permission)?,
    ]
    .concat();
    let originals: Vec<_> = branches
        .iter()
        .map(|b| {
            materials
                .iter()
                .find(|(m, _)| m.ref_name == b.ref_name)
                .expect("material")
                .1
                .clone()
        })
        .collect();
    let bindings: Vec<_> = branches
        .iter()
        .zip(&originals)
        .map(|(b, o)| {
            let mut g = vector::<api::SignedImportGenesisAuthorityV1>(&f, "genesis_dev")
                .body
                .expect("body");
            g.genesis_digest = b.genesis_digest.clone();
            g.original_creator_signature = o.signatures[0].signature.clone();
            g.parent_permission_digest =
                import::signed_permission_digest(&permission).expect("permission");
            g.creator_authority_envelope_digest = codec::hash(&[&envelope]);
            api::SignedImportGenesisAuthorityV1 {
                creator_signature: Some(auth(&g, &key(&f, "device"), import::GENESIS_DOMAIN)),
                body: Some(g),
            }
        })
        .collect();
    let mut d = vector::<api::SignedImportJobDelegationV1>(&f, "delegation")
        .body
        .expect("body");
    d.logical_job_id = parent.logical_job_id;
    d.retry_lineage_id = parent.retry_lineage_id;
    d.delegation_id = codec::hash(&[&seed])[..16].to_vec();
    d.job_public_key = job_key.verifying_key().to_bytes().to_vec();
    d.job_key_id = codec::key_id(&d.job_public_key);
    d.scope = Some(scope);
    d.parent_permission_digest = import::signed_permission_digest(&permission)?;
    d.branch_manifest = branches
        .iter()
        .zip(&bindings)
        .map(|(b, g)| {
            Ok(api::ImportBranchManifestV1 {
                limit: Some(b.clone()),
                genesis_authority_digest: import::signed_genesis_digest(g)?,
            })
        })
        .collect::<Result<_, codec::Reject>>()?;
    let delegation = api::SignedImportJobDelegationV1 {
        delegating_signature: Some(auth(&d, &key(&f, "device"), import::DELEGATION_DOMAIN)),
        body: Some(d),
    };
    let mut proof = vector::<api::CommitImportJobRequest>(&f, "commit_request")
        .proof
        .expect("proof");
    proof.format_version = 2;
    proof.member_permission = Some(permission);
    proof.delegations = vec![delegation];
    proof.genesis_authorities = bindings;
    proof.original_geneses = originals;
    proof.creator_authority_envelopes = vec![envelope];
    Ok(proof)
}
fn verify(proof: &api::ImportPublicProofBundleV1) {
    let f = base();
    let mut request: api::CommitImportJobRequest = vector(&f, "commit_request");
    request.proof = Some(proof.clone());
    let d = proof.delegations[0].body.as_ref().expect("body");
    let scope = d.scope.as_ref().expect("scope");
    let mut source: api::ProviderRepository = vector(&f, "source_public_github");
    source.clone_url = scope.source_url.clone();
    source.provider_repository_id.clear();
    source.connection = None;
    source.installation_id.clear();
    source.hash_algorithm = 2;
    source.refs = scope
        .branches
        .iter()
        .map(|b| api::ProviderRef {
            name: b.ref_name.clone(),
            kind: 1,
            hash_algorithm: 2,
            head_oid: hex::encode(&b.pinned_commit_oid),
        })
        .collect();
    request.source = Some(source.clone());
    let mut config: api::GetImportConfigurationResponse = vector(&f, "import_configuration");
    config.import_proof_bundle_format_version = 2;
    config.limits.as_mut().expect("limits").max_branches = import::MAX_BRANCHES as u32;
    config.limits.as_mut().expect("limits").max_result_bytes = scope.max_result_bytes;
    config.converters[0].converter_version = scope.converter_version.clone();
    config.default_converter_version = Some(scope.converter_version.clone());
    let mut prepared: api::PrepareImportJobResponse = vector(&f, "commit_preparation");
    prepared.proposal = Some(import::delegation_preparation(d));
    let identity = vector(&f, "identity");
    let owner_key = bytes(&f["keys"]["owner"]["public_key_hex"]);
    let chain = bytes(&f["context"]["owner_chain_digest_hex"]);
    let expected = import::ImportOwnerExpectation {
        identity: &identity,
        owner_public_key: &owner_key,
        owner_chain_digest: &chain,
        authority_expires_at_seconds: 2000,
        now_unix_seconds: 1100,
        forbidden_job_keys: &[],
        known_job_associations: &[],
    };
    import::verify_commit_submission(
        &request,
        &prepared,
        "public-git",
        &source,
        &config,
        &expected,
    )
    .expect("complete signed Commit");
}
#[test]
fn partition_rust_ts_shared_golden_jobs_all_verify() {
    let f = fixture();
    let materials = materials(&f);
    let branches: Vec<_> = materials.iter().map(|(b, _)| b.clone()).collect();
    for c in f["cases"].as_array().expect("cases") {
        let limits = import::ImportPartitionLimits {
            max_branches: c["max_branches"].as_u64().expect("count") as usize,
            max_record_bytes: c["max_record_bytes"].as_u64().expect("record") as usize,
            max_bundle_bytes: c["max_bundle_bytes"].as_u64().expect("proof") as usize,
            build_job: |b: &[api::ImportBranchLimitV1]| build_job(b, &materials),
        };
        let jobs = import::partition_import_branches(&branches, &limits).expect("partition");
        assert_eq!(jobs.len(), c["jobs"].as_array().expect("jobs").len());
        for (p, v) in jobs.iter().zip(c["jobs"].as_array().expect("jobs")) {
            assert_eq!(
                p.delegations[0]
                    .body
                    .as_ref()
                    .expect("body")
                    .scope
                    .as_ref()
                    .expect("scope")
                    .branches
                    .len(),
                v["count"].as_u64().expect("count") as usize
            );
            assert_eq!(
                codec::canonical(&p.delegations[0]).expect("record").len(),
                v["record_bytes"].as_u64().expect("record") as usize
            );
            assert_eq!(
                p.encoded_len(),
                v["proof_bytes"].as_u64().expect("proof") as usize
            );
            assert_eq!(
                hex::encode(codec::hash(&[&p.encode_to_vec()])),
                v["proof_sha256"].as_str().expect("digest")
            );
            verify(p);
        }
        assert_eq!(
            jobs.iter()
                .flat_map(|p| &p.delegations[0]
                    .body
                    .as_ref()
                    .expect("body")
                    .scope
                    .as_ref()
                    .expect("scope")
                    .branches)
                .cloned()
                .collect::<Vec<_>>(),
            branches
        );
        println!("PARTITION {}: {} jobs verified", c["id"], jobs.len());
    }
}
#[test]
fn worst_case_at_max_branches_fits_and_verifies() {
    let f = fixture();
    let materials = materials(&f);
    let branches: Vec<_> = materials.iter().map(|(b, _)| b.clone()).collect();
    assert_eq!(import::MAX_BRANCHES, 25);
    assert!(
        branches
            .iter()
            .all(|b| b.ref_name.len() == 1024 && b.pinned_commit_oid.len() == 32)
    );
    let p = build_job(&branches[..import::MAX_BRANCHES], &materials).expect("worst job");
    verify(&p);
    assert!(p.encoded_len() <= import::MAX_BUNDLE_BYTES);
    assert!(codec::canonical(&p.delegations[0]).expect("record").len() <= import::MAX_RECORD_BYTES);
    let mut d = p.delegations[0].clone();
    d.body
        .as_mut()
        .expect("body")
        .scope
        .as_mut()
        .expect("scope")
        .provider = "p".repeat(64);
    assert_eq!(codec::canonical(&d).expect("maximum provider").len(), 63404);
    let mut over = build_job(&branches[..26], &materials).expect("over-count material");
    over.delegations[0]
        .body
        .as_mut()
        .expect("body")
        .scope
        .as_mut()
        .expect("scope")
        .provider = "p".repeat(64);
    assert_eq!(
        codec::canonical(&over.delegations[0])
            .expect("over-bound record")
            .len(),
        65824
    );
    println!(
        "BOUNDARY 25 branches: record {}, proof {}",
        codec::canonical(&p.delegations[0]).expect("record").len(),
        p.encoded_len()
    );
}
#[test]
fn partition_rejects_bad_order_limits_and_oversized_singletons() {
    let f = fixture();
    let materials = materials(&f);
    let mut branches: Vec<_> = materials.iter().map(|(b, _)| b.clone()).collect();
    let mut limits = import::ImportPartitionLimits {
        max_branches: 25,
        max_record_bytes: 65536,
        max_bundle_bytes: import::MAX_BUNDLE_BYTES,
        build_job: |b: &[api::ImportBranchLimitV1]| build_job(b, &materials),
    };
    assert!(
        import::partition_import_branches(&[], &limits)
            .expect("empty")
            .is_empty()
    );
    branches.reverse();
    assert_eq!(
        import::partition_import_branches(&branches, &limits),
        Err(codec::Reject::Canonical)
    );
    branches.reverse();
    limits.max_record_bytes = 1;
    assert_eq!(
        import::partition_import_branches(&branches, &limits),
        Err(codec::Reject::Bounds)
    );
    limits.max_record_bytes = 65536;
    limits.max_bundle_bytes = 1;
    assert_eq!(
        import::partition_import_branches(&branches, &limits),
        Err(codec::Reject::Bounds)
    );
    limits.max_bundle_bytes = import::MAX_BUNDLE_BYTES;
    limits.max_branches = 26;
    assert_eq!(
        import::partition_import_branches(&branches, &limits),
        Err(codec::Reject::Bounds)
    );
}
#[test]
fn format_two_dedup_preserves_frozen_signed_bytes() {
    let f = base();
    let mut request: api::CommitImportJobRequest = vector(&f, "commit_request");
    let original = request.proof.clone().expect("proof");
    let mut source: api::ProviderRepository = vector(&f, "source_connected");
    source.refs = original.delegations[0]
        .body
        .as_ref()
        .expect("body")
        .scope
        .as_ref()
        .expect("scope")
        .branches
        .iter()
        .map(|b| api::ProviderRef {
            name: b.ref_name.clone(),
            kind: 1,
            hash_algorithm: 1,
            head_oid: hex::encode(&b.pinned_commit_oid),
        })
        .collect();
    let mut config: api::GetImportConfigurationResponse = vector(&f, "import_configuration");
    import::validate_commit_request(&request, "github", &source, &config).expect("frozen format 1");
    request.proof.as_mut().expect("proof").format_version = 2;
    request
        .proof
        .as_mut()
        .expect("proof")
        .creator_authority_envelopes
        .truncate(1);
    assert_eq!(
        import::validate_commit_request(&request, "github", &source, &config),
        Err(codec::Reject::Version)
    );
    config.import_proof_bundle_format_version = 2;
    config.limits.as_mut().expect("limits").max_branches = 25;
    import::validate_commit_request(&request, "github", &source, &config).expect("format 2");
    let p = request.proof.as_ref().expect("proof");
    assert_eq!(p.member_permission, original.member_permission);
    assert_eq!(p.delegations, original.delegations);
    assert_eq!(p.genesis_authorities, original.genesis_authorities);
    assert_eq!(p.original_geneses, original.original_geneses);
    let envelope = p.creator_authority_envelopes[0].clone();
    request
        .proof
        .as_mut()
        .expect("proof")
        .creator_authority_envelopes
        .push(envelope);
    assert_eq!(
        import::validate_commit_request(&request, "github", &source, &config),
        Err(codec::Reject::Canonical)
    );
    request.proof = Some(original);
    import::validate_commit_request(&request, "github", &source, &config)
        .expect("old format stays supported");
}

#[test]
fn proof_size_is_linear_at_16_64_and_256_branches() {
    let f = fixture();
    let mut sizes = Vec::new();
    for v in f["sizes"].as_array().expect("size goldens") {
        let mut proof =
            api::ImportPublicProofBundleV1::decode(bytes(&v["after_wire_hex"]).as_slice())
                .expect("measured carrier");
        let after = proof.encoded_len();
        assert_eq!(after, v["after"].as_u64().expect("size") as usize);
        let n = v["branches"].as_u64().expect("branches") as usize;
        assert_eq!(proof.creator_authority_envelopes.len(), 1);
        assert_eq!(proof.genesis_authorities.len(), n);
        assert!(proof.genesis_authorities.iter().all(|g| {
            g.body
                .as_ref()
                .expect("body")
                .creator_authority_envelope_digest
                == codec::hash(&[&proof.creator_authority_envelopes[0]])
        }));
        proof.format_version = 1;
        proof.creator_authority_envelopes = vec![proof.creator_authority_envelopes[0].clone(); n];
        assert_eq!(
            proof.encoded_len(),
            v["before"].as_u64().expect("old size") as usize
        );
        println!("PROOF SIZE {n}: {} -> {after}", proof.encoded_len());
        sizes.push(after as f64);
    }
    assert!(((sizes[2] - sizes[1]) / 192.0 - (sizes[1] - sizes[0]) / 48.0).abs() < 8.0);
    assert!(sizes[2] < 17.0 * sizes[0]);
}

#[test]
fn versioned_bounds_and_context_reserve_are_enforced() {
    let f = fixture();
    let materials = materials(&f);
    let branches: Vec<_> = materials.iter().map(|(b, _)| b.clone()).collect();
    let proof = build_job(&branches[..25], &materials).expect("job");
    let mut request = api::CommitImportJobRequest {
        proof: Some(proof),
        ..Default::default()
    };
    import::validate_commit_request_bounds(&request).expect("format 2");
    request.proof.as_mut().expect("proof").statements.push(
        heddle_api::heddle::api::common::SignedHostedWitnessStatementV1 {
            body: Some(heddle_api::heddle::api::common::HostedWitnessStatementV1 {
                canonical_payload: vec![0; 65536],
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    assert_eq!(
        import::validate_commit_request_bounds(&request),
        Err(codec::Reject::Bounds)
    );
    let proof = request.proof.as_mut().expect("proof");
    proof.statements.clear();
    proof.creator_authority_envelopes = vec![vec![0; 65536]; 25];
    proof.format_version = 1;
    assert_eq!(
        import::validate_commit_request_bounds(&request),
        Err(codec::Reject::Bounds)
    );
    request.proof.as_mut().expect("proof").format_version = 2;
    import::validate_commit_request_bounds(&request).expect("explicit expanded carrier bound");
    request.proof.as_mut().expect("proof").format_version = 3;
    assert_eq!(
        import::validate_commit_request_bounds(&request),
        Err(codec::Reject::Version)
    );
}
#[test]
fn format_two_public_bundle_rejects_noncanonical_table() {
    let mut p: api::ImportPublicProofBundleV1 = vector(&base(), "complete_export");
    p.format_version = 2;
    p.creator_authority_envelopes
        .sort_by_key(|e| codec::hash(&[e]));
    p.creator_authority_envelopes.dedup();
    import::validate_public_bundle(&p).expect("format 2 closure");
    p.creator_authority_envelopes
        .push(p.creator_authority_envelopes[0].clone());
    assert_eq!(
        import::validate_public_bundle(&p),
        Err(codec::Reject::Canonical)
    );
}

#[test]
fn format_two_capacity_includes_maximum_opaque_transport_material() {
    let f = fixture();
    let materials = materials(&f);
    let branches: Vec<_> = materials.iter().map(|(b, _)| b.clone()).collect();
    let mut proof = build_job(&branches[..25], &materials).expect("job");
    for original in &mut proof.original_geneses {
        original.canonical_record = vec![0; import::MAX_RECORD_BYTES];
        original.signatures = vec![
            api::RecordSignature {
                public_key: vec![0; 32],
                signature: vec![0; 64]
            };
            16
        ];
    }
    proof.creator_authority_envelopes = (0..25).map(|i| vec![i; 65536]).collect();
    let size = proof.encoded_len();
    assert!(size <= import::MAX_BUNDLE_BYTES);
    import::validate_commit_request_bounds(&api::CommitImportJobRequest {
        proof: Some(proof),
        ..Default::default()
    })
    .expect("maximum transport material fits");
    println!("OPAQUE CAPACITY {size} <= {}", import::MAX_BUNDLE_BYTES);
}

#[test]
fn format_two_bounds_parent_scope_alongside_child_scope() {
    let f = fixture();
    let materials = materials(&f);
    let branches: Vec<_> = materials.iter().map(|(b, _)| b.clone()).collect();
    let mut proof = build_job(&branches[..25], &materials).expect("job");
    proof
        .member_permission
        .as_mut()
        .expect("permission")
        .body
        .as_mut()
        .expect("body")
        .scope
        .as_mut()
        .expect("scope")
        .branches = branches[..26].to_vec();
    assert_eq!(
        import::validate_public_bundle(&proof),
        Err(codec::Reject::Bounds)
    );
}

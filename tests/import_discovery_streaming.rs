use heddle_api::{heddle::api::v1alpha2 as api, hybrid_codec::Reject, import_authority as import};
use prost::Message;
use serde_json::Value;

fn refs(algorithm: i32) -> Vec<api::ProviderRef> {
    let recipe: Value =
        serde_json::from_str(include_str!("fixtures/import-discovery-v1.json")).expect("recipe");
    let width = if algorithm == 1 { 40 } else { 64 };
    let mut refs = Vec::new();
    for (key, kind, offset) in [
        ("branches", 1, 0),
        ("pull_requests", 3, 8000),
        ("tags", 2, 16000),
    ] {
        for i in 0..recipe[key].as_u64().expect("count") {
            let name = match kind {
                1 => format!("refs/heads/b{i:05}"),
                3 => format!("refs/pull/{}/head", i + 1),
                _ => format!("refs/tags/v{i:05}"),
            };
            refs.push(api::ProviderRef {
                name,
                head_oid: format!("{:0width$x}", i + offset),
                kind,
                hash_algorithm: algorithm,
            });
        }
    }
    refs.sort_by(|a, b| a.name.cmp(&b.name));
    refs
}
fn source(algorithm: i32) -> api::ProviderRepository {
    api::ProviderRepository {
        clone_url: "https://github.com/example/repo.git".into(),
        hash_algorithm: algorithm,
        ..Default::default()
    }
}
fn selected(r: &api::ProviderRef) -> api::ImportBranchLimitV1 {
    api::ImportBranchLimitV1 {
        ref_name: r.name.clone(),
        hash_algorithm: r.hash_algorithm,
        ref_mode: 1,
        pinned_commit_oid: hex::decode(&r.head_oid).expect("oid"),
        genesis_digest: vec![1; 32],
        target_thread_id: vec![2; 32],
        expected_frontier_digest: vec![3; 32],
        ..Default::default()
    }
}
fn validator(
    source: &api::ProviderRepository,
    selected: &[api::ImportBranchLimitV1],
    mode: import::DiscoverySelectionMode,
) -> import::DiscoveryValidator {
    import::DiscoveryValidator::new(
        source,
        true,
        selected,
        import::DiscoveryOptions {
            include_pull_request_refs: true,
        },
        mode,
    )
    .expect("validator")
}
#[test]
fn twenty_thousand_refs_match_shared_rust_ts_digests_and_page_partitions() {
    let recipe: Value =
        serde_json::from_str(include_str!("fixtures/import-discovery-v1.json")).expect("recipe");
    for vector in recipe["vectors"].as_array().expect("vectors") {
        let algorithm = vector["hash_algorithm"].as_i64().expect("algorithm") as i32;
        let refs = refs(algorithm);
        let selected: Vec<_> = [0, 8500, 15999].map(|i| selected(&refs[i])).into();
        for page_size in [1, 127, 512] {
            let mut validator = validator(
                &source(algorithm),
                &selected,
                import::DiscoverySelectionMode::Prepare,
            );
            for page in refs.chunks(page_size) {
                validator.push_page(page).expect("page");
            }
            let digest = validator.finish().expect("complete");
            assert_eq!(digest.ref_count(), 20000);
            assert_eq!(
                hex::encode(digest.digest()),
                vector["sha256"].as_str().expect("digest")
            );
        }
        let mut whole = source(algorithm);
        whole.refs = refs;
        assert_eq!(
            hex::encode(
                import::discover_repository(
                    &whole,
                    &selected,
                    import::DiscoveryOptions {
                        include_pull_request_refs: true
                    },
                    import::DiscoverySelectionMode::Prepare
                )
                .expect("whole")
                .digest()
            ),
            vector["sha256"].as_str().expect("digest")
        );
    }
}
#[test]
fn bad_record_fails_on_its_page_and_poisoned_validator_cannot_finish() {
    for (mutation, expected) in [
        (0, Reject::SourceSelection),
        (1, Reject::Canonical),
        (2, Reject::Bounds),
        (3, Reject::Canonical),
        (4, Reject::SourceSelection),
        (5, Reject::Canonical),
    ] {
        let mut refs = refs(2);
        match mutation {
            0 => refs[512].hash_algorithm = 1,
            1 => refs[512].name = refs[511].name.clone(),
            2 => refs[512].name = "z".repeat(1025),
            3 => refs[512].head_oid = "A".repeat(64),
            4 => refs[512].kind = 2,
            _ => refs[512].name = "refs/pull/01/head".into(),
        }
        let mut validator = validator(&source(2), &[], import::DiscoverySelectionMode::Prepare);
        validator.push_page(&refs[..512]).expect("valid first page");
        assert_eq!(validator.push_page(&refs[512..1024]), Err(expected));
        assert_eq!(validator.push_page(&[]), Err(Reject::Canonical));
        assert!(matches!(validator.finish(), Err(Reject::Canonical)));
    }
}
#[test]
fn membership_pins_namespace_and_page_bounds_are_enforced() {
    let refs = refs(2);
    let mut selected = selected(&refs[0]);
    let mut absent = validator(
        &source(2),
        &[selected.clone()],
        import::DiscoverySelectionMode::Prepare,
    );
    absent.push_page(&[]).expect("empty page");
    assert!(matches!(absent.finish(), Err(Reject::SourceSelection)));
    selected.pinned_commit_oid = vec![9; 32];
    let mut prepare = validator(
        &source(2),
        &[selected.clone()],
        import::DiscoverySelectionMode::Prepare,
    );
    assert_eq!(prepare.push_page(&refs[..1]), Err(Reject::RefPinning));
    let mut commit = validator(
        &source(2),
        &[selected],
        import::DiscoverySelectionMode::Commit,
    );
    commit.push_page(&refs[..1]).expect("frozen pin");
    commit.finish().expect("present");
    let mut v = validator(&source(2), &[], import::DiscoverySelectionMode::Prepare);
    assert_eq!(v.push_page(&refs[..513]), Err(Reject::Bounds));
    for name in [
        "refs/pull/0/head",
        "refs/pull/01/head",
        "refs/pull/1/merge",
        "refs/pull/-1/head",
        "refs/pull/1/head/x",
        "refs/pull/1/head\n",
        "refs/pull/1/head\u{2028}",
    ] {
        let r = api::ProviderRef {
            name: name.into(),
            hash_algorithm: 2,
            kind: 3,
            ..Default::default()
        };
        assert_eq!(
            validator(&source(2), &[], import::DiscoverySelectionMode::Prepare).push_page(&[r]),
            Err(Reject::Canonical)
        );
    }
    let mut off = import::DiscoveryValidator::new(
        &source(2),
        true,
        &[],
        import::DiscoveryOptions::default(),
        import::DiscoverySelectionMode::Prepare,
    )
    .expect("off");
    assert_eq!(off.push_page(&refs[8000..8001]), Err(Reject::Canonical));
}
#[test]
fn safety_ceiling_accepts_exactly_one_million_and_rejects_next_page() {
    let mut v = validator(&source(1), &[], import::DiscoverySelectionMode::Prepare);
    for start in (0..import::MAX_IMPORT_SOURCE_REFS).step_by(512) {
        let page: Vec<_> = (start..start + 512)
            .map(|i| api::ProviderRef {
                name: format!("refs/heads/b{i:07}"),
                head_oid: String::new(),
                kind: 1,
                hash_algorithm: 1,
            })
            .collect();
        v.push_page(&page).expect("within ceiling");
    }
    let mut at = validator(&source(1), &[], import::DiscoverySelectionMode::Prepare);
    // Run a second stream to prove the exact ceiling can finish.
    for start in (0..import::MAX_IMPORT_SOURCE_REFS).step_by(512) {
        let page: Vec<_> = (start..start + 512)
            .map(|i| api::ProviderRef {
                name: format!("refs/heads/b{i:07}"),
                head_oid: String::new(),
                kind: 1,
                hash_algorithm: 1,
            })
            .collect();
        at.push_page(&page).expect("within ceiling");
    }
    assert_eq!(
        at.finish().expect("ceiling").ref_count(),
        import::MAX_IMPORT_SOURCE_REFS
    );
    assert_eq!(
        v.push_page(&[api::ProviderRef {
            name: "refs/heads/z".into(),
            hash_algorithm: 1,
            kind: 1,
            ..Default::default()
        }]),
        Err(Reject::Bounds)
    );
}
// Independent copy of the former one-pass checks, for existing fixture parity.
fn legacy(source: &api::ProviderRepository, known: bool) -> Result<(), Reject> {
    let size = match source.hash_algorithm {
        1 => Some(40),
        2 => Some(64),
        0 if !known => None,
        _ => return Err(Reject::Version),
    };
    if source.refs.len() > 4096 {
        return Err(Reject::Bounds);
    }
    for (i, r) in source.refs.iter().enumerate() {
        if r.name.len() > 1024 {
            return Err(Reject::Bounds);
        }
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
#[test]
fn incremental_and_former_one_pass_agree_on_every_existing_repository_fixture() {
    let fixture: Value =
        serde_json::from_str(heddle_api::IMPORT_AUTHORITY_HOST_WITNESS_V1_FIXTURE_JSON)
            .expect("fixture");
    let mut count = 0;
    for group in ["wire_vectors", "signed_vectors"] {
        for (name, record) in fixture[group].as_object().expect("records") {
            if record["schema"] != "heddle.api.v1alpha2.ProviderRepository" {
                continue;
            }
            let source = api::ProviderRepository::decode(
                hex::decode(record["wire_hex"].as_str().expect("wire"))
                    .expect("hex")
                    .as_slice(),
            )
            .expect("decode");
            for known in [false, true] {
                let result = import::DiscoveryValidator::new(
                    &source,
                    known,
                    &[],
                    import::DiscoveryOptions::default(),
                    import::DiscoverySelectionMode::Prepare,
                )
                .and_then(|mut v| {
                    for page in source.refs.chunks(512) {
                        v.push_page(page)?;
                    }
                    v.finish().map(|_| ())
                });
                assert_eq!(result, legacy(&source, known), "{name}, known={known}");
            }
            count += 1;
        }
    }
    assert!(count > 20, "fixture inventory must be exercised");
}

fn record<T: Message + Default>(f: &Value, name: &str) -> T {
    let v = f["signed_vectors"]
        .get(name)
        .unwrap_or(&f["wire_vectors"][name]);
    T::decode(
        hex::decode(v["wire_hex"].as_str().expect("wire"))
            .expect("hex")
            .as_slice(),
    )
    .expect("fixed record")
}
#[test]
fn finished_evidence_admits_prepare_commit_and_binds_source_selection_and_phase() {
    let f: Value = serde_json::from_str(heddle_api::IMPORT_AUTHORITY_HOST_WITNESS_V1_FIXTURE_JSON)
        .expect("fixture");
    let prepare: api::PrepareImportJobRequest = record(&f, "prepare_public_sha256");
    let metadata: api::ProviderRepository = record(&f, "source_public_sha256");
    let scope = prepare.proposed_scope.as_ref().expect("scope");
    let configuration: api::GetImportConfigurationResponse = record(&f, "import_configuration");
    let destination: api::ImportPermissionScopeV1 = record(&f, "scope");
    let page: Vec<_> = scope
        .branches
        .iter()
        .map(|b| api::ProviderRef {
            name: b.ref_name.clone(),
            hash_algorithm: b.hash_algorithm,
            kind: 1,
            ..Default::default()
        })
        .collect();
    let mut v = validator(
        &metadata,
        &scope.branches,
        import::DiscoverySelectionMode::Prepare,
    );
    v.push_page(&page).expect("page");
    let evidence = v.finish().expect("complete");
    import::prepare_import_source_scope_with_discovery(
        &prepare,
        &metadata,
        None,
        &configuration,
        &destination.destination_version,
        &evidence,
    )
    .expect("paged Prepare");
    let mut changed = metadata.clone();
    changed.hash_algorithm = 1;
    assert_eq!(
        import::prepare_import_source_scope_with_discovery(
            &prepare,
            &changed,
            None,
            &configuration,
            &destination.destination_version,
            &evidence
        ),
        Err(Reject::SourceSelection)
    );
    let mut changed = prepare.clone();
    changed.proposed_scope.as_mut().expect("scope").branches[0].target_thread_id = vec![9; 32];
    assert_eq!(
        import::prepare_import_source_scope_with_discovery(
            &changed,
            &metadata,
            None,
            &configuration,
            &destination.destination_version,
            &evidence
        ),
        Err(Reject::SourceSelection)
    );
    let request: api::CommitImportJobRequest = record(&f, "commit_request");
    let metadata: api::ProviderRepository = record(&f, "source_connected");
    let selected = &request.proof.as_ref().expect("proof").delegations[0]
        .body
        .as_ref()
        .expect("body")
        .scope
        .as_ref()
        .expect("scope")
        .branches;
    let page: Vec<_> = selected
        .iter()
        .map(|b| api::ProviderRef {
            name: b.ref_name.clone(),
            hash_algorithm: b.hash_algorithm,
            kind: 1,
            ..Default::default()
        })
        .collect();
    let mut commit = validator(&metadata, selected, import::DiscoverySelectionMode::Commit);
    commit.push_page(&page).expect("page");
    import::validate_commit_request_with_discovery(
        &request,
        "github",
        &metadata,
        &configuration,
        &commit.finish().expect("complete"),
    )
    .expect("paged Commit");
    let mut wrong = validator(&metadata, selected, import::DiscoverySelectionMode::Prepare);
    wrong.push_page(&page).expect("page");
    assert_eq!(
        import::validate_commit_request_with_discovery(
            &request,
            "github",
            &metadata,
            &configuration,
            &wrong.finish().expect("complete")
        ),
        Err(Reject::SourceSelection)
    );
}

#[test]
fn discovery_options_flow_through_resolve_and_selection_remains_bounded() {
    let f: Value = serde_json::from_str(heddle_api::IMPORT_AUTHORITY_HOST_WITNESS_V1_FIXTURE_JSON)
        .expect("fixture");
    let mut resolved: api::ProviderRepository = record(&f, "source_public_sha256");
    resolved.refs = vec![api::ProviderRef {
        name: "refs/pull/42/head".into(),
        head_oid: "0".repeat(64),
        hash_algorithm: 2,
        kind: 3,
    }];
    let mut request = api::ResolveImportSourceRequest {
        source: Some(api::ProviderRepository {
            clone_url: resolved.clone_url.clone(),
            provider_repository_id: resolved.provider_repository_id.clone(),
            ..Default::default()
        }),
        include_refs: true,
        include_pull_request_refs: true,
        ..Default::default()
    };
    let response = api::ResolveImportSourceResponse {
        source: Some(resolved),
    };
    import::validate_resolve_import_source_response(&request, &response, None)
        .expect("opt-in pull head");
    request.include_pull_request_refs = false;
    assert_eq!(
        import::validate_resolve_import_source_response(&request, &response, None),
        Err(Reject::Canonical)
    );
    let refs = refs(2);
    let selected: Vec<_> = refs[..256].iter().map(selected).collect();
    let mut v = validator(
        &source(2),
        &selected,
        import::DiscoverySelectionMode::Prepare,
    );
    v.push_page(&refs[..256]).expect("256 selections");
    v.finish().expect("all present");
    let mut too_many = selected;
    too_many.push(too_many[0].clone());
    assert!(matches!(
        import::DiscoveryValidator::new(
            &source(2),
            true,
            &too_many,
            import::DiscoveryOptions::default(),
            import::DiscoverySelectionMode::Prepare
        ),
        Err(Reject::Bounds)
    ));
    let mut newline_oid = refs[0].clone();
    newline_oid.head_oid = format!("{}\n", "0".repeat(63));
    assert_eq!(
        validator(&source(2), &[], import::DiscoverySelectionMode::Prepare)
            .push_page(&[newline_oid]),
        Err(Reject::Canonical)
    );
    let mut unicode_oid = refs[0].clone();
    unicode_oid.head_oid = "é".repeat(64);
    assert_eq!(
        validator(&source(2), &[], import::DiscoverySelectionMode::Prepare)
            .push_page(&[unicode_oid]),
        Err(Reject::SourceSelection)
    );
}

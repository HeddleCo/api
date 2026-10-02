#[cfg(feature = "reflection")]
use heddle_api::FILE_DESCRIPTOR_SET;
#[cfg(feature = "reflection")]
use prost_reflect::DescriptorPool;

#[cfg(feature = "reflection")]
#[test]
fn hybrid_messages_and_rpc_are_present_in_the_descriptor() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/import-authority-host-witness-v1.json"
    ))
    .expect("shared conformance fixture");
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor");
    for name in fixture["messages"].as_array().expect("message inventory") {
        let name = name.as_str().expect("message name");
        assert!(pool.get_message_by_name(name).is_some(), "missing {name}");
    }
    let service = pool
        .get_service_by_name("heddle.api.v1alpha2.IntegrationService")
        .expect("integration service");
    for name in [
        "PrepareImportJob",
        "CommitImportJob",
        "RenewImportJob",
        "CancelImportJob",
        "GetHostedWitnessHistoryProof",
    ] {
        assert!(
            service.methods().any(|m| m.name() == name),
            "missing {name}"
        );
    }
}

use heddle_api::heddle::api::{common as host, v1alpha2 as api};
use heddle_api::{hybrid_codec as codec, import_authority as import, witness_trust as witness};
use prost::Message;
use serde_json::Value;

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("fixed hex bytes")
}
fn fixture() -> Value {
    serde_json::from_str(heddle_api::IMPORT_AUTHORITY_HOST_WITNESS_V1_FIXTURE_JSON)
        .expect("fixed fixture")
}
fn record<T: Message + Default>(f: &Value, name: &str) -> T {
    let v = if f["signed_vectors"][name].is_null() {
        &f["wire_vectors"][name]
    } else {
        &f["signed_vectors"][name]
    };
    codec::strict_decode(&bytes(&v["wire_hex"]), import::MAX_BUNDLE_BYTES).expect("fixed wire")
}
struct Context {
    identity: api::ImportIdentityV1,
    owner: Vec<u8>,
    chain: Vec<u8>,
    forbidden: Vec<Vec<u8>>,
    job_keys: Vec<Vec<u8>>,
    root: Vec<u8>,
}
impl Context {
    fn new(f: &Value) -> Self {
        Self {
            identity: record(f, "identity"),
            owner: bytes(&f["keys"]["owner"]["public_key_hex"]),
            chain: bytes(&f["context"]["owner_chain_digest_hex"]),
            forbidden: ["owner", "device", "witness", "next_witness", "root"]
                .map(|k| bytes(&f["keys"][k]["public_key_hex"]))
                .to_vec(),
            job_keys: ["job", "renew_job", "direct_job"]
                .map(|k| bytes(&f["keys"][k]["public_key_hex"]))
                .to_vec(),
            root: bytes(&f["keys"]["root"]["public_key_hex"]),
        }
    }
    fn owner(&self, now: i64) -> import::ImportOwnerExpectation<'_> {
        import::ImportOwnerExpectation {
            identity: &self.identity,
            owner_public_key: &self.owner,
            owner_chain_digest: &self.chain,
            authority_expires_at_seconds: 2000,
            now_unix_seconds: now,
            forbidden_job_keys: &self.forbidden,
            known_job_associations: &[],
        }
    }
    fn set(&self, now: i64) -> witness::SetExpectation<'_> {
        witness::SetExpectation {
            authority: "https://weft.example.test",
            root_id: "descriptor-root-1",
            root_public_key: &self.root,
            root_epoch: 1,
            now_unix_millis: now,
            clock_floor_unix_millis: 1_000_000,
            known_job_keys: &self.job_keys,
        }
    }
}
fn delegation(f: &Value, c: &Context) -> import::VerifiedImportDelegation {
    import::verify_delegation(
        &record(f, "delegation"),
        Some(&record(f, "permission")),
        &c.owner(1100),
    )
    .expect("authorized member control")
}
fn assert_bytes(body: &impl codec::Canonical, signature: &[u8], v: &Value) {
    let canonical = codec::canonical(body).expect("canonical body");
    assert_eq!(canonical, bytes(&v["canonical_hex"]));
    let domain = v["domain"].as_str().expect("fixed domain");
    let input = if domain.ends_with('\0') {
        [domain.as_bytes(), &canonical].concat()
    } else {
        codec::hash(&[domain.as_bytes(), &canonical])
    };
    assert_eq!(input, bytes(&v["signing_input_hex"]));
    assert_eq!(signature, bytes(&v["signature_hex"]));
    codec::verify(&bytes(&v["public_key_hex"]), &input, signature)
        .expect("fixed signature independently verifies");
}
#[test]
fn fixed_canonical_signature_and_wire_vectors_are_shared() {
    let f = fixture();
    for (name, v) in f["signed_vectors"].as_object().expect("vectors") {
        macro_rules! check {
            ($ty:ty,$signature:ident) => {{
                let value: $ty = record(&f, name);
                assert_eq!(value.encode_to_vec(), bytes(&v["wire_hex"]));
                assert_bytes(
                    value.body.as_ref().expect("body"),
                    &value.$signature.as_ref().expect("signature").signature,
                    v,
                );
            }};
        }
        match v["schema"]
            .as_str()
            .expect("schema")
            .rsplit('.')
            .next()
            .expect("name")
        {
            "SignedImportMemberPermissionV1" => {
                check!(api::SignedImportMemberPermissionV1, owner_signature)
            }
            "SignedImportGenesisAuthorityV1" => {
                check!(api::SignedImportGenesisAuthorityV1, creator_signature)
            }
            "SignedImportJobDelegationV1" => {
                check!(api::SignedImportJobDelegationV1, delegating_signature)
            }
            "SignedImportJobRenewalV1" => {
                check!(api::SignedImportJobRenewalV1, delegating_signature)
            }
            "SignedDelegatedImportOperationV1" => {
                check!(api::SignedDelegatedImportOperationV1, job_signature)
            }
            "SignedHostedWitnessSetV1" => {
                let value: host::SignedHostedWitnessSetV1 = record(&f, name);
                assert_eq!(value.encode_to_vec(), bytes(&v["wire_hex"]));
                assert_bytes(value.body.as_ref().expect("body"), &value.root_signature, v);
            }
            "SignedHostedWitnessStatementV1" => {
                let value: host::SignedHostedWitnessStatementV1 = record(&f, name);
                assert_eq!(value.encode_to_vec(), bytes(&v["wire_hex"]));
                assert_bytes(value.body.as_ref().expect("body"), &value.signature, v);
            }
            name => panic!("unhandled fixed signed schema {name}"),
        }
    }
}
#[test]
fn complete_owner_member_job_operation_publication_chain_and_direct_owner_control() {
    let f = fixture();
    let c = Context::new(&f);
    let d = delegation(&f, &c);
    import::verify_member_permission(&record(&f, "permission"), &c.owner(1100))
        .expect("typed parent permission");
    import::verify_delegation(&record(&f, "direct_owner"), None, &c.owner(1100))
        .expect("direct active owner control");
    assert_eq!(
        import::owner_chain_digest(&record(&f, "owner_chain")).expect("owner chain digest"),
        c.chain
    );
    for name in ["dev", "main"] {
        let original = &f["originals"][name];
        let canonical = bytes(&original["canonical_hex"]);
        let signature = bytes(&original["signature_hex"]);
        codec::verify(
            &bytes(&f["keys"]["device"]["public_key_hex"]),
            &[b"heddle-thread-genesis-v1\0".as_slice(), &canonical].concat(),
            &signature,
        )
        .expect("unchanged creator signature");
        import::verify_genesis_authority(
            &record(&f, &format!("genesis_{name}")),
            &d,
            &bytes(&original["genesis_digest_hex"]),
            &signature,
            &codec::hash(&[&bytes(&original["envelope_hex"])]),
        )
        .expect("exact genesis/envelope binding");
        import::verify_new_operation(&record(&f, &format!("operation_{name}")), &d, 1100)
            .expect("job-signed scoped operation");
    }
    let set = witness::verify_set(&record(&f, "current_set"), &c.set(1_100_000), None)
        .expect("current witness");
    let operation = record(&f, "operation_main");
    let manifest = record(&f, "partial_manifest");
    let statement = record(&f, "publication_statement");
    import::verify_publication(&operation, &d, &manifest, &statement, &set, None, 1_100_000)
        .expect("committed exact publication");
    let retired = witness::verify_set(&record(&f, "retired_set"), &c.set(1_350_000), Some(&set))
        .expect("atomic rotation with seal");
    import::verify_publication(
        &operation,
        &d,
        &manifest,
        &statement,
        &retired,
        Some(&record(&f, "publication_proof")),
        1_350_000,
    )
    .expect("exact committed history after expiry");
    assert_eq!(
        import::verify_new_operation(&operation, &d, 1350),
        Err(codec::Reject::Expired)
    );
}
#[test]
fn negative_vectors_isolate_their_named_gate() {
    let f = fixture();
    let c = Context::new(&f);
    let d = delegation(&f, &c);
    for v in f["negative_vectors"].as_array().expect("negative vectors") {
        let wire = bytes(&v["wire_hex"]);
        let result = match v["type"].as_str().expect("gate") {
            "set" => {
                let p = v["previous"].as_str().map(|name| {
                    witness::verify_set(&record(&f, name), &c.set(1_100_000), None)
                        .expect("high water control")
                });
                witness::verify_set(
                    &codec::strict_decode(&wire, witness::MAX_SET_BYTES).expect("root-signed set"),
                    &c.set(1_100_000),
                    p.as_ref(),
                )
                .map(|_| ())
            }
            "statement" => {
                let now = v["now_ms"].as_i64().expect("now");
                let set = witness::verify_set(
                    &record(&f, v["set"].as_str().expect("set")),
                    &c.set(now),
                    None,
                )
                .expect("authenticated historical set");
                witness::resolve_statement(
                    &set,
                    &codec::strict_decode(&wire, import::MAX_BUNDLE_BYTES).expect("statement"),
                    Some(&record(&f, v["proof"].as_str().expect("proof"))),
                    v["new_work"].as_bool().expect("mode"),
                    now,
                )
                .map(|_| ())
            }
            "operation" => import::verify_operation(
                &codec::strict_decode(&wire, import::MAX_RECORD_BYTES).expect("operation"),
                &d,
            ),
            "new_operation" => import::verify_new_operation(
                &codec::strict_decode(&wire, import::MAX_RECORD_BYTES).expect("operation"),
                &d,
                v["now_seconds"].as_i64().expect("now"),
            ),
            "renewal" => {
                let member: api::SignedImportMemberPermissionV1 = record(&f, "permission");
                import::verify_renewal(
                    &codec::strict_decode(&wire, import::MAX_RECORD_BYTES).expect("renewal"),
                    &d,
                    &record(&f, "partial_manifest"),
                    1,
                    if v["member"] == false {
                        None
                    } else {
                        Some(&member)
                    },
                    &c.owner(v["now_seconds"].as_i64().expect("now")),
                )
                .map(|_| ())
            }
            unknown => panic!("unhandled gate {unknown}"),
        };
        assert_eq!(
            format!(
                "{:?}",
                result.expect_err(v["id"].as_str().expect("negative id"))
            ),
            v["expected"].as_str().expect("expected named gate")
        );
    }
}
#[test]
fn unrelated_correctly_signed_capabilities_do_not_supply_import_permission() {
    let f = fixture();
    let c = Context::new(&f);
    for v in f["unrelated_permissions"].as_array().expect("controls") {
        codec::verify(
            &bytes(&v["public_key_hex"]),
            &bytes(&v["signing_input_hex"]),
            &bytes(&v["signature_hex"]),
        )
        .expect("valid unrelated signature");
        if !v["wire_hex"].is_null() {
            let value: api::SignedOwnerCapability =
                codec::strict_decode(&bytes(&v["wire_hex"]), import::MAX_RECORD_BYTES)
                    .expect("actual existing capability wire");
            assert_eq!(
                value.signature.expect("owner signature").signature,
                bytes(&v["signature_hex"])
            );
        }
        assert_eq!(
            import::verify_delegation(&record(&f, "delegation"), None, &c.owner(1100)),
            Err(codec::Reject::ImportPermission)
        );
    }
}
#[test]
fn empty_even_odd_trees_and_every_exact_inclusion_path() {
    let f = fixture();
    for tree in f["trees"].as_array().expect("trees") {
        let leaves = tree["leaves_hex"]
            .as_array()
            .expect("leaves")
            .iter()
            .map(bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            witness::merkle_root(&leaves).expect("static tree"),
            bytes(&tree["root_hex"])
        );
        let entry = host::HostedWitnessEntryV1 {
            executor_id: vec![1; 32],
            state: 2,
            archive_root: bytes(&tree["root_hex"]),
            archive_leaf_count: tree["count"].as_u64().expect("count"),
            ..Default::default()
        };
        for p in tree["paths"].as_array().expect("paths") {
            let proof = host::HostedWitnessHistoryProofV1 {
                executor_id: entry.executor_id.clone(),
                purpose: 3,
                leaf_index: p["index"].as_u64().expect("index"),
                leaf_count: entry.archive_leaf_count,
                siblings: p["siblings_hex"]
                    .as_array()
                    .expect("siblings")
                    .iter()
                    .map(bytes)
                    .collect(),
            };
            witness::verify_inclusion(&leaves[proof.leaf_index as usize], &proof, &entry)
                .expect("exact inclusion shape");
            let mut extra = proof.clone();
            extra.siblings.push(vec![0; 32]);
            assert_eq!(
                witness::verify_inclusion(&leaves[proof.leaf_index as usize], &extra, &entry),
                Err(codec::Reject::Proof)
            );
        }
    }
}
#[test]
fn concurrent_renewals_and_paused_old_worker_obey_retry_contract_fixture() {
    let f = fixture();
    let c = Context::new(&f);
    let old = delegation(&f, &c);
    let scenario = &f["retry_scenarios"][0];
    let committed = record(
        &f,
        scenario["committed_manifest"].as_str().expect("manifest"),
    );
    let mut epoch = scenario["initial_epoch"].as_u64().expect("epoch");
    let mut next = None;
    for event in scenario["events"].as_array().expect("race events") {
        match event["action"].as_str().expect("action") {
            "activate_renewal" => {
                let result = import::verify_renewal(
                    &record(&f, event["certificate"].as_str().expect("renewal")),
                    &old,
                    &committed,
                    epoch,
                    Some(&record(&f, "permission")),
                    &c.owner(1200),
                );
                if event["result"] == "OK" {
                    next = Some(result.expect("first signed renewal wins CAS"));
                    epoch += 1;
                } else {
                    assert_eq!(result, Err(codec::Reject::StaleContext));
                }
            }
            "publish_paused_worker" => {
                let stale: api::SignedDelegatedImportOperationV1 =
                    record(&f, event["operation"].as_str().expect("paused operation"));
                let stale = stale.body.as_ref().expect("paused body");
                assert_eq!(
                    import::check_job_fence(
                        &stale.logical_job_id,
                        &stale.delegation_digest,
                        event["expected_epoch"].as_u64().expect("paused epoch"),
                        next.as_ref().expect("active renewal"),
                        epoch
                    ),
                    Err(codec::Reject::StaleContext)
                );

                assert_ne!(event["expected_epoch"].as_u64().expect("old epoch"), epoch);
                assert_eq!(event["result"], "StaleContext");
                assert!(
                    !import::check_slot_replay(
                        &committed,
                        &record(&f, event["operation"].as_str().expect("old operation"))
                    )
                    .expect("no stale publication")
                );
            }
            "publish" => {
                assert_eq!(
                    event["expected_epoch"].as_u64().expect("current epoch"),
                    epoch
                );
                let operation = record(&f, event["operation"].as_str().expect("operation"));
                import::verify_new_operation(
                    &operation,
                    next.as_ref().expect("activated renewal"),
                    1250,
                )
                .expect("fresh key for remaining slot");
                assert!(
                    import::check_slot_replay(
                        &record(&f, scenario["final_manifest"].as_str().expect("manifest")),
                        &operation
                    )
                    .expect("one committed slot")
                );
            }
            action => panic!("unknown event {action}"),
        }
        assert_eq!(epoch, event["epoch_after"].as_u64().expect("epoch"));
    }
    let final_manifest: api::ImportResultManifestV1 =
        record(&f, scenario["final_manifest"].as_str().expect("manifest"));
    assert_eq!(
        final_manifest.slots.len() as u64,
        scenario["committed_slot_count"].as_u64().expect("slots")
    );
    assert_eq!(
        import::verify_renewal(
            &record(&f, "renewal"),
            &old,
            &final_manifest,
            1,
            Some(&record(&f, "permission")),
            &c.owner(1200)
        ),
        Err(codec::Reject::RenewalFork)
    );
}
#[test]
fn commit_response_loss_retry_and_fresh_fetch_recover_exact_committed_bytes() {
    let f = fixture();
    let c = Context::new(&f);
    let scenario = &f["retry_scenarios"][1];
    let operation: api::SignedDelegatedImportOperationV1 = record(
        &f,
        scenario["original_operation"].as_str().expect("operation"),
    );
    let o = operation.body.as_ref().expect("operation body");
    assert_ne!(
        o.physical_operation_id,
        bytes(&scenario["physical_retry_operation_id_hex"])
    );
    assert_eq!(o.logical_job_id, bytes(&scenario["logical_job_id_hex"]));
    assert_eq!(
        o.retry_lineage_id,
        bytes(&scenario["retry_original_operation_hex"])
    );
    let manifest: api::ImportResultManifestV1 =
        record(&f, scenario["manifest"].as_str().expect("manifest"));
    assert!(import::check_slot_replay(&manifest, &operation).expect("exact result recovery"));
    assert_eq!(manifest.slots.len(), 1);
    let statement = record(&f, scenario["receipt"].as_str().expect("receipt"));
    let set = witness::verify_set(&record(&f, "retired_set"), &c.set(1_350_000), None)
        .expect("fresh Fetch witness set");
    import::verify_publication(
        &operation,
        &delegation(&f, &c),
        &manifest,
        &statement,
        &set,
        Some(&record(&f, "publication_proof")),
        1_350_000,
    )
    .expect("fresh Fetch verifies original receipt after expiry/retirement");
    assert_eq!(
        manifest.encode_to_vec(),
        bytes(&f["wire_vectors"][scenario["manifest"].as_str().expect("manifest")]["wire_hex"])
    );
    let mut conflict: api::SignedDelegatedImportOperationV1 = record(&f, "renewed_operation_dev");
    let conflicting = conflict.body.as_mut().expect("body");
    conflicting.ref_name = o.ref_name.clone();
    conflicting.slot_id = o.slot_id;
    assert_eq!(
        import::check_slot_replay(&manifest, &conflict),
        Err(codec::Reject::SlotConflict)
    );
}
#[test]
fn cached_contexts_fail_at_generation_expiry_clock_and_root_boundaries() {
    let f = fixture();
    let c = Context::new(&f);
    let current =
        witness::verify_set(&record(&f, "current_set"), &c.set(1_100_000), None).expect("current");
    let statement = record(&f, "publication_statement");
    let context = witness::resolve_statement(&current, &statement, None, false, 1_100_000)
        .expect("staged context");
    witness::recheck_context(&context, &current, &statement, 1_100_000).expect("unchanged context");
    let restored = witness::restore_history_snapshot(&record(&f, "newer_set"), &c.set(1_400_000))
        .expect("restore receiver-owned expired high-water");
    assert_eq!(
        witness::verify_set(
            &record(&f, "current_set"),
            &c.set(1_100_000),
            Some(&restored)
        ),
        Err(codec::Reject::HighWater)
    );
    let newer = witness::verify_set(&record(&f, "newer_set"), &c.set(1_100_000), Some(&current))
        .expect("advance durable high water");
    assert_eq!(
        witness::recheck_context(&context, &newer, &statement, 1_100_000),
        Err(codec::Reject::StaleContext)
    );
    assert_eq!(
        witness::recheck_context(&context, &current, &statement, 1_300_000),
        Err(codec::Reject::Expired)
    );
    let mut rollback = c.set(1_100_000);
    rollback.clock_floor_unix_millis = 1_200_000;
    assert_eq!(
        witness::verify_set(&record(&f, "current_set"), &rollback, None),
        Err(codec::Reject::StaleContext)
    );
    let mut replacement = c.set(1_100_000);
    replacement.root_epoch = 2;
    let replaced = witness::verify_set(&record(&f, "current_set"), &replacement, None)
        .expect("explicit root epoch replacement");
    assert_eq!(
        witness::recheck_context(&context, &replaced, &statement, 1_100_000),
        Err(codec::Reject::StaleContext)
    );
}
#[test]
fn malformed_unknown_and_oversized_inputs_reject_before_archive_or_mutation() {
    let f = fixture();
    let mut wire = bytes(&f["signed_vectors"]["current_set"]["wire_hex"]);
    wire.extend_from_slice(&[0xf8, 7, 1]);
    assert_eq!(
        codec::strict_decode::<host::SignedHostedWitnessSetV1>(&wire, witness::MAX_SET_BYTES),
        Err(codec::Reject::Canonical)
    );
    assert_eq!(
        codec::strict_decode::<host::SignedHostedWitnessSetV1>(
            &vec![0; witness::MAX_SET_BYTES + 1],
            witness::MAX_SET_BYTES
        ),
        Err(codec::Reject::Bounds)
    );
    let mut request: api::GetHostedWitnessHistoryProofRequest = record(&f, "lookup_request");
    witness::validate_lookup(&request).expect("exact selectors");
    request.executor_id.pop();
    assert_eq!(
        witness::validate_lookup(&request),
        Err(codec::Reject::Canonical)
    );
    let mut proof: host::HostedWitnessHistoryProofV1 = record(&f, "publication_proof");
    proof.siblings = vec![vec![0; 32]; 65];
    let set: host::SignedHostedWitnessSetV1 = record(&f, "retired_set");
    let entry = set
        .body
        .expect("set")
        .entries
        .into_iter()
        .find(|e| e.state == 2)
        .expect("retired entry");
    assert_eq!(
        witness::verify_inclusion(&[0; 32], &proof, &entry),
        Err(codec::Reject::Bounds)
    );
}
#[test]
fn incompatible_peer_requires_semantic_feature_and_exact_protocol_version() {
    assert_eq!(
        import::require_hybrid_peer(None),
        Err(codec::Reject::Protocol)
    );
    for (version, features) in [(1, vec![1]), (2, vec![]), (2, vec![1, 2]), (2, vec![1, 1])] {
        assert_eq!(
            import::require_hybrid_peer(Some(&host::ProtocolCompatibility {
                protocol_version: version,
                mandatory_features: features
            })),
            Err(codec::Reject::Protocol)
        );
    }
    import::require_hybrid_peer(Some(&host::ProtocolCompatibility {
        protocol_version: 2,
        mandatory_features: vec![1],
    }))
    .expect("explicit compatible peer");
}

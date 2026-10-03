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
    for descriptor in fixture["descriptors"]
        .as_array()
        .expect("frozen descriptors")
    {
        let message = pool
            .get_message_by_name(descriptor["name"].as_str().expect("name"))
            .expect("message");
        assert_eq!(
            message.fields().count(),
            descriptor["fields"].as_array().expect("fields").len()
        );
        for expected in descriptor["fields"].as_array().expect("fields") {
            let field = message
                .get_field(expected["number"].as_u64().expect("tag") as u32)
                .expect("frozen tag");
            assert_eq!(field.name(), expected["name"].as_str().expect("field name"));
            assert_eq!(
                field.is_list(),
                expected["list"].as_bool().expect("cardinality")
            );
        }
    }
    for descriptor in fixture["enums"].as_array().expect("frozen enums") {
        let enumeration = pool
            .get_enum_by_name(descriptor["name"].as_str().expect("enum name"))
            .expect("enum");
        assert_eq!(
            enumeration.values().count(),
            descriptor["values"].as_array().expect("values").len()
        );
        for expected in descriptor["values"].as_array().expect("values") {
            let value = enumeration
                .get_value(expected["number"].as_i64().expect("number") as i32)
                .expect("enum value");
            assert_eq!(value.name(), expected["name"].as_str().expect("value name"));
        }
    }
    let expected = [
        "CancelImportJob",
        "CommitImportJob",
        "GetHostedWitnessHistoryProof",
        "ImportSource",
        "PrepareImportJob",
        "RenewImportJob",
        "RetryImportSource",
        "SynchronizeRemote",
    ]
    .map(|name| format!("/heddle.api.v1alpha2.IntegrationService/{name}"));
    let actual: Vec<_> = heddle_api::v2::ALL_METHODS
        .iter()
        .filter(|method| !method.mandatory_features.is_empty())
        .map(|method| method.path)
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(
        fixture["protocol"]["gated_methods"],
        serde_json::json!(expected)
    );
    for path in &expected {
        let method = heddle_api::v2::method_descriptor(path).expect("generated method");
        assert_eq!(method.mandatory_features, [heddle_api::heddle::api::common::MandatoryProtocolFeature::ImportAuthorityHostWitnessV1]);
        assert_eq!(
            method.verify_protocol(&Default::default()),
            Err(heddle_api::hybrid_codec::Reject::Protocol)
        );
        method
            .verify_protocol(&heddle_api::heddle::api::common::CallContext {
                protocol: Some(heddle_api::heddle::api::common::ProtocolCompatibility {
                    protocol_version: 2,
                    mandatory_features: vec![1],
                }),
                ..Default::default()
            })
            .expect("explicit compatible protocol");
    }
    for name in ["Fetch", "PublishContent", "ReplicateThread"] {
        let method =
            heddle_api::v2::method_descriptor(&format!("/heddle.api.v1alpha2.SyncService/{name}"))
                .expect("Sync method");
        assert!(method.mandatory_features.is_empty(), "{name}");
        method
            .verify_protocol(&Default::default())
            .expect("ordinary Sync without HYBRID");
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
    // This root-only history is verified from the export. Only the owner and
    // descriptor root keys are independently selected; no fixture identity or
    // precomputed chain digest supplies the renewing receiver's context.
    fn from_export(f: &Value, bundle: &api::ImportPublicProofBundleV1) -> Self {
        fn key(out: &mut Vec<u8>, value: &api::AuthorizationVerificationKey) {
            assert_eq!(value.algorithm, 1);
            out.extend_from_slice(&1_u32.to_be_bytes());
            codec::counted(out, &value.public_key).expect("key");
        }
        let history = &bundle.owner_histories[0];
        assert!(history.accepted_transitions.is_empty());
        let signed = history.root.as_ref().expect("exported owner root");
        let root = signed.root.as_ref().expect("root body");
        let owner = bytes(&f["keys"]["owner"]["public_key_hex"]);
        let owner_key = root.authority_key.as_ref().expect("owner key");
        assert_eq!(owner_key.public_key, owner);
        let recovery = root.recovery_policy.as_ref().expect("recovery");
        let mut without_id = root.format_version.to_be_bytes().to_vec();
        codec::counted(&mut without_id, &root.account_uuid).expect("account");
        key(&mut without_id, owner_key);
        without_id.extend_from_slice(&recovery.threshold.to_be_bytes());
        without_id.extend_from_slice(&(recovery.guardians.len() as u32).to_be_bytes());
        for guardian in &recovery.guardians {
            without_id.extend_from_slice(&(guardian.kind as u32).to_be_bytes());
            key(&mut without_id, guardian.key.as_ref().expect("guardian"));
        }
        without_id.extend_from_slice(&recovery.window_secs.unwrap_or(604800).to_be_bytes());
        without_id.push(u8::from(root.claimable_deferred_human));
        codec::counted(&mut without_id, &root.nonce).expect("nonce");
        without_id.extend_from_slice(&root.claimable_until_unix_seconds.to_be_bytes());
        assert_eq!(
            root.owner_id,
            codec::hash(&[b"heddle-owner-root-v1", &without_id])
        );
        let mut canonical = root.format_version.to_be_bytes().to_vec();
        codec::counted(&mut canonical, &root.owner_id).expect("owner ID");
        canonical.extend_from_slice(&without_id[4..]);
        let state_hash = codec::hash(&[b"heddle-owner-root-v1", &canonical]);
        assert_eq!(history.state_hash, state_hash);
        let proof = signed.authority_proof.as_ref().expect("owner proof");
        assert_eq!(proof.signer_key_id, codec::key_id(&owner));
        codec::verify(&owner, &state_hash, &proof.signature).expect("independent owner root");
        assert_eq!(signed.recovery_key_proofs.len(), recovery.guardians.len());
        for (guardian, proof) in recovery.guardians.iter().zip(&signed.recovery_key_proofs) {
            let public = &guardian.key.as_ref().expect("guardian key").public_key;
            assert_eq!(proof.signer_key_id, codec::key_id(public));
            codec::verify(public, &state_hash, &proof.signature).expect("original guardian");
        }
        let signed_genesis = bundle.owner_genesis.as_ref().expect("Spool genesis");
        let genesis = signed_genesis.genesis.as_ref().expect("genesis");
        assert_eq!(genesis.owner_public_key.as_ref(), Some(owner_key));
        let proof = signed_genesis
            .owner_signature
            .as_ref()
            .expect("owner signature");
        assert_eq!(proof.signer_key_id, codec::key_id(&owner));
        codec::verify(
            &owner,
            &codec::hash(&[&owner, &genesis.spool_uuid]),
            &proof.signature,
        )
        .expect("original owner-signed Spool");
        let mut canonical = Vec::new();
        codec::counted(&mut canonical, &genesis.spool_uuid).expect("Spool");
        key(&mut canonical, owner_key);
        let spool_digest = codec::hash(&[b"heddle-spool-owner-genesis-v1", &canonical]);
        let identity = bundle.delegations[0]
            .body
            .as_ref()
            .expect("delegation")
            .identity
            .as_ref()
            .expect("identity")
            .clone();
        assert_eq!(identity.spool_uuid, genesis.spool_uuid);
        assert_eq!(identity.spool_genesis_digest, spool_digest);
        assert_eq!(identity.owner_id, root.owner_id);
        assert_eq!(identity.owner_account_uuid, root.account_uuid);
        assert_eq!(identity.owner_state_hash, state_hash);
        let chain = bundle.owner_chain.as_ref().expect("exported chain");
        assert_eq!(chain.spool_genesis_digest, spool_digest);
        assert_eq!(chain.owner_state_hashes, [state_hash]);
        let root_key = bytes(&f["keys"]["root"]["public_key_hex"]);
        let mut forbidden = vec![owner.clone(), root_key.clone()];
        forbidden.extend(
            bundle
                .original_geneses
                .iter()
                .flat_map(|g| g.signatures.iter().map(|s| s.public_key.clone())),
        );
        forbidden.extend(
            bundle
                .witness_set
                .as_ref()
                .expect("set")
                .body
                .as_ref()
                .expect("set body")
                .entries
                .iter()
                .map(|e| e.public_key.clone()),
        );
        Self {
            identity,
            owner,
            chain: import::owner_chain_digest(chain).expect("verified exported owner chain"),
            forbidden,
            job_keys: bundle
                .delegations
                .iter()
                .map(|d| d.body.as_ref().expect("delegation").job_public_key.clone())
                .collect(),
            root: root_key,
        }
    }
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
        assert!(
            v["first_failing_check"].as_str().is_some(),
            "named first check"
        );
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
                let member: api::SignedImportMemberPermissionV1 = record(&f, "renewed_permission");
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
            v["expected"].as_str().expect("expected named gate"),
            "{}: first failing check {}",
            v["id"],
            v["first_failing_check"]
        );
        match v["type"].as_str().expect("gate") {
            "set" => {
                let previous = v["previous"].as_str().map(|n| {
                    witness::verify_set(&record(&f, n), &c.set(1_100_000), None).expect("previous")
                });
                witness::verify_set(
                    &record(&f, v["control"].as_str().expect("passing control")),
                    &c.set(1_100_000),
                    previous.as_ref(),
                )
                .expect("passing neighboring set");
            }
            "statement" => {
                let fresh = v["new_work"] == true;
                let now = if fresh { 1_100_000 } else { 1_350_000 };
                let set = witness::verify_set(
                    &record(&f, if fresh { "current_set" } else { "retired_set" }),
                    &c.set(now),
                    None,
                )
                .expect("passing control set");
                let proof: host::HostedWitnessHistoryProofV1 = record(&f, "publication_proof");
                witness::resolve_statement(
                    &set,
                    &record(&f, "publication_statement"),
                    if fresh { None } else { Some(&proof) },
                    fresh,
                    now,
                )
                .expect("passing neighboring testimony");
            }
            "operation" => import::verify_operation(&record(&f, "operation_main"), &d)
                .expect("passing operation"),
            "new_operation" => {
                import::verify_new_operation(&record(&f, "operation_main"), &d, 1299)
                    .expect("otherwise valid before expiry")
            }
            "renewal" => {
                import::verify_renewal(
                    &record(&f, "renewal"),
                    &d,
                    &record(&f, "partial_manifest"),
                    1,
                    Some(&record(&f, "renewed_permission")),
                    &c.owner(1200),
                )
                .expect("passing renewal");
            }
            _ => panic!("unknown control"),
        }
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
                    .expect("actual authority format");
            assert_eq!(
                import::select_import_permission(
                    import::ImportPermissionEvidence::OwnerCapability(&value)
                ),
                Err(codec::Reject::ImportPermission)
            );
        } else {
            assert_eq!(
                import::select_import_permission(import::ImportPermissionEvidence::OnlineRole(
                    "Developer"
                )),
                Err(codec::Reject::ImportPermission)
            );
        }
        let parent: api::SignedImportMemberPermissionV1 = record(&f, "permission");
        let selected =
            import::select_import_permission(import::ImportPermissionEvidence::Import(&parent))
                .expect("passing format control");
        import::verify_delegation(&record(&f, "delegation"), Some(selected), &c.owner(1100))
            .expect("valid surrounding authority");
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
                    Some(&record(&f, "renewed_permission")),
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
                import::verify_new_operation(&stale, &old, 1250)
                    .expect("otherwise time-valid old worker");
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
            &record(&f, "completed_slot_renewal"),
            &old,
            &record(&f, "completed_slot_manifest"),
            1,
            Some(&record(&f, "renewed_permission")),
            &c.owner(1200)
        ),
        Err(codec::Reject::CommittedSlot)
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

#[test]
fn frozen_unsigned_payloads_and_cross_model_commitments() {
    let f = fixture();
    for (name, v) in f["commitment_vectors"].as_object().expect("preimages") {
        macro_rules! canonical {
            ($ty:ty) => {
                codec::canonical(
                    &codec::strict_decode::<$ty>(&bytes(&v["wire_hex"]), import::MAX_BUNDLE_BYTES)
                        .expect("wire"),
                )
                .expect("canonical")
            };
        }
        let canonical = match v["schema"]
            .as_str()
            .expect("schema")
            .rsplit('.')
            .next()
            .expect("name")
        {
            "ImportFrontierV1" => {
                let value: api::ImportFrontierV1 =
                    codec::strict_decode(&bytes(&v["wire_hex"]), import::MAX_BUNDLE_BYTES)
                        .expect("frontier");
                assert_eq!(
                    import::frontier_digest(&value).expect("frontier hash"),
                    bytes(&v["digest_hex"])
                );
                canonical!(api::ImportFrontierV1)
            }
            "HostedWitnessBoundaryAcceptanceV1" => {
                canonical!(host::HostedWitnessBoundaryAcceptanceV1)
            }
            "ImportContentV1" => canonical!(api::ImportContentV1),
            "ImportGenesisWitnessV1" => canonical!(api::ImportGenesisWitnessV1),
            "ImportAuthorityWitnessV1" => canonical!(api::ImportAuthorityWitnessV1),
            "HostedLandingWitnessV1" => canonical!(api::HostedLandingWitnessV1),
            "ImportOwnerChainV1" => canonical!(api::ImportOwnerChainV1),
            "ImportResultManifestV1" => canonical!(api::ImportResultManifestV1),
            "ImportPublicationWitnessV1" => canonical!(api::ImportPublicationWitnessV1),
            "SignedImportMemberPermissionV1" => canonical!(api::SignedImportMemberPermissionV1),
            "SignedImportGenesisAuthorityV1" => canonical!(api::SignedImportGenesisAuthorityV1),
            "SignedImportJobDelegationV1" => canonical!(api::SignedImportJobDelegationV1),
            "SignedDelegatedImportOperationV1" => canonical!(api::SignedDelegatedImportOperationV1),
            unknown => panic!("unhandled {unknown}"),
        };
        assert_eq!(canonical, bytes(&v["canonical_hex"]), "{name}");
        let preimage = [v["domain"].as_str().expect("domain").as_bytes(), &canonical].concat();
        assert_eq!(preimage, bytes(&v["preimage_hex"]));
        assert_eq!(codec::hash(&[&preimage]), bytes(&v["digest_hex"]));
    }
}
#[test]
fn purpose_specific_original_signatures_are_independent_of_witness_trust() {
    let f = fixture();
    let c = Context::new(&f);
    let set =
        witness::verify_set(&record(&f, "current_set"), &c.set(1_100_000), None).expect("witness");
    let s: host::SignedHostedWitnessStatementV1 = record(&f, "genesis_admission");
    let p: api::ImportGenesisWitnessV1 = record(&f, "genesis_payload");
    witness::resolve_statement(&set, &s, None, false, 1_100_000).expect("witness signature");
    import::verify_witness_payload(
        s.body.as_ref().expect("statement"),
        import::WitnessPayload::Genesis(&p),
    )
    .expect("actual creator and binding");
    for name in [
        "authority_admission",
        "ownership_admission",
        "resolution_admission",
    ] {
        let s: host::SignedHostedWitnessStatementV1 = record(&f, name);
        let p: api::ImportAuthorityWitnessV1 = record(&f, &format!("{name}_payload"));
        witness::resolve_statement(&set, &s, None, false, 1_100_000).expect("witness signature");
        import::verify_witness_payload(
            s.body.as_ref().expect("statement"),
            import::WitnessPayload::Authority(&p),
        )
        .expect("actual original authority signatures");
        let mut replaced = p.clone();
        replaced.original.as_mut().expect("original").signatures[0].signature = s.signature.clone();
        assert_eq!(
            import::verify_witness_payload(
                s.body.as_ref().expect("statement"),
                import::WitnessPayload::Authority(&replaced)
            ),
            Err(codec::Reject::Signature)
        );
    }
    let s: host::SignedHostedWitnessStatementV1 = record(&f, "landing_statement");
    let mut p: api::HostedLandingWitnessV1 = record(&f, "landing_payload");
    witness::resolve_statement(&set, &s, None, false, 1_100_000).expect("witness signature");
    import::verify_witness_payload(
        s.body.as_ref().expect("statement"),
        import::WitnessPayload::Landing(&p),
    )
    .expect("original landing request/execution/source");
    p.request
        .as_mut()
        .expect("request")
        .signature
        .as_mut()
        .expect("signature")
        .signature = s.signature.clone();
    assert_eq!(
        import::verify_witness_payload(
            s.body.as_ref().expect("statement"),
            import::WitnessPayload::Landing(&p)
        ),
        Err(codec::Reject::Signature)
    );
    let s: host::SignedHostedWitnessStatementV1 = record(&f, "witness_without_owner");
    let p: api::ImportAuthorityWitnessV1 = record(&f, "missing_owner_payload");
    witness::resolve_statement(&set, &s, None, false, 1_100_000)
        .expect("genuine witness even without owner");
    assert_eq!(
        import::verify_witness_payload(
            s.body.as_ref().expect("statement"),
            import::WitnessPayload::Authority(&p)
        ),
        Err(codec::Reject::Signature)
    );
    assert_eq!(
        import::verify_operation(&record(&f, "witness_without_job"), &delegation(&f, &c)),
        Err(codec::Reject::Signature)
    );
}
#[test]
fn fresh_export_contains_replaced_expired_permissions_and_each_original_manifest() {
    let f = fixture();
    let b: api::ImportPublicProofBundleV1 = record(&f, "complete_renewed_export");
    let c = Context::from_export(&f, &b);
    import::validate_public_bundle(&b).expect("complete renewed closure");
    let set = witness::verify_set(
        b.witness_set.as_ref().expect("set"),
        &c.set(1_350_000),
        None,
    )
    .expect("fresh independently rooted witness set");
    let authenticated_time = |name: &str, proof_name: &str| {
        let signed: host::SignedHostedWitnessStatementV1 = record(&f, name);
        assert!(
            b.statements.contains(&signed),
            "original receipt is exported"
        );
        let proof: host::HostedWitnessHistoryProofV1 = record(&f, proof_name);
        witness::resolve_statement(&set, &signed, Some(&proof), false, 1_350_000)
            .expect("original receipt signature and retirement binding");
        let body = signed.body.as_ref().expect("authenticated body");
        assert!(
            b.policies.iter().any(|p| p.body.as_ref().is_some_and(|p| {
                p.sequence == body.policy_sequence
                    && p.policy_state_hash == body.policy_state_hash
                    && p.spool_uuid == body.spool_uuid
            })),
            "selected signed policy exported; native gate verifies its owner and preimage"
        );
        body.observed_at_unix_millis / 1000
    };
    let publication_time = authenticated_time("publication_statement", "publication_proof");
    let renewed_time =
        authenticated_time("renewed_publication_statement", "renewed_publication_proof");
    let old = &b.delegations[0];
    let successor = &b.delegations[1];
    let p0 = import::resolve_bundle_permission(
        &b,
        &old.body.as_ref().expect("old").parent_permission_digest,
    )
    .expect("parent");
    let p1 = import::resolve_bundle_permission(
        &b,
        &successor
            .body
            .as_ref()
            .expect("new")
            .parent_permission_digest,
    )
    .expect("replacement parent");
    assert_ne!(p0, p1);
    assert_eq!(
        import::verify_member_permission(p0.expect("member"), &c.owner(1350)),
        Err(codec::Reject::Expired)
    );
    let previous = import::verify_delegation(old, p0, &c.owner(publication_time))
        .expect("historical authority at original publication");
    for genesis in &b.genesis_authorities {
        let payload = b
            .genesis_witnesses
            .iter()
            .find(|p| p.binding.as_ref() == Some(genesis))
            .expect("each original genesis sidecar");
        let canonical = codec::canonical(payload).expect("payload bytes");
        let admission = b
            .statements
            .iter()
            .find(|s| {
                s.body
                    .as_ref()
                    .is_some_and(|s| s.purpose == 1 && s.canonical_payload == canonical)
            })
            .expect("each original genesis admission");
        let main: host::SignedHostedWitnessStatementV1 = record(&f, "genesis_admission");
        let (name, proof) = if *admission == main {
            ("genesis_admission", "genesis_proof")
        } else {
            ("genesis_dev_admission", "genesis_dev_proof")
        };
        let admission_time = authenticated_time(name, proof);
        let at_admission = import::verify_delegation(old, p0, &c.owner(admission_time))
            .expect("original parent authority at authenticated genesis admission");
        import::verify_witness_payload(
            admission.body.as_ref().expect("receipt"),
            import::WitnessPayload::Genesis(payload),
        )
        .expect("exact original genesis admission payload");
        let binding = genesis.body.as_ref().expect("genesis binding");
        let original = b
            .original_geneses
            .iter()
            .find(|record| {
                let mut hash = blake3::Hasher::new();
                hash.update(record.format.as_bytes());
                hash.update(&(record.canonical_record.len() as u64).to_le_bytes());
                hash.update(b"\0");
                hash.update(&record.canonical_record);
                hash.finalize().as_bytes().as_slice() == binding.genesis_digest
            })
            .expect("exported original genesis");
        assert_eq!(original.format, "heddle-thread-genesis-v1");
        let signature = original
            .signatures
            .iter()
            .find(|s| s.public_key == binding.creator_public_key)
            .expect("original creator");
        codec::verify(
            &signature.public_key,
            &[
                original.format.as_bytes(),
                b"\0",
                &original.canonical_record,
            ]
            .concat(),
            &signature.signature,
        )
        .expect("original native signature");
        let envelope = b
            .creator_authority_envelopes
            .iter()
            .find(|e| codec::hash(&[e]) == binding.creator_authority_envelope_digest)
            .expect("exported original envelope");
        import::verify_genesis_authority(
            genesis,
            &at_admission,
            &binding.genesis_digest,
            &signature.signature,
            &codec::hash(&[envelope]),
        )
        .expect("original genesis context, never replacement parent");
    }
    let renewal = &b.renewals[0];
    let committed = import::resolve_bundle_manifest(
        &b,
        &renewal
            .body
            .as_ref()
            .expect("renewal")
            .committed_manifest_digest,
    )
    .expect("original partial snapshot");
    let next = import::verify_renewal(renewal, &previous, committed, 1, p1, &c.owner(renewed_time))
        .expect("renewal at successor witnessed time");
    for o in &b.operations {
        let is_old = o.body.as_ref().expect("operation").delegation_digest == previous.digest();
        let active = if is_old { &previous } else { &next };
        let proof: host::HostedWitnessHistoryProofV1 = record(
            &f,
            if is_old {
                "publication_proof"
            } else {
                "renewed_publication_proof"
            },
        );
        let (manifest, statement) = b
            .manifests
            .iter()
            .find_map(|m| {
                let payload =
                    codec::canonical(&import::publication_payload(o, m).expect("payload"))
                        .expect("canonical");
                b.statements
                    .iter()
                    .find(|s| {
                        s.body
                            .as_ref()
                            .is_some_and(|s| s.purpose == 3 && s.canonical_payload == payload)
                    })
                    .map(|s| (m, s))
            })
            .expect("each exact immutable publication manifest");
        import::verify_publication(
            o,
            active,
            manifest,
            statement,
            &set,
            Some(&proof),
            1_350_000,
        )
        .expect("original publication after expiry and retirement");
    }
    let mut missing = b.clone();
    missing.member_permissions.clear();
    assert_eq!(
        import::validate_public_bundle(&missing),
        Err(codec::Reject::ImportPermission)
    );
    let mut missing = b.clone();
    missing.manifests.clear();
    assert_eq!(
        import::validate_public_bundle(&missing),
        Err(codec::Reject::StaleManifest)
    );
    let mut duplicated = b.clone();
    duplicated.manifests.push(duplicated.manifests[0].clone());
    assert_eq!(
        import::validate_public_bundle(&duplicated),
        Err(codec::Reject::Canonical)
    );
}
#[test]
fn historical_export_requires_each_selected_policy_and_genesis_admission_original() {
    let f = fixture();
    let b: api::ImportPublicProofBundleV1 = record(&f, "complete_renewed_export");
    import::validate_public_bundle(&b).expect("complete control");
    let mut missing = b.clone();
    missing.policies.clear();
    assert_eq!(
        import::validate_public_bundle(&missing),
        Err(codec::Reject::Scope)
    );
    println!("B REJECT zero-policy export: Scope");
    let mut duplicate = b.clone();
    duplicate.policies.push(duplicate.policies[0].clone());
    assert_eq!(
        import::validate_public_bundle(&duplicate),
        Err(codec::Reject::Canonical)
    );
    // Reference-only chain probe. Native policy/signature mutation rejection
    // is exercised separately by the published-codec gate.
    let mut chain = b.clone();
    let mut second = chain.policies[0].clone();
    let body = second.body.as_mut().expect("policy");
    body.expected_head = Some(api::SignedPolicyHead {
        state_hash: body.policy_state_hash.clone(),
        sequence: 1,
    });
    body.sequence = 2;
    body.policy_state_hash = vec![0x7b; 32];
    chain.policies.push(second);
    for receipt in &mut chain.statements {
        let body = receipt.body.as_mut().expect("receipt");
        body.policy_sequence = 2;
        body.policy_state_hash = vec![0x7b; 32];
    }
    import::validate_public_bundle(&chain).expect("complete predecessor references");
    chain.policies.remove(0);
    assert_eq!(
        import::validate_public_bundle(&chain),
        Err(codec::Reject::Scope)
    );
    for (i, payload) in b.genesis_witnesses.iter().enumerate() {
        for part in ["admission", "payload", "genesis", "envelope"] {
            let mut missing = b.clone();
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
            println!("B REJECT missing branch {i} genesis {part}: Scope");
        }
    }
}

#[test]
fn preparation_wire_state_and_publication_wins_manifest_cas() {
    let f = fixture();
    let c = Context::new(&f);
    let mut response: api::PrepareImportJobResponse = record(&f, "renewal_preparation");
    import::validate_renewal_preparation(&response).expect("coherent snapshot");
    let renewal: api::SignedImportJobRenewalV1 = record(&f, "renewal");
    let state = response.renewal_state.as_ref().expect("CAS state");
    let r = renewal.body.as_ref().expect("renewal");
    assert_eq!(state.authority_epoch, r.expected_authority_epoch);
    assert_eq!(
        import::manifest_digest(state.committed_manifest.as_ref().expect("manifest"))
            .expect("hash"),
        r.committed_manifest_digest
    );
    response
        .renewal_state
        .as_mut()
        .expect("state")
        .logical_job_id = vec![0; 16];
    assert_eq!(
        import::validate_renewal_preparation(&response),
        Err(codec::Reject::StaleContext)
    );
    let renewal: api::SignedImportJobRenewalV1 = record(&f, "publication_wins_renewal");
    let old = delegation(&f, &c);
    let p: api::SignedImportMemberPermissionV1 = record(&f, "renewed_permission");
    import::verify_new_operation(&record(&f, "operation_main"), &old, 1250)
        .expect("time-valid publication wins");
    import::verify_renewal(
        &renewal,
        &old,
        &record(&f, "empty_manifest"),
        1,
        Some(&p),
        &c.owner(1250),
    )
    .expect("passing unchanged CAS control");
    assert_eq!(
        import::verify_renewal(
            &renewal,
            &old,
            &record(&f, "partial_manifest"),
            1,
            Some(&p),
            &c.owner(1250)
        ),
        Err(codec::Reject::StaleManifest)
    );
}
#[test]
fn authentic_legacy_hosted_import_fails_hybrid_dispatch() {
    let f = fixture();
    let record: api::SignedRecord = record(&f, "legacy_hosted_import");
    for s in &record.signatures {
        codec::verify(
            &s.public_key,
            &[record.format.as_bytes(), b"\0", &record.canonical_record].concat(),
            &s.signature,
        )
        .expect("genuine witness on legacy operation");
    }
    assert_eq!(
        import::require_import_operation_format(&record.format),
        Err(codec::Reject::Protocol)
    );
    import::require_import_operation_format(import::OPERATION_DOMAIN)
        .expect("new dispatch control");
}
#[test]
fn shared_multibyte_root_id_boundary_uses_utf8_octets() {
    let f = fixture();
    let c = Context::new(&f);
    for (name, result) in [("root_id_boundary", true), ("root_id_over_boundary", false)] {
        let set: host::SignedHostedWitnessSetV1 = record(&f, name);
        let root_id = &set.body.as_ref().expect("body").descriptor_root_id;
        assert_eq!(root_id.len(), if result { 256 } else { 258 });
        let mut e = c.set(1_100_000);
        e.root_id = root_id;
        let actual = witness::verify_set(&set, &e, None);
        if result {
            actual.expect("256-byte root ID passes");
        } else {
            assert_eq!(actual, Err(codec::Reject::Bounds));
        }
    }
}
#[test]
fn raw_commitment_domains_and_preimages_are_frozen() {
    let f = fixture();
    for (_, v) in f["raw_commitment_vectors"]
        .as_object()
        .expect("raw preimages")
    {
        let preimage = [
            v["domain"].as_str().expect("domain").as_bytes(),
            &bytes(&v["canonical_hex"]),
        ]
        .concat();
        assert_eq!(preimage, bytes(&v["preimage_hex"]));
        assert_eq!(codec::hash(&[&preimage]), bytes(&v["digest_hex"]));
    }
}

#[test]
fn boundary_passing_genesis_and_dependency_vectors() {
    let f = fixture();
    let c = Context::new(&f);
    let set =
        witness::verify_set(&record(&f, "current_set"), &c.set(1_100_000), None).expect("set");
    for v in f["boundary_vectors"]["passing"]
        .as_array()
        .expect("passing")
    {
        let statement: host::SignedHostedWitnessStatementV1 =
            record(&f, v["statement"].as_str().expect("statement"));
        witness::resolve_statement(&set, &statement, None, false, 1_100_000)
            .expect("authentic witness");
        if v["kind"] == "genesis" {
            let payload = record(&f, v["payload"].as_str().expect("payload"));
            import::verify_witness_payload(
                statement.body.as_ref().expect("body"),
                import::WitnessPayload::Genesis(&payload),
            )
            .expect("exact acceptance");
        } else {
            let payload = record(&f, v["payload"].as_str().expect("payload"));
            import::verify_witness_payload(
                statement.body.as_ref().expect("body"),
                import::WitnessPayload::Authority(&payload),
            )
            .expect("exact dependency binding");
        }
    }
}
fn boundary_negative(name: &str) {
    let f = fixture();
    let c = Context::new(&f);
    let set =
        witness::verify_set(&record(&f, "current_set"), &c.set(1_100_000), None).expect("set");
    let v = f["boundary_vectors"]["negative"]
        .as_array()
        .expect("negative")
        .iter()
        .find(|v| v["name"] == name)
        .expect("named vector");
    let bad: host::SignedHostedWitnessStatementV1 =
        record(&f, v["statement"].as_str().expect("statement"));
    let payload: api::ImportGenesisWitnessV1 = record(&f, v["payload"].as_str().expect("payload"));
    // Every negative has an authentic witness signature. The rejection must be
    // exact acceptance binding, never Signature or generic payload Scope.
    codec::verify(
        &bytes(&f["keys"]["witness"]["public_key_hex"]),
        &witness::statement_signing_digest(bad.body.as_ref().expect("body")).expect("digest"),
        &bad.signature,
    )
    .expect("genuine negative signature");
    if name == "missing_binding" {
        assert_eq!(
            witness::resolve_statement(&set, &bad, None, false, 1_100_000),
            Err(codec::Reject::BoundaryAcceptance)
        );
    } else {
        witness::resolve_statement(&set, &bad, None, false, 1_100_000)
            .expect("authenticated substituted payload");
    }
    assert_eq!(
        import::verify_witness_payload(
            bad.body.as_ref().expect("body"),
            import::WitnessPayload::Genesis(&payload)
        ),
        Err(codec::Reject::BoundaryAcceptance),
        "{name}"
    );
    println!("BOUNDARY REJECT {name}: BoundaryAcceptance");
    let good: host::SignedHostedWitnessStatementV1 = record(&f, "boundary_genesis_statement");
    let payload = record(&f, "boundary_genesis_payload");
    witness::resolve_statement(&set, &good, None, false, 1_100_000).expect("control witness");
    import::verify_witness_payload(
        good.body.as_ref().expect("body"),
        import::WitnessPayload::Genesis(&payload),
    )
    .expect("neighboring exact control");
    println!("BOUNDARY PASS {name}: exact control");
}
macro_rules! boundary_test {
    ($name:ident, $vector:literal) => {
        #[test]
        fn $name() {
            boundary_negative($vector);
        }
    };
}
boundary_test!(
    boundary_acceptance_swapped_between_originals,
    "acceptance_swapped_between_originals"
);
boundary_test!(boundary_manifest_mismatch, "manifest_mismatch");
boundary_test!(boundary_intent_mismatch, "intent_mismatch");
boundary_test!(
    boundary_receipt_from_another_acceptance,
    "receipt_from_another_acceptance"
);
boundary_test!(boundary_missing_binding, "missing_binding");
#[test]
fn boundary_dependency_requires_exact_evidence() {
    let f = fixture();
    let s: host::SignedHostedWitnessStatementV1 =
        record(&f, "boundary_dependency_missing_statement");
    let p = record(&f, "boundary_dependency_missing_payload");
    assert_eq!(
        import::verify_witness_payload(
            s.body.as_ref().expect("body"),
            import::WitnessPayload::Authority(&p)
        ),
        Err(codec::Reject::BoundaryAcceptance)
    );
    println!("BOUNDARY REJECT dependency_missing_binding: BoundaryAcceptance");
    let s: host::SignedHostedWitnessStatementV1 = record(&f, "boundary_authority_statement");
    let p = record(&f, "boundary_authority_payload");
    import::verify_witness_payload(
        s.body.as_ref().expect("body"),
        import::WitnessPayload::Authority(&p),
    )
    .expect("matched dependencies");
    println!("BOUNDARY PASS dependency_missing_binding: exact control");
}

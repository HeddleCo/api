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
        "GetImportJobState",
        "ImportSource",
        "PrepareImportJob",
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

#[test]
fn submission_observe_requires_signed_disclosure() {
    let f = fixture();
    let mut scope: api::ImportPermissionScopeV1 = record(&f, "scope");
    import::validate_scope(&scope).expect("pinned control");
    scope.branches[0].ref_mode = 2;
    scope.branches[0].pinned_commit_oid.clear();
    assert!(
        import::validate_scope(&scope).is_err(),
        "observe mode must carry the signed disclosure"
    );
}

#[test]
fn submission_changed_prepare_scope_is_rejected() {
    let f = fixture();
    let request = record(&f, "prepare_request");
    assert_eq!(
        import::validate_preparation_response(
            &request,
            &record(&f, "prepare_changed_converterVersion")
        ),
        Err(codec::Reject::PreparedFields)
    );
    import::validate_preparation_response(&request, &record(&f, "commit_preparation"))
        .expect("unchanged control");
}

#[test]
fn submission_commit_requires_source() {
    let f = fixture();
    assert_eq!(
        import::validate_commit_request(
            &record(&f, "submission_missing_source"),
            "github",
            &record(&f, "source_connected"),
            &record(&f, "import_configuration")
        ),
        Err(codec::Reject::SourceSelection)
    );
    import::validate_commit_request(
        &record(&f, "commit_request"),
        "github",
        &record(&f, "source_connected"),
        &record(&f, "import_configuration"),
    )
    .expect("complete control");
}

#[test]
fn submission_import_source_is_closed() {
    let f = fixture();
    assert_eq!(
        import::validate_import_source(&record(&f, "import_source_misuse")),
        Err(codec::Reject::ImportSourceRequiresCommit)
    );
    import::validate_commit_request(
        &record(&f, "commit_request"),
        "github",
        &record(&f, "source_connected"),
        &record(&f, "import_configuration"),
    )
    .expect("Commit control");
}

#[test]
fn submission_contract_vectors() {
    let f = fixture();
    let request: api::PrepareImportJobRequest = record(&f, "prepare_request");
    let response: api::PrepareImportJobResponse = record(&f, "commit_preparation");
    for v in f["submission_vectors"]["changed_preparations"]
        .as_array()
        .expect("scope changes")
    {
        let changed = record(&f, v["response"].as_str().expect("response"));
        assert_eq!(
            import::validate_preparation_response(&request, &changed),
            Err(codec::Reject::PreparedFields)
        );
        println!(
            "SUBMISSION REJECT prepare.{}: PreparedFields",
            v["id"].as_str().expect("field")
        );
        import::validate_preparation_response(&request, &response).expect("exact scope control");
        println!(
            "SUBMISSION PASS prepare.{}: unchanged control",
            v["id"].as_str().expect("field")
        );
    }
    let issue_token: api::PrepareImportJobRequest = record(&f, "prepare_issue_token");
    import::validate_preparation_response(&issue_token, &response).expect("host-issued token");
    let scope: api::ImportPermissionScopeV1 = record(&f, "scope");
    let mut unknown_refusal: api::PrepareImportJobResponse =
        record(&f, "prepare_refusal_converter");
    unknown_refusal.refusal.as_mut().expect("refusal").reason = 99;
    assert_eq!(
        import::validate_preparation_response(&request, &unknown_refusal),
        Err(codec::Reject::Version)
    );
    let config = record(&f, "import_configuration");
    let selected = import::prepare_scope(
        issue_token.proposed_scope.as_ref().expect("scope"),
        &config,
        &scope.destination_version,
    )
    .expect("issued CAS");
    assert_eq!(selected, scope);
    assert!(
        issue_token
            .proposed_scope
            .as_ref()
            .expect("scope")
            .destination_version
            .is_empty()
    );
    for v in f["submission_vectors"]["scope_refusals"]
        .as_array()
        .expect("refusals")
    {
        let bad = record(&f, v["scope"].as_str().expect("scope"));
        let config = record(&f, v["configuration"].as_str().expect("config"));
        let reason = api::ImportPreparationRefusalReason::try_from(
            v["reason"].as_i64().expect("reason") as i32,
        )
        .expect("typed reason");
        assert_eq!(
            import::prepare_scope(&bad, &config, &scope.destination_version),
            Err(codec::Reject::PreparationRefused(reason))
        );
        let refused = record(
            &f,
            &format!("prepare_refusal_{}", v["id"].as_str().expect("id")),
        );
        assert_eq!(
            import::validate_preparation_response(&request, &refused),
            Err(codec::Reject::PreparationRefused(reason))
        );
        import::prepare_scope(&scope, &config, &scope.destination_version).expect("scope control");
        println!(
            "SUBMISSION REJECT then PASS scope.{}: {reason:?}",
            v["id"].as_str().expect("id")
        );
    }
    for v in f["submission_vectors"]["commit_negatives"]
        .as_array()
        .expect("commit negatives")
    {
        let bad: api::CommitImportJobRequest = record(&f, v["request"].as_str().expect("request"));
        let provider = if bad.source.as_ref().is_some_and(|s| s.connection.is_none()) {
            "public-git"
        } else {
            "github"
        };
        let actual = import::validate_commit_request(
            &bad,
            provider,
            &record(
                &f,
                if provider == "public-git" {
                    "source_public_github"
                } else {
                    "source_connected"
                },
            ),
            &record(&f, "import_configuration"),
        );
        assert_eq!(
            format!("{:?}", actual.expect_err("negative")),
            v["expected"].as_str().expect("reason")
        );
        println!(
            "SUBMISSION REJECT commit.{}: {:?}",
            v["id"].as_str().expect("id"),
            actual.expect_err("negative")
        );
        import::validate_commit_request(
            &record(&f, "commit_request"),
            "github",
            &record(&f, "source_connected"),
            &record(&f, "import_configuration"),
        )
        .expect("complete Commit control");
        println!(
            "SUBMISSION PASS commit.{}: complete control",
            v["id"].as_str().expect("id")
        );
    }
    for name in ["commit_hosted_base", "commit_public_source"] {
        import::validate_commit_request(
            &record(&f, name),
            if name == "commit_public_source" {
                "public-git"
            } else {
                "github"
            },
            &record(
                &f,
                if name == "commit_public_source" {
                    "source_public_github"
                } else {
                    "source_connected"
                },
            ),
            &record(&f, "import_configuration"),
        )
        .expect("optional base / public source");
    }
    let commit: api::CommitImportJobRequest = record(&f, "commit_request");
    let c = Context::new(&f);
    import::verify_commit_submission(
        &commit,
        &response,
        "github",
        &record(&f, "source_connected"),
        &record(&f, "import_configuration"),
        &c.owner(1100),
    )
    .expect("complete signed initial submission");
    assert_eq!(
        import::validate_commit_request(
            &commit,
            "gitlab",
            &record(&f, "source_connected"),
            &record(&f, "import_configuration")
        ),
        Err(codec::Reject::SourceSelection)
    );
    let pending = record(&f, "commit_response");
    import::check_commit_replay(&commit, &commit, &pending).expect("exact replay");
    let mut changed = commit.clone();
    changed.initial_base_state.clear();
    assert_eq!(
        import::check_commit_replay(&changed, &commit, &pending),
        Err(codec::Reject::OperationIdReused)
    );
    let applied = api::MutationResponse {
        receipt: Some(api::MutationReceipt {
            client_operation_id: commit.client_operation_id.clone(),
            outcome: Some(api::mutation_receipt::Outcome::Applied(
                api::Applied::default(),
            )),
            ..Default::default()
        }),
    };
    assert_eq!(
        import::validate_commit_response(&commit, &applied),
        Err(codec::Reject::PendingOperation)
    );
    assert_eq!(
        import::validate_import_source(&record(&f, "import_source_misuse")),
        Err(codec::Reject::ImportSourceRequiresCommit)
    );
    println!("SUBMISSION REJECT ImportSource misuse: ImportSourceRequiresCommit");
    import::validate_commit_request(
        &commit,
        "github",
        &record(&f, "source_connected"),
        &record(&f, "import_configuration"),
    )
    .expect("use Commit instead");
    println!("SUBMISSION PASS ImportSource misuse: Commit control");
    let observe: api::ImportPermissionScopeV1 = record(&f, "scope_observe_disclosed");
    let undisclosed = record(&f, "scope_observe_undisclosed");
    assert_eq!(
        import::validate_scope(&undisclosed),
        Err(codec::Reject::RefDisclosure)
    );
    import::validate_scope(&observe).expect("explicit fallback");
    println!("SUBMISSION REJECT then PASS observe_without_disclosure: RefDisclosure");
    import::validate_ref_selection(
        &scope.branches[0],
        Some(&scope.branches[0].pinned_commit_oid),
    )
    .expect("known exact OID");
    assert_eq!(
        import::validate_ref_selection(
            &observe.branches[0],
            Some(&scope.branches[0].pinned_commit_oid)
        ),
        Err(codec::Reject::RefPinning)
    );
    import::validate_ref_selection(&observe.branches[0], None)
        .expect("unknown OID disclosed fallback");
    let c = Context::new(&f);
    let geneses = [
        record(&f, "direct_genesis_0"),
        record(&f, "direct_genesis_1"),
    ];
    let bad = import::verify_prepared_delegation(
        &record(&f, "submission_observe_undisclosed_preparation"),
        &record(&f, "submission_observe_undisclosed_delegation"),
        None,
        &geneses,
        &c.owner(1100),
    );
    assert_eq!(bad.err(), Some(codec::Reject::RefDisclosure));
    import::verify_prepared_delegation(
        &record(&f, "submission_observe_preparation"),
        &record(&f, "submission_observe_delegation"),
        None,
        &geneses,
        &c.owner(1100),
    )
    .expect("signed disclosed fallback");
    let advertised = &config.converters[0];
    assert_eq!(
        import::conversion_options_digest(
            &advertised.converter_version,
            &advertised.default_options
        )
        .expect("default encoding digest"),
        scope.options_digest
    );
    let mut malformed = config.clone();
    malformed.converters[0].default_options = vec![1];
    assert_eq!(
        import::validate_import_configuration(&malformed),
        Err(codec::Reject::Canonical)
    );
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
    // precomputed chain digest supplies the receiving verifier's context.
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
            job_keys: ["job", "sibling_job", "direct_job"]
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
        import::verify_new_operation(
            &record(&f, &format!("operation_{name}")),
            &d,
            1100,
            &empty_for(&d),
        )
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
        import::verify_new_operation(&operation, &d, 1350, &empty_for(&d)),
        Err(codec::Reject::Expired)
    );
}
#[test]
fn negative_vectors_isolate_their_named_gate() {
    let f = fixture();
    let c = Context::new(&f);
    let d = delegation(&f, &c);
    for v in f["negative_vectors"].as_array().expect("negative vectors") {
        assert!(v["id"].as_str().is_some(), "named first check");
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
                &empty_for(&d),
            ),
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
            "new_operation" => import::verify_new_operation(
                &record(&f, "operation_main"),
                &d,
                1299,
                &empty_for(&d),
            )
            .expect("otherwise valid before expiry"),
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
            "ImportJobPreparationV1" => canonical!(api::ImportJobPreparationV1),
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
    // Shared matching validates commitments; native negatives are rejected by
    // the separate published-codec semantic gate.
    for v in f["boundary_vectors"]["passing"]
        .as_array()
        .expect("passing")
        .iter()
        .chain(
            f["boundary_vectors"]["native_negative"]
                .as_array()
                .expect("native negatives"),
        )
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

fn commit_input<'a>(v: &'a Value, field: &str, control: bool) -> &'a Value {
    if control {
        v.get(format!("control_{field}")).unwrap_or(&v[field])
    } else {
        &v[field]
    }
}

fn commit_negative(f: &Value, v: &Value) {
    let c = Context::new(f);
    let d: api::SignedImportJobDelegationV1 =
        record(f, v["delegation"].as_str().expect("delegation"));
    let prepared: api::PrepareImportJobResponse =
        record(f, v["preparation"].as_str().unwrap_or("commit_preparation"));
    let parent: Option<api::SignedImportMemberPermissionV1> =
        if v.get("parent") == Some(&Value::Null) {
            None
        } else {
            Some(record(f, v["parent"].as_str().unwrap_or("permission")))
        };
    let genesis_names = |control| {
        commit_input(v, "geneses", control)
            .as_array()
            .map(|names| {
                names
                    .iter()
                    .map(|name| name.as_str().expect("genesis name"))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["genesis_dev", "genesis_main"])
    };
    let geneses: Vec<api::SignedImportGenesisAuthorityV1> = genesis_names(false)
        .iter()
        .map(|name| record(f, name))
        .collect();
    let now = v["now_seconds"].as_i64().unwrap_or(1100);
    let body = d.body.as_ref().expect("body");
    let id = v["id"].as_str().expect("id");
    match id {
        "parent_amplification" | "parent_ref" => {
            for (g, m) in geneses.iter().zip(&body.branch_manifest) {
                assert_eq!(
                    g.body
                        .as_ref()
                        .expect("genesis body")
                        .parent_permission_digest,
                    body.parent_permission_digest,
                    "{id}: genesis must bind the child's parent"
                );
                assert_eq!(
                    import::signed_genesis_digest(g).expect("genesis digest"),
                    m.genesis_authority_digest
                );
            }
        }
        "window_duration" | "window_too_early" => {
            let p = parent
                .as_ref()
                .expect("parent")
                .body
                .as_ref()
                .expect("parent body");
            assert!(
                body.not_before_unix_seconds >= p.not_before_unix_seconds,
                "{id}: parent must contain child start"
            );
            assert!(
                body.expires_at_unix_seconds <= p.expires_at_unix_seconds,
                "{id}: parent must contain child end"
            );
        }
        "window_empty" => assert!(
            body.expires_at_unix_seconds > now,
            "reversed window must not also violate E>T"
        ),
        "reservation_expired" => {
            let p = parent
                .as_ref()
                .expect("parent")
                .body
                .as_ref()
                .expect("parent body");
            assert_eq!(now, prepared.reservation_expires_at_unix_seconds);
            assert!(
                body.not_before_unix_seconds < now
                    && body.expires_at_unix_seconds > now
                    && p.expires_at_unix_seconds > now,
                "reservation must expire during otherwise valid authority"
            );
            assert_eq!(commit_input(v, "now_seconds", true).as_i64(), Some(now - 1));
            assert_eq!(v["control"], v["delegation"]);
        }
        _ => {}
    }
    let mut expected = c.owner(now);
    expected.authority_expires_at_seconds =
        v["authority_expires_at_seconds"].as_i64().unwrap_or(2000);
    let rejection =
        import::verify_prepared_delegation(&prepared, &d, parent.as_ref(), &geneses, &expected)
            .expect_err(id);
    assert_eq!(
        format!("{rejection:?}"),
        v["expected"].as_str().expect("reason"),
        "{id}"
    );
    println!(
        "COMMIT REJECT {id}: {rejection:?} ({})",
        v["first_failing_check"]
    );
    let control_prepared = record(
        f,
        commit_input(v, "preparation", true)
            .as_str()
            .unwrap_or("commit_preparation"),
    );
    let control_parent = record(
        f,
        commit_input(v, "parent", true)
            .as_str()
            .unwrap_or("permission"),
    );
    let control_geneses: Vec<_> = genesis_names(true)
        .iter()
        .map(|name| record(f, name))
        .collect();
    // Ordinary controls share the negative's context; reservation controls are adjacent.
    let control_now = commit_input(v, "now_seconds", true)
        .as_i64()
        .unwrap_or(1100);
    let mut expected = c.owner(control_now);
    expected.authority_expires_at_seconds = commit_input(v, "authority_expires_at_seconds", true)
        .as_i64()
        .unwrap_or(2000);
    import::verify_prepared_delegation(
        &control_prepared,
        &record(f, v["control"].as_str().expect("control")),
        Some(&control_parent),
        &control_geneses,
        &expected,
    )
    .expect("neighboring passing commit after rejection");
    println!("COMMIT PASS {id} control at {control_now}");
}

#[test]
fn prepared_commit_vectors_reject_then_accept() {
    let f = fixture();
    for v in f["commit_vectors"]["negative"]
        .as_array()
        .expect("commit negatives")
    {
        commit_negative(&f, v);
    }
    let c = Context::new(&f);
    for name in f["commit_vectors"]["passing"]
        .as_array()
        .expect("passing commits")
    {
        import::verify_prepared_delegation(
            &record(&f, "commit_preparation"),
            &record(&f, name.as_str().expect("name")),
            Some(&record(&f, "permission")),
            &[record(&f, "genesis_dev"), record(&f, "genesis_main")],
            &c.owner(1100),
        )
        .expect("browser-completed commit within host bounds");
        println!("COMMIT PASS {name}");
    }
}

macro_rules! commit_isolation_test {
    ($name:ident, $id:literal) => {
        #[test]
        fn $name() {
            let f = fixture();
            let v = f["commit_vectors"]["negative"]
                .as_array()
                .expect("negatives")
                .iter()
                .find(|v| v["id"] == $id)
                .expect("named case");
            commit_negative(&f, v);
        }
    };
}
commit_isolation_test!(commit_isolated_parent_amplification, "parent_amplification");
commit_isolation_test!(commit_isolated_parent_ref, "parent_ref");
commit_isolation_test!(commit_isolated_window_empty, "window_empty");
commit_isolation_test!(commit_isolated_window_duration, "window_duration");
commit_isolation_test!(commit_isolated_window_too_early, "window_too_early");
commit_isolation_test!(commit_isolated_reservation_expired, "reservation_expired");

#[test]
fn commit_future_operation_obeys_signed_start() {
    let f = fixture();
    let c = Context::new(&f);
    let d = import::verify_prepared_delegation(
        &record(&f, "commit_preparation"),
        &record(&f, "commit_future_within_skew"),
        Some(&record(&f, "permission")),
        &[record(&f, "genesis_dev"), record(&f, "genesis_main")],
        &c.owner(1100),
    )
    .expect("future commit within skew");
    let operation = record(&f, "commit_future_operation");
    assert_eq!(
        import::verify_new_operation(&operation, &d, 1199, &empty_for(&d)),
        Err(codec::Reject::Expired)
    );
    import::verify_new_operation(&operation, &d, 1200, &empty_for(&d))
        .expect("matching job-signed operation at signed start");
    println!("COMMIT FUTURE OPERATION: 1199 Expired; 1200 PASS");
}

#[test]
fn p2_isolated_private_source() {
    let f = fixture();
    let good: api::CommitImportJobRequest = record(&f, "commit_public_source");
    let mut bad: api::CommitImportJobRequest = record(&f, "submission_private_without_connection");
    bad.source.as_mut().expect("source").private = false;
    assert_eq!(bad, good);
    bad.source.as_mut().expect("source").private = true;
    import::validate_commit_request(
        &good,
        "public-git",
        &record(&f, "source_public_github"),
        &record(&f, "import_configuration"),
    )
    .expect("public control");
    println!("P2 PRIVATE CONTROL PASS");
    assert_eq!(
        import::validate_commit_request(
            &bad,
            "public-git",
            &record(
                &f,
                if true {
                    "source_public_github"
                } else {
                    "source_connected"
                }
            ),
            &record(&f, "import_configuration")
        ),
        Err(codec::Reject::SourceSelection)
    );
    println!("P2 PRIVATE NEGATIVE SourceSelection");
}
#[test]
fn p2_isolated_signed_direct_owner_disclosure() {
    let f = fixture();
    let c = Context::new(&f);
    let good: api::CommitImportJobRequest = record(&f, "submission_observe_request");
    let mut bad: api::CommitImportJobRequest = record(&f, "submission_observe_undisclosed_request");
    let gd = good.proof.as_ref().expect("proof");
    let bd = bad.proof.as_mut().expect("proof");
    let body = bd.delegations[0].body.as_mut().expect("body");
    body.scope.as_mut().expect("scope").branches[0].ref_disclosure = 1;
    body.branch_manifest[0]
        .limit
        .as_mut()
        .expect("limit")
        .ref_disclosure = 1;
    assert_eq!(body, gd.delegations[0].body.as_ref().expect("control"));
    assert_eq!(bd.original_geneses, gd.original_geneses);
    assert_eq!(bd.genesis_authorities, gd.genesis_authorities);
    import::verify_commit_submission(
        &good,
        &record(&f, "submission_observe_preparation"),
        "github",
        &record(&f, "source_connected"),
        &record(&f, "import_configuration"),
        &c.owner(1100),
    )
    .expect("signed direct owner control");
    println!("P2 DISCLOSURE CONTROL PASS");
    assert_eq!(
        import::verify_commit_submission(
            &record(&f, "submission_observe_undisclosed_request"),
            &record(&f, "submission_observe_undisclosed_preparation"),
            "github",
            &record(&f, "source_connected"),
            &record(&f, "import_configuration"),
            &c.owner(1100)
        )
        .err(),
        Some(codec::Reject::RefDisclosure)
    );
    println!("P2 DISCLOSURE NEGATIVE RefDisclosure");
}

fn empty_for(active: &import::VerifiedImportDelegation) -> api::ImportResultManifestV1 {
    api::ImportResultManifestV1 {
        format_version: 1,
        logical_job_id: active.body().logical_job_id.clone(),
        retry_lineage_id: active.body().retry_lineage_id.clone(),
        slots: vec![],
    }
}

fn bundle_check(
    f: &Value,
    name: &str,
    now: i64,
) -> Result<import::VerifiedImportBundleWitnesses, codec::Reject> {
    bundle_check_context(f, name, now, 0, 2000, false)
}

fn bundle_check_context(
    f: &Value,
    name: &str,
    now: i64,
    effective_from: i64,
    authority_expiry: i64,
    revoked: bool,
) -> Result<import::VerifiedImportBundleWitnesses, codec::Reject> {
    let c = Context::from_export(f, &record(f, "complete_export"));
    import::verify_import_bundle_witnesses(
        &record(f, name),
        &import::ImportWitnessRootPin {
            authority: "https://weft.example.test".into(),
            root_id: "descriptor-root-1".into(),
            public_key: c.root.clone(),
            epoch: 1,
        },
        None,
        now,
        |_time| {
            Ok(import::ImportBundleOwnerExpectation {
                identity: &c.identity,
                owner_public_key: &c.owner,
                owner_chain_digest: &c.chain,
                authority_expires_at_seconds: authority_expiry,
                effective_from_unix_seconds: effective_from,
                effective_until_unix_seconds: None,
                forbidden_job_keys: &c.forbidden,
                known_job_associations: &[],
            })
        },
        |_b, _s| {
            if revoked {
                Err(codec::Reject::Revoked)
            } else {
                Ok(())
            }
        },
    )
}
#[test]
fn alpha33_owner_effective_interval_expiry_and_live_revocation() {
    let f = fixture();
    assert_eq!(
        bundle_check_context(&f, "current_export", 1_200_000, 1200, 2000, false).err(),
        Some(codec::Reject::Scope)
    );
    assert_eq!(
        bundle_check_context(&f, "current_export", 1_200_000, 0, 1299, false).err(),
        Some(codec::Reject::Scope)
    );
    assert_eq!(
        bundle_check_context(&f, "complete_export", 1_350_000, 0, 2000, true).err(),
        Some(codec::Reject::Revoked)
    );
    bundle_check(&f, "complete_export", 1_350_000).expect("live authority control");
}

#[test]
fn alpha33_parent_and_delegation_revocation_are_independent() {
    let f = fixture();
    let delegation: api::SignedImportJobDelegationV1 = record(&f, "delegation");
    let parent: api::SignedImportMemberPermissionV1 = record(&f, "permission");
    for id in [
        &delegation
            .body
            .as_ref()
            .expect("delegation")
            .cancellation_id,
        &parent.body.as_ref().expect("parent").cancellation_id,
    ] {
        assert_eq!(
            import::check_import_revocations(&delegation, Some(&parent), std::slice::from_ref(id)),
            Err(codec::Reject::Revoked)
        );
        import::check_import_revocations(&delegation, Some(&parent), &[])
            .expect("unrevoked control");
    }
}

#[test]
fn alpha33_p1_window_and_p1_p3_transaction_order() {
    let f = fixture();
    for v in f["bundle_vectors"]["negative"].as_array().expect("vectors") {
        let now = v["now_ms"].as_i64().unwrap_or(1_350_000);
        let result = bundle_check(&f, v["bundle"].as_str().expect("bundle"), now)
            .expect_err("negative refuses");
        assert_eq!(
            format!("{result:?}"),
            v["expected"].as_str().expect("reason")
        );
        bundle_check(&f, v["control"].as_str().expect("control"), now).expect("valid control");
    }
    let accepted = bundle_check(&f, "complete_export", 1_350_000).expect("complete export");
    assert_eq!(accepted.evidence, import::ImportBundleEvidence::Witnessed);
    assert_eq!(accepted.owner_check_time_unix_seconds, Some(1100));
    assert_eq!(accepted.accepted_history, record(&f, "terminal_manifest"));
}
#[test]
fn alpha33_24h_window_is_host_advertised() {
    let f = fixture();
    let c = Context::new(&f);
    let mut owner = c.owner(1100);
    owner.authority_expires_at_seconds = 100_000;
    let d: api::SignedImportJobDelegationV1 = record(&f, "window_24h");
    let geneses = [
        record(&f, "direct_genesis_0"),
        record(&f, "direct_genesis_1"),
    ];
    let mut prepared: api::PrepareImportJobResponse = record(&f, "window_24h_preparation");
    import::verify_prepared_delegation(&prepared, &d, None, &geneses, &owner).expect("24h window");
    prepared.max_validity_duration_seconds = 3600;
    assert_eq!(
        import::verify_prepared_delegation(&prepared, &d, None, &geneses, &owner).err(),
        Some(codec::Reject::ValidityBounds)
    );
}
#[test]
fn alpha33_cumulative_budget_two_operations_one_delegation() {
    let f = fixture();
    assert_eq!(
        bundle_check(&f, "aggregate_over", 1_200_000).err(),
        Some(codec::Reject::Scope)
    );
    let accepted = bundle_check(&f, "aggregate_at", 1_200_000).expect("exact 2x total");
    assert_eq!(accepted.accepted_history.slots.len(), 2);
}
#[test]
fn alpha33_minimal_state_retry_and_cancel() {
    let f = fixture();
    let c = Context::new(&f);
    let active = delegation(&f, &c);
    let state: api::GetImportJobStateResponse = record(&f, "job_state");
    import::validate_job_state_response(&record(&f, "job_state_request"), &state)
        .expect("minimal state");
    let source: api::ImportSourceSelectionV1 =
        record::<api::PrepareImportJobRequest>(&f, "prepare_request")
            .source
            .expect("source");
    let original = record(&f, "retry_original");
    let manifest = record(&f, "empty_manifest");
    let request = record(&f, "retry_request");
    let mut context = import::ImportRetryAdmission {
        read: &state,
        original: &original,
        retry_lineage_id: &active.body().retry_lineage_id,
        logical_job_terminal: false,
        retained_source: &source,
        committed_manifest: &manifest,
        now_unix_seconds: 1100,
    };
    let mut caller = import::ImportControlCaller {
        authenticated_pop: true,
        destination_writer: true,
        caller_account: "owner",
        connection_owner_account: Some("owner"),
        authorized_source: Some(&source),
        exact_grants_current: true,
        selected_commits_available: true,
    };
    import::check_retry_admission(&request, &context, &active, &caller)
        .expect("same certificate retry");
    context.now_unix_seconds = 1300;
    assert_eq!(
        import::check_retry_admission(&request, &context, &active, &caller),
        Err(codec::Reject::Expired)
    );
    context.now_unix_seconds = 1100;
    caller.connection_owner_account = Some("other");
    assert_eq!(
        import::check_retry_admission(&request, &context, &active, &caller),
        Err(codec::Reject::SourceSelection)
    );
    import::check_import_control_caller(
        import::ImportControlAction::Cancel,
        &source,
        active.body().scope.as_ref().expect("scope"),
        &caller,
    )
    .expect("cancel without custody");
    context.logical_job_terminal = true;
    assert_eq!(
        import::check_retry_admission(&request, &context, &active, &caller),
        Err(codec::Reject::Revoked)
    );
    import::check_retry_replay(&[1], &[1]).expect("frozen replay");
    assert_eq!(
        import::check_retry_replay(&[1], &[2]),
        Err(codec::Reject::OperationIdReused)
    );
}

#[test]
fn alpha33_direct_publication_budget_remainder() {
    let f = fixture();
    let c = Context::new(&f);
    for (name, passes) in [("aggregate_over", false), ("aggregate_at", true)] {
        let b: api::ImportPublicProofBundleV1 = record(&f, name);
        let active = import::verify_delegation(
            &b.delegations[0],
            b.member_permission.as_ref(),
            &c.owner(1100),
        )
        .expect("signed budget");
        let mut committed = b.terminal_manifest.expect("manifest");
        let digest = import::signed_operation_digest(&b.operations[0]).expect("op1 digest");
        committed
            .slots
            .retain(|s| s.signed_operation_digest == digest);
        assert_eq!(committed.slots.len(), 1);
        let remaining = import::remaining_import_scope(
            active.body().scope.as_ref().expect("scope"),
            &committed,
        )
        .expect("remainder");
        assert_eq!(remaining.max_operations, 1);
        assert_eq!(
            b.operations[1].body.as_ref().expect("op2").result_bytes,
            remaining.max_result_bytes + u64::from(!passes)
        );
        let result = import::check_import_publication_budget(&b.operations[1], &active, &committed);
        assert_eq!(
            result,
            if passes {
                Ok(())
            } else {
                Err(codec::Reject::Scope)
            }
        );
    }
}

#[test]
fn alpha33_direct_p1_pair_outside_window() {
    let f = fixture();
    let c = Context::new(&f);
    let active = delegation(&f, &c);
    let bad: api::ImportPublicProofBundleV1 = record(&f, "p1_p3_outside_window");
    let good: api::ImportPublicProofBundleV1 = record(&f, "current_export");
    let p1 = bad.statements[0].body.as_ref().expect("P1");
    let p3 = bad.statements[2].body.as_ref().expect("P3");
    assert_eq!(p1.observed_at_unix_millis, p3.observed_at_unix_millis);
    assert_eq!(p1.host_transaction_id, p3.host_transaction_id);
    assert_eq!(p1.executor_id, p3.executor_id);
    assert!(p1.admission_order < p3.admission_order);
    assert_eq!(
        import::check_import_genesis_publication_pair(&active, p1, p3),
        Err(codec::Reject::Expired)
    );
    import::check_import_genesis_publication_pair(
        &active,
        good.statements[0].body.as_ref().expect("P1"),
        good.statements[2].body.as_ref().expect("P3"),
    )
    .expect("pair control");
}

#[test]
fn alpha33_window_ceiling_and_preflight() {
    let f = fixture();
    let c = Context::new(&f);
    let mut e = c.owner(1100);
    e.authority_expires_at_seconds = i64::MAX;
    let geneses = [
        record(&f, "direct_genesis_0"),
        record(&f, "direct_genesis_1"),
    ];
    for name in ["window_7d", "window_24h"] {
        import::verify_delegation(&record(&f, name), None, &e).expect("bounded signed window");
    }
    for name in ["window_over_7d", "window_extreme"] {
        assert_eq!(
            import::verify_delegation(&record(&f, name), None, &e).err(),
            Some(codec::Reject::ValidityBounds)
        );
    }
    let d = record(&f, "window_24h");
    let mut p: api::PrepareImportJobResponse = record(&f, "window_24h_preparation");
    p.max_validity_duration_seconds = import::MAX_DELEGATION_WINDOW_SECONDS;
    import::verify_prepared_delegation(&p, &d, None, &geneses, &e).expect("ceiling host control");
    import::preflight_prepared_delegation(&p, &d, None, &geneses, &e).expect("browser control");
    p.max_validity_duration_seconds += 1;
    assert_eq!(
        import::verify_prepared_delegation(&p, &d, None, &geneses, &e).err(),
        Some(codec::Reject::ValidityBounds)
    );
    assert_eq!(
        import::preflight_prepared_delegation(&p, &d, None, &geneses, &e),
        Err(codec::Reject::ValidityBounds)
    );
}

#[test]
fn alpha33_status_retry_reason_agreement() {
    let f = fixture();
    let request = record(&f, "job_state_request");
    for status in 1..=5 {
        for reason in 1..=7 {
            let mut state: api::GetImportJobStateResponse = record(&f, "job_state");
            state.status = status;
            state.retry_availability = Some(
                api::get_import_job_state_response::RetryAvailability::RetryUnavailable(reason),
            );
            let agrees = matches!(
                (status, reason),
                (1, 1 | 2 | 6) | (2, 3) | (3, 4) | (4, 5) | (5, 7)
            );
            assert_eq!(
                import::validate_retry_state_response(&request, &state),
                if agrees {
                    Ok(())
                } else {
                    Err(codec::Reject::Canonical)
                },
                "status {status}, reason {reason}"
            );
        }
    }
}

#[test]
fn alpha33_commit_conflict_wire_encoding() {
    let f = fixture();
    for (name, reject) in [
        (
            "commit_destination_conflict",
            codec::Reject::PreparationRefused(
                api::ImportPreparationRefusalReason::DestinationConflict,
            ),
        ),
        ("commit_stale_destination", codec::Reject::StaleContext),
    ] {
        let failure: host::CallFailure = record(&f, name);
        assert_eq!(
            import::import_commit_conflict_failure(&reject),
            Some(failure)
        );
    }
    assert!(import::import_commit_conflict_failure(&codec::Reject::Scope).is_none());
}

#[test]
fn alpha33_hostile_missing_operation_body_is_typed() {
    let f = fixture();
    let c = Context::new(&f);
    let mut b: api::ImportPublicProofBundleV1 = record(&f, "current_export");
    b.operations[1].body = None;
    assert_eq!(
        import::verify_import_bundle_witnesses(
            &b,
            &import::ImportWitnessRootPin {
                authority: "https://weft.example.test".into(),
                root_id: "descriptor-root-1".into(),
                public_key: c.root.clone(),
                epoch: 1
            },
            None,
            1_200_000,
            |_| Ok(import::ImportBundleOwnerExpectation {
                identity: &c.identity,
                owner_public_key: &c.owner,
                owner_chain_digest: &c.chain,
                authority_expires_at_seconds: 2000,
                effective_from_unix_seconds: 0,
                effective_until_unix_seconds: None,
                forbidden_job_keys: &c.forbidden,
                known_job_associations: &[]
            }),
            |_, _| Ok(()),
        )
        .err(),
        Some(codec::Reject::Canonical)
    );
}

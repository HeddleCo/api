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
                let member: api::SignedImportMemberPermissionV1 =
                    record(&f, v["parent"].as_str().unwrap_or("renewed_permission"));
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
        import::verify_new_operation(&operation, &d, 1199),
        Err(codec::Reject::Expired)
    );
    import::verify_new_operation(&operation, &d, 1200)
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
#[test]
fn remaining_parent_permission_nonce_and_revocation_vectors() {
    let f = fixture();
    let c = Context::new(&f);
    let old = delegation(&f, &c);
    for v in f["amendment_vectors"]["permission_negatives"]
        .as_array()
        .expect("cases")
    {
        let result = import::verify_renewal(
            &record(&f, v["renewal"].as_str().expect("renewal")),
            &old,
            &record(&f, "partial_manifest"),
            1,
            Some(&record(&f, v["parent"].as_str().expect("parent"))),
            &c.owner(1200),
        );
        assert_eq!(
            format!("{:?}", result.expect_err("invalid renewal parent")),
            v["expected"].as_str().expect("reason")
        );
    }
    let p0: api::SignedImportMemberPermissionV1 = record(&f, "permission");
    let p1: api::SignedImportMemberPermissionV1 = record(&f, "renewed_permission");
    let d: api::SignedImportJobDelegationV1 = record(&f, "renewed_delegation");
    let a = p0.body.as_ref().expect("old");
    let b = p1.body.as_ref().expect("new");
    assert_eq!(a.cancellation_id, b.cancellation_id);
    assert_ne!(a.nonce, b.nonce);
    assert_eq!(b.scope, d.body.as_ref().expect("child").scope);
    import::verify_member_permission(&p1, &c.owner(1350)).expect("reissue");
    import::verify_member_permission(&record(&f, "renewed_permission"), &c.owner(1350))
        .expect("byte-identical replay");
    assert_eq!(
        p1.encode_to_vec(),
        bytes(&f["signed_vectors"]["renewed_permission"]["wire_hex"])
    );
    import::verify_renewal(
        &record(&f, "renewal"),
        &old,
        &record(&f, "partial_manifest"),
        1,
        Some(&p1),
        &c.owner(1200),
    )
    .expect("remaining parent control");
    let same_parent = import::verify_delegation(&d, Some(&p1), &c.owner(1350))
        .expect("still valid remaining-only parent");
    import::verify_renewal(
        &record(&f, "reused_parent_renewal"),
        &same_parent,
        &record(&f, "partial_manifest"),
        2,
        Some(&p1),
        &c.owner(1350),
    )
    .expect("byte-identical parent reuse retains nonce");
    import::check_import_revocations(&d, Some(&p1), &[]).expect("unrevoked control");
    for id in [
        &a.cancellation_id,
        &d.body.as_ref().expect("child").cancellation_id,
    ] {
        assert_eq!(
            import::check_import_revocations(&d, Some(&p1), std::slice::from_ref(id)),
            Err(codec::Reject::Revoked)
        );
    }
}
#[test]
fn active_cancel_selector_and_replay_vectors() {
    let f = fixture();
    for v in f["amendment_vectors"]["cancel_negatives"]
        .as_array()
        .expect("cases")
    {
        let result = import::check_cancel_request(
            &record(&f, v["request"].as_str().expect("request")),
            &record(&f, v["active"].as_str().expect("active")),
            v["epoch"].as_u64().expect("epoch"),
            v["cancelled"].as_bool().expect("terminal"),
        );
        assert_eq!(
            format!("{:?}", result.expect_err("negative")),
            v["expected"].as_str().expect("reason")
        );
        import::check_cancel_request(
            &record(&f, "cancel_active"),
            &record(&f, "delegation"),
            1,
            false,
        )
        .expect("active selector control");
    }
    let request = record(&f, "cancel_active");
    import::check_cancel_replay(&request, &request).expect("terminal replay before epoch check");
    assert_eq!(
        import::check_cancel_replay(&record(&f, "cancel_changed_replay"), &request),
        Err(codec::Reject::OperationIdReused)
    );
}
#[test]
fn expired_predecessor_recovery_without_publication_receipt() {
    let f = fixture();
    let c = Context::new(&f);
    for v in f["amendment_vectors"]["recovery"]
        .as_array()
        .expect("cases")
    {
        let state: api::ImportJobCasStateV1 = record(&f, v["state"].as_str().expect("state"));
        let renewal = record(&f, v["renewal"].as_str().expect("renewal"));
        let now = v["now"].as_i64().expect("clock");
        let parent = record(&f, "permission");
        let current = record(&f, "renewed_permission");
        assert_eq!(
            import::verify_delegation(
                state.active_predecessor.as_ref().expect("predecessor"),
                Some(&parent),
                &c.owner(now)
            )
            .err(),
            Some(codec::Reject::Expired)
        );
        let token = import::verify_renewal_predecessor(&state, Some(&parent), &c.owner(now))
            .expect("structural recovery only");
        let next = import::verify_renewal_from_state(
            &renewal,
            &token,
            &state,
            Some(&current),
            &c.owner(now),
        )
        .expect("current replacement");
        assert_eq!(
            next.digest(),
            import::signed_delegation_digest(&record(&f, "renewed_delegation")).expect("digest")
        );
        for field in 0..4 {
            let mut changed = state.clone();
            match field {
                0 => changed.authority_epoch += 1,
                1 => changed.logical_job_id[0] ^= 1,
                2 => {
                    let m = changed.committed_manifest.as_mut().expect("manifest");
                    if m.slots.is_empty() {
                        let partial: api::ImportResultManifestV1 = record(&f, "partial_manifest");
                        m.slots.push(partial.slots[0].clone());
                    } else {
                        m.slots[0].signed_operation_digest[0] ^= 1;
                    }
                }
                _ => {
                    changed
                        .active_predecessor
                        .as_mut()
                        .expect("active")
                        .delegating_signature
                        .as_mut()
                        .expect("signature")
                        .signature[0] ^= 1
                }
            }
            assert_eq!(
                import::verify_renewal_from_state(
                    &renewal,
                    &token,
                    &changed,
                    Some(&current),
                    &c.owner(now)
                )
                .err(),
                Some(codec::Reject::StaleContext)
            );
        }
        let mut bad = state.clone();
        bad.active_predecessor
            .as_mut()
            .expect("active")
            .delegating_signature
            .as_mut()
            .expect("sig")
            .signature[0] ^= 1;
        assert_eq!(
            import::verify_renewal_predecessor(&bad, Some(&parent), &c.owner(now)).err(),
            Some(codec::Reject::Signature)
        );
        assert_eq!(
            import::verify_renewal_from_state(
                &renewal,
                &token,
                &state,
                Some(&current),
                &c.owner(1800)
            )
            .err(),
            Some(codec::Reject::Expired)
        );
    }
}
#[test]
fn browser_preflight_keeps_strict_host_commit_clock() {
    let f = fixture();
    let c = Context::new(&f);
    let p = record(&f, "commit_preparation");
    let d = record(&f, "delegation");
    let parent = record(&f, "permission");
    let g = [record(&f, "genesis_dev"), record(&f, "genesis_main")];
    for v in f["amendment_vectors"]["preflight"]
        .as_array()
        .expect("cases")
    {
        let e = c.owner(v["now"].as_i64().expect("clock"));
        let preflight = import::preflight_prepared_delegation(&p, &d, Some(&parent), &g, &e);
        let host = import::verify_prepared_delegation(&p, &d, Some(&parent), &g, &e).map(|_| ());
        for (r, name) in [(preflight, "preflight"), (host, "host")] {
            let actual = r.map_or_else(|error| format!("{error:?}"), |()| "OK".into());
            assert_eq!(
                actual,
                v[name].as_str().expect("result"),
                "{} {name}",
                v["id"]
            );
        }
    }
    assert_eq!(
        import::preflight_prepared_delegation(
            &p,
            &record(&f, "commit_bad_signature"),
            Some(&parent),
            &g,
            &c.owner(999)
        ),
        Err(codec::Reject::Signature)
    );
    assert_eq!(
        import::preflight_prepared_delegation(
            &record(&f, "prepare_changed_converterVersion"),
            &d,
            Some(&parent),
            &g,
            &c.owner(999)
        ),
        Err(codec::Reject::PreparedFields)
    );
    assert_eq!(
        import::preflight_prepared_delegation(&p, &d, None, &g, &c.owner(999)),
        Err(codec::Reject::ImportPermission)
    );
}
#[test]
fn initial_lineage_uuid_reservation_and_receipt_vectors() {
    let f = fixture();
    for v in f["amendment_vectors"]["lineage"].as_array().expect("cases") {
        let result = import::initial_operation_id(
            &bytes(&v["lineage_hex"]),
            v["occupied"].as_bool().expect("occupied"),
        );
        if v["expected"] == "OK" {
            assert_eq!(
                result.expect("reserved first ID"),
                v["operation_id"].as_str().expect("UUID")
            );
        } else {
            assert_eq!(
                format!("{:?}", result.expect_err("invalid allocation")),
                v["expected"].as_str().expect("reason")
            );
        }
    }
    let request = record(&f, "commit_request");
    import::validate_commit_response(&request, &record(&f, "commit_response"))
        .expect("lineage control");
    assert_eq!(
        import::validate_commit_response(&request, &record(&f, "commit_wrong_lineage_response")),
        Err(codec::Reject::PendingOperation)
    );
}

#[test]
fn alpha24_renew_and_read_negatives_reject_then_pass() {
    let f = fixture();
    let vectors = &f["renew_submission_vectors"];
    let mut failures = Vec::new();
    for v in vectors["negative"].as_array().expect("renew negatives") {
        let mut request: api::RenewImportJobRequest =
            record(&f, v["request"].as_str().expect("request"));
        if let Some(size) = v["outer_field_bytes"].as_u64() {
            request.client_operation_id = "x".repeat(size as usize);
        }
        if let Some(size) = v["envelope_bytes"].as_u64() {
            request
                .proof
                .as_mut()
                .expect("proof")
                .creator_authority_envelopes = vec![vec![1; size as usize]];
        }
        let read = record(&f, v["read"].as_str().expect("read"));
        let result = import::validate_renew_request(&request, &read);
        let actual = result
            .err()
            .map(|r| format!("{r:?}"))
            .unwrap_or_else(|| "OK".into());
        println!("Renew {}: {} -> control PASS", v["id"], actual);
        if actual != v["expected"].as_str().expect("expected") {
            failures.push(format!("Renew {}: {actual}", v["id"]));
        }
        import::validate_renew_request(&record(&f, v["control"].as_str().expect("control")), &read)
            .expect("passing control");
    }
    for v in vectors["read_request_negative"]
        .as_array()
        .expect("request negatives")
    {
        let result = import::validate_job_state_request(&record(
            &f,
            v["request"].as_str().expect("request"),
        ));
        let actual = result
            .err()
            .map(|r| format!("{r:?}"))
            .unwrap_or_else(|| "OK".into());
        println!("Read request {}: {} -> control PASS", v["id"], actual);
        if actual != v["expected"].as_str().expect("expected") {
            failures.push(format!("Read request {}: {actual}", v["id"]));
        }
        import::validate_job_state_request(&record(&f, "job_state_request"))
            .expect("passing control");
    }
    for v in vectors["read_negative"].as_array().expect("read negatives") {
        let request = record(&f, "job_state_request");
        let mut response: api::GetImportJobStateResponse =
            record(&f, v["response"].as_str().expect("response"));
        if let Some(size) = v["outer_field_bytes"].as_u64() {
            response.state.as_mut().expect("state").logical_job_id = vec![1; size as usize];
        }
        if let Some(size) = v["envelope_bytes"].as_u64() {
            response
                .retained_proof
                .as_mut()
                .expect("proof")
                .creator_authority_envelopes = vec![vec![1; size as usize]];
        }
        let result = import::validate_job_state_response(&request, &response);
        let actual = result
            .err()
            .map(|r| format!("{r:?}"))
            .unwrap_or_else(|| "OK".into());
        println!("Read {}: {} -> control PASS", v["id"], actual);
        if actual != v["expected"].as_str().expect("expected") {
            failures.push(format!("Read {}: {actual}", v["id"]));
        }
        import::validate_job_state_response(
            &request,
            &record(&f, v["control"].as_str().expect("control")),
        )
        .expect("passing control");
    }
    for v in vectors["prepare_negative"]
        .as_array()
        .expect("race negatives")
    {
        let request = record(&f, v["request"].as_str().expect("request"));
        let response = record(&f, v["response"].as_str().expect("response"));
        let result = import::validate_renewal_preparation_from_read(
            &request,
            &response,
            &record(&f, v["read"].as_str().expect("read")),
        );
        let actual = result
            .err()
            .map(|r| format!("{r:?}"))
            .unwrap_or_else(|| "OK".into());
        println!("Prepare {}: {} -> control PASS", v["id"], actual);
        if actual != v["expected"].as_str().expect("expected") {
            failures.push(format!("Prepare {}: {actual}", v["id"]));
        }
        import::validate_renewal_preparation_from_read(
            &request,
            &response,
            &record(&f, v["control"].as_str().expect("control")),
        )
        .expect("passing control");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn alpha24_actual_renew_requests_separate_rotated_and_expired_contexts() {
    let f = fixture();
    let original = Context::from_export(&f, &record(&f, "complete_renewed_export"));
    let rotation: api::SignedOwnerKeyTransition = record(&f, "renew_owner_rotation");
    let canonical = bytes(&f["renew_submission_vectors"]["rotation"]["canonical_hex"]);
    let digest = codec::hash(&[b"heddle-owner-key-transition-v1", &canonical]);
    assert_eq!(
        digest,
        bytes(&f["renew_submission_vectors"]["rotation"]["digest_hex"])
    );
    let next_key = bytes(&f["keys"]["rotated_owner"]["public_key_hex"]);
    for (key, signature) in [
        (&original.owner, &rotation.authorizations[0]),
        (
            &next_key,
            rotation
                .next_authority_key_proof
                .as_ref()
                .expect("next PoP"),
        ),
    ] {
        assert_eq!(signature.signer_key_id, codec::key_id(key));
        codec::verify(key, &digest, &signature.signature).expect("co-signed rotation");
    }
    for v in f["renew_submission_vectors"]["passing"]
        .as_array()
        .expect("passing")
    {
        let request: api::RenewImportJobRequest =
            record(&f, v["request"].as_str().expect("request"));
        let read = record(&f, v["read"].as_str().expect("read"));
        let mut current = Context::new(&f);
        if v["rotated"].as_bool().expect("rotated") {
            current.identity = record(&f, "renew_rotated_identity");
            current.owner = next_key.clone();
            current.chain = import::owner_chain_digest(&record(&f, "renew_rotated_chain"))
                .expect("current chain");
            assert!(matches!(
                import::verify_renew_submission(
                    &request,
                    &read,
                    &current.owner(1350),
                    &current.owner(1350)
                ),
                Err(codec::Reject::Root)
            ));
        }
        let verified = import::verify_renew_submission(
            &request,
            &read,
            &original.owner(1350),
            &current.owner(1350),
        )
        .expect("historical predecessor and current replacement");
        assert_eq!(
            verified.digest(),
            import::signed_delegation_digest(
                request
                    .renewal
                    .as_ref()
                    .expect("renewal")
                    .body
                    .as_ref()
                    .expect("body")
                    .replacement
                    .as_ref()
                    .expect("replacement")
            )
            .expect("digest")
        );
        let wire = request.encode_to_vec();
        assert_eq!(
            wire,
            bytes(&f["wire_vectors"][v["request"].as_str().expect("request")]["wire_hex"])
        );
        import::check_renew_replay(&wire, &wire).expect("frozen replay");
        let mut changed = wire.clone();
        changed.push(0);
        assert_eq!(
            import::check_renew_replay(&changed, &wire),
            Err(codec::Reject::OperationIdReused)
        );
        assert!(matches!(
            import::verify_renew_submission(
                &request,
                &read,
                &original.owner(1350),
                &current.owner(1800)
            ),
            Err(codec::Reject::Expired)
        ));
    }
}

#[test]
fn alpha24_job_state_read_is_authenticated_writer_only_and_gated() {
    use heddle_api::v2::*;
    let m = method_descriptor("/heddle.api.v1alpha2.IntegrationService/GetImportJobState")
        .expect("read method");
    assert_eq!(m.effect, host::RpcEffect::ReadOnly);
    assert_eq!(m.retry_behavior, host::RetryBehavior::Safe);
    assert_eq!(
        m.authorization_access,
        host::AuthorizationAccess::AuthenticatedPrincipal
    );
    assert_eq!(
        m.authorization.role,
        host::AuthorizationRole::ResourceWriter
    );
    assert_eq!(m.signing_tier, host::SigningTier::ProofOfPossession);
    assert_eq!(
        m.authorization.existence,
        host::AuthorizationExistence::Hide
    );
    assert_eq!(m.authorization.targets[0].path, "destination");
    assert_eq!(
        m.authorization.targets[0].role,
        host::AuthorizationRole::ResourceWriter
    );
    assert_eq!(
        m.verify_protocol(&Default::default()),
        Err(codec::Reject::Protocol)
    );
}

fn alpha25_result(result: Result<(), codec::Reject>, v: &Value, failures: &mut Vec<String>) {
    let actual = result
        .err()
        .map(|r| format!("{r:?}"))
        .unwrap_or_else(|| "OK".into());
    println!("ALPHA25 {}: {} -> control PASS", v["id"], actual);
    if actual != v["expected"].as_str().expect("expected") {
        failures.push(format!("{}: {actual}", v["id"]));
    }
}
#[test]
fn alpha25_configuration_negatives() {
    let f = fixture();
    let mut failures = Vec::new();
    for v in f["source_vectors"]["configuration_negative"]
        .as_array()
        .expect("cases")
    {
        alpha25_result(
            import::validate_import_configuration(&record(
                &f,
                v["configuration"].as_str().expect("configuration"),
            )),
            v,
            &mut failures,
        );
        import::validate_import_configuration(&record(&f, v["control"].as_str().expect("control")))
            .expect("control");
    }
    import::validate_import_configuration(&record(&f, "configuration_no_default"))
        .expect("explicit chooser");
    assert!(failures.is_empty(), "{failures:?}");
}
#[test]
fn alpha25_resolver_negatives() {
    let f = fixture();
    let mut failures = Vec::new();
    for v in f["source_vectors"]["resolution"].as_array().expect("cases") {
        let result = import::resolve_import_provider(
            &record(&f, v["source"].as_str().expect("source")),
            v["connection_provider"].as_str(),
        );
        if v["expected"].is_string() {
            alpha25_result(result.map(|_| ()), v, &mut failures);
            import::resolve_import_provider(
                &record(&f, v["control"].as_str().expect("control")),
                v["control_connection_provider"].as_str(),
            )
            .expect("control");
        } else {
            assert_eq!(
                result.expect("resolved provider"),
                v["provider"].as_str().expect("provider")
            );
        }
    }
    assert!(failures.is_empty(), "{failures:?}");
}
#[test]
fn alpha25_hash_discovery_negatives() {
    let f = fixture();
    let mut failures = Vec::new();
    for v in f["source_vectors"]["hash_negative"]
        .as_array()
        .expect("cases")
    {
        alpha25_result(
            import::validate_repository_hash_algorithm(
                &record(&f, v["source"].as_str().expect("source")),
                v["known"].as_bool().expect("known"),
            ),
            v,
            &mut failures,
        );
        import::validate_repository_hash_algorithm(
            &record(&f, v["control"].as_str().expect("control")),
            true,
        )
        .expect("control");
    }
    import::validate_repository_hash_algorithm(&record(&f, "source_unknown"), false)
        .expect("retryable unknown discovery");
    assert!(failures.is_empty(), "{failures:?}");
}
#[test]
fn alpha25_discovered_scope_negatives() {
    let f = fixture();
    let mut failures = Vec::new();
    for v in f["source_vectors"]["scope_negative"]
        .as_array()
        .expect("cases")
    {
        alpha25_result(
            import::validate_discovered_import_scope(
                &record(&f, v["scope"].as_str().expect("scope")),
                &record(&f, v["source"].as_str().expect("source")),
            ),
            v,
            &mut failures,
        );
        import::validate_discovered_import_scope(
            &record(&f, "scope_public_sha256_observe"),
            &record(&f, "source_public_sha256"),
        )
        .expect("SHA256 observe control");
    }
    assert!(failures.is_empty(), "{failures:?}");
}
#[test]
fn alpha25_prepare_source_negatives() {
    let f = fixture();
    let mut failures = Vec::new();
    let scope: api::ImportPermissionScopeV1 = record(&f, "scope");
    for v in f["source_vectors"]["prepare_negative"]
        .as_array()
        .expect("cases")
    {
        alpha25_result(
            import::prepare_import_source_scope(
                &record(&f, v["request"].as_str().expect("request")),
                &record(&f, "source_public_sha256"),
                None,
                &record(&f, "import_configuration"),
                &scope.destination_version,
            )
            .map(|_| ()),
            v,
            &mut failures,
        );
        import::prepare_import_source_scope(
            &record(&f, "prepare_public_sha256"),
            &record(&f, "source_public_sha256"),
            None,
            &record(&f, "import_configuration"),
            &scope.destination_version,
        )
        .expect("control");
    }
    assert!(failures.is_empty(), "{failures:?}");
}
fn alpha25_remaining_parent(id: &str) {
    let f = fixture();
    let c = Context::new(&f);
    let old = delegation(&f, &c);
    let v = f["amendment_vectors"]["permission_negatives"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|v| v["id"] == id)
        .expect("case");
    let p: api::SignedImportMemberPermissionV1 = record(&f, v["parent"].as_str().expect("parent"));
    let good: api::SignedImportMemberPermissionV1 = record(&f, "renewed_permission");
    let a = p
        .body
        .as_ref()
        .expect("body")
        .scope
        .as_ref()
        .expect("scope");
    let b = good
        .body
        .as_ref()
        .expect("body")
        .scope
        .as_ref()
        .expect("scope");
    assert_eq!(a.branches, b.branches);
    if id == "operations_budget" {
        assert_eq!(a.max_result_bytes, b.max_result_bytes);
    } else {
        assert_eq!(a.max_operations, b.max_operations);
    }
    assert_eq!(
        import::verify_renewal(
            &record(&f, v["renewal"].as_str().expect("renewal")),
            &old,
            &record(&f, "partial_manifest"),
            1,
            Some(&p),
            &c.owner(1200)
        )
        .err(),
        Some(codec::Reject::RenewalFork)
    );
    import::verify_renewal(
        &record(&f, "renewal"),
        &old,
        &record(&f, "partial_manifest"),
        1,
        Some(&good),
        &c.owner(1200),
    )
    .expect("control");
    println!("ALPHA25 REJECT then PASS remaining_parent.{id}: RenewalFork");
}
#[test]
fn alpha25_remaining_parent_operations_budget() {
    alpha25_remaining_parent("operations_budget");
}
#[test]
fn alpha25_remaining_parent_result_bytes_budget() {
    alpha25_remaining_parent("result_bytes_budget");
}
#[test]
fn alpha25_commit_source_negatives() {
    let f = fixture();
    let mut failures = Vec::new();
    for v in f["source_vectors"]["commit_negative"]
        .as_array()
        .expect("cases")
    {
        alpha25_result(
            import::validate_commit_request(
                &record(&f, v["request"].as_str().expect("request")),
                "github",
                &record(&f, v["source"].as_str().expect("source")),
                &record(&f, v["configuration"].as_str().expect("configuration")),
            ),
            v,
            &mut failures,
        );
        import::validate_commit_request(
            &record(&f, v["control"].as_str().expect("control")),
            "github",
            &record(&f, v["control_source"].as_str().expect("source")),
            &record(&f, "import_configuration"),
        )
        .expect("control");
    }
    assert!(failures.is_empty(), "{failures:?}");
}
#[test]
fn alpha25_signed_sha256_observe_and_converter_choice() {
    let f = fixture();
    let c = Context::new(&f);
    for v in f["source_vectors"]["signed_observe"]
        .as_array()
        .expect("cases")
    {
        import::verify_commit_submission(
            &record(&f, v["request"].as_str().expect("request")),
            &record(&f, v["preparation"].as_str().expect("preparation")),
            v["provider"].as_str().expect("provider"),
            &record(&f, v["source"].as_str().expect("source")),
            &record(&f, "import_configuration"),
            &c.owner(1100),
        )
        .expect("signed SHA256 observe");
        println!("ALPHA25 signed SHA256 observe {}: PASS", v["id"]);
    }
    import::validate_import_configuration(&record(&f, "configuration_multiple"))
        .expect("later entry recommended");
}
#[test]
fn alpha25_public_selector_may_omit_repository_id() {
    let f = fixture();
    let mut request: api::CommitImportJobRequest = record(&f, "commit_public_source");
    request
        .source
        .as_mut()
        .expect("source")
        .provider_repository_id
        .clear();
    import::validate_commit_request(
        &request,
        "public-git",
        &record(&f, "source_public_github"),
        &record(&f, "import_configuration"),
    )
    .expect("current discovery binds exact URL");
    let mut prepare: api::PrepareImportJobRequest = record(&f, "prepare_public_sha256");
    prepare
        .source
        .as_mut()
        .expect("selector")
        .provider_repository_id
        .clear();
    let scope: api::ImportPermissionScopeV1 = record(&f, "scope");
    import::prepare_import_source_scope(
        &prepare,
        &record(&f, "source_public_sha256"),
        None,
        &record(&f, "import_configuration"),
        &scope.destination_version,
    )
    .expect("public Prepare input may omit redundant ID");
}

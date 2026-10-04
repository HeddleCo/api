use heddle_api::{
    heddle::api::v1alpha2 as api, hybrid_codec as codec, native_witness as native,
    witness_trust as witness,
};
use prost::Message;
use serde_json::Value;
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/native-host-witness-v1.json"))
        .expect("fixed native fixture")
}
fn hex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex")).expect("bytes")
}
fn wire<T: Message + Default>(f: &Value, name: &str) -> T {
    codec::strict_decode(&hex(&f["wire_vectors"][name]["wire_hex"]), 1048576)
        .expect("strict fixed wire")
}
fn verify(f: &Value, b: &api::NativePublicProofBundleV1) -> Result<(), codec::Reject> {
    let root = hex(&f["keys"]["root"]["public_key_hex"]);
    // Fixture context independently supplies the authenticated set. The carrier
    // must match it; substituting the carrier digest cannot change this pin.
    let selected: heddle_api::heddle::api::common::SignedHostedWitnessSetV1 = wire(
        f,
        if b.witness_set
            .as_ref()
            .and_then(|s| s.body.as_ref())
            .map(|s| s.generation)
            == Some(51)
        {
            "retired_set"
        } else {
            "current_set"
        },
    );
    let now = selected
        .body
        .as_ref()
        .ok_or(codec::Reject::Canonical)?
        .issued_at_unix_millis
        + 1;
    let set = witness::verify_set(
        &selected,
        &witness::SetExpectation {
            authority: "https://weft.example.test",
            root_id: "descriptor-root-1",
            root_public_key: &root,
            root_epoch: 1,
            now_unix_millis: now,
            clock_floor_unix_millis: 1000000,
            known_job_keys: &[],
        },
        None,
    )?;
    native::verify_bundle_witnesses(b, &set, now)
}
#[test]
fn native_positive_bundles() {
    let f = fixture();
    for name in f["positive"].as_array().expect("cases") {
        let name = name.as_str().expect("name");
        verify(&f, &wire(&f, name)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        println!("NATIVE PASS {name}");
    }
}
#[test]
fn signed_native_authority_negatives_require_the_native_gate() {
    let f = fixture();
    for v in f["native_negative"].as_array().expect("native negatives") {
        let name = v["id"].as_str().expect("name");
        verify(&f, &wire(&f, v["control"].as_str().expect("control")))
            .expect("passing signed control");
        verify(&f, &wire(&f, name)).expect("portable closure is valid; native authority must reject");
        println!("PORTABLE PASS {name}; native authorization required");
    }
}
#[test]
fn bindings_select_distinct_retained_owner_chains() {
    let f = fixture();
    let b: api::NativePublicProofBundleV1 = wire(&f, "distinct_owner_chains");
    assert_eq!(b.owner_chains.len(), 2);
    let selected: Vec<_> = b
        .genesis_witnesses
        .iter()
        .map(|p| {
            &p.binding
                .as_ref()
                .expect("binding")
                .body
                .as_ref()
                .expect("body")
                .owner_chain_digest
        })
        .collect();
    assert_eq!(selected.len(), 2);
    assert_ne!(selected[0], selected[1]);
    for digest in selected {
        assert!(b.owner_chains.iter().any(|c| {
            heddle_api::import_authority::owner_chain_digest(c).expect("chain") == *digest
        }));
    }
    let missing: api::NativePublicProofBundleV1 = wire(&f, "missing_selected_owner_chain");
    assert_eq!(missing.owner_chains.len(), 1);
    assert_eq!(missing.genesis_witnesses, b.genesis_witnesses);
    assert_eq!(missing.statements, b.statements);
}
#[test]
fn post_landing_capture_retains_exact_execution_dependency() {
    let f = fixture();
    let b: api::NativePublicProofBundleV1 = wire(&f, "post_landing_capture");
    let execution = b.landing_witnesses[0]
        .execution
        .as_ref()
        .expect("execution");
    assert!(
        b.authority_witnesses
            .iter()
            .any(|p| p.dependencies.contains(execution))
    );
    assert!(
        !b.authority_witnesses
            .iter()
            .any(|p| p.original.as_ref() == Some(execution))
    );
}
#[test]
fn native_canonical_parity() {
    let f = fixture();
    for (name, v) in f["canonical_vectors"].as_object().expect("vectors") {
        let bytes = hex(&v["wire_hex"]);
        let (canonical, digest) = match v["schema"].as_str().expect("type") {
            "heddle.api.v1alpha2.NativeGenesisAuthorityV1" => {
                let p: api::NativeGenesisAuthorityV1 =
                    codec::strict_decode(&bytes, 65536).expect("body");
                (
                    codec::canonical(&p).expect("canonical"),
                    codec::signing_digest(v["domain"].as_str().expect("domain"), &p)
                        .expect("digest"),
                )
            }
            "heddle.api.v1alpha2.SignedNativeGenesisAuthorityV1" => {
                let p: api::SignedNativeGenesisAuthorityV1 =
                    codec::strict_decode(&bytes, 65536).expect("binding");
                (
                    codec::canonical(&p).expect("canonical"),
                    native::signed_genesis_digest(&p).expect("digest"),
                )
            }
            "heddle.api.v1alpha2.NativeGenesisWitnessV1" => {
                let p: api::NativeGenesisWitnessV1 =
                    codec::strict_decode(&bytes, 65536).expect("payload");
                (
                    codec::canonical(&p).expect("canonical"),
                    codec::signing_digest(v["domain"].as_str().expect("domain"), &p)
                        .expect("digest"),
                )
            }
            _ => panic!("unhandled schema"),
        };
        assert_eq!(canonical, hex(&v["canonical_hex"]), "{name}");
        assert_eq!(digest, hex(&v["digest_hex"]), "{name}");
    }
}
fn negative(name: &str) {
    let f = fixture();
    let v = f["negative"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|v| v["id"] == name)
        .expect("negative");
    let control = v["control"].as_str().expect("control");
    let result = match v["gate"].as_str().expect("gate") {
        "import" => {
            let control: api::ImportPublicProofBundleV1 = wire(&f, control);
            native::validate_carriers(Some(&control), None).expect("import control");
            let b = wire(&f, name);
            native::validate_carriers(Some(&b), None)
        }
        "dispatch" => {
            let b: api::NativePublicProofBundleV1 = wire(&f, control);
            verify(&f, &b).expect("native control");
            let i: api::ImportPublicProofBundleV1 = wire(&f, "import_complete");
            native::validate_carriers(Some(&i), Some(&b))
        }
        _ => {
            verify(&f, &wire(&f, control)).expect("passing control");
            verify(&f, &wire(&f, name))
        }
    };
    println!("NATIVE NEGATIVE {name}: {result:?}");
    assert_eq!(
        format!("{:?}", result.expect_err("guard must reject")),
        v["expected"].as_str().expect("reason")
    );
}
macro_rules! negatives {($($name:ident),*)=>{$(#[test] fn $name(){negative(stringify!($name));})*};}
negatives!(
    missing_binding,
    forged_binding,
    substituted_envelope,
    missing_genesis_statement,
    missing_owner_history,
    missing_owner_chain,
    missing_selected_owner_chain,
    post_landing_missing_purpose4,
    post_landing_missing_purpose4_statement,
    post_landing_substituted_purpose4,
    carried_set_digest_substitution,
    missing_policy,
    missing_ownership_claim,
    missing_authority_statement,
    missing_native_authority_dependency,
    boundary_receipt_substitution,
    retired_proof_missing,
    retired_proof_substitution,
    import_without_delegation,
    dual_carriers
);
negatives!(
    local_integration_forged_signature,
    local_integration_missing_claim,
    local_integration_purpose2,
    local_integration_empty_purpose2,
    local_integration_purpose4,
    account_integration_as_local
);
#[test]
fn local_integration_push_retains_native_work_and_claim() {
    let f = fixture();
    let b: api::NativePublicProofBundleV1 = wire(&f, "local_integration_push");
    verify(&f, &b).expect("local capture, integration and push");
    let claim = b
        .authority_witnesses
        .iter()
        .find(|p| p.kind == 2)
        .expect("claim");
    assert_eq!(
        claim.dependencies.len(),
        5,
        "both geneses, captures and integration"
    );
    assert_eq!(
        b.authority_witnesses.len(),
        2,
        "account source and ownership claim only"
    );
    assert!(b.landing_witnesses.is_empty());
}
#[test]
fn producers_carry_exact_binding() {
    let f = fixture();
    let start: api::StartThreadRequest = wire(&f, "start_request");
    let record: api::ThreadGenesisRecord = wire(&f, "thread_genesis_record");
    assert_eq!(start.thread_genesis, record.genesis);
    assert_eq!(start.creator_authority, record.creator_authority);
    assert_eq!(
        start.native_genesis_authority,
        record.native_genesis_authority
    );
    native::verify_genesis_authority(
        start.native_genesis_authority.as_ref().expect("binding"),
        start.thread_genesis.as_ref().expect("original"),
        &start.creator_authority,
    )
    .expect("producer proof");
}
#[cfg(feature = "reflection")]
#[test]
fn native_carriers_cover_sync() {
    let pool =
        prost_reflect::DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("descriptor");
    for (name, tag) in [
        ("TransferReady", 21),
        ("PublicationReceipt", 10),
        ("PublishContentOpen", 11),
        ("ReplicationOpen", 12),
        ("ReplicationReady", 9),
        ("ReplicationOperations", 5),
    ] {
        let msg = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}"))
            .expect("message");
        assert_eq!(
            msg.get_field(tag).expect("carrier").name(),
            "native_authority"
        );
    }
    for name in ["Fetch", "PublishContent", "ReplicateThread"] {
        assert!(
            heddle_api::v2::method_descriptor(&format!("/heddle.api.v1alpha2.SyncService/{name}"))
                .expect("method")
                .mandatory_features
                .is_empty()
        );
    }
}

use heddle_api::{
    heddle::api::common as host, hybrid_codec as codec, import_authority as import,
    native_witness as native, witness_trust as witness,
};
use prost::Message;
use serde_json::Value;
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/foreign-dependencies-alpha34.json"))
        .expect("fixture")
}
fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex")).expect("bytes")
}
fn wire<T: Message + Default>(f: &Value, name: &str) -> T {
    codec::strict_decode(&bytes(&f["wire_vectors"][name]["wire_hex"]), 8388608).expect("fixed wire")
}
fn check(f: &Value, name: &str, carrier: &str) -> Result<(), codec::Reject> {
    if let Some(roles) = f["negative"]
        .as_array()
        .and_then(|v| v.iter().find(|v| v["id"] == name))
        .and_then(|v| v["roles"].as_str())
    {
        if roles.starts_with("import_") {
            let b: heddle_api::heddle::api::v1alpha2::ImportPublicProofBundleV1 = wire(f, name);
            let pin = import::ImportWitnessRootPin {
                authority: "https://weft.example.test".into(),
                root_id: "descriptor-root-1".into(),
                public_key: bytes(&f["keys"]["root"]["public_key_hex"]),
                epoch: 1,
            };
            let owner = bytes(&f["keys"]["owner"]["public_key_hex"]);
            let device = bytes(&f["keys"]["device"]["public_key_hex"]);
            let d = b.delegations[0].body.as_ref().expect("fixed delegation");
            let chain = import::owner_chain_digest(b.owner_chain.as_ref().expect("fixed chain"))?;
            let known = if roles == "import_known" {
                vec![(device.clone(), d.logical_job_id.clone())]
            } else {
                vec![]
            };
            let forbidden = if roles == "import_forbidden" {
                vec![device]
            } else {
                vec![]
            };
            let pinned: heddle_api::heddle::api::v1alpha2::ImportPublicProofBundleV1 =
                wire(f, "import_stage");
            import::verify_import_bundle_witnesses(
                &b,
                &pin,
                None,
                1200001,
                |_| {
                    Ok(import::ImportBundleOwnerExpectation {
                        identity: d.identity.as_ref().expect("identity"),
                        owner_public_key: &owner,
                        owner_chain_digest: &chain,
                        authority_expires_at_seconds: 2000,
                        effective_from_unix_seconds: 0,
                        effective_until_unix_seconds: None,
                        forbidden_job_keys: &[],
                        forbidden_landing_keys: &forbidden,
                        known_job_associations: &known,
                    })
                },
                |b, _| {
                    if b.owner_genesis != pinned.owner_genesis
                        || b.owner_histories != pinned.owner_histories
                        || b.policies != pinned.policies
                    {
                        return Err(codec::Reject::Scope);
                    }
                    Ok(())
                },
            )?;
            return Ok(());
        }
        let b: heddle_api::heddle::api::v1alpha2::NativePublicProofBundleV1 = wire(f, name);
        let keys = [bytes(&f["keys"]["job"]["public_key_hex"])];
        for p in &b.landing_witnesses {
            import::verify_landing_key_roles(
                p,
                if roles == "known" { &keys } else { &[] },
                if roles == "forbidden" { &keys } else { &[] },
            )?;
        }
    }
    match carrier {
        "native" if name == "job_signed_landing" => {
            let root = bytes(&f["keys"]["root"]["public_key_hex"]);
            let job = bytes(&f["keys"]["job"]["public_key_hex"]);
            let set = witness::verify_set(
                &wire(f, "mixed_set"),
                &witness::SetExpectation {
                    authority: "https://weft.example.test",
                    root_id: "descriptor-root-1",
                    root_public_key: &root,
                    root_epoch: 1,
                    now_unix_millis: 1200001,
                    clock_floor_unix_millis: 1000000,
                    known_job_keys: &[job],
                },
                None,
            )?;
            native::verify_bundle_witnesses(&wire(f, name), &set, 1200001, &[])
        }
        "native" => native::validate_public_bundle(&wire(f, name)),
        "import" => import::validate_public_bundle(&wire(f, name)),
        "dispatch" => {
            native::validate_carriers(Some(&wire(f, "import_stage")), Some(&wire(f, name)))
        }
        _ => panic!("carrier"),
    }
}
#[test]
fn mixed_origin_reference_closures() {
    let f = fixture();
    for v in f["positive"].as_array().expect("positives") {
        let name = v["id"].as_str().expect("id");
        check(&f, name, v["carrier"].as_str().expect("carrier")).expect(name);
        println!("FOREIGN PASS {name}");
    }
}
#[test]
fn foreign_guards_reject_then_exact_controls_pass() {
    let f = fixture();
    for v in f["negative"].as_array().expect("negatives") {
        let name = v["id"].as_str().expect("id");
        let carrier = v["carrier"].as_str().expect("carrier");
        let error = check(
            &f,
            if carrier == "dispatch" {
                v["control"].as_str().expect("control")
            } else {
                name
            },
            carrier,
        )
        .expect_err(name);
        assert_eq!(
            format!("{error:?}"),
            v["expected"].as_str().expect("reason"),
            "{name}"
        );
        check(
            &f,
            v["control"].as_str().expect("control"),
            if carrier == "dispatch" {
                "native"
            } else {
                carrier
            },
        )
        .expect("exact control");
        println!("FOREIGN REJECT {name}: {error:?}; PASS exact control");
    }
}
#[test]
fn foreign_native_closures_still_recheck_all_witnesses() {
    let f = fixture();
    let selected: host::SignedHostedWitnessSetV1 = wire(&f, "mixed_set");
    let root = bytes(&f["keys"]["root"]["public_key_hex"]);
    let job = bytes(&f["keys"]["job"]["public_key_hex"]);
    let set = witness::verify_set(
        &selected,
        &witness::SetExpectation {
            authority: "https://weft.example.test",
            root_id: "descriptor-root-1",
            root_public_key: &root,
            root_epoch: 1,
            now_unix_millis: 1200001,
            clock_floor_unix_millis: 1000000,
            known_job_keys: &[job],
        },
        None,
    )
    .expect("independent witness pin");
    for v in f["positive"].as_array().expect("positives") {
        if v["carrier"] == "native" {
            native::verify_bundle_witnesses(
                &wire(&f, v["id"].as_str().expect("name")),
                &set,
                1200001,
                &[],
            )
            .expect("all P1/P2/P4");
        }
    }
}
#[cfg(feature = "reflection")]
#[test]
fn exact_foreign_dependency_proto_surface() {
    let pool =
        prost_reflect::DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("descriptor");
    for (name, tag) in [
        ("NativePublicProofBundleV1", 13),
        ("ImportPublicProofBundleV1", 23),
    ] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}"))
            .expect("bundle");
        let field = message.get_field(tag).expect("foreign field");
        assert!(field.is_list());
        assert_eq!(field.name(), "foreign_dependencies");
    }
    let message = pool
        .get_message_by_name("heddle.api.v1alpha2.ForeignDependencyV1")
        .expect("reference");
    assert_eq!(message.fields().count(), 5);
    for (tag, name) in [
        (1, "format_version"),
        (2, "origin"),
        (3, "thread_genesis_digest"),
        (4, "signed_native_digest"),
        (5, "prefix_admission_order"),
    ] {
        assert_eq!(message.get_field(tag).expect("field").name(), name);
    }
}

#[test]
fn native_witnesses_apply_forbidden_landing_keys() {
    let f = fixture();
    let root = bytes(&f["keys"]["root"]["public_key_hex"]);
    let job = bytes(&f["keys"]["job"]["public_key_hex"]);
    let set = witness::verify_set(
        &wire(&f, "mixed_set"),
        &witness::SetExpectation {
            authority: "https://weft.example.test",
            root_id: "descriptor-root-1",
            root_public_key: &root,
            root_epoch: 1,
            now_unix_millis: 1200001,
            clock_floor_unix_millis: 1000000,
            known_job_keys: &[job],
        },
        None,
    ).expect("independent witness pin");
    let b = wire(&f, "import_tip_native_fast_forward");
    let device = bytes(&f["keys"]["device"]["public_key_hex"]);
    assert_eq!(native::verify_bundle_witnesses(&b, &set, 1200001, &[device]), Err(codec::Reject::KeyRole));
    native::verify_bundle_witnesses(&b, &set, 1200001, &[]).expect("ordinary device can land");
}

#[test]
fn local_cutoff_ignores_later_claim_and_resolution_in_both_install_orders() {
    let f = fixture();
    let original = wire(&f, "local_cutoff_original");
    let prefix = wire(&f, "local_cutoff_prefix");
    let history = wire(&f, "local_cutoff_history");
    let carrier: heddle_api::heddle::api::v1alpha2::ImportPublicProofBundleV1 = wire(&f, "local_cutoff_dependent");
    import::validate_public_bundle(&carrier).expect("same dependent carrier");
    let dependent_order = carrier.statements.iter().filter_map(|s| s.body.as_ref()).find(|s| s.purpose == 2).expect("authenticated dependent statement").admission_order;
    assert_eq!(dependent_order, 236);
    let reference = &carrier.foreign_dependencies[0];
    assert_eq!(reference.signed_native_digest, import::signed_native_digest(&original).expect("original"));
    for histories in [[&prefix, &history], [&history, &prefix]] {
        for installed in histories {
            native::validate_public_bundle(installed).expect("ownership history");
            assert_eq!(native::local_work_cutoff(installed, &original, dependent_order).expect("as-of closure"), reference.prefix_admission_order);
        }
    }
    assert_eq!(native::local_work_cutoff(&history, &original, 238).expect("later resolution"), 238);
}

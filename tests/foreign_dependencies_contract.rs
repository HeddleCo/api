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
    codec::strict_decode(&bytes(&f["wire_vectors"][name]["wire_hex"]), 1048576).expect("fixed wire")
}
fn check(f: &Value, name: &str, carrier: &str) -> Result<(), codec::Reject> {
    match carrier {
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
    assert_eq!(message.fields().count(), 4);
    for (tag, name) in [
        (1, "format_version"),
        (2, "origin"),
        (3, "thread_genesis_digest"),
        (4, "signed_native_digest"),
    ] {
        assert_eq!(message.get_field(tag).expect("field").name(), name);
    }
}

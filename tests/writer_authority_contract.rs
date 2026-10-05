use heddle_api::{heddle::api::v1alpha2 as api, hybrid_codec as codec, native_witness};
use prost::Message;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/writer-authority-alpha35.json")).expect("fixed fixture")
}
fn wire<T: Message + Default>(f: &Value, name: &str) -> T {
    codec::strict_decode(
        &hex::decode(f["vectors"][name]["wire_hex"].as_str().expect("hex")).expect("bytes"),
        1048576,
    )
    .expect("canonical fixture")
}
fn genesis(f: &Value, name: &str) -> Result<(), codec::Reject> {
    let p: api::NativeGenesisWitnessV1 = wire(f, name);
    native_witness::verify_genesis_authority(
        p.binding.as_ref().expect("binding"),
        p.original_genesis.as_ref().expect("original"),
        &p.creator_authority_envelope,
    )
}
#[test]
fn cowriter_start_thread() {
    genesis(&fixture(), "cowriter_start_thread").expect("author account is independent of Spool owner");
}
#[test]
fn account_mismatch_reject_then_pass() {
    let f = fixture();
    assert_eq!(genesis(&f, "account_mismatch"), Err(codec::Reject::GenesisBinding));
    genesis(&f, "cowriter_start_thread").expect("exact passing control");
}
#[test]
fn self_signed_owner_uuid_reject_then_pass() {
    let f = fixture();
    assert_eq!(genesis(&f, "self_signed_owner_uuid"), Err(codec::Reject::Root));
    genesis(&f, "cowriter_start_thread").expect("exact passing control");
}

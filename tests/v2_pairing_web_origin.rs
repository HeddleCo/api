use heddle_api::heddle::api::v1alpha2 as api;
use prost::Message;

#[test]
fn pairing_web_origin_matches_typescript_golden_in_both_directions() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/pairing-web-origin.json"))
            .expect("shared golden JSON");
    let wire =
        hex::decode(fixture["wire_hex"].as_str().expect("wire hex")).expect("valid golden bytes");
    let request = api::BeginPairingRequest {
        client_operation_id: fixture["client_operation_id"]
            .as_str()
            .expect("operation id")
            .into(),
        web_origin: fixture["web_origin"].as_str().expect("web origin").into(),
        ..Default::default()
    };
    assert_eq!(request.web_origin, "https://preview.example.com");
    assert_eq!(
        api::BeginPairingRequest::decode(wire.as_slice()).expect("TS wire"),
        request
    );
    assert_eq!(request.encode_to_vec(), wire, "Rust wire matches TS golden");
    let legacy = api::BeginPairingRequest {
        web_origin: String::new(),
        ..request
    };
    assert!(
        api::BeginPairingRequest::decode(legacy.encode_to_vec().as_slice())
            .expect("legacy wire")
            .web_origin
            .is_empty()
    );
}

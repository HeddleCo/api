use heddle_api::{
    heddle::api::v1alpha1::{DescriptorKeyRotation, EndpointDescriptor, RelayAdmissionClaims},
    signing::{endpoint_descriptor_bytes, relay_admission_bytes},
};

#[derive(serde::Deserialize)]
struct Fixture {
    endpoint_descriptor_hex: String,
    endpoint_signing_bytes_hex: String,
    relay_admission_hex: String,
    relay_signing_bytes_hex: String,
}

fn endpoint_descriptor() -> EndpointDescriptor {
    EndpointDescriptor {
        version: 1,
        endpoint_id: "iroh-endpoint-01".to_string(),
        relay_urls: vec![
            "https://relay-us.example.test".to_string(),
            "https://relay-eu.example.test".to_string(),
        ],
        supported_alpns: vec![heddle_api::HOSTED_ALPN_V1.to_vec()],
        direct_addresses: vec!["203.0.113.7:4433".to_string()],
        issued_at_unix_millis: 1_750_000_000_000,
        expires_at_unix_millis: 1_750_003_600_000,
        rotation: Some(DescriptorKeyRotation {
            next_key_id: "descriptor-2026-08".to_string(),
            next_public_key: (0_u8..32).collect(),
            activates_at_unix_millis: 1_750_001_800_000,
        }),
    }
}

fn relay_admission() -> RelayAdmissionClaims {
    RelayAdmissionClaims {
        version: 1,
        token_id: "0197-token".to_string(),
        subject: "user:42".to_string(),
        client_endpoint_id: "browser-device-07".to_string(),
        allowed_origins: vec!["https://app.example.test".to_string()],
        relay_region: "us-central".to_string(),
        issued_at_unix_millis: 1_750_000_000_000,
        expires_at_unix_millis: 1_750_000_300_000,
        max_connections: 4,
        max_bytes_per_minute: 67_108_864,
    }
}

#[test]
fn bootstrap_fixture_is_exact_and_domain_separated() {
    use prost::Message;

    let fixture: Fixture =
        serde_json::from_str(heddle_api::TRANSPORT_BOOTSTRAP_V1_FIXTURE_JSON).unwrap();
    let descriptor = endpoint_descriptor();
    let admission = relay_admission();
    assert_eq!(
        hex::encode(descriptor.encode_to_vec()),
        fixture.endpoint_descriptor_hex
    );
    assert_eq!(
        hex::encode(endpoint_descriptor_bytes(&descriptor)),
        fixture.endpoint_signing_bytes_hex
    );
    assert_eq!(
        hex::encode(admission.encode_to_vec()),
        fixture.relay_admission_hex
    );
    assert_eq!(
        hex::encode(relay_admission_bytes(&admission)),
        fixture.relay_signing_bytes_hex
    );
    assert_ne!(
        endpoint_descriptor_bytes(&descriptor),
        relay_admission_bytes(&admission)
    );
}

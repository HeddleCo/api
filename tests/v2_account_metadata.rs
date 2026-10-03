use heddle_api::heddle::api::v1alpha2 as api;
use heddle_api::v2::account_metadata::{
    HELD_NAME_REQUEST_LAPSED, HELD_NAME_REQUESTED, normalize_advisory_label,
    normalize_display_name, validate_aaguid, validate_passkey_credential_id,
    validate_session_user_agent,
};
use prost::Message;

#[test]
fn account_wire_vectors_match_typescript() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/account-management-wire.json"))
            .expect("wire vectors");
    let timestamp = |seconds| Some(prost_types::Timestamp { seconds, nanos: 0 });
    let vectors = [
        (
            "RemovePasskeyRequest",
            api::RemovePasskeyRequest {
                client_operation_id: "remove-1".into(),
                passkey: Some(api::RecordRef {
                    id: "passkey-1".into(),
                    spool: None,
                }),
                expected_version: vec![1; 32],
            }
            .encode_to_vec(),
        ),
        (
            "SetDisplayNameRequest",
            api::SetDisplayNameRequest {
                client_operation_id: "name-1".into(),
                display_name: "José".into(),
            }
            .encode_to_vec(),
        ),
        (
            "SetPrimaryHandleRequest",
            api::SetPrimaryHandleRequest {
                client_operation_id: "primary-1".into(),
                handle: "alice".into(),
            }
            .encode_to_vec(),
        ),
        (
            "RemoveHandleRequest",
            api::RemoveHandleRequest {
                client_operation_id: "handle-1".into(),
                handle: "alice2".into(),
            }
            .encode_to_vec(),
        ),
        (
            "PasskeyRecord",
            api::PasskeyRecord {
                created_at: timestamp(1),
                last_used_at: timestamp(2),
                aaguid: Some(vec![0; 16]),
                authenticator_name: Some("Key".into()),
                ..Default::default()
            }
            .encode_to_vec(),
        ),
        (
            "CurrentCredentialRecord",
            api::CurrentCredentialRecord {
                passkey_credential_id: Some(vec![1, 2]),
                ..Default::default()
            }
            .encode_to_vec(),
        ),
        (
            "SessionRecord",
            api::SessionRecord {
                user_agent: "Browser".into(),
                device_label: Some("Laptop".into()),
                ..Default::default()
            }
            .encode_to_vec(),
        ),
        (
            "ObserveIdentityRequest",
            api::ObserveIdentityRequest {
                sessions: Some(api::PageRequest::default()),
                session_state: api::SessionStateFilter::Active as i32,
                ..Default::default()
            }
            .encode_to_vec(),
        ),
    ];
    assert_eq!(
        fixture.as_array().expect("vector list").len(),
        vectors.len()
    );
    for (name, bytes) in vectors {
        let vector = fixture
            .as_array()
            .expect("vector list")
            .iter()
            .find(|v| v["type"] == name)
            .expect(name);
        assert_eq!(
            hex::encode(bytes),
            vector["hex"].as_str().expect("hex"),
            "{name}"
        );
    }
}

#[test]
fn account_metadata_bounds_match_shared_typescript_vectors() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/account-metadata.json"))
            .expect("shared vectors");
    for vector in fixture["labels"].as_array().expect("labels") {
        let input = vector["input"].as_str().expect("input");
        for normalize in [normalize_display_name, normalize_advisory_label] {
            if let Some(expected) = vector["normalized"].as_str() {
                assert_eq!(normalize(input).expect("valid label"), expected);
            } else {
                assert!(normalize(input).is_err(), "{vector}");
            }
        }
    }
    // Also run every existing passkey normalization vector through display-name
    // and advisory-label helpers, so the promised policy cannot drift.
    let labels: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/passkey-label-unicode.json"))
            .expect("Unicode vectors");
    for vector in labels.as_array().expect("labels") {
        let input = vector["input"].as_str().expect("input");
        for normalize in [normalize_display_name, normalize_advisory_label] {
            if let Some(expected) = vector["normalized"].as_str() {
                assert_eq!(normalize(input).expect("valid label"), expected);
            } else {
                assert!(normalize(input).is_err(), "{vector}");
            }
        }
    }
    for vector in fixture["label_bounds"].as_array().expect("label bounds") {
        let input = vector["character"]
            .as_str()
            .expect("character")
            .repeat(vector["count"].as_u64().expect("count") as usize);
        for normalize in [normalize_display_name, normalize_advisory_label] {
            assert_eq!(
                normalize(&input).is_ok(),
                vector["valid"].as_bool().expect("valid"),
                "{vector}"
            );
        }
    }
    for (section, validate) in [
        ("aaguid", validate_aaguid as fn(Option<&[u8]>) -> _),
        ("credential_ids", validate_passkey_credential_id),
    ] {
        for vector in fixture[section].as_array().expect(section) {
            let bytes = vector["length"].as_u64().map(|len| vec![0; len as usize]);
            assert_eq!(
                validate(bytes.as_deref()).is_ok(),
                vector["valid"].as_bool().expect("valid"),
                "{section}: {vector}"
            );
        }
    }
    for vector in fixture["user_agents"].as_array().expect("user agents") {
        let input = vector["character"]
            .as_str()
            .expect("character")
            .repeat(vector["count"].as_u64().expect("count") as usize);
        assert_eq!(
            validate_session_user_agent(&input).is_ok(),
            vector["valid"].as_bool().expect("valid"),
            "{vector}"
        );
    }
    assert_eq!(HELD_NAME_REQUESTED, "HELD_NAME_REQUESTED");
    assert_eq!(HELD_NAME_REQUEST_LAPSED, "HELD_NAME_REQUEST_LAPSED");
}

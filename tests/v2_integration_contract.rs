use heddle_api::heddle::api::v1alpha2 as api;
use prost::Message;
#[test]
fn integration_records_have_distinct_typed_identities() {
    let reference = api::RecordRef {
        id: "connection".into(),
        spool: None,
    };
    let connection = api::EntityRef {
        entity: Some(api::entity_ref::Entity::ProviderConnection(
            reference.clone(),
        )),
    };
    let remote = api::EntityRef {
        entity: Some(api::entity_ref::Entity::RemoteLink(reference)),
    };
    assert_ne!(connection.encode_to_vec(), remote.encode_to_vec());
    assert_eq!(
        api::EntityRef::decode(connection.encode_to_vec().as_slice()).expect("connection"),
        connection
    );
    assert_eq!(
        api::EntityRef::decode(remote.encode_to_vec().as_slice()).expect("remote"),
        remote
    );
}

#[test]
fn linked_spools_match_typescript_golden_in_both_directions() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/provider-repository-linked-spools.json"
    ))
    .expect("shared golden JSON");
    let wire =
        hex::decode(fixture["wire_hex"].as_str().expect("wire hex")).expect("valid golden bytes");
    let repository = api::ProviderRepository {
        provider_repository_id: fixture["provider_repository_id"]
            .as_str()
            .expect("repository id")
            .into(),
        clone_url: fixture["clone_url"].as_str().expect("clone URL").into(),
        linked_spools: fixture["linked_spool_ids"]
            .as_array()
            .expect("spool ids")
            .iter()
            .map(|id| api::SpoolRef {
                id: id.as_str().expect("spool UUID").into(),
            })
            .collect(),
        ..Default::default()
    };
    assert_eq!(repository.linked_spools.len(), 2);
    assert_eq!(
        api::ProviderRepository::decode(wire.as_slice()).expect("TS wire"),
        repository
    );
    assert_eq!(
        repository.encode_to_vec(),
        wire,
        "Rust wire matches TS golden"
    );
    let legacy = api::ProviderRepository {
        linked_spools: vec![],
        ..repository
    };
    assert!(
        api::ProviderRepository::decode(legacy.encode_to_vec().as_slice())
            .expect("legacy wire")
            .linked_spools
            .is_empty()
    );
}

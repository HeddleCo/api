use heddle_api::heddle::api::v2alpha1 as api;
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

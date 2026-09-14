#![cfg(feature = "reflection")]

use heddle_api::FILE_DESCRIPTOR_SET;
use prost_reflect::DescriptorPool;

#[test]
fn thread_creation_and_replication_preserve_the_same_signed_genesis() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled contract");
    let start = pool
        .get_message_by_name("heddle.api.v2alpha1.StartThreadRequest")
        .expect("Thread creation");
    let open = pool
        .get_message_by_name("heddle.api.v2alpha1.ReplicationOpen")
        .expect("Thread replication");
    let creation = start
        .get_field_by_name("thread_genesis")
        .expect("creation retains the original creator signature");
    let carrier = pool
        .get_message_by_name("heddle.api.v2alpha1.ThreadGenesisRecord")
        .expect("portable original ownership proof carrier");
    assert_eq!(
        creation.kind(),
        carrier
            .get_field_by_name("genesis")
            .expect("same signed genesis in the carrier")
            .kind()
    );
    assert_eq!(
        open.get_field_by_name("thread_genesis")
            .expect("replication proof")
            .kind(),
        prost_reflect::Kind::Message(carrier.clone()),
    );
    assert_eq!(
        start
            .get_field_by_name("creator_authority")
            .expect("original creation authority")
            .kind(),
        carrier
            .get_field_by_name("creator_authority")
            .expect("original authority survives replication")
            .kind(),
    );
    assert_eq!(
        start
            .fields()
            .map(|field| field.name().to_owned())
            .collect::<Vec<_>>(),
        [
            "client_operation_id",
            "spool",
            "thread_genesis",
            "creator_authority"
        ],
        "signed creation data has one representation; a new immutable identity has no mutable CAS target"
    );
}

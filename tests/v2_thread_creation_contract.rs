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
    assert_eq!(
        creation.kind(),
        open.get_field_by_name("thread_genesis")
            .expect("same genesis during later replication")
            .kind()
    );
    assert_eq!(
        start
            .fields()
            .map(|field| field.name().to_owned())
            .collect::<Vec<_>>(),
        ["client_operation_id", "spool", "thread_genesis"],
        "signed creation data has one representation; a new immutable identity has no mutable CAS target"
    );
}

#![cfg(feature = "reflection")]
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn remote_sync_destination_is_an_explicit_thread_identity() {
    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("contract");
    let remote = pool
        .get_message_by_name("heddle.api.v2alpha1.RemoteLinkRecord")
        .expect("remote record");
    let target = remote
        .get_field_by_name("target")
        .expect("remote must select its Thread explicitly");
    assert_eq!(target.number(), 11);
    let Kind::Message(thread) = target.kind() else {
        panic!("target must be a typed Thread identity")
    };
    assert_eq!(thread.full_name(), "heddle.api.v2alpha1.ThreadRef");
    assert!(
        !target.is_list(),
        "one remote has one explicit target; divergence never chooses another"
    );
}

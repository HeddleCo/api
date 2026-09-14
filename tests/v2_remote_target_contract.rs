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

#[test]
fn remote_policy_deadline_and_atomic_repository_replacement_are_typed() {
    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("contract");
    for (message, field, number, target) in [
        (
            "RemoteLinkRecord",
            "expires_at",
            12,
            "google.protobuf.Timestamp",
        ),
        (
            "IntegrationEvent",
            "replace_section",
            7,
            "heddle.api.v2alpha1.SectionReplacement",
        ),
    ] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.v2alpha1.{message}"))
            .expect("message");
        let field = message
            .get_field_by_name(field)
            .expect("explicit native policy/stream field");
        assert_eq!(field.number(), number);
        let Kind::Message(value) = field.kind() else {
            panic!("typed field required")
        };
        assert_eq!(value.full_name(), target);
    }
}

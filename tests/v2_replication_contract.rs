//! Replication is a durable exchange, distinct from observing a projection.
#![cfg(feature = "reflection")]
use heddle_api::{FILE_DESCRIPTOR_SET, StreamingShape, v2::ALL_METHODS};
use prost_reflect::DescriptorPool;

#[test]
fn thread_replication_exposes_causal_frontiers_without_a_single_tip() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor");
    let rpc = ALL_METHODS.iter().find(|rpc| rpc.path == "/heddle.api.v2alpha1.SyncService/ReplicateThread").expect("live replication RPC");
    assert_eq!(rpc.streaming, StreamingShape::Bidirectional);
    assert!(!ALL_METHODS.iter().any(|rpc| rpc.path == "/heddle.api.v2alpha1.SyncService/Publish"));
    let overview = pool.get_message_by_name("heddle.api.v2alpha1.ThreadOverview").expect("Thread view");
    assert!(overview.get_field_by_name("source_heads").expect("concurrent source heads").is_list());
    assert!(overview.get_field_by_name("integrated_revision").is_some());
    assert!(overview.get_field_by_name("tip").is_none());
    let append = pool.get_message_by_name("heddle.api.v2alpha1.AppendDiscussionRequest").expect("append");
    assert!(append.get_field_by_name("causal_parents").expect("independent appends").is_list());
    assert!(append.get_field_by_name("expected_version").is_none());
}

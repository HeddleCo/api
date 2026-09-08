//! Replication is a durable exchange, distinct from observing a projection.
#![cfg(feature = "reflection")]
use heddle_api::{FILE_DESCRIPTOR_SET, StreamingShape, v2::ALL_METHODS};
use prost_reflect::DescriptorPool;

#[test]
fn thread_replication_exposes_causal_frontiers_without_a_single_tip() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor");
    let rpc = ALL_METHODS
        .iter()
        .find(|rpc| rpc.path == "/heddle.api.v2alpha1.SyncService/ReplicateThread")
        .expect("live replication RPC");
    assert_eq!(rpc.streaming, StreamingShape::Bidirectional);
    assert!(
        !ALL_METHODS
            .iter()
            .any(|rpc| rpc.path == "/heddle.api.v2alpha1.SyncService/Publish")
    );
    let overview = pool
        .get_message_by_name("heddle.api.v2alpha1.ThreadOverview")
        .expect("Thread view");
    assert!(
        overview
            .get_field_by_name("source_heads")
            .expect("concurrent source heads")
            .is_list()
    );
    assert!(overview.get_field_by_name("integrated_revision").is_some());
    assert!(overview.get_field_by_name("tip").is_none());
    let append = pool
        .get_message_by_name("heddle.api.v2alpha1.AppendDiscussionRequest")
        .expect("append");
    assert!(
        append
            .get_field_by_name("causal_parents")
            .expect("independent appends")
            .is_list()
    );
    assert!(append.get_field_by_name("expected_version").is_none());
}

#[test]
fn bulk_publication_has_a_thread_bound_upload_and_a_durable_availability_receipt() {
    use heddle_api::heddle::api::v1alpha1::{AuthorizationRole, SigningTier};
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor");
    let rpc = ALL_METHODS.iter().find(|rpc| rpc.path == "/heddle.api.v2alpha1.SyncService/PublishContent")
        .expect("source bytes need an upload path independent of causal metadata");
    assert_eq!(rpc.streaming, StreamingShape::Bidirectional);
    assert_eq!(rpc.authorization.role, AuthorizationRole::ResourceWriter);
    assert_eq!(rpc.signing_tier, SigningTier::StreamingProofOfPossession);
    assert!(rpc.client_operation_id_required);
    let open = pool.get_message_by_name("heddle.api.v2alpha1.PublishContentOpen").expect("publication opening");
    for field in ["thread", "revision", "packs", "sharing_policy_version", "checkpoint"] {
        assert!(open.get_field_by_name(field).is_some(), "opening binds {field}");
    }
    assert!(open.get_field_by_name("expected_tip").is_none(), "content availability must not replace concurrent heads");
    let client = pool.get_message_by_name(rpc.input).expect("upload frames");
    assert!(client.get_field_by_name("pack").is_some(), "client can stream pack bytes");
    let server = pool.get_message_by_name(rpc.output).expect("response frames");
    let receipt = server.get_field_by_name("receipt").expect("durable content receipt");
    assert_eq!(receipt.kind().as_message().expect("receipt message").full_name(), "heddle.api.v2alpha1.PublicationReceipt");
}

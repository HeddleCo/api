use heddle_api::heddle::api::v1alpha2::{
    CatalogActivitySummary, CatalogEvent, CatalogSort, ObserveCatalogRequest, PageRequest,
    PublicOwner, SpoolOverview, catalog_event,
};
use prost::Message;

#[test]
fn catalog_row_and_sort_round_trip() {
    let request = ObserveCatalogRequest {
        query: "spool".into(),
        spools: Some(PageRequest {
            size: 20,
            after_page: vec![1, 2, 3],
        }),
        sort: CatalogSort::RecentActivity as i32,
        ..Default::default()
    };
    let decoded =
        ObserveCatalogRequest::decode(request.encode_to_vec().as_slice()).expect("catalog request");
    assert_eq!(decoded, request);
    assert_eq!(decoded.sort, CatalogSort::RecentActivity as i32);

    let spool = SpoolOverview {
        name: "Public spool".into(),
        public_owner: Some(PublicOwner {
            handle: "ada".into(),
            display_name: "Ada".into(),
        }),
        last_activity_at: Some(prost_types::Timestamp {
            seconds: 1_750_000_000,
            nanos: 123_000_000,
        }),
        catalog_activity: Some(CatalogActivitySummary {
            open_thread_count: 4,
            landed_30d: 7,
        }),
        ..Default::default()
    };
    let event = CatalogEvent {
        payload: Some(catalog_event::Payload::Spool(spool.clone())),
        ..Default::default()
    };
    let decoded = CatalogEvent::decode(event.encode_to_vec().as_slice()).expect("catalog event");
    assert_eq!(decoded, event);
    let Some(catalog_event::Payload::Spool(decoded_spool)) = decoded.payload else {
        panic!("catalog row was lost");
    };
    assert_eq!(decoded_spool.public_owner, spool.public_owner);
    assert_eq!(decoded_spool.last_activity_at, spool.last_activity_at);
    assert_eq!(decoded_spool.catalog_activity, spool.catalog_activity);
}

#[cfg(feature = "reflection")]
#[test]
fn public_owner_is_defined_in_common_for_catalog_and_invitation() {
    let pool = prost_reflect::DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET)
        .expect("valid descriptor");
    let owner = pool
        .get_message_by_name("heddle.api.v1alpha2.PublicOwner")
        .expect("shared public owner");
    assert_eq!(
        owner.parent_file().name(),
        "heddle/api/v1alpha2/common.proto"
    );
}

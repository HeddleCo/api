#![cfg(feature = "reflection")]
use heddle_api::FILE_DESCRIPTOR_SET;
use prost_reflect::DescriptorPool;

#[test]
fn bookmark_versions_have_a_caller_private_identity_and_return_tombstones() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled contract");
    let reference = pool
        .get_message_by_name("heddle.api.v2alpha1.BookmarkRef")
        .expect("private bookmark identity");
    assert_eq!(
        reference
            .get_field_by_name("account")
            .expect("account binding")
            .kind()
            .as_message()
            .expect("principal ref")
            .full_name(),
        "heddle.api.v2alpha1.PrincipalRef"
    );
    let targets: Vec<_> = reference
        .oneofs()
        .find(|o| o.name() == "target")
        .expect("one target")
        .fields()
        .map(|f| f.name().to_owned())
        .collect();
    assert_eq!(targets, ["spool", "thread"]);
    let entity = pool
        .get_message_by_name("heddle.api.v2alpha1.EntityRef")
        .expect("entity");
    assert_eq!(
        entity
            .get_field_by_name("bookmark")
            .expect("independent CAS identity")
            .kind()
            .as_message()
            .expect("bookmark reference")
            .full_name(),
        reference.full_name()
    );
    let method = pool
        .get_service_by_name("heddle.api.v2alpha1.SpoolService")
        .expect("spools")
        .methods()
        .find(|m| m.name() == "SetBookmark")
        .expect("mutation");
    assert_eq!(
        method.output().full_name(),
        "heddle.api.v2alpha1.BookmarkMutationResponse"
    );
    let record = method
        .output()
        .get_field_by_name("bookmark")
        .expect("resulting bookmark without another read")
        .kind()
        .as_message()
        .expect("record")
        .clone();
    assert!(record.get_field_by_name("version").is_some());
    assert!(
        record.get_field_by_name("bookmarked").is_some(),
        "tombstones retain a CAS version"
    );
    assert!(
        record.get_field_by_name("resource").is_none(),
        "target identity must not masquerade as bookmark identity"
    );
}

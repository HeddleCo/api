#![cfg(feature = "reflection")]

use heddle_api::FILE_DESCRIPTOR_SET;
use prost_reflect::DescriptorPool;

#[test]
fn content_tree_entries_preserve_typed_native_and_foreign_targets() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    let event = pool
        .get_message_by_name("heddle.api.v2alpha1.ContentEvent")
        .expect("content event");
    let entry = event
        .get_field_by_name("tree_entry")
        .expect("tree selection")
        .kind()
        .as_message()
        .expect("tree entry message")
        .clone();
    assert_eq!(
        entry.full_name(),
        "heddle.api.v2alpha1.ContentTreeEntry",
        "v2 must not squeeze a spool/revision pointer into a generic hash"
    );
    assert!(
        entry.get_field_by_name("path").is_some(),
        "batched subtrees carry root-relative paths"
    );
    let target = entry
        .oneofs()
        .find(|oneof| oneof.name() == "target")
        .expect("one typed target per entry");
    let names: std::collections::BTreeSet<_> = target
        .fields()
        .map(|field| field.name().to_owned())
        .collect();
    assert_eq!(
        names,
        ["tree_hash", "file", "symlink", "gitlink", "spoollink"]
            .map(str::to_owned)
            .into()
    );
    let spool = entry
        .get_field_by_name("spoollink")
        .expect("native child spool");
    assert_eq!(
        spool
            .kind()
            .as_message()
            .expect("anchored spool pointer")
            .full_name(),
        "heddle.api.v2alpha1.ContentSpoolLink"
    );
    let link = spool.kind().as_message().expect("spool link").clone();
    assert!(
        link.get_field_by_name("native_spool_id").is_some(),
        "preserve the source-encoded namespace/name identity"
    );
    assert!(
        link.get_field_by_name("state").is_some(),
        "preserve the anchored immutable revision"
    );
    let file = entry
        .get_field_by_name("file")
        .expect("file")
        .kind()
        .as_message()
        .expect("file metadata")
        .clone();
    assert!(
        file.get_field_by_name("size")
            .expect("decoded size")
            .supports_presence(),
        "unknown length differs from an empty file"
    );
    assert!(
        file.get_field_by_name("executable").is_some(),
        "source mode survives the read"
    );
}

#[test]
fn state_attachment_selections_report_kind_coverage_separately_from_completion() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    let event = pool
        .get_message_by_name("heddle.api.v2alpha1.ContentEvent")
        .expect("content event");
    let attachment = event
        .get_field_by_name("attachment")
        .expect("attachment selection")
        .kind()
        .as_message()
        .expect("typed attachment")
        .clone();
    assert_eq!(
        attachment.full_name(),
        "heddle.api.v2alpha1.StateAttachmentContent"
    );
    assert_eq!(
        attachment
            .get_field_by_name("coverage")
            .expect("per-kind coverage")
            .kind()
            .as_enum()
            .expect("coverage enum")
            .full_name(),
        "heddle.api.v2alpha1.Coverage"
    );
    assert!(attachment.get_field_by_name("kind").is_some());
    assert!(attachment.get_field_by_name("attachment_id").is_some());
    let bodies: Vec<_> = attachment
        .oneofs()
        .find(|oneof| oneof.name() == "body")
        .expect("optional disclosed body")
        .fields()
        .map(|field| field.name().to_owned())
        .collect();
    assert_eq!(bodies, ["structured_conflicts", "raw_object"]);
    assert!(
        event.get_field_by_name("selection_complete").is_some(),
        "one selection completion remains independent of each attachment's availability"
    );
}

#[test]
fn content_attachment_kinds_exclude_thread_authored_records() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    for (message, field) in [("StateRead", "attachment_kinds"), ("StateAttachmentContent", "kind")] {
        let descriptor = pool.get_message_by_name(&format!("heddle.api.v2alpha1.{message}"))
            .expect("content message").get_field_by_name(field).expect("kind field")
            .kind().as_enum().expect("source-only enum").clone();
        assert_eq!(descriptor.full_name(), "heddle.api.v2alpha1.SourceAttachmentKind");
        let values: Vec<_> = descriptor.values().map(|value| (value.name().to_owned(), value.number())).collect();
        assert_eq!(values, vec![
            ("SOURCE_ATTACHMENT_KIND_UNSPECIFIED".into(), 0),
            ("SOURCE_ATTACHMENT_KIND_RISK_SIGNALS".into(), 1),
            ("SOURCE_ATTACHMENT_KIND_STRUCTURED_CONFLICTS".into(), 2),
            ("SOURCE_ATTACHMENT_KIND_SEMANTIC_INDEX".into(), 3),
        ], "authored records require their original Thread authority");
    }
}

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

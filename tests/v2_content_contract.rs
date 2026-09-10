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
fn raw_state_reads_cannot_disclose_authored_sidecars() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    let event = pool
        .get_message_by_name("heddle.api.v2alpha1.ContentEvent")
        .expect("content event");
    assert!(
        event.get_field_by_name("attachment").is_none(),
        "authored sidecars require their originating Thread authority"
    );
    assert!(event.get_field_by_name("state").is_some());
    assert!(event.get_field_by_name("selection_complete").is_some());
    let state = pool
        .get_message_by_name("heddle.api.v2alpha1.StateRead")
        .expect("state selection");
    assert_eq!(
        state.fields().count(),
        0,
        "State selection always returns its summary"
    );
    assert!(
        pool.get_message_by_name("heddle.api.v2alpha1.StateAttachmentContent")
            .is_none()
    );
    assert!(
        pool.get_enum_by_name("heddle.api.v2alpha1.SourceAttachmentKind")
            .is_none()
    );
}

#[test]
fn source_transfers_share_original_operation_and_authority_receipt_batches() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    for name in ["FetchServerFrame", "PublishContentClientFrame"] {
        let frame = pool
            .get_message_by_name(&format!("heddle.api.v2alpha1.{name}"))
            .expect("source frame");
        let batch = frame
            .get_field_by_name("operations")
            .expect("original operation batch");
        assert_eq!(batch.number(), 6);
        assert_eq!(
            batch
                .kind()
                .as_message()
                .expect("batch message")
                .full_name(),
            "heddle.api.v2alpha1.ReplicationOperations"
        );
        assert!(
            frame.get_field_by_name("operation").is_none(),
            "no separate unreceipted source framing"
        );
    }
    let batch = pool
        .get_message_by_name("heddle.api.v2alpha1.ReplicationOperations")
        .expect("shared batch");
    assert!(
        batch
            .get_field_by_name("operations")
            .expect("original signatures")
            .is_list()
    );
    assert!(
        batch
            .get_field_by_name("authority_admissions")
            .expect("retained testimony")
            .is_list()
    );
}

#[test]
fn source_genesis_transfers_preserve_claim_conflicts_and_matched_admission() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    let wrapper = pool
        .get_message_by_name("heddle.api.v2alpha1.ThreadGenesisRecord")
        .expect("original wrapper");
    for (name, number) in [("ownership_claims", 4), ("ownership_claim_admissions", 5)] {
        let field = wrapper
            .get_field_by_name(name)
            .expect("claim provenance survives transfer");
        assert_eq!(field.number(), number);
        assert!(
            field.is_list(),
            "preserve conflicts rather than choosing an owner"
        );
        assert_eq!(
            field
                .kind()
                .as_message()
                .expect("signed claim or admission")
                .full_name(),
            "heddle.api.v2alpha1.SignedRecord"
        );
    }
}

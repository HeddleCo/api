use heddle_api::heddle::api::v1alpha2::{
    Coverage, PageInfo, RecordRef, RevisionRef, SectionStatus, SectionStatusReason,
};
use prost::Message;

// The five-field schema used before reason was added. Decoding with it proves
// older clients still receive the same status while ignoring the new field.
#[derive(Clone, PartialEq, Message)]
struct LegacySectionStatus {
    #[prost(string, tag = "1")]
    section: String,
    #[prost(enumeration = "Coverage", tag = "2")]
    coverage: i32,
    #[prost(message, optional, tag = "3")]
    computed_for: Option<RevisionRef>,
    #[prost(message, optional, tag = "4")]
    operation: Option<RecordRef>,
    #[prost(message, optional, tag = "5")]
    page: Option<PageInfo>,
}

#[test]
fn section_status_reasons_match_shared_wire_vectors_and_older_clients() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/section-status-reasons.json"))
            .expect("shared reason vectors");
    for vector in fixture["vectors"].as_array().expect("vectors") {
        let name = vector["name"].as_str().expect("vector name");
        let coverage = vector["coverage"].as_i64().expect("coverage") as i32;
        let reason = vector["reason"].as_i64().expect("reason") as i32;
        let status = SectionStatus {
            section: "review".into(),
            coverage,
            reason,
            ..Default::default()
        };
        let wire =
            hex::decode(vector["wire_hex"].as_str().expect("wire hex")).expect("valid wire hex");
        assert_eq!(status.encode_to_vec(), wire, "{name}");
        assert_eq!(SectionStatus::decode(wire.as_slice()).expect(name), status);
        let legacy = LegacySectionStatus::decode(wire.as_slice()).expect(name);
        assert_eq!(legacy.section, status.section, "{name}");
        assert_eq!(legacy.coverage, coverage, "{name}");
        assert_eq!(legacy.computed_for, status.computed_for, "{name}");
        assert_eq!(legacy.operation, status.operation, "{name}");
        assert_eq!(legacy.page, status.page, "{name}");
        let from_legacy =
            SectionStatus::decode(legacy.encode_to_vec().as_slice()).expect("older server status");
        assert_eq!(from_legacy.reason, SectionStatusReason::Unspecified as i32);
        if reason <= 4 {
            assert_eq!(
                SectionStatusReason::try_from(reason)
                    .expect("known reason")
                    .as_str_name(),
                vector["reason_name"].as_str().expect("reason name"),
                "{name}"
            );
        } else {
            assert!(SectionStatusReason::try_from(reason).is_err());
        }
    }
}

#[test]
fn section_status_reason_keeps_existing_nested_fields() {
    let legacy = LegacySectionStatus {
        section: "review".into(),
        coverage: Coverage::Partial as i32,
        computed_for: Some(RevisionRef::default()),
        operation: Some(RecordRef::default()),
        page: Some(PageInfo::default()),
    };
    let mut status =
        SectionStatus::decode(legacy.encode_to_vec().as_slice()).expect("legacy nested fields");
    assert_eq!(status.reason, SectionStatusReason::Unspecified as i32);
    status.reason = SectionStatusReason::CoverageIncomplete as i32;
    assert_eq!(
        LegacySectionStatus::decode(status.encode_to_vec().as_slice())
            .expect("new status read by older schema"),
        legacy
    );
}

#[cfg(feature = "reflection")]
#[test]
fn section_status_reason_preserves_existing_fields_and_has_stable_codes() {
    use heddle_api::FILE_DESCRIPTOR_SET;
    use prost_reflect::{DescriptorPool, Kind};

    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled contract");
    let status = pool
        .get_message_by_name("heddle.api.v1alpha2.SectionStatus")
        .expect("section status");
    assert_eq!(
        status
            .fields()
            .map(|field| (field.name().to_owned(), field.number()))
            .collect::<Vec<_>>(),
        [
            ("section".into(), 1),
            ("coverage".into(), 2),
            ("computed_for".into(), 3),
            ("operation".into(), 4),
            ("page".into(), 5),
            ("reason".into(), 6),
        ]
    );
    let reason = pool
        .get_enum_by_name("heddle.api.v1alpha2.SectionStatusReason")
        .expect("typed section reason");
    assert_eq!(
        status.get_field_by_name("reason").expect("reason").kind(),
        Kind::Enum(reason.clone())
    );
    assert_eq!(
        reason
            .values()
            .map(|value| (value.name().to_owned(), value.number()))
            .collect::<Vec<_>>(),
        [
            ("SECTION_STATUS_REASON_UNSPECIFIED".into(), 0),
            ("SECTION_STATUS_REASON_BASE_ANCESTRY_UNAVAILABLE".into(), 1),
            ("SECTION_STATUS_REASON_ACCESS_WITHHELD".into(), 2),
            ("SECTION_STATUS_REASON_MULTIPLE_HEADS".into(), 3),
            ("SECTION_STATUS_REASON_COVERAGE_INCOMPLETE".into(), 4),
        ]
    );
}

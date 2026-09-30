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

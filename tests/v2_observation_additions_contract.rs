#[cfg(feature = "reflection")]
use heddle_api::FILE_DESCRIPTOR_SET;
#[cfg(feature = "reflection")]
use prost_reflect::{DescriptorPool, Kind};

#[cfg(feature = "reflection")]
#[test]
fn observation_additions_have_stable_typed_placement() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    for (message, field, tag, target) in [
        ("OperationRecord", "subject", 15, "OperationSubject"),
        (
            "OperationRecord",
            "created_at",
            16,
            "google.protobuf.Timestamp",
        ),
        (
            "OperationRecord",
            "started_at",
            17,
            "google.protobuf.Timestamp",
        ),
        (
            "OperationRecord",
            "finished_at",
            18,
            "google.protobuf.Timestamp",
        ),
        ("OperationRecord", "retry_of", 19, "OperationRef"),
        ("OperationRecord", "superseded_by", 20, "OperationRef"),
        (
            "ThreadOverview",
            "landing_assessment_status",
            29,
            "LandingAssessmentStatus",
        ),
        (
            "ThreadAlternative",
            "assessment_status",
            7,
            "LandingAssessmentStatus",
        ),
        ("LandingAssessmentStatus", "reason", 2, "Requirement"),
        ("SpoolSettings", "default_thread", 10, "ThreadRef"),
    ] {
        let descriptor = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
            .expect("existing message");
        let field = descriptor.get_field_by_name(field).expect("additive field");
        assert_eq!(field.number(), tag);
        assert!(!field.is_list());
        let target = if target.contains('.') {
            target.to_owned()
        } else {
            format!("heddle.api.v1alpha2.{target}")
        };
        assert_eq!(
            field
                .kind()
                .as_message()
                .expect("typed message")
                .full_name(),
            target
        );
        assert!(field.supports_presence());
    }
    let subject = pool
        .get_message_by_name("heddle.api.v1alpha2.OperationSubject")
        .expect("subject union");
    let import = subject
        .get_field_by_name("import")
        .expect("typed import subject");
    assert_eq!(import.number(), 1);
    assert_eq!(
        import.containing_oneof().expect("extensible union").name(),
        "subject"
    );
    assert_eq!(
        import.kind().as_message().expect("import message").name(),
        "ImportOperationSubject"
    );
    let policy = pool
        .get_message_by_name("heddle.api.v1alpha2.SignedSpoolPolicy")
        .expect("signed policy");
    assert_eq!(policy.fields().count(), 2);
    let revise = pool
        .get_message_by_name("heddle.api.v1alpha2.ReviseSpoolRequest")
        .expect("existing CAS route");
    assert_eq!(
        revise
            .get_field_by_name("settings")
            .expect("delegated settings")
            .number(),
        5
    );
    assert_eq!(
        revise
            .get_field_by_name("expected_version")
            .expect("spool CAS")
            .kind(),
        Kind::Bytes
    );
    let overview = pool
        .get_message_by_name("heddle.api.v1alpha2.SpoolOverview")
        .expect("spool observation");
    assert_eq!(
        overview
            .get_field_by_name("settings")
            .expect("observed settings")
            .number(),
        6
    );
}

#[cfg(feature = "reflection")]
#[test]
fn landing_gap_states_have_stable_values() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    let state = pool
        .get_enum_by_name("heddle.api.v1alpha2.LandingAssessmentStatus.State")
        .expect("landing gap state");
    assert_eq!(
        state
            .values()
            .map(|value| (value.name().to_owned(), value.number()))
            .collect::<Vec<_>>(),
        [
            "UNSPECIFIED",
            "PENDING",
            "FAILED",
            "NOT_ELIGIBLE",
            "NO_PUBLISHED_HEAD",
            "BASE_UNREADABLE",
            "UNAVAILABLE",
            "MULTIPLE_HEADS"
        ]
        .into_iter()
        .enumerate()
        .map(|(number, name)| (format!("STATE_{name}"), number as i32))
        .collect::<Vec<_>>()
    );
    let status = pool
        .get_message_by_name("heddle.api.v1alpha2.LandingAssessmentStatus")
        .expect("gap status");
    let field = status.get_field_by_name("state").expect("state field");
    assert_eq!(field.number(), 1);
    assert_eq!(field.kind(), Kind::Enum(state));
}

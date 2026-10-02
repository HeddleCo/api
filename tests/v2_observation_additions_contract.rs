#[cfg(feature = "reflection")]
use heddle_api::FILE_DESCRIPTOR_SET;
use heddle_api::heddle::api::v1alpha2::{
    LandingAssessmentStatus, OperationRecord, RecordRef, ReviseSpoolRequest, SpoolOverview,
    SpoolRef, SpoolSettings, ThreadOverview, ThreadRef, landing_assessment_status,
    operation_subject,
};
use prost::Message;
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
    for (message, field, tag, kind) in [
        ("OperationRef", "id", 2, Kind::String),
        ("ImportOperationSubject", "source_url", 1, Kind::String),
        ("ImportOperationSubject", "provider", 2, Kind::String),
        (
            "ImportOperationSubject",
            "provider_repository_id",
            3,
            Kind::String,
        ),
    ] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
            .expect("subject/reference shape");
        let field = message.get_field_by_name(field).expect("identity field");
        assert_eq!(field.number(), tag);
        assert_eq!(field.kind(), kind);
    }
    let reference = pool
        .get_message_by_name("heddle.api.v1alpha2.OperationRef")
        .expect("operation identity");
    let spool = reference
        .get_field_by_name("spool")
        .expect("operation spool");
    assert_eq!(spool.number(), 1);
    assert_eq!(
        spool.kind().as_message().expect("spool identity").name(),
        "SpoolRef"
    );
    let rpc = heddle_api::v2::method_descriptor("/heddle.api.v1alpha2.SpoolService/ReviseSpool")
        .expect("admin mutation route");
    assert_eq!(
        rpc.authorization.role,
        heddle_api::heddle::api::common::AuthorizationRole::ResourceAdministrator
    );
    assert_eq!(
        rpc.signing_tier,
        heddle_api::heddle::api::common::SigningTier::ProofOfPossession
    );
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

// Original fields used by the fixture, with old nested schemas where additions
// must be ignored. They intentionally do not depend on the new field definitions.
#[derive(Clone, PartialEq, Message)]
struct LegacyOperation {
    #[prost(message, optional, tag = "1")]
    record: Option<RecordRef>,
    #[prost(string, tag = "2")]
    client_operation_id: String,
    #[prost(bytes = "vec", tag = "3")]
    version: Vec<u8>,
    #[prost(int32, tag = "4")]
    state: i32,
    #[prost(message, optional, tag = "10")]
    failure: Option<heddle_api::heddle::api::common::CallFailure>,
}
#[derive(Clone, PartialEq, Message)]
struct LegacyAlternative {
    #[prost(message, optional, tag = "1")]
    head: Option<heddle_api::heddle::api::v1alpha2::RevisionRef>,
    #[prost(message, optional, tag = "5")]
    assessment: Option<heddle_api::heddle::api::v1alpha2::LandingAssessment>,
}
#[derive(Clone, PartialEq, Message)]
struct LegacyThread {
    #[prost(message, optional, tag = "1")]
    thread: Option<ThreadRef>,
    #[prost(bytes = "vec", tag = "3")]
    version: Vec<u8>,
    #[prost(message, repeated, tag = "5")]
    source_heads: Vec<heddle_api::heddle::api::v1alpha2::RevisionRef>,
    #[prost(message, optional, tag = "25")]
    assessment: Option<heddle_api::heddle::api::v1alpha2::LandingAssessment>,
    #[prost(message, repeated, tag = "26")]
    assessments: Vec<heddle_api::heddle::api::v1alpha2::LandingAssessment>,
    #[prost(message, repeated, tag = "27")]
    alternatives: Vec<LegacyAlternative>,
}
#[derive(Clone, PartialEq, Message)]
struct LegacySettings {
    #[prost(string, tag = "3")]
    description: String,
}
#[derive(Clone, PartialEq, Message)]
struct LegacySpool {
    #[prost(message, optional, tag = "1")]
    spool: Option<SpoolRef>,
    #[prost(bytes = "vec", tag = "4")]
    version: Vec<u8>,
    #[prost(message, optional, tag = "6")]
    settings: Option<LegacySettings>,
}
#[derive(Clone, PartialEq, Message)]
struct LegacyRevise {
    #[prost(string, tag = "1")]
    client_operation_id: String,
    #[prost(message, optional, tag = "2")]
    spool: Option<SpoolRef>,
    #[prost(bytes = "vec", tag = "3")]
    expected_version: Vec<u8>,
    #[prost(string, tag = "4")]
    name: String,
    #[prost(message, optional, tag = "5")]
    settings: Option<LegacySettings>,
}

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/observation-additions-v1.json"))
        .expect("shared Rust/TypeScript fixture")
}
fn wire(vector: &serde_json::Value) -> Vec<u8> {
    hex::decode(vector.as_str().expect("wire hex")).expect("valid hex")
}
fn round_trip<M: Message + Default>(bytes: &[u8]) -> M {
    let value = M::decode(bytes).expect("shared vector decodes");
    assert_eq!(
        value.encode_to_vec(),
        bytes,
        "canonical transport round trip"
    );
    value
}

#[test]
fn import_subject_timestamps_and_retry_chain_match_shared_vectors() {
    let fixture = fixture();
    let operations = fixture["operations"].as_array().expect("operation vectors");
    let records = operations
        .iter()
        .map(|vector| {
            let bytes = wire(&vector["wire_hex"]);
            let record: OperationRecord = round_trip(&bytes);
            let old = LegacyOperation::decode(bytes.as_slice()).expect("older operation reader");
            assert_eq!(old.record, record.r#ref);
            assert_eq!(old.client_operation_id, record.client_operation_id);
            assert_eq!(old.version, record.version);
            assert_eq!(old.state, record.state);
            assert_eq!(old.failure, record.failure);
            let reread = OperationRecord::decode(old.encode_to_vec().as_slice())
                .expect("new reader of old operation");
            assert!(reread.subject.is_none());
            assert!(reread.created_at.is_none());
            assert!(reread.started_at.is_none());
            assert!(reread.finished_at.is_none());
            assert!(reread.retry_of.is_none());
            assert!(reread.superseded_by.is_none());
            record
        })
        .collect::<Vec<_>>();
    let [a, b, c, canceled, legacy] = records.as_slice() else {
        panic!("five operation cases")
    };
    let Some(operation_subject::Subject::Import(import)) = a
        .subject
        .as_ref()
        .and_then(|subject| subject.subject.as_ref())
    else {
        panic!("typed import source")
    };
    assert_eq!(import.source_url, "https://github.com/sharkdp/hexyl.git");
    assert_eq!(import.provider, "github");
    assert_eq!(import.provider_repository_id, "repo-42");
    assert_eq!(a.subject, b.subject);
    assert_eq!(b.subject, c.subject);
    assert_eq!(a.state, 4, "superseded attempt stays failed");
    assert_eq!(b.state, 4);
    let failure = a.failure.as_ref().expect("historical failure retained");
    assert_eq!(failure.code, 14);
    assert_eq!(failure.message, "Source fetch failed");
    assert_eq!(a.failure, b.failure);
    assert_eq!(c.state, 1);
    let created = a.created_at.as_ref().expect("admission timestamp");
    assert_eq!(created.seconds, 1_780_000_000);
    assert_eq!(created.nanos, 123_456_789);
    assert_eq!(
        a.started_at.as_ref().expect("execution start").seconds,
        1_780_000_001
    );
    assert_eq!(a.finished_at.as_ref().expect("terminal time").nanos, 42);
    for (prior, next) in [(a, b), (b, c)] {
        let replacement = prior.superseded_by.as_ref().expect("direct replacement");
        let next_ref = next.r#ref.as_ref().expect("new attempt identity");
        assert_eq!(replacement.spool, next_ref.spool);
        assert_eq!(replacement.id, next_ref.id);
        let predecessor = next.retry_of.as_ref().expect("direct predecessor");
        let prior_ref = prior.r#ref.as_ref().expect("old attempt identity");
        assert_eq!(predecessor.spool, prior_ref.spool);
        assert_eq!(predecessor.id, prior_ref.id);
    }
    assert!(a.retry_of.is_none());
    assert!(c.superseded_by.is_none());
    assert!(c.started_at.is_none() && c.finished_at.is_none());
    assert_eq!(canceled.state, 5);
    assert!(canceled.started_at.is_none());
    assert!(canceled.created_at.is_some() && canceled.finished_at.is_some());
    assert!(legacy.subject.is_none() && legacy.created_at.is_none());
}

#[test]
fn landing_gap_states_and_typed_reasons_match_shared_vectors() {
    let fixture = fixture();
    for vector in fixture["statuses"].as_array().expect("status vectors") {
        let status: LandingAssessmentStatus = round_trip(&wire(&vector["wire_hex"]));
        assert_eq!(
            i64::from(status.state),
            vector["state"].as_i64().expect("enum code")
        );
        if (1..=7).contains(&status.state) {
            let reason = status.reason.expect("typed explanation");
            assert!(reason.kind > 0 && !reason.explanation.is_empty());
            assert!(
                reason.subject.is_none() && reason.policy.is_none(),
                "generic fixture does not disclose a hidden resource"
            );
        } else {
            assert!(status.reason.is_none(), "unknown supplies no verdict");
        }
    }
    assert!(landing_assessment_status::State::try_from(99).is_err());
    assert_eq!(
        LandingAssessmentStatus::default().state,
        landing_assessment_status::State::Unspecified as i32
    );
}

#[test]
fn overview_and_alternative_gaps_match_shared_vectors_and_old_readers() {
    let fixture = fixture();
    for vector in fixture["overviews"].as_array().expect("overview vectors") {
        let bytes = wire(&vector["wire_hex"]);
        let overview: ThreadOverview = round_trip(&bytes);
        let name = vector["name"].as_str().expect("case name");
        if let Some(state) = name.strip_prefix("gap-") {
            let state: i32 = state.parse().expect("state number");
            assert_eq!(
                overview
                    .landing_assessment_status
                    .as_ref()
                    .expect("overview gap")
                    .state,
                state
            );
            assert!(overview.landing_assessment.is_none());
            assert!(overview.landing_assessments.is_empty());
            assert_eq!(overview.alternatives.len(), usize::from(state != 4));
            for alternative in &overview.alternatives {
                assert!(alternative.assessment.is_none());
                assert_eq!(
                    alternative.assessment_status,
                    overview.landing_assessment_status
                );
                assert_eq!(alternative.head.as_ref(), overview.source_heads.first());
            }
        } else if name == "assessed" || name == "multiple-heads" {
            assert_eq!(
                overview.landing_assessment.is_none(),
                name == "multiple-heads"
            );
            assert_eq!(
                overview
                    .landing_assessment_status
                    .as_ref()
                    .map(|status| status.state),
                (name == "multiple-heads").then_some(7)
            );
            assert_eq!(
                overview.alternatives.len(),
                if name == "multiple-heads" { 2 } else { 1 }
            );
            for (alternative, assessment) in overview
                .alternatives
                .iter()
                .zip(&overview.landing_assessments)
            {
                assert!(alternative.assessment_status.is_none());
                assert_eq!(alternative.assessment.as_ref(), Some(assessment));
                assert_eq!(alternative.head, assessment.source);
            }
        } else {
            assert!(overview.landing_assessment_status.is_none());
            assert!(overview.alternatives[0].assessment_status.is_none());
        }
        let old = LegacyThread::decode(bytes.as_slice()).expect("older nested Thread reader");
        assert_eq!(old.thread, overview.r#ref);
        assert_eq!(old.version, overview.version);
        assert_eq!(old.source_heads, overview.source_heads);
        assert_eq!(old.assessment, overview.landing_assessment);
        assert_eq!(old.assessments, overview.landing_assessments);
        for (old, new) in old.alternatives.iter().zip(&overview.alternatives) {
            assert_eq!(old.head, new.head);
            assert_eq!(old.assessment, new.assessment);
        }
        let reread =
            ThreadOverview::decode(old.encode_to_vec().as_slice()).expect("older server Thread");
        assert!(reread.landing_assessment_status.is_none());
        assert!(
            reread
                .alternatives
                .iter()
                .all(|alternative| alternative.assessment_status.is_none())
        );
    }
}

#[test]
fn default_thread_settings_cas_and_observation_match_vectors_and_old_readers() {
    let fixture = fixture();
    let settings: SpoolSettings = round_trip(&wire(&fixture["settings_wire_hex"]));
    let revise_bytes = wire(&fixture["revise_wire_hex"]);
    let revise: ReviseSpoolRequest = round_trip(&revise_bytes);
    let spool_bytes = wire(&fixture["spool_wire_hex"]);
    let spool: SpoolOverview = round_trip(&spool_bytes);
    assert_eq!(revise.settings.as_ref(), Some(&settings));
    assert_eq!(spool.settings.as_ref(), Some(&settings));
    let default = settings.default_thread.as_ref().expect("default Thread");
    assert_eq!(default.spool, spool.r#ref);
    assert_eq!(
        default.id.as_ref().expect("stable Thread id").value,
        [3; 32]
    );
    assert_eq!(revise.expected_version, spool.version);
    assert_eq!(spool.version, [5]);
    assert_eq!(revise.client_operation_id, "set-default");
    let old = LegacySpool::decode(spool_bytes.as_slice()).expect("older spool reader");
    assert_eq!(old.spool, spool.r#ref);
    assert_eq!(old.version, spool.version);
    assert_eq!(
        old.settings.as_ref().expect("old settings").description,
        settings.description
    );
    let reread = SpoolOverview::decode(old.encode_to_vec().as_slice()).expect("older spool server");
    assert!(
        reread
            .settings
            .expect("existing settings")
            .default_thread
            .is_none()
    );
    let old = LegacyRevise::decode(revise_bytes.as_slice()).expect("older revision reader");
    assert_eq!(old.expected_version, revise.expected_version);
    assert_eq!(old.spool, revise.spool);
    assert_eq!(old.client_operation_id, revise.client_operation_id);
    let reread =
        ReviseSpoolRequest::decode(old.encode_to_vec().as_slice()).expect("older settings writer");
    assert!(
        reread
            .settings
            .expect("existing settings")
            .default_thread
            .is_none()
    );
    let omitted: SpoolSettings = round_trip(&wire(&fixture["omitted_settings_wire_hex"]));
    assert!(
        omitted.default_thread.is_none(),
        "unset/deleted/unreadable projections are omitted"
    );
    assert!(SpoolSettings::default().default_thread.is_none());
}

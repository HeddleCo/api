use heddle_api::heddle::api::v1alpha2::{
    EvidenceCurrency, LandingRequirementKind, ThreadOverview, capture_summary,
};
use prost::Message;

#[test]
fn golden_thread_round_trips_two_heads_evidence_and_landing_fields() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/decision-thread-v1.json"))
            .expect("golden fixture JSON");
    let wire =
        hex::decode(fixture["wire_hex"].as_str().expect("wire hex")).expect("valid fixture bytes");
    let overview = ThreadOverview::decode(wire.as_slice()).expect("golden Thread overview");
    assert_eq!(
        overview.encode_to_vec(),
        wire,
        "Rust preserves TS-produced wire"
    );
    assert_eq!(overview.source_heads.len(), 2);
    assert_eq!(overview.landing_assessments.len(), 2);
    assert_eq!(overview.alternatives.len(), 2);
    for (head, alternative) in overview.source_heads.iter().zip(&overview.alternatives) {
        assert_eq!(alternative.head.as_ref(), Some(head));
        assert_eq!(
            alternative
                .assessment
                .as_ref()
                .and_then(|a| a.source.as_ref()),
            Some(head)
        );
        assert_eq!(
            alternative
                .producer
                .as_ref()
                .and_then(|p| p.revision.as_ref()),
            Some(head)
        );
        assert_eq!(
            alternative
                .producer
                .as_ref()
                .expect("producer")
                .attribution_assurance,
            capture_summary::AttributionAssurance::Claimed as i32
        );
    }
    let first = &overview.alternatives[0];
    assert_eq!(
        first.producer.as_ref().expect("first actor").agent_provider,
        "openai"
    );
    assert_eq!(first.reviews.len(), 1);
    assert_eq!(first.checks[0].currency, EvidenceCurrency::Stale as i32);
    assert_ne!(
        first.checks[0].recorded_revision.as_ref(),
        first.head.as_ref()
    );
    assert_eq!(first.checks[0].agent_id, "agent-a");
    assert_eq!(first.checks[1].currency, EvidenceCurrency::Current as i32);
    assert_eq!(
        first.checks[1].recorded_revision.as_ref(),
        first.head.as_ref()
    );
    let assessment = first.assessment.as_ref().expect("first assessment");
    assert_eq!(
        assessment.requirements[0].landing_kind,
        LandingRequirementKind::EvidenceStale as i32
    );
    assert_eq!(
        assessment.requirements[1].landing_kind,
        LandingRequirementKind::ConflictMultipleHeads as i32
    );
    assert_eq!(
        assessment
            .satisfied_by
            .as_ref()
            .expect("satisfaction")
            .requirements[0]
            .approvals[0]
            .id,
        "approval-a"
    );
    assert_eq!(
        assessment
            .satisfied_by
            .as_ref()
            .expect("satisfaction")
            .requirements[1]
            .evidence[0]
            .id,
        "evidence-lint-a"
    );
    let second = &overview.alternatives[1];
    assert_eq!(second.checks[0].currency, EvidenceCurrency::Missing as i32);
    assert_eq!(second.checks[1].currency, EvidenceCurrency::Failed as i32);
    assert_eq!(
        second.checks[1].recorded_revision.as_ref(),
        second.head.as_ref()
    );
    assert_eq!(
        second
            .assessment
            .as_ref()
            .expect("second assessment")
            .requirements[0]
            .landing_kind,
        LandingRequirementKind::ReviewRejected as i32
    );
    assert_eq!(
        second
            .assessment
            .as_ref()
            .expect("second assessment")
            .requirements[1]
            .landing_kind,
        LandingRequirementKind::ConflictMultipleHeads as i32
    );
    let landing = overview
        .landing_record
        .as_ref()
        .expect("prior landing projection");
    assert_eq!(landing.policy_version.len(), 32);
    assert_eq!(landing.review_evidence_digests.len(), 2);
    assert_eq!(landing.executor_key, vec![11; 32]);
    assert_eq!(landing.raw_signed_operation, vec![13; 32]);
}

#[cfg(feature = "reflection")]
#[test]
fn descriptor_pins_landing_cause_and_projection_fields() {
    use heddle_api::FILE_DESCRIPTOR_SET;
    use prost_reflect::DescriptorPool;

    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor");
    let message = |name| pool.get_message_by_name(name).expect("message");
    for (name, fields) in [
        (
            "heddle.api.v1alpha2.ThreadOverview",
            vec![
                ("landing_assessments", 26),
                ("alternatives", 27),
                ("landing_record", 28),
            ],
        ),
        (
            "heddle.api.v1alpha2.LandingAssessment",
            vec![("satisfied_by", 7), ("checks", 8)],
        ),
        (
            "heddle.api.v1alpha2.CaptureSummary",
            vec![
                ("agent_provider", 8),
                ("agent_model", 9),
                ("attribution_assurance", 10),
            ],
        ),
        ("heddle.api.v1alpha2.Requirement", vec![("landing_kind", 7)]),
        (
            "heddle.api.v1alpha2.LandingRecord",
            vec![("policy_version", 7), ("raw_signed_operation", 13)],
        ),
    ] {
        let descriptor = message(name);
        for (field, number) in fields {
            assert_eq!(
                descriptor.get_field_by_name(field).expect("field").number(),
                number,
                "{name}.{field}"
            );
        }
    }
    let kinds = pool
        .get_enum_by_name("heddle.api.v1alpha2.LandingRequirementKind")
        .expect("landing causes");
    for (name, number) in [
        ("LANDING_REQUIREMENT_KIND_EVIDENCE_MISSING", 1),
        ("LANDING_REQUIREMENT_KIND_EVIDENCE_STALE", 2),
        ("LANDING_REQUIREMENT_KIND_EVIDENCE_FAILED", 3),
        ("LANDING_REQUIREMENT_KIND_REVIEW_MISSING", 4),
        ("LANDING_REQUIREMENT_KIND_REVIEW_REJECTED", 5),
        ("LANDING_REQUIREMENT_KIND_REVIEW_CONCURRENT", 6),
        ("LANDING_REQUIREMENT_KIND_REFRESH_TARGET_MOVED", 7),
        ("LANDING_REQUIREMENT_KIND_POLICY_VERSION_CHANGED", 8),
        ("LANDING_REQUIREMENT_KIND_CONFLICT_MULTIPLE_HEADS", 9),
        ("LANDING_REQUIREMENT_KIND_CONFLICT_UNRESOLVED_METADATA", 10),
        ("LANDING_REQUIREMENT_KIND_DISCUSSION_BLOCKING", 11),
    ] {
        assert_eq!(
            kinds.get_value_by_name(name).expect("cause").number(),
            number
        );
    }
    let currency = pool
        .get_enum_by_name("heddle.api.v1alpha2.EvidenceCurrency")
        .expect("evidence currency");
    for (name, number) in [
        ("EVIDENCE_CURRENCY_CURRENT", 1),
        ("EVIDENCE_CURRENCY_STALE", 2),
        ("EVIDENCE_CURRENCY_FAILED", 3),
        ("EVIDENCE_CURRENCY_MISSING", 4),
    ] {
        assert_eq!(
            currency.get_value_by_name(name).expect("currency").number(),
            number
        );
    }
    let broad = pool
        .get_enum_by_name("heddle.api.v1alpha2.RequirementKind")
        .expect("broad requirement kinds");
    for (name, number) in [
        ("REQUIREMENT_KIND_POLICY", 11),
        ("REQUIREMENT_KIND_DISCUSSION", 12),
    ] {
        assert_eq!(
            broad.get_value_by_name(name).expect("broad kind").number(),
            number
        );
    }
}

use heddle_api::heddle::api::v1alpha2::{
    CaptureSummary, ResolutionKind, ResolvedAlternative, ReviewDecision, ReviewRecord, RevisionRef,
    capture_summary, review_decision, revision_ref,
};
use prost::Message;

fn revision(oid: &str) -> RevisionRef {
    RevisionRef {
        revision: Some(revision_ref::Revision::GitCommitOid(oid.to_owned())),
        ..Default::default()
    }
}

#[test]
fn resolved_merge_preserves_parents_actors_and_rejection() {
    let left = revision("a".repeat(40).as_str());
    let right = revision("b".repeat(40).as_str());
    let merged = revision("c".repeat(40).as_str());
    let producer = CaptureSummary {
        revision: Some(left.clone()),
        agent_provider: "anthropic".into(),
        agent_model: "model-a".into(),
        attribution_assurance: capture_summary::AttributionAssurance::Claimed as i32,
        ..Default::default()
    };
    let resolver = CaptureSummary {
        revision: Some(merged.clone()),
        agent_provider: "openai".into(),
        agent_model: "model-b".into(),
        attribution_assurance: capture_summary::AttributionAssurance::Claimed as i32,
        parent_revisions: vec![left.clone(), right.clone()],
        ..Default::default()
    };
    let alternative = ResolvedAlternative {
        head: Some(left.clone()),
        producer: Some(producer),
        reviews: vec![ReviewRecord {
            decision: Some(ReviewDecision {
                source: Some(left.clone()),
                kind: review_decision::Kind::Rejection as i32,
                ..Default::default()
            }),
            ..Default::default()
        }],
        resolving_revision: Some(merged.clone()),
        resolver: Some(resolver),
        kind: ResolutionKind::Merged as i32,
    };
    let decoded = ResolvedAlternative::decode(alternative.encode_to_vec().as_slice())
        .expect("resolved alternative wire round trip");
    assert_eq!(decoded.head, Some(left.clone()));
    assert_eq!(
        decoded.producer.as_ref().and_then(|p| p.revision.as_ref()),
        Some(&left)
    );
    assert_eq!(
        decoded.reviews[0]
            .decision
            .as_ref()
            .and_then(|d| d.source.as_ref()),
        Some(&left)
    );
    assert_eq!(
        decoded.reviews[0].decision.as_ref().expect("review").kind,
        review_decision::Kind::Rejection as i32
    );
    assert_eq!(decoded.resolving_revision, Some(merged.clone()));
    let resolver = decoded.resolver.expect("resolving capture");
    assert_eq!(resolver.revision, Some(merged));
    assert_eq!(resolver.parent_revisions, vec![left, right]);
    assert_eq!(resolver.agent_provider, "openai");
    assert_eq!(decoded.kind, ResolutionKind::Merged as i32);
}

#[cfg(feature = "reflection")]
#[test]
fn resolved_alternatives_have_an_independent_observe_thread_page() {
    use prost_reflect::{DescriptorPool, Kind};

    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("descriptor");
    for (message, field, number, target) in [
        ("ThreadPages", "resolved_alternatives", 6, "PageRequest"),
        (
            "ThreadEvent",
            "resolved_alternative",
            24,
            "ResolvedAlternative",
        ),
        ("CaptureSummary", "parent_revisions", 15, "RevisionRef"),
        ("ResolvedAlternative", "reviews", 3, "ReviewRecord"),
    ] {
        let descriptor = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
            .expect("message");
        let field = descriptor.get_field_by_name(field).expect("field");
        assert_eq!(field.number(), number);
        let Kind::Message(actual) = field.kind() else {
            panic!("expected message field")
        };
        assert_eq!(actual.name(), target);
    }
    let section = pool
        .get_enum_by_name("heddle.api.v1alpha2.ThreadSection")
        .expect("sections");
    assert_eq!(
        section
            .get_value_by_name("THREAD_SECTION_RESOLVED_ALTERNATIVES")
            .expect("section")
            .number(),
        10
    );
}

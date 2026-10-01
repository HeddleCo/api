#[cfg(feature = "reflection")]
use heddle_api::FILE_DESCRIPTOR_SET;
use heddle_api::heddle::api::v1alpha2::{
    BlockingDiscussionResolveRule, DiscussionActionKind, DiscussionRecord, LandingRecord,
    RecordRef, SpoolSettings,
};
use prost::Message;
#[cfg(feature = "reflection")]
use prost_reflect::{DescriptorPool, Kind};

// Only the original fields populated by the shared fixture are needed here.
#[derive(Clone, PartialEq, Message)]
struct LegacyDiscussion {
    #[prost(message, optional, tag = "1")]
    record: Option<RecordRef>,
    #[prost(bytes = "vec", tag = "2")]
    version: Vec<u8>,
    #[prost(int32, tag = "5")]
    status: i32,
    #[prost(bool, tag = "6")]
    blocking: bool,
}

#[test]
fn blocking_rules_and_read_metadata_match_shared_wire_vectors() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/blocking-discussion-v1.json"))
            .expect("shared transport fixture");
    assert_eq!(
        SpoolSettings::default().blocking_discussion_resolve_rule,
        BlockingDiscussionResolveRule::Unspecified as i32,
        "older settings inherit; root ANY_WRITER is an effective default"
    );
    for vector in fixture["settings"].as_array().expect("settings vectors") {
        let wire = hex::decode(vector["wire_hex"].as_str().expect("wire hex"))
            .expect("valid settings bytes");
        let settings = SpoolSettings::decode(wire.as_slice()).expect("settings round trip");
        assert_eq!(
            settings.blocking_discussion_resolve_rule as i64,
            vector["rule"].as_i64().expect("rule")
        );
        assert_eq!(settings.encode_to_vec(), wire);
    }
    assert!(BlockingDiscussionResolveRule::try_from(99).is_err());
    let wire = hex::decode(
        fixture["discussion_wire_hex"]
            .as_str()
            .expect("discussion wire"),
    )
    .expect("valid discussion bytes");
    let discussion = DiscussionRecord::decode(wire.as_slice()).expect("discussion round trip");
    assert_eq!(discussion.encode_to_vec(), wire);
    assert_eq!(discussion.actions.len(), 3);
    let resolve = &discussion.actions[0];
    assert_eq!(resolve.action, DiscussionActionKind::Resolve as i32);
    assert!(resolve.implemented);
    assert!(!resolve.authorized);
    assert!(
        resolve.requirements[0]
            .explanation
            .contains("opener or an administrator")
    );
    assert_eq!(resolve.observed_versions[0].version, [2]);
    assert_eq!(
        discussion.actions[1].action,
        DiscussionActionKind::Reopen as i32
    );
    assert!(discussion.actions[1].authorized);
    assert_eq!(
        discussion.actions[2].action,
        DiscussionActionKind::ChangeBlocking as i32
    );
    assert!(!discussion.actions[2].implemented);
    let resolution = &discussion.resolutions[0];
    assert!(resolution.administrator_override);
    assert_eq!(
        resolution.rule,
        BlockingDiscussionResolveRule::OpenerOrAdmin as i32
    );
    assert_eq!(resolution.principal_id, "administrator-person");
    assert_eq!(resolution.agent_id, "review-agent");
    assert_eq!(resolution.causal_id, [7; 32]);
    let legacy =
        LegacyDiscussion::decode(wire.as_slice()).expect("older reader ignores new fields");
    assert_eq!(legacy.record, discussion.r#ref);
    assert_eq!(legacy.version, discussion.version);
    assert_eq!(legacy.status, discussion.status);
    assert_eq!(legacy.blocking, discussion.blocking);
    let older = DiscussionRecord::decode(legacy.encode_to_vec().as_slice()).expect("older server");
    assert!(older.actions.is_empty());
    assert!(
        older.resolutions.is_empty(),
        "missing metadata means unknown"
    );

    let wire = hex::decode(fixture["landing_wire_hex"].as_str().expect("landing wire"))
        .expect("valid landing bytes");
    let landing = LandingRecord::decode(wire.as_slice()).expect("landing round trip");
    assert_eq!(landing.encode_to_vec(), wire);
    assert_eq!(
        landing.blocking_discussion_resolutions,
        discussion.resolutions
    );
    assert_eq!(
        landing.raw_signed_operation,
        [1, 2, 3],
        "opaque signed bytes stay intact"
    );
}

#[cfg(feature = "reflection")]
#[test]
fn blocking_discussion_rule_has_stable_values_and_delegated_placement() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    let rule = pool
        .get_enum_by_name("heddle.api.v1alpha2.BlockingDiscussionResolveRule")
        .expect("blocking discussion rule");
    assert_eq!(
        rule.values()
            .map(|value| (value.name().to_owned(), value.number()))
            .collect::<Vec<_>>(),
        [
            ("BLOCKING_DISCUSSION_RESOLVE_RULE_UNSPECIFIED".into(), 0),
            ("BLOCKING_DISCUSSION_RESOLVE_RULE_ANY_WRITER".into(), 1),
            ("BLOCKING_DISCUSSION_RESOLVE_RULE_OPENER_OR_ADMIN".into(), 2),
            ("BLOCKING_DISCUSSION_RESOLVE_RULE_OPENER_ONLY".into(), 3),
        ]
    );
    let settings = pool
        .get_message_by_name("heddle.api.v1alpha2.SpoolSettings")
        .expect("delegated settings");
    let field = settings
        .get_field_by_name("blocking_discussion_resolve_rule")
        .expect("inherited rule");
    assert_eq!(field.number(), 9);
    assert_eq!(field.kind(), Kind::Enum(rule));
    let policy = pool
        .get_message_by_name("heddle.api.v1alpha2.SignedSpoolPolicy")
        .expect("owner signed policy");
    assert_eq!(policy.fields().count(), 2, "signed policy stays unchanged");
}

#[cfg(feature = "reflection")]
#[test]
fn discussion_capabilities_and_override_are_read_projections() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    for (message, field, tag, target) in [
        (
            "DiscussionRecord",
            "actions",
            12,
            "DiscussionActionAvailability",
        ),
        (
            "DiscussionRecord",
            "resolutions",
            13,
            "DiscussionResolutionRecord",
        ),
        (
            "LandingRecord",
            "blocking_discussion_resolutions",
            16,
            "DiscussionResolutionRecord",
        ),
    ] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
            .expect("read projection");
        let field = message.get_field_by_name(field).expect("additive field");
        assert_eq!(field.number(), tag);
        assert!(field.is_list());
        assert_eq!(
            field
                .kind()
                .as_message()
                .expect("message field")
                .full_name(),
            format!("heddle.api.v1alpha2.{target}")
        );
    }
    let request = pool
        .get_message_by_name("heddle.api.v1alpha2.ResolveDiscussionRequest")
        .expect("signed resolution delivery");
    assert_eq!(request.fields().count(), 7);
    assert!(
        request
            .get_field_by_name("administrator_override")
            .is_none()
    );
    assert_eq!(
        request
            .get_field_by_name("signed_operation")
            .expect("original signed operation")
            .number(),
        7
    );
    let rpc = heddle_api::v2::method_descriptor(
        "/heddle.api.v1alpha2.CollaborationService/ResolveDiscussion",
    )
    .expect("resolution route");
    assert_eq!(
        rpc.signing_tier,
        heddle_api::heddle::api::common::SigningTier::ProofOfPossession
    );
}

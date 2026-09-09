#![cfg(feature = "reflection")]
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn retained_analysis_is_versioned_and_preserves_typed_results() {
    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("contract");
    let artifact = pool
        .get_message_by_name("heddle.api.v2alpha1.AnalysisArtifact")
        .expect("typed analysis artifact");
    assert_eq!(
        artifact
            .get_field_by_name("schema_version")
            .expect("explicit codec version")
            .number(),
        1
    );
    for (name, number, target, repeated) in [
        ("source", 2, "heddle.api.v2alpha1.RevisionRef", false),
        ("base", 3, "heddle.api.v2alpha1.RevisionRef", false),
        ("analyses", 4, "heddle.api.v2alpha1.AnalysisRecord", true),
        ("findings", 5, "heddle.api.v2alpha1.AnalysisFinding", true),
        ("diffs", 6, "heddle.api.v1alpha1.FileDiff", true),
        ("hot_spots", 7, "heddle.api.v1alpha1.SemanticHotSpot", true),
        (
            "behavior_changes",
            8,
            "heddle.api.v2alpha1.BehaviorChange",
            true,
        ),
        (
            "behavior_coverage",
            9,
            "heddle.api.v2alpha1.BehaviorAnalysisCoverage",
            true,
        ),
    ] {
        let field = artifact.get_field_by_name(name).expect("result field");
        assert_eq!(field.number(), number);
        assert_eq!(field.is_list(), repeated);
        let Kind::Message(message) = field.kind() else {
            panic!("typed result required")
        };
        assert_eq!(message.full_name(), target);
    }
}

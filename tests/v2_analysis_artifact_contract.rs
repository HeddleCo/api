#![cfg(feature = "reflection")]
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn analysis_execution_only_reads_its_base() {
    use heddle_api::heddle::api::common::AuthorizationRole;
    let method =
        heddle_api::v2::method_descriptor("/heddle.api.v1alpha2.AnalysisService/StartAnalysis")
            .expect("analysis route");
    let targets: Vec<_> = method
        .authorization
        .targets
        .iter()
        .map(|target| (target.path, target.role))
        .collect();
    assert_eq!(
        targets,
        vec![
            ("thread.spool", AuthorizationRole::ResourceWriter),
            ("base_thread.spool", AuthorizationRole::ResourceReader)
        ],
        "a comparison reads its base without requiring permission to mutate it"
    );
}

#[test]
fn semantic_index_artifact_retains_its_usable_closure() {
    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("contract");
    let artifact = pool
        .get_message_by_name("heddle.api.v1alpha2.AnalysisArtifact")
        .expect("artifact");
    let Kind::Message(index) = artifact
        .get_field_by_name("semantic_index")
        .expect("usable index artifact")
        .kind()
    else {
        panic!("typed index");
    };
    assert_eq!(
        index.full_name(),
        "heddle.api.v1alpha2.SemanticIndexArtifact"
    );
    for field in ["root_hash", "nodes", "parsed_files", "opaque_files"] {
        assert!(
            index.get_field_by_name(field).is_some(),
            "index must retain {field}"
        );
    }
}

#[test]
fn analysis_inputs_preserve_exact_owning_threads() {
    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("contract");
    for name in [
        "ObserveAnalysisRequest",
        "StartAnalysisRequest",
        "AnalysisRecord",
        "AnalysisArtifact",
    ] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}"))
            .expect("analysis message");
        for field in ["thread", "base_thread"] {
            let owner = message
                .get_field_by_name(field)
                .unwrap_or_else(|| panic!("{name}.{field} must identify its source owner"));
            let Kind::Message(owner) = owner.kind() else {
                panic!("typed source ownership required")
            };
            assert_eq!(owner.full_name(), "heddle.api.v1alpha2.ThreadRef");
        }
    }
}

#[test]
fn retained_analysis_is_versioned_and_preserves_typed_results() {
    let pool = DescriptorPool::decode(heddle_api::FILE_DESCRIPTOR_SET).expect("contract");
    let artifact = pool
        .get_message_by_name("heddle.api.v1alpha2.AnalysisArtifact")
        .expect("typed analysis artifact");
    assert_eq!(
        artifact
            .get_field_by_name("schema_version")
            .expect("explicit codec version")
            .number(),
        1
    );
    for (name, number, target, repeated) in [
        ("source", 2, "heddle.api.v1alpha2.RevisionRef", false),
        ("base", 3, "heddle.api.v1alpha2.RevisionRef", false),
        ("analyses", 4, "heddle.api.v1alpha2.AnalysisRecord", true),
        ("findings", 5, "heddle.api.v1alpha2.AnalysisFinding", true),
        ("diffs", 6, "heddle.api.common.FileDiff", true),
        ("hot_spots", 7, "heddle.api.common.SemanticHotSpot", true),
        (
            "behavior_changes",
            8,
            "heddle.api.v1alpha2.BehaviorChange",
            true,
        ),
        (
            "behavior_coverage",
            9,
            "heddle.api.v1alpha2.BehaviorAnalysisCoverage",
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

#![cfg(feature = "reflection")]

use heddle_api::{FILE_DESCRIPTOR_SET, heddle::api::common::*};
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn navigation_methods_share_content_authorization_and_exact_ownership() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    for name in [
        "GetFileSymbols",
        "GetDefinition",
        "GetSemanticRefs",
        "GetSemanticImporters",
    ] {
        let method = heddle_api::v2::method_descriptor(&format!(
            "/heddle.api.v1alpha2.ContentService/{name}"
        ))
        .expect("declared navigation method");
        assert_eq!(method.effect, RpcEffect::ReadOnly);
        assert_eq!(method.signing_tier, SigningTier::ProofIfAuthenticated);
        assert_eq!(method.authorization_access, AuthorizationAccess::Public);
        assert_eq!(method.authorization.existence, AuthorizationExistence::Hide);
        assert_eq!(method.authorization.targets.len(), 1);
        assert_eq!(method.authorization.targets[0].path, "revision.spool");
        assert_eq!(
            method.authorization.targets[0].role,
            AuthorizationRole::ResourceReader
        );
        assert!(!method.live_stream);
        let request = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}Request"))
            .expect("exact query");
        for (field, target) in [
            ("revision", "RevisionRef"),
            ("thread", "ThreadRef"),
            ("budget", "ReadBudget"),
        ] {
            let Kind::Message(message) = request
                .get_field_by_name(field)
                .expect("typed scope")
                .kind()
            else {
                panic!("typed navigation scope");
            };
            assert_eq!(message.full_name(), format!("heddle.api.v1alpha2.{target}"));
        }
    }
}

#[test]
fn navigation_metadata_and_outcomes_are_explicit() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    let metadata = pool
        .get_message_by_name("heddle.api.v1alpha2.CodeNavigationMetadata")
        .expect("shared readiness and provenance");
    for field in [
        "revision",
        "thread",
        "index_present",
        "resolver_present",
        "language",
        "attestation",
        "resolvers",
        "attachment_hash",
    ] {
        assert!(
            metadata.get_field_by_name(field).is_some(),
            "metadata retains {field}"
        );
    }
    let reason = pool
        .get_enum_by_name("heddle.api.v1alpha2.CodeNavigationReason")
        .expect("typed reasons");
    for name in [
        "NO_INDEX",
        "NO_RESOLVER_FOR_LANGUAGE",
        "AMBIGUOUS",
        "NOT_FOUND",
        "OUT_OF_BOUNDS",
    ] {
        assert!(
            reason
                .get_value_by_name(&format!("CODE_NAVIGATION_REASON_{name}"))
                .is_some()
        );
    }
    for name in [
        "GetFileSymbolsResponse",
        "GetSemanticRefsResponse",
        "GetSemanticImportersResponse",
    ] {
        let response = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{name}"))
            .expect("paged result");
        assert!(response.get_field_by_name("metadata").is_some());
        assert!(response.get_field_by_name("page").is_some());
    }
    let refs = pool
        .get_message_by_name("heddle.api.v1alpha2.GetSemanticRefsResponse")
        .expect("refs");
    assert!(refs.get_field_by_name("truncated").is_some());
    let definition = pool
        .get_message_by_name("heddle.api.v1alpha2.GetDefinitionResponse")
        .expect("definition");
    let outcome = definition
        .oneofs()
        .find(|oneof| oneof.name() == "outcome")
        .expect("exclusive resolved/unresolved outcome");
    assert_eq!(
        outcome
            .fields()
            .map(|field| field.name().to_owned())
            .collect::<Vec<_>>(),
        ["definition", "reason"]
    );
}

#[test]
fn client_ingestion_commits_complete_closure_and_advertises_bounds() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("compiled descriptor");
    let open = pool
        .get_message_by_name("heddle.api.v1alpha2.PublishContentOpen")
        .expect("publication");
    let manifest = open
        .get_field_by_name("semantic_indexes")
        .expect("opening binds attested closure");
    assert_eq!(manifest.number(), 8);
    assert!(manifest.is_list());
    let Kind::Message(manifest) = manifest.kind() else {
        panic!("typed manifest")
    };
    for field in ["attachment", "root_hash", "source_tree_hash", "objects"] {
        assert!(
            manifest.get_field_by_name(field).is_some(),
            "manifest retains {field}"
        );
    }
    let ready = pool
        .get_message_by_name("heddle.api.v1alpha2.TransferReady")
        .expect("transfer ready");
    assert_eq!(
        ready
            .get_field_by_name("semantic_index_limits")
            .expect("negotiated hard limits")
            .number(),
        17
    );
    let limits = pool
        .get_message_by_name("heddle.api.v1alpha2.SemanticIndexLimits")
        .expect("limits");
    for field in ["max_nodes", "max_bytes", "max_depth"] {
        assert!(limits.get_field_by_name(field).is_some());
    }
}

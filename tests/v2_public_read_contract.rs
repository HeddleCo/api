#![cfg(feature = "reflection")]
use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::v1alpha1::{AuthorizationAccess, RpcEffect, SigningTier},
};
use prost_reflect::DescriptorPool;

#[test]
fn public_resource_reads_require_proof_when_an_account_credential_is_supplied() {
    for suffix in [
        "WorkspaceService/ResolveResources",
        "WorkspaceService/ObserveCatalog",
        "IdentityService/ResolveHandles",
        "SpoolService/ObserveSpool",
        "ThreadService/ObserveThreads",
        "ThreadService/ObserveThread",
        "ContentService/ReadContent",
        "AnalysisService/ObserveAnalysis",
        "CollaborationService/ObserveCollaboration",
        "SearchService/Search",
    ] {
        let path = format!("/heddle.api.v2alpha1.{suffix}");
        let method = heddle_api::v2::method_descriptor(&path).expect("public resource method");
        assert_eq!(
            method.signing_tier,
            SigningTier::ProofIfAuthenticated,
            "{path}"
        );
        assert_eq!(
            method.authorization_access,
            AuthorizationAccess::Public,
            "{path}"
        );
        assert_eq!(
            method.effect,
            RpcEffect::ReadOnly,
            "conditional proof cannot admit writes"
        );
    }
    let workspace =
        heddle_api::v2::method_descriptor("/heddle.api.v2alpha1.WorkspaceService/ObserveWorkspace")
            .expect("account workspace");
    assert_eq!(
        workspace.authorization_access,
        AuthorizationAccess::AuthenticatedPrincipal
    );
    assert_eq!(workspace.signing_tier, SigningTier::ProofOfPossession);
}

#[test]
fn public_catalog_has_no_account_or_private_collections() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("valid descriptor");
    let event = pool
        .get_message_by_name("heddle.api.v2alpha1.CatalogEvent")
        .expect("catalog event");
    assert_eq!(
        event
            .fields()
            .map(|field| field.name().to_owned())
            .collect::<Vec<_>>(),
        ["frame", "spool", "status", "removal", "replace_section"]
    );
    let request = pool
        .get_message_by_name("heddle.api.v2alpha1.ObserveCatalogRequest")
        .expect("catalog query");
    assert_eq!(
        request
            .fields()
            .map(|field| field.name().to_owned())
            .collect::<Vec<_>>(),
        ["query", "spools", "observe"]
    );
}

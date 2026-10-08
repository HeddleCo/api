//! HeddleCo/api#388: complete discovery handed to Prepare/Commit is bounded by
//! `MAX_IMPORT_SOURCE_REFS` (weft's retained-ref cap), not the 512-ref page size.
use heddle_api::heddle::api::v1alpha2 as api;
use heddle_api::{hybrid_codec as codec, import_authority as import};
use prost::Message;
use serde_json::Value;

const REAL_REPO_REFS: usize = 600;

fn fixture() -> Value {
    serde_json::from_str(heddle_api::IMPORT_AUTHORITY_HOST_WITNESS_V1_FIXTURE_JSON)
        .expect("fixed fixture")
}

fn record<T: Message + Default>(f: &Value, name: &str) -> T {
    let v = if f["signed_vectors"][name].is_null() {
        &f["wire_vectors"][name]
    } else {
        &f["signed_vectors"][name]
    };
    let hex = v["wire_hex"].as_str().expect("hex string");
    codec::strict_decode(
        &hex::decode(hex).expect("fixed hex"),
        import::MAX_BUNDLE_BYTES,
    )
    .expect("fixed wire")
}

/// Sorted, unique tag refs that never collide with the signed branch selection.
fn with_refs(mut source: api::ProviderRepository, count: usize) -> api::ProviderRepository {
    let oid_hex = match source.hash_algorithm {
        1 => 40,
        2 => 64,
        other => panic!("fixture source must have a known algorithm, got {other}"),
    };
    source.refs = (0..count)
        .map(|i| api::ProviderRef {
            name: format!("refs/tags/v{i:05}"),
            head_oid: format!("{i:0oid_hex$x}"),
            kind: 2,
            hash_algorithm: source.hash_algorithm,
        })
        .collect();
    source
}

struct Prepare {
    request: api::PrepareImportJobRequest,
    source: api::ProviderRepository,
    configuration: api::GetImportConfigurationResponse,
    destination_version: Vec<u8>,
}

impl Prepare {
    fn new() -> Self {
        let f = fixture();
        let scope: api::ImportPermissionScopeV1 = record(&f, "scope");
        Self {
            request: record(&f, "prepare_public_sha256"),
            source: record(&f, "source_public_sha256"),
            configuration: record(&f, "import_configuration"),
            destination_version: scope.destination_version,
        }
    }

    fn run(&self, source: &api::ProviderRepository) -> Result<(), codec::Reject> {
        import::prepare_import_source_scope(
            &self.request,
            source,
            None,
            &self.configuration,
            &self.destination_version,
        )
        .map(|_| ())
    }
}

#[test]
fn prepare_accepts_a_mature_repository_with_more_refs_than_one_page() {
    let p = Prepare::new();
    p.run(&p.source).expect("fixture control");
    p.run(&with_refs(p.source.clone(), REAL_REPO_REFS))
        .expect("600 refs (rails-sized) must not hit the discovery page bound");
}

#[test]
fn prepare_accepts_exactly_the_bound_and_rejects_one_more() {
    assert_eq!(import::MAX_IMPORT_SOURCE_REFS, 4096);
    let p = Prepare::new();
    let at = with_refs(p.source.clone(), import::MAX_IMPORT_SOURCE_REFS);
    p.run(&at).expect("4096 refs accepted");
    let over = with_refs(p.source.clone(), import::MAX_IMPORT_SOURCE_REFS + 1);
    assert_eq!(p.run(&over), Err(codec::Reject::Bounds));
    let scope = p.request.proposed_scope.as_ref().expect("scope");
    assert_eq!(
        import::validate_discovered_import_scope(scope, &over),
        Err(codec::Reject::Bounds)
    );
}

#[test]
fn complete_discovery_still_rejects_unsorted_and_duplicate_refs() {
    let p = Prepare::new();
    let mut unsorted = with_refs(p.source.clone(), import::MAX_IMPORT_SOURCE_REFS);
    unsorted.refs.swap(100, 101);
    assert_eq!(p.run(&unsorted), Err(codec::Reject::Canonical));
    let mut duplicate = with_refs(p.source.clone(), import::MAX_IMPORT_SOURCE_REFS);
    duplicate.refs[101].name = duplicate.refs[100].name.clone();
    assert_eq!(p.run(&duplicate), Err(codec::Reject::Canonical));
}

#[test]
fn every_discovered_ref_name_is_bounded_like_a_signed_ref() {
    let p = Prepare::new();
    let mut source = with_refs(p.source.clone(), REAL_REPO_REFS);
    let last = source.refs.last_mut().expect("refs");
    last.name = format!("refs/tags/{}", "z".repeat(import::MAX_REF_BYTES - 10));
    assert_eq!(last.name.len(), import::MAX_REF_BYTES);
    p.run(&source)
        .expect("a ref name at MAX_REF_BYTES is accepted");
    source.refs.last_mut().expect("refs").name.push('z');
    assert_eq!(p.run(&source), Err(codec::Reject::Bounds));
}

#[test]
fn resolve_page_keeps_its_512_ref_page_bound() {
    assert_eq!(import::MAX_IMPORT_SOURCE_REF_PAGE, 512);
    let source: api::ProviderRepository = record(&fixture(), "source_public_sha256");
    let page = with_refs(source.clone(), import::MAX_IMPORT_SOURCE_REF_PAGE);
    import::validate_repository_hash_algorithm(&page, true).expect("full page accepted");
    let over = with_refs(source, import::MAX_IMPORT_SOURCE_REF_PAGE + 1);
    assert_eq!(
        import::validate_repository_hash_algorithm(&over, true),
        Err(codec::Reject::Bounds)
    );
    let request = api::ResolveImportSourceRequest {
        source: Some(api::ProviderRepository {
            clone_url: page.clone_url.clone(),
            provider_repository_id: page.provider_repository_id.clone(),
            ..Default::default()
        }),
        include_refs: true,
        page: None,
    };
    let response = |source| api::ResolveImportSourceResponse {
        source: Some(source),
    };
    import::validate_resolve_import_source_response(&request, &response(page), None)
        .expect("512-ref page accepted");
    assert_eq!(
        import::validate_resolve_import_source_response(&request, &response(over), None),
        Err(codec::Reject::Bounds)
    );
}

#[test]
fn commit_accepts_complete_discovery_up_to_the_bound() {
    let f = fixture();
    let request: api::CommitImportJobRequest = record(&f, "commit_request");
    let source: api::ProviderRepository = record(&f, "source_connected");
    let configuration: api::GetImportConfigurationResponse = record(&f, "import_configuration");
    let commit = |current: &api::ProviderRepository| {
        import::validate_commit_request(&request, "github", current, &configuration)
    };
    commit(&source).expect("fixture control");
    commit(&with_refs(source.clone(), REAL_REPO_REFS)).expect("600 refs accepted");
    commit(&with_refs(source.clone(), import::MAX_IMPORT_SOURCE_REFS)).expect("4096 accepted");
    assert_eq!(
        commit(&with_refs(source, import::MAX_IMPORT_SOURCE_REFS + 1)),
        Err(codec::Reject::Bounds)
    );
}

use heddle_api::heddle::api::v1alpha2 as api;
use prost::Message;

fn vector(name: &str) -> Vec<u8> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/code-navigation-v2.json"))
            .expect("shared Rust/TypeScript vectors");
    hex::decode(fixture[name].as_str().expect("wire vector")).expect("wire hex")
}

fn decode<T: Message + Default>(name: &str) -> T {
    let bytes = vector(name);
    let result = T::decode(bytes.as_slice()).expect("shared vector decodes");
    assert_eq!(result.encode_to_vec(), bytes, "stable {name} wire");
    result
}

#[test]
fn navigation_preserves_provenance_unresolved_occurrences_and_position_presence() {
    let outline: api::GetFileSymbolsResponse = decode("outline");
    let metadata = outline.metadata.expect("readiness");
    assert!(metadata.index_present);
    assert_eq!(
        metadata.attestation,
        api::SemanticAttestation::ClientAttested as i32
    );
    let symbol = &outline.symbols[0];
    assert_eq!(
        symbol
            .address
            .as_ref()
            .expect("symbol address")
            .definition_index,
        Some(0)
    );
    assert_eq!(symbol.span.as_ref().expect("line span").start_byte, None);
    assert_eq!(symbol.semantic_hash.len(), 32);
    let definition: api::GetDefinitionResponse = decode("definition");
    assert_eq!(
        definition.outcome,
        Some(api::get_definition_response::Outcome::Definition(
            symbol.clone()
        ))
    );
    let unresolved: api::GetDefinitionResponse = decode("unresolved");
    assert_eq!(unresolved.occurrence, definition.occurrence);
    let readiness = unresolved.metadata.expect("language readiness");
    assert!(!readiness.resolver_present);
    assert_eq!(readiness.language, "python");
    assert_eq!(
        readiness.attestation,
        api::SemanticAttestation::ClientAttested as i32
    );
    assert_eq!(
        unresolved.outcome,
        Some(api::get_definition_response::Outcome::Reason(
            api::CodeNavigationReason::NoResolverForLanguage as i32
        ))
    );
    let query: api::GetDefinitionRequest = decode("position");
    let position = query
        .at
        .expect("file position")
        .position
        .expect("byte position");
    assert_eq!(
        (position.byte_offset, position.line, position.column),
        (Some(0), Some(1), Some(1))
    );
    assert_eq!(api::CodePosition::default().byte_offset, None);
    let absent: api::GetFileSymbolsResponse = decode("no_index");
    let readiness = absent.metadata.expect("no-index metadata");
    assert!(!readiness.index_present);
    assert_eq!(
        readiness.attestation,
        api::SemanticAttestation::Unspecified as i32
    );
    assert_eq!(absent.reason, api::CodeNavigationReason::NoIndex as i32);
    assert!(!absent.page.expect("unavailable collection").exhausted);
}

#[test]
fn graph_preserves_edge_direction_hops_and_independent_pagination() {
    let refs: api::GetSemanticRefsResponse = decode("refs");
    let edge = &refs.refs[0];
    assert_eq!(edge.kind, api::CodeEdgeKind::Calls as i32);
    assert_eq!(
        edge.source.as_ref().expect("caller occurrence").path,
        "src/main.rs"
    );
    assert_eq!(
        edge.target
            .as_ref()
            .expect("target definition")
            .address
            .as_ref()
            .expect("target address")
            .path,
        "src/lib.rs"
    );
    assert_eq!(edge.hop, 1);
    assert!(refs.truncated);
    let page = refs.page.expect("bounded page");
    assert!(!page.exhausted);
    assert_eq!(page.next_page, [9, 10]);
    let importers: api::GetSemanticImportersResponse = decode("importers");
    assert_eq!(importers.importers[0].path, "src/main.rs");
    assert_eq!(importers.importers[0].hop, 1);
    assert!(!importers.truncated);
    assert!(importers.page.expect("complete importers").exhausted);
}

// Faithful old reader of the fields populated by the publication vector. It
// cannot ingest a manifest, but still understands exact source ownership.
#[derive(Clone, PartialEq, Message)]
struct SourceOnlyPublication {
    #[prost(message, optional, tag = "1")]
    thread: Option<api::ThreadRef>,
    #[prost(message, optional, tag = "2")]
    revision: Option<api::RevisionRef>,
}

#[test]
fn ingestion_preserves_manifest_bounds_fetch_opt_in_and_older_source_readers() {
    let open: api::PublishContentOpen = decode("publication");
    let ready: api::TransferReady = decode("ready");
    assert_eq!(ready.semantic_indexes, open.semantic_indexes);
    let index = &open.semantic_indexes[0];
    assert_eq!(
        index
            .attachment
            .as_ref()
            .expect("native attachment")
            .algorithm,
        "state-attachment"
    );
    assert_eq!(index.source_tree_hash.len(), 32);
    assert_eq!(index.objects.len(), 2);
    assert_eq!(index.root_hash, index.objects[0].hash);
    assert_eq!(
        index
            .objects
            .iter()
            .map(|object| object.size)
            .collect::<Vec<_>>(),
        [20, 30]
    );
    let limits = ready
        .semantic_index_limits
        .expect("explicit supported ingestion");
    assert_eq!(
        (limits.max_nodes, limits.max_bytes, limits.max_depth),
        (100000, 67108864, 64)
    );
    assert!(
        api::TransferReady::default()
            .semantic_index_limits
            .is_none()
    );
    assert!(
        api::PublishContentOpen::default()
            .semantic_indexes
            .is_empty()
    );
    assert!(decode::<api::TransferSelection>("fetch").include_semantic_index);
    assert!(!api::TransferSelection::default().include_semantic_index);
    let old =
        SourceOnlyPublication::decode(vector("publication").as_slice()).expect("old source reader");
    assert_eq!(old.thread, open.thread);
    assert_eq!(old.revision, open.revision);
    let upgraded =
        api::PublishContentOpen::decode(old.encode_to_vec().as_slice()).expect("old reader output");
    assert!(upgraded.semantic_indexes.is_empty());
    assert_eq!(upgraded.thread, open.thread);
}

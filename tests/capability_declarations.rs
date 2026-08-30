// SPDX-License-Identifier: Apache-2.0
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use prost_reflect::DescriptorPool;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const API_PACKAGE: &str = "heddle.api.v1alpha1";
const CONSUMERS: [(&str, [&str; 2]); 3] = [
    ("heddle", ["client", "cli"]),
    ("tapestry", ["server_adapter", "ui"]),
    ("weft", ["implementation", "registration"]),
];
const DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/heddle_api_descriptor.bin"));

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    schema_version: u64,
    consumer: String,
    rpc_mappings: Vec<RpcMapping>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcMapping {
    rpc: String,
    layers: BTreeMap<String, Layer>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Layer {
    #[serde(rename = "status")]
    _status: Status,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Status {
    Shipped,
    Partial,
    Planned,
    IntentionallyUnsupported,
    Blocked,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sources {
    schema_version: u64,
    attestations: BTreeMap<String, Attestation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attestation {
    kind: String,
    snapshot: String,
    sha256: String,
}

/// Proves the descriptor/declaration structural audit can run entirely in `cargo test`.
///
/// Follow-up (tapestry#468): run the reverse understatement check in a workspace with
/// each consumer's source available, and fail when a row marked other than `shipped`
/// has a discoverable call edge. The API crate alone cannot inspect those call sites.
#[test]
fn capability_declarations_match_compiled_descriptor() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let declaration_dir = root.join("capabilities/declarations");
    let descriptor_rpcs = descriptor_rpcs();

    assert!(
        !descriptor_rpcs.is_empty(),
        "compiled descriptor contains no RPCs in {API_PACKAGE}"
    );

    for (consumer, expected_layers) in CONSUMERS {
        audit_declaration(
            &declaration_dir.join(format!("{consumer}.json")),
            consumer,
            &expected_layers.into_iter().collect(),
            &descriptor_rpcs,
        );
    }

    audit_attestations(&root, &declaration_dir);
}

fn descriptor_rpcs() -> BTreeSet<String> {
    let pool = DescriptorPool::decode(DESCRIPTOR_SET).expect("decode compiled descriptor set");
    pool.services()
        .filter(|service| service.package_name() == API_PACKAGE)
        .flat_map(|service| {
            let service_name = service.full_name().to_owned();
            service
                .methods()
                .map(move |method| format!("{service_name}/{}", method.name()))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn audit_declaration(
    path: &Path,
    consumer: &str,
    expected_layers: &BTreeSet<&str>,
    descriptor_rpcs: &BTreeSet<String>,
) {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let declaration: Declaration = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));

    assert_eq!(
        declaration.schema_version, 2,
        "unsupported declaration schema for {consumer}"
    );
    assert_eq!(
        declaration.consumer, consumer,
        "consumer name mismatch for {consumer}"
    );

    let mut declared_rpcs = BTreeSet::new();
    for row in declaration.rpc_mappings {
        assert!(
            descriptor_rpcs.contains(&row.rpc),
            "nonexistent RPC declared by {consumer}: {}",
            row.rpc
        );
        assert!(
            declared_rpcs.insert(row.rpc.clone()),
            "duplicate mapping for {consumer}: {}",
            row.rpc
        );

        let actual_layers: BTreeSet<_> = row.layers.keys().map(String::as_str).collect();
        assert_eq!(
            &actual_layers, expected_layers,
            "layer set mismatch for {consumer}: {}",
            row.rpc
        );
    }

    let missing: Vec<_> = descriptor_rpcs.difference(&declared_rpcs).collect();
    assert!(
        missing.is_empty(),
        "missing descriptor RPC in {consumer}: {}",
        missing
            .into_iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn audit_attestations(root: &Path, declaration_dir: &Path) {
    let path = root.join("capabilities/sources.json");
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let sources: Sources = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));

    assert_eq!(sources.schema_version, 2, "unsupported provenance schema");
    let expected_consumers: BTreeSet<_> = CONSUMERS.iter().map(|(name, _)| *name).collect();
    let actual_consumers: BTreeSet<_> = sources.attestations.keys().map(String::as_str).collect();
    assert_eq!(
        actual_consumers, expected_consumers,
        "provenance consumer set mismatch"
    );

    for (consumer, _) in CONSUMERS {
        let attestation = &sources.attestations[consumer];
        let snapshot = format!("capabilities/declarations/{consumer}.json");
        assert_eq!(
            attestation.kind, "consumer-derived-sanitized-declaration",
            "public attestation kind mismatch for {consumer}"
        );
        assert_eq!(
            attestation.snapshot, snapshot,
            "public attestation snapshot mismatch for {consumer}"
        );

        let declaration = declaration_dir.join(format!("{consumer}.json"));
        let declaration_bytes = fs::read(&declaration)
            .unwrap_or_else(|error| panic!("read {}: {error}", declaration.display()));
        let actual_sha = hex::encode(Sha256::digest(declaration_bytes));
        assert_eq!(
            attestation.sha256, actual_sha,
            "attested content hash mismatch for {consumer}"
        );
    }
}

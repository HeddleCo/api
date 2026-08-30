use heddle_api::{
    heddle::api::v1alpha1::{
        TreadleArgv, TreadleCheck, TreadleCheckClass, TreadleDefinition, TreadleDeterminismClass,
        TreadleEnvEntry, TreadleIsolationHints, TreadleJob, TreadleMatrixValue,
        TreadleNetworkAccess, TreadlePlatform, TreadleRetry, TreadleSecretRef, TreadleSecretTier,
        TreadleServiceContainer, TreadleTargetEnvironment, TreadleTrigger, TreadleTriggerKind,
        treadle_env_entry,
    },
    treadle::{
        TreadleDefinitionError, canonical_treadle_definition_bytes,
        decode_canonical_treadle_definition, treadle_definition_blake3,
    },
};
use prost::Message;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    producer: String,
    canonical_hex: String,
    blake3_hex: String,
}

fn literal_env(name: &str, value: &str) -> TreadleEnvEntry {
    TreadleEnvEntry {
        name: name.into(),
        source: Some(treadle_env_entry::Source::LiteralValue(value.into())),
    }
}

fn secret_env(name: &str, secret_ref: &str) -> TreadleEnvEntry {
    TreadleEnvEntry {
        name: name.into(),
        source: Some(treadle_env_entry::Source::SecretRef(secret_ref.into())),
    }
}

fn trigger(kind: TreadleTriggerKind, cron_expression: &str) -> TreadleTrigger {
    TreadleTrigger {
        kind: kind as i32,
        cron_expression: cron_expression.into(),
    }
}

fn retry(max_retries: u32, flake_signatures: &[&str]) -> Option<TreadleRetry> {
    Some(TreadleRetry {
        max_retries,
        flake_signatures: flake_signatures
            .iter()
            .map(|value| (*value).into())
            .collect(),
    })
}

fn isolation(
    network_access: TreadleNetworkAccess,
    profile: &str,
    cpu_millis: u32,
    memory_bytes: u64,
    process_limit: u32,
) -> Option<TreadleIsolationHints> {
    Some(TreadleIsolationHints {
        profile: profile.into(),
        network_access: network_access as i32,
        cpu_millis,
        memory_bytes,
        process_limit,
    })
}

fn sha256_digest(hex_digit: char) -> String {
    format!("sha256:{}", hex_digit.to_string().repeat(64))
}

fn target_environment(hex_digit: char, os: &str, arch: &str) -> Option<TreadleTargetEnvironment> {
    Some(TreadleTargetEnvironment {
        oci_image_digest: sha256_digest(hex_digit),
        platform: Some(TreadlePlatform {
            os: os.into(),
            arch: arch.into(),
        }),
    })
}

// This is the same logical definition as tools/verify-treadle-conformance.mjs,
// independently built with the generated prost types and intentionally unordered.
fn rust_definition() -> TreadleDefinition {
    TreadleDefinition {
        format_version: 1,
        name: "heddle-ci".into(),
        secret_refs: vec![
            TreadleSecretRef {
                name: "registry-token".into(),
                provider: "vault".into(),
                tier: TreadleSecretTier::TrustedRunnerOnly as i32,
            },
            TreadleSecretRef {
                name: "db-password".into(),
                provider: String::new(),
                tier: TreadleSecretTier::Standard as i32,
            },
        ],
        services: vec![TreadleServiceContainer {
            name: "postgres".into(),
            image: "postgres:16".into(),
            ports: vec![5433, 5432],
            env: vec![
                literal_env("POSTGRES_DB", "treadle"),
                secret_env("POSTGRES_PASSWORD", "db-password"),
            ],
            readiness: Some(TreadleArgv {
                command: "pg_isready".into(),
                args: vec!["-U".into(), "treadle".into()],
            }),
            oci_image_digest: sha256_digest('4'),
        }],
        jobs: vec![
            TreadleJob {
                name: "test-linux".into(),
                matrix: vec![
                    TreadleMatrixValue {
                        name: "toolchain".into(),
                        value: "stable".into(),
                    },
                    TreadleMatrixValue {
                        name: "target".into(),
                        value: "x86_64-unknown-linux-gnu".into(),
                    },
                ],
                checks: vec![
                    TreadleCheck {
                        name: "unit".into(),
                        command: "cargo".into(),
                        args: vec!["test".into(), "--locked".into()],
                        class: TreadleCheckClass::Required as i32,
                        timeout_seconds: 1800,
                        env: vec![
                            secret_env("REGISTRY_TOKEN", "registry-token"),
                            literal_env("RUST_LOG", "info"),
                            literal_env("CARGO_TERM_COLOR", "always"),
                        ],
                        working_directory: String::new(),
                        service_dependencies: vec!["postgres".into()],
                        retry: retry(2, &["connection reset", "timed out"]),
                        cache_paths: vec!["target/debug".into(), "target".into()],
                        isolation: isolation(
                            TreadleNetworkAccess::ServicesOnly,
                            "linux-medium",
                            2000,
                            4_294_967_296,
                            256,
                        ),
                        triggers: vec![
                            trigger(TreadleTriggerKind::Manual, ""),
                            trigger(TreadleTriggerKind::Cron, "0 3 * * 1"),
                            trigger(TreadleTriggerKind::Push, ""),
                        ],
                        supersede_older_runs: true,
                        target_environment: target_environment('1', "linux", "amd64"),
                        determinism_class: TreadleDeterminismClass::Deterministic as i32,
                    },
                    TreadleCheck {
                        name: "lint".into(),
                        command: "cargo".into(),
                        args: vec!["clippy".into(), "--".into(), "-D".into(), "warnings".into()],
                        class: TreadleCheckClass::Advisory as i32,
                        timeout_seconds: 900,
                        working_directory: "crates/core".into(),
                        retry: retry(0, &[]),
                        isolation: isolation(TreadleNetworkAccess::None, "", 0, 0, 0),
                        triggers: vec![trigger(TreadleTriggerKind::Push, "")],
                        target_environment: target_environment('2', "linux", "arm64"),
                        determinism_class: TreadleDeterminismClass::Deterministic as i32,
                        ..Default::default()
                    },
                ],
            },
            TreadleJob {
                name: "docs".into(),
                checks: vec![TreadleCheck {
                    name: "build".into(),
                    command: "npm".into(),
                    args: vec!["run".into(), "docs".into()],
                    class: TreadleCheckClass::Informational as i32,
                    timeout_seconds: 600,
                    working_directory: "docs".into(),
                    retry: retry(0, &[]),
                    isolation: isolation(TreadleNetworkAccess::Full, "", 0, 0, 0),
                    triggers: vec![trigger(TreadleTriggerKind::Manual, "")],
                    supersede_older_runs: true,
                    target_environment: target_environment('3', "linux", "amd64"),
                    determinism_class: TreadleDeterminismClass::Nondeterministic as i32,
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
    }
}

#[test]
fn rust_and_typescript_canonical_bytes_and_blake3_are_identical() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/treadle-definition-v1.json"))
            .expect("valid treadle fixture");
    assert!(fixture.producer.contains("TypeScript"));

    let definition = rust_definition();
    let canonical = canonical_treadle_definition_bytes(&definition).expect("canonical definition");
    assert_eq!(hex::encode(&canonical), fixture.canonical_hex);
    assert_eq!(
        hex::encode(treadle_definition_blake3(&definition).expect("treadle BLAKE3")),
        fixture.blake3_hex
    );
    assert_eq!(
        decode_canonical_treadle_definition(&canonical).expect("canonical decode"),
        TreadleDefinition::decode(canonical.as_slice()).expect("protobuf decode")
    );
}

#[test]
fn reader_fails_closed_on_old_and_noncanonical_definitions() {
    let mut old = rust_definition();
    old.format_version = 0;
    assert!(matches!(
        canonical_treadle_definition_bytes(&old),
        Err(TreadleDefinitionError::UnsupportedVersion { .. })
    ));

    let raw_unordered = rust_definition().encode_to_vec();
    assert!(matches!(
        decode_canonical_treadle_definition(&raw_unordered),
        Err(TreadleDefinitionError::NonCanonicalBytes)
    ));
}

#[test]
fn missing_target_environment_or_platform_fails_validation_and_decode() {
    let mut missing_environment = rust_definition();
    missing_environment.jobs[0].checks[0].target_environment = None;
    assert!(matches!(
        canonical_treadle_definition_bytes(&missing_environment),
        Err(TreadleDefinitionError::Invalid(message))
            if message.contains("omits target_environment")
    ));
    assert!(matches!(
        decode_canonical_treadle_definition(&missing_environment.encode_to_vec()),
        Err(TreadleDefinitionError::Invalid(message))
            if message.contains("omits target_environment")
    ));

    let mut missing_platform = rust_definition();
    missing_platform.jobs[0].checks[0]
        .target_environment
        .as_mut()
        .expect("fixture target environment")
        .platform = None;
    assert!(matches!(
        canonical_treadle_definition_bytes(&missing_platform),
        Err(TreadleDefinitionError::Invalid(message))
            if message.contains("omits target_environment.platform")
    ));
    assert!(matches!(
        decode_canonical_treadle_definition(&missing_platform.encode_to_vec()),
        Err(TreadleDefinitionError::Invalid(message))
            if message.contains("omits target_environment.platform")
    ));
}

#[derive(Deserialize)]
struct LockFile {
    format_version: u32,
    definition_digest: String,
}

// linux/amd64 compile of packages/typescript/examples/local-host.mjs
// (host-exec dummy digest). verify-treadle-conformance.mjs recompiles on
// linux/x64 and byte-compares this fixture.
#[test]
fn compiled_local_host_example_is_canonical_and_matches_lock() {
    let bytes = include_bytes!("fixtures/treadle-local-host.definition.bin");
    let lock: LockFile =
        serde_json::from_str(include_str!("fixtures/treadle-local-host.lock.json"))
            .expect("valid local-host lock");
    let decoded =
        decode_canonical_treadle_definition(bytes).expect("canonical compiled definition");
    assert_eq!(decoded.format_version, 1);
    assert_eq!(decoded.name, "local-host");
    assert_eq!(lock.format_version, 1);
    assert_eq!(
        hex::encode(treadle_definition_blake3(&decoded).expect("compiled blake3")),
        lock.definition_digest
    );
    let job_names: Vec<&str> = decoded.jobs.iter().map(|job| job.name.as_str()).collect();
    assert_eq!(job_names, ["also", "fast"]);
    let check_names: Vec<Vec<&str>> = decoded
        .jobs
        .iter()
        .map(|job| job.checks.iter().map(|check| check.name.as_str()).collect())
        .collect();
    assert_eq!(
        check_names,
        [vec!["pwd-check"], vec!["echo-ok", "true-check"]]
    );
    for check in decoded.jobs.iter().flat_map(|job| job.checks.iter()) {
        assert_eq!(check.command, "sh");
        let environment = check
            .target_environment
            .as_ref()
            .expect("compiled check target_environment");
        let platform = environment
            .platform
            .as_ref()
            .expect("compiled check platform");
        assert!(matches!(
            platform.os.as_str(),
            "darwin" | "linux" | "windows"
        ));
        assert!(matches!(platform.arch.as_str(), "amd64" | "arm64"));
    }
}

#[test]
fn reordered_set_like_fields_canonicalize_to_identical_bytes() {
    let definition = rust_definition();
    let mut reordered = definition.clone();
    reordered.jobs.reverse();
    reordered.services.reverse();
    reordered.secret_refs.reverse();
    for job in &mut reordered.jobs {
        job.matrix.reverse();
        job.checks.reverse();
        for check in &mut job.checks {
            check.env.reverse();
            check.service_dependencies.reverse();
            check
                .retry
                .as_mut()
                .expect("fixture retry")
                .flake_signatures
                .reverse();
            check.cache_paths.reverse();
            check.triggers.reverse();
        }
    }
    for service in &mut reordered.services {
        service.ports.reverse();
        service.env.reverse();
    }

    assert_eq!(
        canonical_treadle_definition_bytes(&definition).expect("canonical definition"),
        canonical_treadle_definition_bytes(&reordered).expect("canonical reordered definition")
    );
}

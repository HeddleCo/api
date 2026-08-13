// SPDX-License-Identifier: Apache-2.0
//! Canonical encoding for the signed treadle definition contract.

use std::collections::BTreeSet;

use prost::Message;
use thiserror::Error;

use crate::heddle::api::v1alpha1::{
    TreadleCheck, TreadleCheckClass, TreadleDefinition, TreadleEnvEntry, TreadleJob,
    TreadleNetworkAccess, TreadleServiceContainer, TreadleTrigger, TreadleTriggerKind,
    treadle_env_entry,
};

/// The only treadle definition format accepted by this release.
pub const TREADLE_DEFINITION_FORMAT_VERSION: u32 = 1;

/// Canonical treadle definition validation/decoding errors.
#[derive(Debug, Error)]
pub enum TreadleDefinitionError {
    #[error(
        "unsupported treadle definition format version {actual}; migrate to version {expected} before reading"
    )]
    UnsupportedVersion { actual: u32, expected: u32 },
    #[error("invalid treadle definition: {0}")]
    Invalid(String),
    #[error("invalid treadle protobuf: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("treadle definition bytes are not canonical")]
    NonCanonicalBytes,
}

/// Validate, normalize, and encode a definition using the v1 canonical wire rule.
pub fn canonical_treadle_definition_bytes(
    definition: &TreadleDefinition,
) -> Result<Vec<u8>, TreadleDefinitionError> {
    let normalized = canonical_treadle_definition(definition)?;
    Ok(normalized.encode_to_vec())
}

/// Return the BLAKE3 content address of the v1 canonical protobuf bytes.
pub fn treadle_definition_blake3(
    definition: &TreadleDefinition,
) -> Result<[u8; 32], TreadleDefinitionError> {
    Ok(*blake3::hash(&canonical_treadle_definition_bytes(definition)?).as_bytes())
}

/// Decode only a byte-exact canonical current-version definition.
///
/// This rejects alternate protobuf encodings, unknown fields, unsorted repeated
/// sets, invalid definitions, and old/future versions. Migration is a separate,
/// explicit operation; this reader never provides a dual-read fallback.
pub fn decode_canonical_treadle_definition(
    bytes: &[u8],
) -> Result<TreadleDefinition, TreadleDefinitionError> {
    let decoded = TreadleDefinition::decode(bytes)?;
    let normalized = canonical_treadle_definition(&decoded)?;
    if normalized.encode_to_vec() != bytes {
        return Err(TreadleDefinitionError::NonCanonicalBytes);
    }
    Ok(normalized)
}

fn canonical_treadle_definition(
    definition: &TreadleDefinition,
) -> Result<TreadleDefinition, TreadleDefinitionError> {
    if definition.format_version != TREADLE_DEFINITION_FORMAT_VERSION {
        return Err(TreadleDefinitionError::UnsupportedVersion {
            actual: definition.format_version,
            expected: TREADLE_DEFINITION_FORMAT_VERSION,
        });
    }
    non_empty("pipeline name", &definition.name)?;

    let mut normalized = definition.clone();
    normalized
        .secret_refs
        .sort_by(|left, right| left.name.cmp(&right.name));
    normalized
        .services
        .sort_by(|left, right| left.name.cmp(&right.name));
    normalized
        .jobs
        .sort_by(|left, right| left.name.cmp(&right.name));
    if normalized.jobs.is_empty() {
        return invalid("pipeline has no jobs".into());
    }

    let secret_names = unique_named(
        "secret declaration",
        normalized
            .secret_refs
            .iter()
            .map(|secret| secret.name.as_str()),
    )?;
    for secret in &normalized.secret_refs {
        identifier("secret", &secret.name)?;
        no_nul("secret provider", &secret.provider)?;
    }

    let service_names = unique_named(
        "service",
        normalized
            .services
            .iter()
            .map(|service| service.name.as_str()),
    )?;
    for service in &mut normalized.services {
        normalize_service(service, &secret_names)?;
    }

    unique_named("job", normalized.jobs.iter().map(|job| job.name.as_str()))?;
    for job in &mut normalized.jobs {
        normalize_job(job, &service_names, &secret_names)?;
    }

    Ok(normalized)
}

fn normalize_job(
    job: &mut TreadleJob,
    service_names: &BTreeSet<String>,
    secret_names: &BTreeSet<String>,
) -> Result<(), TreadleDefinitionError> {
    identifier("job", &job.name)?;
    job.matrix.sort_by(|left, right| left.name.cmp(&right.name));
    unique_named(
        "matrix dimension",
        job.matrix.iter().map(|value| value.name.as_str()),
    )?;
    for value in &job.matrix {
        identifier("matrix dimension", &value.name)?;
        no_nul("matrix value", &value.value)?;
        if value.value.contains("${") || value.value.contains("{{") {
            return invalid(format!(
                "job {:?} matrix value {:?} looks unresolved",
                job.name, value.value
            ));
        }
    }

    job.checks.sort_by(|left, right| left.name.cmp(&right.name));
    unique_named("check", job.checks.iter().map(|check| check.name.as_str()))?;
    if job.checks.is_empty() {
        return invalid(format!("job {:?} has no checks", job.name));
    }
    for check in &mut job.checks {
        normalize_check(check, service_names, secret_names)?;
    }
    Ok(())
}

fn normalize_check(
    check: &mut TreadleCheck,
    service_names: &BTreeSet<String>,
    secret_names: &BTreeSet<String>,
) -> Result<(), TreadleDefinitionError> {
    identifier("check", &check.name)?;
    non_empty("check command", &check.command)?;
    for arg in &check.args {
        no_nul("check argument", arg)?;
    }
    match TreadleCheckClass::try_from(check.class) {
        Ok(
            TreadleCheckClass::Required
            | TreadleCheckClass::Advisory
            | TreadleCheckClass::Informational,
        ) => {}
        _ => return invalid(format!("check {:?} has an invalid class", check.name)),
    }
    if check.timeout_seconds == 0 {
        return invalid(format!(
            "check {:?} timeout_seconds must be positive",
            check.name
        ));
    }
    normalize_env(&mut check.env, secret_names)?;
    relative_path("working_directory", &check.working_directory, true)?;

    check.service_dependencies.sort();
    unique_strings("service dependency", &check.service_dependencies)?;
    for dependency in &check.service_dependencies {
        if !service_names.contains(dependency) {
            return invalid(format!(
                "check {:?} references undeclared service {:?}",
                check.name, dependency
            ));
        }
    }

    let retry = check.retry.as_mut().ok_or_else(|| {
        TreadleDefinitionError::Invalid(format!("check {:?} omits retry", check.name))
    })?;
    retry.flake_signatures.sort();
    unique_strings("flake signature", &retry.flake_signatures)?;
    for signature in &retry.flake_signatures {
        non_empty("flake signature", signature)?;
    }

    check.cache_paths.sort();
    unique_strings("cache path", &check.cache_paths)?;
    for path in &check.cache_paths {
        relative_path("cache path", path, false)?;
    }

    let isolation = check.isolation.as_ref().ok_or_else(|| {
        TreadleDefinitionError::Invalid(format!("check {:?} omits isolation", check.name))
    })?;
    no_nul("isolation profile", &isolation.profile)?;
    if TreadleNetworkAccess::try_from(isolation.network_access).is_err() {
        return invalid(format!("check {:?} has invalid network_access", check.name));
    }

    check.triggers.sort_by(|left, right| {
        (left.kind, left.cron_expression.as_str())
            .cmp(&(right.kind, right.cron_expression.as_str()))
    });
    if check.triggers.is_empty() {
        return invalid(format!("check {:?} has no triggers", check.name));
    }
    let mut trigger_keys = BTreeSet::new();
    for trigger in &check.triggers {
        validate_trigger(check, trigger)?;
        if !trigger_keys.insert((trigger.kind, trigger.cron_expression.clone())) {
            return invalid(format!("check {:?} has a duplicate trigger", check.name));
        }
    }
    Ok(())
}

fn validate_trigger(
    check: &TreadleCheck,
    trigger: &TreadleTrigger,
) -> Result<(), TreadleDefinitionError> {
    match TreadleTriggerKind::try_from(trigger.kind) {
        Ok(TreadleTriggerKind::Push | TreadleTriggerKind::Manual)
            if trigger.cron_expression.is_empty() =>
        {
            Ok(())
        }
        Ok(TreadleTriggerKind::Cron) if valid_cron(&trigger.cron_expression) => Ok(()),
        _ => invalid(format!("check {:?} has an invalid trigger", check.name)),
    }
}

fn normalize_service(
    service: &mut TreadleServiceContainer,
    secret_names: &BTreeSet<String>,
) -> Result<(), TreadleDefinitionError> {
    identifier("service", &service.name)?;
    non_empty("service image", &service.image)?;
    service.ports.sort_unstable();
    if service
        .ports
        .iter()
        .any(|port| *port == 0 || *port > u16::MAX.into())
    {
        return invalid(format!("service {:?} has an invalid port", service.name));
    }
    if service.ports.windows(2).any(|pair| pair[0] == pair[1]) {
        return invalid(format!("service {:?} has a duplicate port", service.name));
    }
    normalize_env(&mut service.env, secret_names)?;
    if let Some(readiness) = &service.readiness {
        non_empty("service readiness command", &readiness.command)?;
        for arg in &readiness.args {
            no_nul("service readiness argument", arg)?;
        }
    }
    Ok(())
}

fn normalize_env(
    env: &mut [TreadleEnvEntry],
    secret_names: &BTreeSet<String>,
) -> Result<(), TreadleDefinitionError> {
    env.sort_by(|left, right| left.name.cmp(&right.name));
    unique_named(
        "environment entry",
        env.iter().map(|entry| entry.name.as_str()),
    )?;
    for entry in env {
        non_empty("environment name", &entry.name)?;
        match entry.source.as_ref() {
            Some(treadle_env_entry::Source::LiteralValue(value)) => {
                no_nul("environment literal", value)?;
            }
            Some(treadle_env_entry::Source::SecretRef(name)) if secret_names.contains(name) => {}
            Some(treadle_env_entry::Source::SecretRef(name)) => {
                return invalid(format!("environment references undeclared secret {name:?}"));
            }
            None => return invalid(format!("environment {:?} has no source", entry.name)),
        }
    }
    Ok(())
}

fn unique_named<'a>(
    kind: &str,
    names: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<String>, TreadleDefinitionError> {
    let mut seen = BTreeSet::new();
    for name in names {
        if !seen.insert(name.to_owned()) {
            return invalid(format!("duplicate {kind} name {name:?}"));
        }
    }
    Ok(seen)
}

fn unique_strings(kind: &str, values: &[String]) -> Result<(), TreadleDefinitionError> {
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return invalid(format!("duplicate {kind}"));
    }
    Ok(())
}

fn identifier(kind: &str, value: &str) -> Result<(), TreadleDefinitionError> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:-".contains(&byte)
        })
    {
        return invalid(format!("{kind} name {value:?} must match [a-z0-9._:-]+"));
    }
    Ok(())
}

fn non_empty(kind: &str, value: &str) -> Result<(), TreadleDefinitionError> {
    if value.is_empty() {
        return invalid(format!("{kind} must not be empty"));
    }
    no_nul(kind, value)
}

fn no_nul(kind: &str, value: &str) -> Result<(), TreadleDefinitionError> {
    if value.contains('\0') {
        return invalid(format!("{kind} must not contain NUL"));
    }
    Ok(())
}

fn relative_path(kind: &str, value: &str, allow_empty: bool) -> Result<(), TreadleDefinitionError> {
    if value.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            invalid(format!("{kind} must not be empty"))
        };
    }
    if value.starts_with('/')
        || value.contains('\\')
        || value.as_bytes().get(1) == Some(&b':')
        || value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return invalid(format!(
            "{kind} {value:?} must be a normalized repository-relative path"
        ));
    }
    no_nul(kind, value)
}

fn valid_cron(value: &str) -> bool {
    let fields = value.split(' ').collect::<Vec<_>>();
    fields.len() == 5
        && fields.iter().all(|field| {
            !field.is_empty()
                && field
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || b"*,-/".contains(&byte))
        })
}

fn invalid<T>(message: String) -> Result<T, TreadleDefinitionError> {
    Err(TreadleDefinitionError::Invalid(message))
}

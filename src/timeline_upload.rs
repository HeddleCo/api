//! Shared bounds for the hosted v1 timeline input projection.
//! Servers must also reject unknown protobuf fields before decoding them away.

use prost::Message;
use sha2::{Digest, Sha256};

use crate::heddle::api::v1alpha2::{
    RegisterTimelineOriginRequest, TimelineAdmissionAcceptance, TimelineOriginCredentialClass,
    TimelineOriginEndorsement, UploadRunSummary, UploadScrubbedTimelineRequest,
    UploadTimelineEvent, UploadTimelineEventKind, UploadTimelineTool, operation_record,
    timeline_admission_acceptance::Authority,
};

pub const MAX_TIMELINE_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_TIMELINE_EVENT_BYTES: usize = 2 * 1024;
pub const MAX_TIMELINE_SNAPSHOT_BYTES: usize = 4 * 1024;
pub const MAX_TIMELINE_EVENTS: usize = 64;
pub const ORIGIN_DOMAIN: &[u8] = b"heddle-timeline-run-origin-v1\0";
pub const ACCEPTANCE_DOMAIN: &[u8] = b"heddle-timeline-run-acceptance-v1\0";
pub const UPLOAD_DOMAIN: &[u8] = b"heddle-timeline-upload-v1\0";
const MAX_POSITION: u64 = i64::MAX as u64;
const MAX_TIMESTAMP_SECONDS: i64 = 253_402_300_799;
const MIN_TIMESTAMP_SECONDS: i64 = -62_135_596_800;

#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
#[error("invalid hosted timeline {0}")]
pub struct TimelineValidationError(pub &'static str);

/// Inspect transport lengths before full protobuf allocation. Unknown fields
/// must be checked separately by the receiving server's wire decoder.
pub fn validate_raw_request_size(raw: &[u8]) -> Result<(), TimelineValidationError> {
    check(raw.len() <= MAX_TIMELINE_REQUEST_BYTES, "request size")
}
pub fn validate_raw_event_size(raw: &[u8]) -> Result<(), TimelineValidationError> {
    check(raw.len() <= MAX_TIMELINE_EVENT_BYTES, "event size")
}
pub fn validate_raw_snapshot_size(raw: &[u8]) -> Result<(), TimelineValidationError> {
    check(raw.len() <= MAX_TIMELINE_SNAPSHOT_BYTES, "snapshot size")
}

fn check(ok: bool, field: &'static str) -> Result<(), TimelineValidationError> {
    if ok {
        Ok(())
    } else {
        Err(TimelineValidationError(field))
    }
}

pub fn valid_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

pub fn valid_run_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn valid_agent_label(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// The verified credential supplies this display-only label. Direct-human
/// runs require the empty label; an agent may be unlabelled.
pub fn valid_verified_agent_id(value: &str, agent: bool) -> bool {
    if agent {
        value.is_empty() || valid_agent_label(value)
    } else {
        value.is_empty()
    }
}

pub fn validate_summary(value: &UploadRunSummary) -> Result<(), TimelineValidationError> {
    check(
        value.encoded_len() <= MAX_TIMELINE_SNAPSHOT_BYTES,
        "snapshot size",
    )?;
    check(
        matches!(
            operation_record::State::try_from(value.state),
            Ok(operation_record::State::Queued
                | operation_record::State::Running
                | operation_record::State::Completed
                | operation_record::State::Failed
                | operation_record::State::Canceled
                | operation_record::State::WaitingForHuman
                | operation_record::State::Paused)
        ),
        "snapshot state",
    )?;
    check(
        matches!(value.harness.as_str(), "claude-code" | "codex" | "other"),
        "snapshot harness",
    )
}

pub fn validate_event(
    value: &UploadTimelineEvent,
    now_micros: i128,
) -> Result<(), TimelineValidationError> {
    check(
        value.encoded_len() <= MAX_TIMELINE_EVENT_BYTES,
        "event size",
    )?;
    check(value.position <= MAX_POSITION, "event position")?;
    let kind = UploadTimelineEventKind::try_from(value.kind)
        .map_err(|_| TimelineValidationError("event kind"))?;
    check(kind != UploadTimelineEventKind::Unspecified, "event kind")?;
    let timestamp = value
        .recorded_at
        .as_ref()
        .ok_or(TimelineValidationError("recorded_at"))?;
    check(
        (MIN_TIMESTAMP_SECONDS..=MAX_TIMESTAMP_SECONDS).contains(&timestamp.seconds)
            && (0..1_000_000_000).contains(&timestamp.nanos)
            && timestamp.nanos % 1000 == 0
            && i128::from(timestamp.seconds) * 1_000_000 + i128::from(timestamp.nanos / 1000)
                <= now_micros + 300_000_000,
        "recorded_at",
    )?;
    let tool_kind = matches!(
        kind,
        UploadTimelineEventKind::ToolStarted | UploadTimelineEventKind::ToolFinished
    );
    check(value.tool_name.is_some() == tool_kind, "tool_name presence")?;
    if let Some(tool) = value.tool_name {
        check(
            matches!(UploadTimelineTool::try_from(tool), Ok(value) if value != UploadTimelineTool::Unspecified),
            "tool_name",
        )?;
    }
    Ok(())
}

fn validate_origin_fields(
    value: &TimelineOriginEndorsement,
) -> Result<(), TimelineValidationError> {
    check(value.deployment_public_key.len() == 32, "deployment key")?;
    check(valid_canonical_uuid(&value.spool_id), "origin spool")?;
    check(value.thread_id.len() == 32, "origin thread")?;
    check(valid_run_id(&value.run_id), "origin run")?;
    check(
        valid_canonical_uuid(&value.principal_id),
        "origin principal",
    )?;
    check(
        matches!(
            TimelineOriginCredentialClass::try_from(value.credential_class),
            Ok(TimelineOriginCredentialClass::DirectHuman | TimelineOriginCredentialClass::Agent)
        ),
        "origin credential class",
    )?;
    check(
        value.effective_pop_key_sha256.len() == 32,
        "origin actor digest",
    )?;
    check(
        (1..=128).contains(&value.origin_credential_id.len()),
        "origin credential ID",
    )?;
    check(
        value.uploader_device_public_key.len() == 32,
        "origin uploader key",
    )?;
    Ok(())
}

pub fn validate_origin(value: &TimelineOriginEndorsement) -> Result<(), TimelineValidationError> {
    validate_origin_fields(value)?;
    check(value.signature.len() == 64, "origin signature")
}

fn validate_acceptance_fields(
    value: &TimelineAdmissionAcceptance,
) -> Result<(), TimelineValidationError> {
    check(value.origin_sha256.len() == 32, "acceptance origin digest")?;
    check(
        value.uploader_device_public_key.len() == 32,
        "acceptance uploader key",
    )?;
    check(
        value.deployment_public_key.len() == 32,
        "acceptance deployment key",
    )?;
    check(
        value.request_sha256.len() == 32,
        "acceptance request digest",
    )?;
    check(value.first_position <= MAX_POSITION, "acceptance position")?;
    check(
        value.event_count <= MAX_TIMELINE_EVENTS as u32,
        "acceptance event count",
    )?;
    match value.authority.as_ref() {
        Some(Authority::PrincipalCredentialId(id)) => {
            check((1..=128).contains(&id.len()), "acceptance credential ID")
        }
        Some(Authority::OwnerDerivedCapability(bytes)) => {
            check((1..=4096).contains(&bytes.len()), "acceptance capability")
        }
        None => Err(TimelineValidationError("acceptance authority")),
    }
}

pub fn validate_acceptance(
    value: &TimelineAdmissionAcceptance,
) -> Result<(), TimelineValidationError> {
    validate_acceptance_fields(value)?;
    check(value.signature.len() == 64, "acceptance signature")
}

fn validate_binding(
    thread: Option<&crate::heddle::api::v1alpha2::ThreadRef>,
    run: Option<&crate::heddle::api::v1alpha2::RecordRef>,
    origin: &TimelineOriginEndorsement,
) -> Result<(), TimelineValidationError> {
    let thread = thread.ok_or(TimelineValidationError("thread"))?;
    let run = run.ok_or(TimelineValidationError("run"))?;
    let spool = thread
        .spool
        .as_ref()
        .ok_or(TimelineValidationError("thread spool"))?;
    let id = thread
        .id
        .as_ref()
        .ok_or(TimelineValidationError("thread ID"))?;
    check(valid_canonical_uuid(&spool.id), "spool UUID")?;
    check(id.value.len() == 32, "thread ID")?;
    check(valid_run_id(&run.id), "run ID")?;
    check(
        run.spool.as_ref().is_some_and(|r| r.id == spool.id),
        "run spool",
    )?;
    check(
        origin.spool_id == spool.id && origin.thread_id == id.value && origin.run_id == run.id,
        "origin binding",
    )
}

pub fn validate_registration(
    value: &RegisterTimelineOriginRequest,
) -> Result<(), TimelineValidationError> {
    check(
        valid_canonical_uuid(&value.client_operation_id),
        "client operation ID",
    )?;
    let origin = value
        .origin
        .as_ref()
        .ok_or(TimelineValidationError("origin"))?;
    validate_origin(origin)?;
    validate_binding(value.thread.as_ref(), value.run.as_ref(), origin)
}

pub fn validate_upload(
    value: &UploadScrubbedTimelineRequest,
    now_micros: i128,
) -> Result<(), TimelineValidationError> {
    check(
        value.encoded_len() <= MAX_TIMELINE_REQUEST_BYTES,
        "request size",
    )?;
    check(
        valid_canonical_uuid(&value.client_operation_id),
        "client operation ID",
    )?;
    check(
        value.canonicalization_version == 1,
        "canonicalization version",
    )?;
    check(value.first_position <= MAX_POSITION, "first position")?;
    check(value.events.len() <= MAX_TIMELINE_EVENTS, "event count")?;
    check(
        !value.events.is_empty() || value.snapshot.is_some(),
        "run-only snapshot",
    )?;
    check(
        value
            .first_position
            .checked_add(value.events.len() as u64)
            .is_some(),
        "position overflow",
    )?;
    if let Some(snapshot) = &value.snapshot {
        validate_summary(snapshot)?;
    }
    for (offset, event) in value.events.iter().enumerate() {
        validate_event(event, now_micros)?;
        check(
            event.position == value.first_position + offset as u64,
            "event sequence",
        )?;
    }
    let origin = value
        .origin
        .as_ref()
        .ok_or(TimelineValidationError("origin"))?;
    validate_origin(origin)?;
    validate_binding(value.thread.as_ref(), value.run.as_ref(), origin)?;
    if let Some(acceptance) = &value.acceptance {
        validate_acceptance(acceptance)?;
        check(
            acceptance.origin_sha256 == origin_digest(origin)?,
            "acceptance origin",
        )?;
        check(
            acceptance.uploader_device_public_key == origin.uploader_device_public_key
                && acceptance.deployment_public_key == origin.deployment_public_key,
            "acceptance binding",
        )?;
        check(
            acceptance.first_position == value.first_position
                && acceptance.event_count as usize == value.events.len(),
            "acceptance range",
        )?;
        check(
            acceptance.request_sha256 == logical_digest_bytes(value)?,
            "acceptance request digest",
        )?;
    }
    Ok(())
}

/// The exact v1 logical digest excludes both acceptance and fresh transport
/// proof. Reusing the operation ID with any other digest is a conflict.
pub fn logical_request_digest(
    value: &UploadScrubbedTimelineRequest,
    now_micros: i128,
) -> Result<[u8; 32], TimelineValidationError> {
    validate_upload(value, now_micros)?;
    logical_digest_bytes(value)
}

fn logical_digest_bytes(
    value: &UploadScrubbedTimelineRequest,
) -> Result<[u8; 32], TimelineValidationError> {
    let thread = value
        .thread
        .as_ref()
        .ok_or(TimelineValidationError("thread"))?;
    let spool = thread
        .spool
        .as_ref()
        .ok_or(TimelineValidationError("spool"))?;
    let thread_id = thread
        .id
        .as_ref()
        .ok_or(TimelineValidationError("thread ID"))?;
    let run = value.run.as_ref().ok_or(TimelineValidationError("run"))?;
    let origin = value
        .origin
        .as_ref()
        .ok_or(TimelineValidationError("origin"))?;
    let mut bytes = UPLOAD_DOMAIN.to_vec();
    counted(value.client_operation_id.as_bytes(), &mut bytes);
    counted(spool.id.as_bytes(), &mut bytes);
    counted(&thread_id.value, &mut bytes);
    counted(run.id.as_bytes(), &mut bytes);
    bytes.extend_from_slice(&value.canonicalization_version.to_be_bytes());
    bytes.extend_from_slice(&value.run_revision.to_be_bytes());
    bytes.push(u8::from(value.snapshot.is_some()));
    if let Some(snapshot) = &value.snapshot {
        bytes.extend_from_slice(&(snapshot.state as u32).to_be_bytes());
        counted(snapshot.harness.as_bytes(), &mut bytes);
    }
    bytes.extend_from_slice(&(value.events.len() as u32).to_be_bytes());
    for event in &value.events {
        bytes.extend_from_slice(&event.position.to_be_bytes());
        bytes.extend_from_slice(&(event.kind as u32).to_be_bytes());
        let at = event
            .recorded_at
            .as_ref()
            .ok_or(TimelineValidationError("recorded_at"))?;
        bytes.extend_from_slice(&at.seconds.to_be_bytes());
        bytes.extend_from_slice(&(at.nanos as u32).to_be_bytes());
        bytes.push(u8::from(event.tool_name.is_some()));
        if let Some(tool) = event.tool_name {
            bytes.extend_from_slice(&(tool as u32).to_be_bytes());
        }
    }
    counted(&origin_digest(origin)?, &mut bytes);
    bytes.extend_from_slice(&value.first_position.to_be_bytes());
    Ok(Sha256::digest(bytes).into())
}

fn counted(bytes: &[u8], into: &mut Vec<u8>) {
    into.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    into.extend_from_slice(bytes);
}

/// Exact domain-separated bytes signed by the immutable origin credential.
pub fn origin_signing_bytes(
    value: &TimelineOriginEndorsement,
) -> Result<Vec<u8>, TimelineValidationError> {
    validate_origin_fields(value)?;
    let mut bytes = ORIGIN_DOMAIN.to_vec();
    counted(&value.deployment_public_key, &mut bytes);
    counted(value.spool_id.as_bytes(), &mut bytes);
    counted(&value.thread_id, &mut bytes);
    counted(value.run_id.as_bytes(), &mut bytes);
    counted(value.principal_id.as_bytes(), &mut bytes);
    bytes.push(value.credential_class as u8);
    counted(&value.effective_pop_key_sha256, &mut bytes);
    counted(&value.origin_credential_id, &mut bytes);
    counted(&value.uploader_device_public_key, &mut bytes);
    Ok(bytes)
}

/// Digest identifies one endorsement, including its original signature.
pub fn origin_digest(
    value: &TimelineOriginEndorsement,
) -> Result<[u8; 32], TimelineValidationError> {
    validate_origin(value)?;
    let mut bytes = origin_signing_bytes(value)?;
    bytes.extend_from_slice(&value.signature);
    Ok(Sha256::digest(bytes).into())
}

/// Exact domain-separated acceptance transcript; authority is verified in the
/// server transaction against current principal or owner-derived scope.
pub fn acceptance_signing_bytes(
    value: &TimelineAdmissionAcceptance,
) -> Result<Vec<u8>, TimelineValidationError> {
    validate_acceptance_fields(value)?;
    let mut bytes = ACCEPTANCE_DOMAIN.to_vec();
    counted(&value.origin_sha256, &mut bytes);
    counted(&value.uploader_device_public_key, &mut bytes);
    counted(&value.deployment_public_key, &mut bytes);
    counted(&value.request_sha256, &mut bytes);
    bytes.extend_from_slice(&value.first_position.to_be_bytes());
    bytes.extend_from_slice(&value.event_count.to_be_bytes());
    match value
        .authority
        .as_ref()
        .ok_or(TimelineValidationError("acceptance authority"))?
    {
        Authority::PrincipalCredentialId(id) => {
            bytes.push(1);
            counted(id, &mut bytes);
        }
        Authority::OwnerDerivedCapability(capability) => {
            bytes.push(2);
            counted(capability, &mut bytes);
        }
    }
    Ok(bytes)
}

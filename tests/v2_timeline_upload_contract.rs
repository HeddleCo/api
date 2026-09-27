#![cfg(feature = "reflection")]

use std::collections::BTreeSet;

use heddle_api::heddle::api::common::{
    AuthorizationAccess, AuthorizationExistence, AuthorizationRole, AuthorizationScopeSource,
    DeploymentTarget, RetryBehavior, RpcEffect, SigningTier, StableSigningIdentity,
};
use heddle_api::heddle::api::v1alpha2::{
    OperationRecord, RecordRef, SpoolRef, ThreadId, ThreadRef, TimelineAdmissionAcceptance,
    TimelineOriginCredentialClass, TimelineOriginEndorsement, UploadRunSummary,
    UploadScrubbedTimelineRequest, UploadTimelineEvent, UploadTimelineEventKind,
    UploadTimelineTool, operation_record, timeline_admission_acceptance::Authority,
};
use heddle_api::timeline_upload::{
    MAX_TIMELINE_EVENT_BYTES, MAX_TIMELINE_REQUEST_BYTES, MAX_TIMELINE_SNAPSHOT_BYTES,
    acceptance_signing_bytes, logical_request_digest, origin_digest, origin_signing_bytes,
    valid_agent_label, valid_canonical_uuid, valid_run_id, valid_verified_agent_id, validate_event,
    validate_raw_event_size, validate_raw_request_size, validate_raw_snapshot_size,
    validate_summary, validate_upload,
};
use heddle_api::{FILE_DESCRIPTOR_SET, StreamingShape, v2::method_descriptor};
use prost_reflect::{DescriptorPool, Kind, MessageDescriptor};

const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";

fn origin() -> TimelineOriginEndorsement {
    TimelineOriginEndorsement {
        deployment_public_key: vec![1; 32],
        spool_id: UUID.into(),
        thread_id: vec![2; 32],
        run_id: "run_7".into(),
        principal_id: UUID.into(),
        credential_class: TimelineOriginCredentialClass::Agent as i32,
        effective_pop_key_sha256: vec![3; 32],
        origin_credential_id: vec![4; 16],
        uploader_device_public_key: vec![5; 32],
        signature: vec![6; 64],
    }
}

#[allow(clippy::needless_update)] // Keep the fixture compiling when a forbidden field is added.
fn request() -> UploadScrubbedTimelineRequest {
    let event = UploadTimelineEvent {
        position: 0,
        kind: UploadTimelineEventKind::ToolStarted as i32,
        recorded_at: Some(prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_000_000,
        }),
        tool_name: Some(UploadTimelineTool::Bash as i32),
        ..Default::default()
    };
    UploadScrubbedTimelineRequest {
        client_operation_id: UUID.into(),
        thread: Some(ThreadRef {
            spool: Some(SpoolRef { id: UUID.into() }),
            id: Some(ThreadId { value: vec![2; 32] }),
        }),
        run: Some(RecordRef {
            spool: Some(SpoolRef { id: UUID.into() }),
            id: "run_7".into(),
        }),
        canonicalization_version: 1,
        run_revision: 1,
        snapshot: Some(UploadRunSummary {
            state: operation_record::State::Running as i32,
            harness: "codex".into(),
        }),
        events: vec![event],
        origin: Some(origin()),
        first_position: 0,
        ..Default::default()
    }
}

#[test]
fn timeline_routes_pin_weft_writer_proof_and_client_operation_retry() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    let service = pool
        .get_service_by_name("heddle.api.v1alpha2.SyncService")
        .unwrap();
    let contract = pool
        .get_extension_by_name("heddle.api.common.rpc_contract")
        .unwrap();
    for name in ["RegisterTimelineOrigin", "UploadScrubbedTimeline"] {
        let method = service.methods().find(|m| m.name() == name).unwrap();
        assert!(
            method.options().has_extension(&contract),
            "{name} lacks rpc_contract"
        );
        let route = method_descriptor(&format!("/heddle.api.v1alpha2.SyncService/{name}")).unwrap();
        assert_eq!(route.streaming, StreamingShape::Unary);
        assert_eq!(
            route.signing_identity,
            StableSigningIdentity::AuthenticatedPrincipal
        );
        assert_eq!(route.signing_tier, SigningTier::ProofOfPossession);
        assert_eq!(route.effect, RpcEffect::DurableWrite);
        assert_eq!(route.retry_behavior, RetryBehavior::ClientOperationId);
        assert!(route.client_operation_id_required);
        assert_eq!(route.client_operation_id_field_number, Some(1));
        assert_eq!(route.deployment_targets, &[DeploymentTarget::Weft]);
        assert_eq!(
            route.authorization_access,
            AuthorizationAccess::AuthenticatedPrincipal
        );
        assert_eq!(route.authorization.role, AuthorizationRole::ResourceWriter);
        assert_eq!(
            route.authorization.scope_source,
            AuthorizationScopeSource::RequestResource
        );
        assert_eq!(route.authorization.existence, AuthorizationExistence::Hide);
        assert_eq!(route.authorization.targets.len(), 1);
        assert_eq!(route.authorization.targets[0].path, "thread.spool");
        assert_eq!(
            route.authorization.targets[0].role,
            AuthorizationRole::ResourceWriter
        );
    }
}

fn walk_no_free_text(message: MessageDescriptor, visited: &mut BTreeSet<String>) {
    if !visited.insert(message.full_name().to_owned()) {
        return;
    }
    for field in message.fields() {
        if field.kind() == Kind::String {
            let name = field.name().to_ascii_lowercase();
            assert!(
                ![
                    "summary", "detail", "command", "message", "model", "action", "path",
                    "artifact"
                ]
                .iter()
                .any(|forbidden| name.contains(forbidden)),
                "free-text upload field {}.{} is forbidden",
                message.full_name(),
                field.name()
            );
        }
        if let Kind::Message(child) = field.kind() {
            walk_no_free_text(child, visited);
        }
    }
}

#[test]
fn upload_inputs_have_only_the_allowlisted_projection_fields_and_no_free_text() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    let summary = pool
        .get_message_by_name("heddle.api.v1alpha2.UploadRunSummary")
        .unwrap();
    let event = pool
        .get_message_by_name("heddle.api.v1alpha2.UploadTimelineEvent")
        .unwrap();
    let request = pool
        .get_message_by_name("heddle.api.v1alpha2.UploadScrubbedTimelineRequest")
        .unwrap();
    walk_no_free_text(request, &mut BTreeSet::new());
    let summary_fields: BTreeSet<_> = summary
        .fields()
        .map(|field| field.name().to_owned())
        .collect();
    let event_fields: BTreeSet<_> = event
        .fields()
        .map(|field| field.name().to_owned())
        .collect();
    assert_eq!(
        summary_fields,
        BTreeSet::from(["state".into(), "harness".into()])
    );
    assert_eq!(
        event_fields,
        BTreeSet::from([
            "position".into(),
            "kind".into(),
            "recorded_at".into(),
            "tool_name".into()
        ])
    );
}

#[test]
fn ids_enums_positions_timestamps_and_bounds_reject_invalid_values() {
    assert!(valid_canonical_uuid(UUID));
    assert!(!valid_canonical_uuid(&UUID.to_uppercase()));
    assert!(valid_run_id("a-Z_09"));
    assert!(!valid_run_id("a/b"));
    assert!(!valid_run_id(&"x".repeat(129)));
    assert!(valid_agent_label("agent.b:1-2"));
    assert!(!valid_agent_label("bad label"));
    assert!(!valid_agent_label(&"x".repeat(65)));
    assert!(valid_verified_agent_id("", false));
    assert!(!valid_verified_agent_id("agent", false));
    let now = 1_700_000_000_i128 * 1_000_000;
    let mut value = request();
    validate_upload(&value, now).unwrap();
    let mut run_only = request();
    run_only.events.clear();
    validate_upload(&run_only, now).unwrap();
    run_only.snapshot = None;
    assert!(validate_upload(&run_only, now).is_err());
    value.snapshot.as_mut().unwrap().state = OperationRecord::default().state;
    assert!(validate_upload(&value, now).is_err());
    value.snapshot.as_mut().unwrap().state = 99;
    assert!(validate_upload(&value, now).is_err());
    value.snapshot.as_mut().unwrap().state = operation_record::State::Running as i32;
    value.events[0].kind = 99;
    assert!(validate_upload(&value, now).is_err());
    value.events[0].kind = UploadTimelineEventKind::ToolStarted as i32;
    value.events[0].tool_name = Some(99);
    assert!(validate_upload(&value, now).is_err());
    value.events[0].tool_name = Some(UploadTimelineTool::Bash as i32);
    value.events[0].recorded_at.as_mut().unwrap().nanos = 123_000_001;
    assert!(validate_upload(&value, now).is_err());
    value.events[0].recorded_at.as_mut().unwrap().nanos = 0;
    value.events[0].recorded_at.as_mut().unwrap().seconds += 301;
    assert!(validate_upload(&value, now).is_err());
    value.events[0].recorded_at.as_mut().unwrap().seconds -= 301;
    value.events[0].position = 1;
    assert!(validate_upload(&value, now).is_err());
    value.events[0].position = 0;
    value.events = vec![value.events[0]; 65];
    assert!(validate_upload(&value, now).is_err());
    let mut summary = value.snapshot.unwrap();
    summary.harness = "x".repeat(MAX_TIMELINE_SNAPSHOT_BYTES + 1);
    assert!(validate_summary(&summary).is_err());
    let mut oversized = request();
    oversized.origin.as_mut().unwrap().signature = vec![0; MAX_TIMELINE_REQUEST_BYTES];
    assert!(validate_upload(&oversized, now).is_err());
    assert_eq!(MAX_TIMELINE_EVENT_BYTES, 2048);
    assert!(validate_raw_request_size(&vec![0; MAX_TIMELINE_REQUEST_BYTES + 1]).is_err());
    assert!(validate_raw_event_size(&vec![0; MAX_TIMELINE_EVENT_BYTES + 1]).is_err());
    assert!(validate_raw_snapshot_size(&vec![0; MAX_TIMELINE_SNAPSHOT_BYTES + 1]).is_err());
    assert!(validate_event(&request().events[0], now).is_ok());
}

#[test]
fn origin_transcript_binds_every_identity_field_and_signature() {
    let base = origin();
    let signed = origin_signing_bytes(&base).unwrap();
    assert_eq!(
        origin_signing_bytes(&TimelineOriginEndorsement {
            signature: vec![],
            ..base.clone()
        })
        .unwrap(),
        signed
    );
    let acceptance = TimelineAdmissionAcceptance {
        origin_sha256: vec![1; 32],
        uploader_device_public_key: vec![2; 32],
        deployment_public_key: vec![3; 32],
        request_sha256: vec![4; 32],
        first_position: 0,
        event_count: 1,
        authority: Some(Authority::PrincipalCredentialId(vec![5])),
        signature: vec![],
    };
    assert!(
        acceptance_signing_bytes(&acceptance)
            .unwrap()
            .starts_with(b"heddle-timeline-run-acceptance-v1\0")
    );
    assert_ne!(
        acceptance_signing_bytes(&acceptance).unwrap(),
        acceptance_signing_bytes(&TimelineAdmissionAcceptance {
            authority: Some(Authority::PrincipalCredentialId(vec![6])),
            ..acceptance
        })
        .unwrap()
    );
    assert!(signed.starts_with(b"heddle-timeline-run-origin-v1\0"));
    assert_ne!(
        signed,
        origin_signing_bytes(&TimelineOriginEndorsement {
            run_id: "other".into(),
            ..base.clone()
        })
        .unwrap()
    );
    assert_ne!(
        origin_digest(&base).unwrap(),
        origin_digest(&TimelineOriginEndorsement {
            signature: vec![7; 64],
            ..base
        })
        .unwrap()
    );
    assert_ne!(
        logical_request_digest(&request(), 1_700_000_000_000_000).unwrap(),
        logical_request_digest(
            &UploadScrubbedTimelineRequest {
                run_revision: 2,
                ..request()
            },
            1_700_000_000_000_000
        )
        .unwrap()
    );
    assert_eq!(
        hex::encode(logical_request_digest(&request(), 1_700_000_000_000_000).unwrap()),
        "5b46eb711c38a7aa9c0587ee5c579872892afcf7327602fb31e9ae01fd404fd5"
    );
}

#[test]
fn acceptance_is_bound_to_one_original_and_exact_batch_range() {
    let now = 1_700_000_000_000_000;
    let mut value = request();
    let origin = value.origin.as_ref().unwrap();
    value.acceptance = Some(TimelineAdmissionAcceptance {
        origin_sha256: origin_digest(origin).unwrap().to_vec(),
        uploader_device_public_key: origin.uploader_device_public_key.clone(),
        deployment_public_key: origin.deployment_public_key.clone(),
        request_sha256: logical_request_digest(&value, now).unwrap().to_vec(),
        first_position: 0,
        event_count: 1,
        authority: Some(Authority::PrincipalCredentialId(vec![5])),
        signature: vec![6; 64],
    });
    validate_upload(&value, now).unwrap();
    value.acceptance.as_mut().unwrap().event_count = 2;
    assert!(validate_upload(&value, now).is_err());
    value.acceptance.as_mut().unwrap().event_count = 1;
    value.acceptance.as_mut().unwrap().request_sha256[0] ^= 1;
    assert!(validate_upload(&value, now).is_err());
}

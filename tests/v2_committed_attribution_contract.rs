#![cfg(feature = "reflection")]

use heddle_api::{
    FILE_DESCRIPTOR_SET,
    heddle::api::{common::*, v1alpha2::*},
    source_format::{
        NativeSourceFormatError, STATE_V6_ATTRIBUTION_V1, require_native_source_formats,
    },
};
use prost::Message;
use prost_reflect::{DescriptorPool, Kind};

#[test]
fn native_source_additions_require_explicit_independent_support() {
    let v6 = STATE_V6_ATTRIBUTION_V1;
    assert!(require_native_source_formats(&[], &[]).is_ok());
    assert_eq!(
        require_native_source_formats(&[v6], &[]),
        Err(NativeSourceFormatError::UnsupportedByPeer(v6))
    );
    assert_eq!(
        require_native_source_formats(&[v6], &[99]),
        Err(NativeSourceFormatError::UnsupportedByPeer(v6))
    );
    assert!(require_native_source_formats(&[v6], &[99, v6]).is_ok());
    for unknown in [0, -1, 99] {
        assert_eq!(
            require_native_source_formats(&[unknown], &[unknown]),
            Err(NativeSourceFormatError::InvalidRequiredFormat(unknown))
        );
    }
    assert_eq!(
        require_native_source_formats(&[v6, v6], &[v6]),
        Err(NativeSourceFormatError::DuplicateRequiredFormat(v6))
    );
    // A recognized signed-operation envelope does not imply a source codec.
    let endpoint = DescribeEndpointResponse {
        understood_signed_record_formats: vec!["heddle-thread-operation-v1".into()],
        ..Default::default()
    };
    assert!(
        require_native_source_formats(&[v6], &endpoint.understood_native_source_formats).is_err()
    );
}

#[test]
fn native_capabilities_bind_discovery_openings_and_exact_transfer_plan() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    for (message, field, tag) in [
        (
            "DescribeEndpointResponse",
            "understood_native_source_formats",
            12,
        ),
        ("FetchOpen", "understood_native_source_formats", 8),
        ("TransferReady", "native_source_formats", 19),
        ("PublishContentOpen", "required_native_source_formats", 9),
        ("ReplicationOpen", "understood_native_source_formats", 10),
        ("ReplicationReady", "understood_native_source_formats", 7),
    ] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.v1alpha2.{message}"))
            .unwrap();
        let field = message.get_field_by_name(field).unwrap();
        assert_eq!(field.number(), tag);
        assert!(field.is_list());
        let Kind::Enum(kind) = field.kind() else {
            panic!("typed native format")
        };
        assert_eq!(kind.full_name(), "heddle.api.common.NativeSourceFormat");
    }
    let receipt = pool
        .get_message_by_name("heddle.api.v1alpha2.ReplicationReceipt")
        .unwrap();
    assert!(receipt.get_field_by_name("missing_objects").is_some());
    let ready = pool
        .get_message_by_name("heddle.api.v1alpha2.TransferReady")
        .unwrap();
    assert!(ready.get_field_by_name("full_closure_available").is_some());
}

#[test]
fn state_and_capture_reads_share_a_typed_projection_without_a_second_rpc() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    for (message, tag) in [
        ("heddle.api.common.StateSummary", 12),
        ("heddle.api.v1alpha2.CaptureSummary", 16),
    ] {
        let message = pool.get_message_by_name(message).unwrap();
        let field = message.get_field_by_name("attribution").unwrap();
        assert_eq!(field.number(), tag);
        let Kind::Message(kind) = field.kind() else {
            panic!("typed attribution")
        };
        assert_eq!(kind.full_name(), "heddle.api.common.StateAttribution");
    }
    for name in [
        "StateAttribution",
        "AttributionEvidenceV1",
        "AttributionClaim",
        "ModelAttribution",
        "AttributionScope",
        "AttributionOperationIdentity",
        "AttributionBlobHash",
        "AttributionFileChange",
        "AttributionOperation",
    ] {
        let message = pool
            .get_message_by_name(&format!("heddle.api.common.{name}"))
            .unwrap();
        assert!(!message.fields().any(|field| field.is_map()));
        for forbidden in [
            "prompt",
            "token",
            "metadata",
            "raw_payload",
            "transcript",
            "source_path",
            "credential",
        ] {
            assert!(
                message.get_field_by_name(forbidden).is_none(),
                "{name}.{forbidden}"
            );
        }
    }
    assert!(
        !heddle_api::v2::ALL_METHODS
            .iter()
            .any(|method| method.path.contains("Attribution"))
    );
}

#[test]
fn frozen_selected_and_response_claims_survive_the_cross_language_wire_fixture() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/state-attribution-v1.json")).unwrap();
    let wire = hex::decode(fixture["wire_hex"].as_str().unwrap()).unwrap();
    let attribution = StateAttribution::decode(wire.as_slice()).unwrap();
    assert_eq!(attribution.evidence_hash, vec![42; 32]);
    let evidence = attribution.evidence.as_ref().unwrap();
    assert_eq!(evidence.format_version, 1);
    assert_eq!(evidence.harness.as_ref().unwrap().value, "codex");
    assert_eq!(
        evidence.harness_version_scope,
        Some(HarnessVersionScope::SessionCreation as i32)
    );
    let selected = evidence.selected.as_ref().unwrap();
    let response = evidence.response.as_ref().unwrap();
    assert_eq!(
        selected.model.as_ref().unwrap().value,
        "custom/request-alias"
    );
    assert_eq!(
        selected.model.as_ref().unwrap().basis,
        AttributionBasis::RequestReported as i32
    );
    assert_eq!(
        response.model.as_ref().unwrap().value,
        "custom/response-model"
    );
    assert_eq!(
        response.model.as_ref().unwrap().basis,
        AttributionBasis::ResponseReported as i32
    );
    assert!(selected.version.is_none());
    assert!(response.version.is_none());
    let scope = evidence.scope.as_ref().unwrap();
    assert_eq!(scope.actor_id.as_deref(), Some("child-A"));
    assert_eq!(scope.parent_actor_id.as_deref(), Some("root"));
    assert_eq!(scope.attempt_id.as_deref(), Some("retry-2"));
    assert_eq!(attribution.encode_to_vec(), wire);
}

#[test]
fn missing_evidence_retains_a_reference_and_never_synthesizes_human_or_model() {
    let legacy = StateSummary::decode(&[][..]).unwrap();
    assert!(legacy.attribution.is_none());
    let pending = StateAttribution {
        evidence_hash: vec![7; 32],
        evidence: None,
    };
    let decoded = StateAttribution::decode(pending.encode_to_vec().as_slice()).unwrap();
    assert_eq!(decoded, pending);
    let unknown_model = AttributionEvidenceV1 {
        format_version: 1,
        harness: Some(AttributionClaim {
            value: "custom-harness".into(),
            basis: AttributionBasis::Observed as i32,
            source: AttributionSource::Process as i32,
            observation_id: None,
        }),
        ..Default::default()
    };
    let decoded = AttributionEvidenceV1::decode(unknown_model.encode_to_vec().as_slice()).unwrap();
    assert!(decoded.harness.is_some());
    assert!(decoded.selected.is_none());
    assert!(decoded.response.is_none());
}

#[test]
fn contributor_wire_fields_are_additive_typed_and_presence_preserving() {
    let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    for (message, fields) in [
        (
            "AttributionEvidenceV1",
            vec![
                ("format_version", 1),
                ("harness", 2),
                ("harness_version", 3),
                ("harness_version_scope", 4),
                ("selected", 5),
                ("response", 6),
                ("scope", 7),
                ("operations", 8),
                ("operations_incomplete", 9),
            ],
        ),
        (
            "AttributionOperationIdentity",
            vec![
                ("harness", 1),
                ("harness_version", 2),
                ("harness_version_scope", 3),
                ("selected", 4),
                ("response", 5),
                ("scope", 6),
                ("collection_methods", 7),
            ],
        ),
        (
            "AttributionOperation",
            vec![("identity", 1), ("changes", 2), ("resolution", 3)],
        ),
        (
            "AttributionFileChange",
            vec![("path", 1), ("before", 2), ("after", 3)],
        ),
        ("AttributionBlobHash", vec![("value", 1)]),
    ] {
        let descriptor = pool
            .get_message_by_name(&format!("heddle.api.common.{message}"))
            .unwrap();
        for (field, number) in fields {
            assert_eq!(
                descriptor.get_field_by_name(field).unwrap().number(),
                number,
                "{message}.{field}"
            );
        }
    }
    for (message, field, expected, list) in [
        (
            "AttributionEvidenceV1",
            "operations",
            "AttributionOperation",
            true,
        ),
        (
            "AttributionOperation",
            "identity",
            "AttributionOperationIdentity",
            false,
        ),
        (
            "AttributionOperation",
            "changes",
            "AttributionFileChange",
            true,
        ),
        (
            "AttributionFileChange",
            "before",
            "AttributionBlobHash",
            false,
        ),
        (
            "AttributionFileChange",
            "after",
            "AttributionBlobHash",
            false,
        ),
    ] {
        let descriptor = pool
            .get_message_by_name(&format!("heddle.api.common.{message}"))
            .unwrap();
        let field = descriptor.get_field_by_name(field).unwrap();
        assert_eq!(field.is_list(), list);
        assert_eq!(field.supports_presence(), !list);
        let Kind::Message(kind) = field.kind() else {
            panic!("typed contributor field")
        };
        assert_eq!(kind.full_name(), format!("heddle.api.common.{expected}"));
    }
    let identity = pool
        .get_message_by_name("heddle.api.common.AttributionOperationIdentity")
        .unwrap();
    let methods = identity.get_field_by_name("collection_methods").unwrap();
    assert!(methods.is_list());
    assert!(!methods.supports_presence());
    let Kind::Enum(kind) = methods.kind() else {
        panic!("typed collector origins")
    };
    assert_eq!(
        kind.full_name(),
        "heddle.api.common.AttributionCollectionMethod"
    );
    assert_eq!(AttributionCollectionMethod::Unspecified as i32, 0);
    assert_eq!(AttributionCollectionMethod::Hook as i32, 1);
    assert_eq!(AttributionCollectionMethod::EventStream as i32, 2);
    assert_eq!(AttributionCollectionMethod::OpenTelemetry as i32, 3);
    assert_eq!(AttributionCollectionMethod::Transcript as i32, 4);
    assert_eq!(AttributionCollectionMethod::Proxy as i32, 5);
    assert_eq!(AttributionCollectionMethod::Explicit as i32, 6);
    assert_eq!(AttributionOperationResolution::Unspecified as i32, 0);
    assert_eq!(AttributionOperationResolution::Unresolved as i32, 1);
    assert_eq!(AttributionOperationResolution::ContentBound as i32, 2);
}

#[test]
fn contributor_wire_fixture_keeps_scopes_hash_presence_and_uncertainty_separate() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/state-attribution-operations-v1.json"
    ))
    .unwrap();
    let wire = hex::decode(fixture["wire_hex"].as_str().unwrap()).unwrap();
    let attribution = StateAttribution::decode(wire.as_slice()).unwrap();
    let evidence = attribution.evidence.as_ref().unwrap();
    assert_eq!(evidence.harness.as_ref().unwrap().value, "capture-harness");
    assert_eq!(
        evidence
            .selected
            .as_ref()
            .unwrap()
            .model
            .as_ref()
            .unwrap()
            .value,
        "capture-model"
    );
    assert_eq!(
        evidence.scope.as_ref().unwrap().actor_id.as_deref(),
        Some("capture-caller")
    );
    assert!(evidence.operations_incomplete);
    assert_eq!(evidence.operations.len(), 2);
    let bound = &evidence.operations[0];
    assert_eq!(
        bound.resolution,
        AttributionOperationResolution::ContentBound as i32
    );
    let identity = bound.identity.as_ref().unwrap();
    assert_eq!(
        identity.collection_methods,
        vec![
            AttributionCollectionMethod::Hook as i32,
            AttributionCollectionMethod::Transcript as i32
        ]
    );
    assert_eq!(identity.harness.as_ref().unwrap().value, "codex");
    assert_eq!(identity.harness_version.as_ref().unwrap().value, "1.2.3");
    assert_eq!(
        identity.harness_version_scope,
        Some(HarnessVersionScope::CurrentInvocation as i32)
    );
    assert_eq!(
        identity
            .selected
            .as_ref()
            .unwrap()
            .provider
            .as_ref()
            .unwrap()
            .value,
        "router-a"
    );
    assert_eq!(
        identity
            .selected
            .as_ref()
            .unwrap()
            .model
            .as_ref()
            .unwrap()
            .value,
        "selected-a"
    );
    let response = identity.response.as_ref().unwrap();
    assert!(response.provider.is_none());
    let response_model = response.model.as_ref().unwrap();
    assert_eq!(response_model.value, "reported-a");
    assert_eq!(
        response_model.basis,
        AttributionBasis::ResponseReported as i32
    );
    assert_eq!(response_model.source, AttributionSource::Response as i32);
    assert_eq!(response_model.observation_id.as_deref(), Some("response-a"));
    let scope = identity.scope.as_ref().unwrap();
    assert_eq!(scope.actor_id.as_deref(), Some("actor-a"));
    assert_eq!(scope.harness_session_id.as_deref(), Some("session-a"));
    assert_eq!(scope.request_id.as_deref(), Some("request-a"));
    assert_eq!(scope.response_id.as_deref(), Some("response-a"));
    assert_eq!(scope.attempt_id.as_deref(), Some("attempt-a"));
    assert_eq!(scope.message_id.as_deref(), Some("message-a"));
    assert_eq!(scope.root_turn_id.as_deref(), Some("root-turn"));
    assert_eq!(scope.tool_call_id.as_deref(), Some("tool-a"));
    assert_eq!(bound.changes.len(), 3);
    assert_eq!(bound.changes[0].path, "src/modified.rs");
    assert_eq!(
        bound.changes[0].before.as_ref().unwrap().value,
        vec![11; 32]
    );
    assert_eq!(bound.changes[0].after.as_ref().unwrap().value, vec![12; 32]);
    assert!(bound.changes[1].before.is_none());
    assert_eq!(bound.changes[1].after.as_ref().unwrap().value, vec![13; 32]);
    assert_eq!(
        bound.changes[2].before.as_ref().unwrap().value,
        vec![14; 32]
    );
    assert!(bound.changes[2].after.is_none());
    let unresolved = &evidence.operations[1];
    assert_eq!(
        unresolved.resolution,
        AttributionOperationResolution::Unresolved as i32
    );
    let identity = unresolved.identity.as_ref().unwrap();
    assert_eq!(
        identity.collection_methods,
        vec![AttributionCollectionMethod::Transcript as i32]
    );
    assert_eq!(identity.harness.as_ref().unwrap().value, "custom-harness");
    assert!(identity.selected.is_none());
    assert!(identity.response.is_none());
    assert_eq!(
        identity.scope.as_ref().unwrap().actor_id.as_deref(),
        Some("actor-b")
    );
    assert_eq!(
        identity.scope.as_ref().unwrap().attempt_id.as_deref(),
        Some("attempt-b")
    );
    assert_eq!(attribution.encode_to_vec(), wire);
}

#[test]
fn legacy_projection_defaults_do_not_invent_operations_or_completeness() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/state-attribution-v1.json")).unwrap();
    let wire = hex::decode(fixture["wire_hex"].as_str().unwrap()).unwrap();
    let attribution = StateAttribution::decode(wire.as_slice()).unwrap();
    let evidence = attribution.evidence.as_ref().unwrap();
    assert!(evidence.operations.is_empty());
    assert!(!evidence.operations_incomplete);
    assert_eq!(attribution.encode_to_vec(), wire);
}

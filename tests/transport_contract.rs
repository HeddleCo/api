// SPDX-License-Identifier: Apache-2.0

use heddle_api::{HOSTED_ALPN_V1, StreamingShape, method_descriptor};
use heddle_api::heddle::api::v1alpha1::{
    CallContext, CallFailure, CallFailureCode, HumanVerification, RequestProof, TraceContext,
};

#[test]
fn generated_descriptor_preserves_the_list_refs_contract() {
    let descriptor = method_descriptor("/heddle.api.v1alpha1.RepoSyncService/ListRefs")
        .expect("ListRefs descriptor");

    assert_eq!(HOSTED_ALPN_V1, b"heddle-api/1");
    assert_eq!(descriptor.input, "heddle.api.v1alpha1.ListRefsRequest");
    assert_eq!(descriptor.output, "heddle.api.v1alpha1.ListRefsResponse");
    assert_eq!(descriptor.streaming, StreamingShape::Unary);
    assert!(descriptor.allows_zero_rtt());
}

#[test]
fn call_context_carries_transport_neutral_auth_and_trace_fields() {
    let context = CallContext {
        bearer_capability: b"opaque-biscuit".to_vec(),
        request_proof: Some(RequestProof {
            algorithm: "ed25519".to_string(),
            signing_identity: "principal:alice".to_string(),
            timestamp_millis: 1_784_059_200_123,
            nonce: (0_u8..16).collect(),
            signature: vec![7; 64],
        }),
        human_verification: Some(HumanVerification {
            client_data_json: b"{}".to_vec(),
            authenticator_data: vec![1, 2, 3],
            user_handle: b"alice".to_vec(),
        }),
        client_operation_id: "018f4f6a-8dcb-7f80-a4a1-000000000001".to_string(),
        trace: Some(TraceContext {
            traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
            tracestate: String::new(),
            baggage: String::new(),
        }),
        ..Default::default()
    };

    assert_eq!(context.bearer_capability, b"opaque-biscuit");
    assert_eq!(
        context.request_proof.expect("request proof").signing_identity,
        "principal:alice"
    );
}

#[test]
fn call_failure_uses_contract_owned_codes() {
    let failure = CallFailure {
        code: CallFailureCode::PermissionDenied as i32,
        message: "repository is not visible".to_string(),
        details: Vec::new(),
    };

    assert_eq!(
        failure.code(),
        CallFailureCode::PermissionDenied,
        "failure vocabulary must not depend on a transport status type"
    );
}

// SPDX-License-Identifier: Apache-2.0

use heddle_api::framing::{
    ResponseFrame, StreamFrame, decode_request_frame, decode_response_frame, decode_stream_frame,
    encode_failure_response, encode_request_frame, encode_stream_failure, encode_stream_message,
};
use heddle_api::heddle::api::v1alpha1::{
    AuthorizationAccess, CallContext, CallFailure, CallFailureCode, HumanVerification,
    RequestProof, TraceContext,
};
use heddle_api::{ALL_METHODS, HOSTED_ALPN_V1, StreamingShape, method_descriptor};
use prost::Message;
use serde::Deserialize;

#[derive(Deserialize)]
struct HostedCallFixture {
    alpn: String,
    method: String,
    bearer_capability_hex: String,
    client_operation_id: String,
    traceparent: String,
    request_hex: String,
    framed_request_hex: String,
    failure_code: String,
    failure_message: String,
    detail_type_url: String,
    detail_value_hex: String,
    failure_hex: String,
    framed_failure_hex: String,
}

#[test]
fn streaming_frames_are_incremental_and_transport_neutral() {
    let message = encode_stream_message(b"one").expect("stream message");
    assert!(decode_stream_frame(&message[..4]).unwrap().is_none());
    let (decoded, consumed) = decode_stream_frame(&message)
        .unwrap()
        .expect("complete frame");
    assert_eq!(consumed, message.len());
    assert!(matches!(decoded, StreamFrame::Message(b"one")));

    let failure = CallFailure {
        code: CallFailureCode::Cancelled as i32,
        message: "caller cancelled".into(),
        details: Vec::new(),
    };
    let framed = encode_stream_failure(&failure).expect("stream failure");
    let (decoded, consumed) = decode_stream_frame(&framed)
        .unwrap()
        .expect("failure frame");
    assert_eq!(consumed, framed.len());
    match decoded {
        StreamFrame::Failure(decoded) => assert_eq!(decoded, failure),
        StreamFrame::Message(_) => panic!("failure decoded as message"),
    }
}

#[test]
fn generated_descriptor_preserves_the_list_refs_contract() {
    let descriptor = method_descriptor("/heddle.api.v1alpha1.RepoSyncService/ListRefs")
        .expect("ListRefs descriptor");

    assert_eq!(HOSTED_ALPN_V1, b"heddle-api/1");
    assert_eq!(descriptor.input, "heddle.api.v1alpha1.ListRefsRequest");
    assert_eq!(descriptor.output, "heddle.api.v1alpha1.ListRefsResponse");
    assert_eq!(descriptor.streaming, StreamingShape::Unary);
    assert!(descriptor.allows_zero_rtt());
    assert_eq!(
        descriptor.authorization_access,
        AuthorizationAccess::AuthenticatedPrincipal
    );
    assert_eq!(
        method_descriptor("/heddle.api.v1alpha1.IdentityService/CreateDeviceAuthorization")
            .expect("public device authorization descriptor")
            .authorization_access,
        AuthorizationAccess::Public
    );
    assert_eq!(ALL_METHODS.len(), 150);
    assert!(
        ALL_METHODS
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
    );
    assert_eq!(
        method_descriptor("/heddle.api.v1alpha1.IdentityService/WaitForDeviceAuthorization")
            .expect("WaitForDeviceAuthorization descriptor")
            .streaming,
        StreamingShape::ServerStreaming
    );
    for path in [
        "/heddle.api.v1alpha1.RepoSyncService/Push",
        "/heddle.api.v1alpha1.RepoSyncService/Pull",
    ] {
        assert_eq!(
            method_descriptor(path).expect("sync descriptor").streaming,
            StreamingShape::Bidirectional
        );
    }
}

#[test]
fn call_context_carries_transport_neutral_auth_and_trace_fields() {
    let context = CallContext {
        bearer_capability: b"opaque-biscuit".to_vec(),
        bearer_grant_envelope: b"opaque-grant-envelope".to_vec(),
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
    assert_eq!(context.bearer_grant_envelope, b"opaque-grant-envelope");
    assert_eq!(
        context
            .request_proof
            .expect("request proof")
            .signing_identity,
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

#[test]
fn hosted_call_framing_and_failure_match_the_cross_product_fixture() {
    let fixture: HostedCallFixture =
        serde_json::from_str(include_str!("fixtures/hosted-call-v1.json"))
            .expect("hosted-call fixture");
    let context = CallContext {
        bearer_capability: hex::decode(&fixture.bearer_capability_hex).expect("bearer hex"),
        client_operation_id: fixture.client_operation_id,
        trace: Some(TraceContext {
            traceparent: fixture.traceparent,
            ..Default::default()
        }),
        ..Default::default()
    };
    let request = hex::decode(&fixture.request_hex).expect("request hex");
    let framed = encode_request_frame(&fixture.method, &context, &request).expect("frame request");
    assert_eq!(fixture.alpn.as_bytes(), HOSTED_ALPN_V1);
    assert_eq!(hex::encode(&framed), fixture.framed_request_hex);
    let decoded = decode_request_frame(&framed).expect("decode request");
    assert_eq!(decoded.method, fixture.method);
    assert_eq!(decoded.context, context);
    assert_eq!(decoded.body, request);

    assert_eq!(fixture.failure_code, "PERMISSION_DENIED");
    let failure = CallFailure {
        code: CallFailureCode::PermissionDenied as i32,
        message: fixture.failure_message,
        details: vec![prost_types::Any {
            type_url: fixture.detail_type_url,
            value: hex::decode(&fixture.detail_value_hex).expect("typed detail hex"),
        }],
    };
    assert_eq!(hex::encode(failure.encode_to_vec()), fixture.failure_hex);
    let framed_failure = encode_failure_response(&failure).expect("frame failure");
    assert_eq!(hex::encode(&framed_failure), fixture.framed_failure_hex);
    match decode_response_frame(&framed_failure).expect("decode failure") {
        ResponseFrame::Failure(decoded) => assert_eq!(decoded, failure),
        ResponseFrame::Success(_) => panic!("failure fixture decoded as success"),
    }
}

// SPDX-License-Identifier: Apache-2.0

use bytes::BytesMut;
use heddle_api::framing::{
    ResponseFrame, StreamFrame, decode_request_frame, decode_request_prelude,
    decode_response_frame, decode_stream_frame, encode_failure_response,
    encode_failure_response_into, encode_request_frame, encode_request_prelude,
    encode_stream_failure, encode_stream_failure_into, encode_stream_message,
    encode_stream_message_into, encode_stream_raw_body, encode_stream_raw_body_into,
    encode_success_response, encode_success_response_into,
};
use heddle_api::heddle::api::common::{
    CallContext, CallFailure, CallFailureCode, ErrorDetail, ErrorReason, HumanVerification,
    HumanVerificationChallenge, PolicyDenial, RequestProof, RetryBehavior, RpcEffect, SigningTier,
    TraceContext, error_detail,
};
use heddle_api::heddle::api::v1alpha2::CreateSpoolRequest;
use heddle_api::{HOSTED_ALPN_V1, StreamingShape, method_descriptor};
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
    error_reason: String,
    error_resource: String,
    policy_id: String,
    policy_rule: String,
    policy_human_verification_can_override: bool,
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
        error: None,
    };
    let framed = encode_stream_failure(&failure).expect("stream failure");
    let (decoded, consumed) = decode_stream_frame(&framed)
        .unwrap()
        .expect("failure frame");
    assert_eq!(consumed, framed.len());
    match decoded {
        StreamFrame::Failure(decoded) => assert_eq!(decoded, failure),
        StreamFrame::Message(_) => panic!("failure decoded as message"),
        StreamFrame::RawBody { .. } => panic!("failure decoded as raw body"),
    }
}

#[test]
fn control_frame_encoders_reuse_the_caller_buffer_without_changing_wire_bytes() {
    let failure = CallFailure {
        code: CallFailureCode::PermissionDenied as i32,
        message: "repository is not visible".into(),
        error: None,
    };
    let mut frame = BytesMut::with_capacity(4096);
    let capacity = frame.capacity();
    let allocation = frame.as_ptr();

    encode_success_response_into(&mut frame, b"response").expect("success frame");
    assert_eq!(
        frame.as_ref(),
        encode_success_response(b"response").unwrap()
    );
    assert_eq!(frame.capacity(), capacity);
    assert_eq!(frame.as_ptr(), allocation);

    encode_failure_response_into(&mut frame, &failure).expect("failure frame");
    assert_eq!(frame.as_ref(), encode_failure_response(&failure).unwrap());
    assert_eq!(frame.capacity(), capacity);
    assert_eq!(frame.as_ptr(), allocation);

    encode_stream_message_into(&mut frame, b"stream message").expect("stream message");
    assert_eq!(
        frame.as_ref(),
        encode_stream_message(b"stream message").unwrap()
    );
    assert_eq!(frame.capacity(), capacity);
    assert_eq!(frame.as_ptr(), allocation);

    encode_stream_failure_into(&mut frame, &failure).expect("stream failure");
    assert_eq!(frame.as_ref(), encode_stream_failure(&failure).unwrap());
    assert_eq!(frame.capacity(), capacity);
    assert_eq!(frame.as_ptr(), allocation);

    encode_stream_raw_body_into(&mut frame, 1_048_576).expect("raw body header");
    assert_eq!(frame.as_ref(), encode_stream_raw_body(1_048_576).unwrap());
    assert_eq!(frame.capacity(), capacity);
    assert_eq!(frame.as_ptr(), allocation);
}

#[test]
fn raw_stream_body_has_a_bounded_known_length_header() {
    let header = encode_stream_raw_body(1_048_576).expect("raw body header");
    assert!(decode_stream_frame(&header[..8]).unwrap().is_none());
    let (decoded, consumed) = decode_stream_frame(&header)
        .unwrap()
        .expect("complete raw body header");
    assert_eq!(consumed, 9);
    assert!(matches!(
        decoded,
        StreamFrame::RawBody { length: 1_048_576 }
    ));
    assert!(encode_stream_raw_body(0).is_err());
}

#[test]
fn request_prelude_can_be_routed_before_a_bidi_stream_finishes() {
    let context = CallContext {
        bearer_capability: b"token".to_vec(),
        ..Default::default()
    };
    let prelude = encode_request_prelude("/heddle.api.v1alpha2.SyncService/Fetch", &context)
        .expect("request prelude");
    assert!(decode_request_prelude(&prelude[..5]).unwrap().is_none());
    let (decoded, consumed) = decode_request_prelude(&prelude)
        .unwrap()
        .expect("complete prelude");
    assert_eq!(consumed, prelude.len());
    assert_eq!(decoded.method, "/heddle.api.v1alpha2.SyncService/Fetch");
    assert_eq!(decoded.context, context);
}

#[test]
fn generated_descriptor_extracts_client_operation_id_without_route_specific_code() {
    let method = method_descriptor("/heddle.api.v1alpha2.SpoolService/CreateSpool")
        .expect("create spool descriptor");
    assert!(method.client_operation_id_required);
    assert!(method.client_operation_id_field_number.is_some());
    let request = CreateSpoolRequest {
        client_operation_id: "operation-123".to_string(),
        ..Default::default()
    }
    .encode_to_vec();
    assert_eq!(
        method.client_operation_id(&request).expect("valid request"),
        Some("operation-123")
    );
}

#[test]
fn call_context_carries_transport_neutral_auth_and_trace_fields() {
    let context = CallContext {
        bearer_capability: b"opaque-biscuit".to_vec(),
        bearer_authority_proof: b"portable-owner-authority".to_vec(),
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

    let context =
        CallContext::decode(context.encode_to_vec().as_slice()).expect("context round trip");
    assert_eq!(context.bearer_authority_proof, b"portable-owner-authority");
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
        error: None,
    };

    assert_eq!(
        failure.code(),
        CallFailureCode::PermissionDenied,
        "failure vocabulary must not depend on a transport status type"
    );
}

#[test]
fn human_verification_challenge_is_a_typed_failure_detail() {
    let detail = heddle_api::human_verification_error_detail(HumanVerificationChallenge {
        action_url: "https://app.heddle.dev/verify-action".to_string(),
        oauth_link: None,
    });
    let decoded = heddle_api::human_verification_challenge(&detail)
        .expect("decode human verification challenge");
    assert_eq!(decoded.action_url, "https://app.heddle.dev/verify-action");
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
    assert_eq!(fixture.error_reason, "POLICY_DENIED");
    let failure = CallFailure {
        code: CallFailureCode::PermissionDenied as i32,
        message: fixture.failure_message,
        error: Some(ErrorDetail {
            reason: ErrorReason::PolicyDenied as i32,
            resource: fixture.error_resource,
            field: String::new(),
            context: Some(error_detail::Context::Policy(PolicyDenial {
                policy_id: fixture.policy_id,
                rule: fixture.policy_rule,
                human_verification_can_override: fixture.policy_human_verification_can_override,
                billing_lock: None,
            })),
        }),
    };
    assert_eq!(hex::encode(failure.encode_to_vec()), fixture.failure_hex);
    let framed_failure = encode_failure_response(&failure).expect("frame failure");
    assert_eq!(hex::encode(&framed_failure), fixture.framed_failure_hex);
    match decode_response_frame(&framed_failure).expect("decode failure") {
        ResponseFrame::Failure(decoded) => assert_eq!(decoded, failure),
        ResponseFrame::Success(_) => panic!("failure fixture decoded as success"),
    }
}

#[test]
fn promotion_is_routed_as_a_pop_signed_durable_write() {
    let method = method_descriptor("/heddle.api.v1alpha2.SpoolService/PromoteSpool")
        .expect("promotion route generated from canonical service");
    assert_eq!(
        method.route,
        heddle_api::MethodRoute::SpoolServicePromoteSpool
    );
    assert_eq!(method.signing_tier, SigningTier::ProofOfPossession);
    assert_eq!(method.effect, RpcEffect::DurableWrite);
    assert_eq!(method.retry_behavior, RetryBehavior::ClientOperationId);
    assert_eq!(method.streaming, StreamingShape::Unary);
}

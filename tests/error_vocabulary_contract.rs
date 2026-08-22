// SPDX-License-Identifier: Apache-2.0

//! Failure-vocabulary contract: the extended `ErrorDetail.context` arms that
//! keep the hosted failure surface able to express everything a client mirror
//! needs — terminal stream failures and lossless unknown-detail pass-through.

use heddle_api::heddle::api::v1alpha1::{
    CallFailure, CallFailureCode, CursorFailure, ErrorDetail, ErrorReason, RetryAdvice,
    StreamFailure, UnknownDetail, cursor_failure, error_detail,
};
use prost::Message;

#[test]
fn stream_detail_round_trips_inside_error_detail() {
    // A mid-stream abort carries its typed code/message inside the single
    // structured channel; the resume hint rides the top-level retry arm.
    let failure = CallFailure {
        code: CallFailureCode::Unavailable as i32,
        message: "pull stream aborted".to_string(),
        error: Some(ErrorDetail {
            reason: ErrorReason::Transient as i32,
            resource: "spool:org/b/repo".to_string(),
            field: String::new(),
            context: Some(error_detail::Context::Stream(Box::new(StreamFailure {
                code: CallFailureCode::Internal as i32,
                message: "pack writer reset".to_string(),
                error: Some(Box::new(ErrorDetail {
                    reason: ErrorReason::CursorInvalid as i32,
                    resource: String::new(),
                    field: String::new(),
                    context: Some(error_detail::Context::Cursor(CursorFailure {
                        reason: cursor_failure::Reason::Stale as i32,
                        expired_at: None,
                        restart_cursor: "page-42".to_string(),
                    })),
                })),
            }))),
        }),
    };

    let encoded = failure.encode_to_vec();
    let decoded = CallFailure::decode(encoded.as_slice()).expect("decode CallFailure");
    assert_eq!(decoded, failure);

    let Some(error_detail::Context::Stream(stream)) = decoded.error.expect("error").context else {
        panic!("stream arm must survive the wire trip");
    };
    assert_eq!(stream.code, CallFailureCode::Internal as i32);
    assert_eq!(stream.message, "pack writer reset");
    let Some(error_detail::Context::Cursor(cursor)) = stream.error.expect("nested error").context
    else {
        panic!("cursor hint must nest inside the StreamFailure");
    };
    assert_eq!(cursor.restart_cursor, "page-42");
}

#[test]
fn retry_advice_nests_inside_stream_failure_for_resumable_aborts() {
    let detail = ErrorDetail {
        reason: ErrorReason::Transient as i32,
        resource: String::new(),
        field: String::new(),
        context: Some(error_detail::Context::Stream(Box::new(StreamFailure {
            code: CallFailureCode::ResourceExhausted as i32,
            message: "backpressure".to_string(),
            error: Some(Box::new(ErrorDetail {
                reason: ErrorReason::RateLimited as i32,
                resource: String::new(),
                field: String::new(),
                context: Some(error_detail::Context::Retry(RetryAdvice {
                    retry_after: Some(prost_types::Duration {
                        seconds: 3,
                        nanos: 0,
                    }),
                })),
            })),
        }))),
    };

    let decoded =
        ErrorDetail::decode(detail.encode_to_vec().as_slice()).expect("decode ErrorDetail");
    let Some(error_detail::Context::Stream(stream)) = decoded.context else {
        panic!("stream arm must decode");
    };
    match stream.error.expect("nested error").context {
        Some(error_detail::Context::Retry(advice)) => {
            assert_eq!(advice.retry_after.expect("retry_after").seconds, 3);
        }
        other => panic!("retry advice must nest inside StreamFailure, got {other:?}"),
    }
}

#[test]
fn unknown_context_round_trips_losslessly() {
    // A newer server sends a context arm this client's vocabulary lacks. The
    // client re-encodes it as `unknown` (typed_url + verbatim bytes) so an
    // upstream hop or a later reader can still recover it.
    let future_arm = StreamFailure {
        code: CallFailureCode::FailedPrecondition as i32,
        message: "from the future".to_string(),
        error: None,
    };

    let unknown = UnknownDetail {
        type_url: "type.googleapis.com/heddle.api.v1alpha1.StreamFailure".to_string(),
        value: future_arm.encode_to_vec(),
    };
    let failure = CallFailure {
        code: CallFailureCode::Unknown as i32,
        message: "unrecognized detail preserved".to_string(),
        error: Some(ErrorDetail {
            reason: ErrorReason::Unimplemented as i32,
            resource: "operation:CreateGrant:op-123".to_string(),
            field: String::new(),
            context: Some(error_detail::Context::Unknown(unknown)),
        }),
    };

    let encoded = failure.encode_to_vec();
    let decoded = CallFailure::decode(encoded.as_slice()).expect("decode CallFailure");
    assert_eq!(decoded, failure);

    let Some(error_detail::Context::Unknown(preserved)) = decoded.error.expect("error").context
    else {
        panic!("unknown arm must survive the wire trip");
    };
    assert_eq!(
        preserved.type_url,
        "type.googleapis.com/heddle.api.v1alpha1.StreamFailure"
    );
    // The opaque bytes decode back into the original typed message.
    let recovered =
        StreamFailure::decode(preserved.value.as_slice()).expect("recovered typed payload");
    assert_eq!(recovered, future_arm);
}

#[test]
fn unknown_payload_bytes_are_verbatim() {
    let detail = ErrorDetail {
        reason: ErrorReason::Internal as i32,
        resource: String::new(),
        field: String::new(),
        context: Some(error_detail::Context::Unknown(UnknownDetail {
            type_url: "type.googleapis.com/heddle.api.v1alpha1.FutureDetail".to_string(),
            value: vec![0x08, 0x96, 0x01], // field 1 varint 150 — arbitrary bytes
        })),
    };

    let encoded = detail.encode_to_vec();
    let decoded = ErrorDetail::decode(encoded.as_slice()).expect("decode ErrorDetail");
    let Some(error_detail::Context::Unknown(preserved)) = decoded.context else {
        panic!("unknown arm must decode");
    };
    assert_eq!(preserved.value, vec![0x08, 0x96, 0x01]);
}

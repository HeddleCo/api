//! Terminal stream failures belong to the wire contract, independent of a host.

use crate::heddle::api::v1alpha1::{CallFailure, CursorFailure, RetryAdvice};

impl CallFailure {
    /// Preserve the original failure inside the terminal stream context.
    /// Explicit retry advice takes precedence over a cursor, then existing detail.
    pub fn into_stream_failure(
        self,
        _retry: Option<RetryAdvice>,
        _cursor: Option<CursorFailure>,
    ) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::heddle::api::v1alpha1::{
        CallFailure, CallFailureCode, CursorFailure, ErrorDetail, ErrorReason, PolicyDenial,
        RetryAdvice, error_detail,
    };
    use prost::Message;

    #[test]
    fn terminal_failure_preserves_policy_and_is_idempotent_on_the_wire() {
        let detail = ErrorDetail {
            reason: ErrorReason::PolicyDenied as i32,
            resource: "spool:owner/private".into(),
            field: "sharing_policy".into(),
            context: Some(error_detail::Context::Policy(PolicyDenial {
                policy_id: "thread.sharing".into(),
                rule: "sharing revoked".into(),
                human_verification_can_override: false,
            })),
        };
        let failure = CallFailure {
            code: CallFailureCode::PermissionDenied as i32,
            message: "sharing revoked".into(),
            error: Some(detail.clone()),
        }.into_stream_failure(None, None);
        let encoded = failure.encode_to_vec();
        assert_eq!(encoded, failure.clone().into_stream_failure(None, None).encode_to_vec());
        let restored = CallFailure::decode(encoded.as_slice()).expect("decode terminal frame");
        assert_eq!(restored.code, failure.code);
        assert_eq!(restored.message, failure.message);
        let outer = restored.error.expect("typed failure");
        assert_eq!(outer.reason, detail.reason);
        assert_eq!(outer.resource, detail.resource);
        assert_eq!(outer.field, detail.field);
        let Some(error_detail::Context::Stream(stream)) = outer.context else {
            panic!("terminal failure must carry a stream context");
        };
        assert_eq!(stream.code, failure.code);
        assert_eq!(stream.message, failure.message);
        assert_eq!(stream.error.as_deref(), Some(&detail));
    }

    #[test]
    fn explicit_hints_have_deterministic_precedence() {
        let base = CallFailure {
            code: CallFailureCode::Unavailable as i32,
            message: "resume".into(),
            error: None,
        };
        let cursor = CursorFailure { restart_cursor: "page-42".into(), ..Default::default() };
        let retry = RetryAdvice { retry_after: Some(prost_types::Duration { seconds: 3, nanos: 0 }) };
        for (advice, expected) in [(Some(retry), ErrorReason::Transient), (None, ErrorReason::CursorInvalid)] {
            let failure = base.clone().into_stream_failure(advice, Some(cursor.clone()));
            let outer = failure.error.expect("stream error");
            assert_eq!(outer.reason, expected as i32);
            let Some(error_detail::Context::Stream(stream)) = outer.context else {
                panic!("terminal stream context");
            };
            let hint = stream.error.expect("nested hint");
            match (advice, hint.context) {
                (Some(expected), Some(error_detail::Context::Retry(actual))) => assert_eq!(actual, expected),
                (None, Some(error_detail::Context::Cursor(actual))) => assert_eq!(actual, cursor),
                _ => panic!("explicit hint must determine recovery"),
            }
        }
    }
}

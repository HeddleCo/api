// SPDX-License-Identifier: Apache-2.0

use crate::heddle::api::v1alpha1::{
    AuthorizationAccess, CallContext, DeploymentTarget, ErrorDetail, ErrorReason,
    HumanVerificationChallenge, RetryBehavior, RpcEffect, ServiceMaturity, SigningTier,
    error_detail,
};

/// Production ALPN for the first transport-neutral hosted-call protocol.
pub const HOSTED_ALPN_V1: &[u8] = b"heddle-api/1";

/// Build an `ErrorDetail` carrying a human-verification challenge (policy-denied
/// with an actionable challenge), for the `ErrorDetail.human_verification` arm.
pub fn human_verification_error_detail(challenge: HumanVerificationChallenge) -> ErrorDetail {
    ErrorDetail {
        reason: ErrorReason::PolicyDenied as i32,
        resource: String::new(),
        field: String::new(),
        context: Some(error_detail::Context::HumanVerification(challenge)),
    }
}

/// Extract a human-verification challenge from an `ErrorDetail`, if present.
pub fn human_verification_challenge(detail: &ErrorDetail) -> Option<HumanVerificationChallenge> {
    match &detail.context {
        Some(error_detail::Context::HumanVerification(challenge)) => Some(challenge.clone()),
        _ => None,
    }
}

/// Message cardinality on each side of a contract method.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StreamingShape {
    /// One request and one response.
    Unary,
    /// A stream of requests and one response.
    ClientStreaming,
    /// One request and a stream of responses.
    ServerStreaming,
    /// Streams in both directions.
    Bidirectional,
}

include!(concat!(env!("OUT_DIR"), "/heddle_api_methods.rs"));

impl MethodDescriptor {
    /// Whether the contract permits this method on a replayable 0-RTT path.
    pub const fn allows_zero_rtt(&self) -> bool {
        matches!(self.effect, RpcEffect::ReadOnly)
            && matches!(self.retry_behavior, RetryBehavior::Safe)
    }

    /// Extracts the request's declared `client_operation_id`, when its input
    /// message has that field. The generated field number keeps clients and
    /// producers from maintaining handwritten per-route catalogs.
    pub fn client_operation_id<'a>(
        &self,
        request: &'a [u8],
    ) -> Result<Option<&'a str>, RequestMetadataError> {
        let Some(field_number) = self.client_operation_id_field_number else {
            return Ok(None);
        };
        protobuf_string_field(request, field_number)
    }
}

/// Malformed protobuf while extracting transport-level request metadata.
#[derive(Debug, thiserror::Error)]
#[error("invalid request metadata protobuf: {0}")]
pub struct RequestMetadataError(&'static str);

fn protobuf_string_field(
    mut request: &[u8],
    target_field: u32,
) -> Result<Option<&str>, RequestMetadataError> {
    while !request.is_empty() {
        let key = take_varint(&mut request)?;
        let field = u32::try_from(key >> 3).map_err(|_| RequestMetadataError("field overflow"))?;
        let wire = (key & 0x07) as u8;
        if field == 0 {
            return Err(RequestMetadataError("field zero"));
        }
        match wire {
            0 => {
                let _ = take_varint(&mut request)?;
            }
            1 => {
                let _ = take_bytes(&mut request, 8)?;
            }
            2 => {
                let length = usize::try_from(take_varint(&mut request)?)
                    .map_err(|_| RequestMetadataError("length overflow"))?;
                let value = take_bytes(&mut request, length)?;
                if field == target_field {
                    return std::str::from_utf8(value)
                        .map(Some)
                        .map_err(|_| RequestMetadataError("operation id is not UTF-8"));
                }
            }
            5 => {
                let _ = take_bytes(&mut request, 4)?;
            }
            _ => return Err(RequestMetadataError("unsupported wire type")),
        }
    }
    Ok(None)
}

fn take_varint(input: &mut &[u8]) -> Result<u64, RequestMetadataError> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let (&byte, rest) = input
            .split_first()
            .ok_or(RequestMetadataError("truncated varint"))?;
        *input = rest;
        if shift == 63 && byte > 1 {
            return Err(RequestMetadataError("varint overflow"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(RequestMetadataError("varint overflow"))
}

fn take_bytes<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], RequestMetadataError> {
    if input.len() < length {
        return Err(RequestMetadataError("truncated field"));
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

/// Transport-neutral information passed from an operation-stream decoder to a
/// contract router before the request body is decoded.
#[derive(Debug)]
pub struct RoutedCall<'a> {
    /// Generated contract descriptor selected by the fully-qualified path.
    pub method: &'static MethodDescriptor,
    /// Typed authentication, deadline, idempotency, and trace fields.
    pub context: &'a CallContext,
}

impl<'a> RoutedCall<'a> {
    /// Selects a generated route or returns `None` for an unknown method path.
    pub fn new(path: &str, context: &'a CallContext) -> Option<Self> {
        method_descriptor(path).map(|method| Self { method, context })
    }
}

// SPDX-License-Identifier: Apache-2.0

use prost::Message;

use crate::heddle::api::v1alpha1::{CallContext, CallFailure};

/// Largest fully-qualified method path accepted by the hosted-call protocol.
pub const MAX_METHOD_PATH: usize = 1024;
/// Largest encoded call context accepted before dispatch.
pub const MAX_CALL_CONTEXT: usize = 64 * 1024;
/// Largest protobuf control body carried in a FIN-delimited frame.
pub const MAX_CONTROL_BODY: usize = 8 * 1024 * 1024;

const RESPONSE_SUCCESS: u8 = 0;
const RESPONSE_FAILURE: u8 = 1;
const STREAM_MESSAGE: u8 = 0;
const STREAM_FAILURE: u8 = 1;
const STREAM_HEADER: usize = 5;

/// Malformed or oversized hosted-call framing.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// A length or path violates the contract ceiling.
    #[error("invalid hosted-call frame: {0}")]
    Invalid(String),
    /// A protobuf context or failure envelope could not be decoded.
    #[error("invalid hosted-call protobuf: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Decoded request whose body remains borrowed from the FIN-delimited frame.
#[derive(Debug)]
pub struct RequestFrame<'a> {
    /// Canonical fully-qualified method path.
    pub method: &'a str,
    /// Typed call metadata decoded before routing.
    pub context: CallContext,
    /// Encoded method request body.
    pub body: &'a [u8],
}

/// Decoded unary response outcome.
#[derive(Debug)]
pub enum ResponseFrame<'a> {
    /// Encoded successful response body.
    Success(&'a [u8]),
    /// Contract-owned failure envelope.
    Failure(CallFailure),
}

/// One length-delimited item within a server or bidirectional stream.
#[derive(Debug)]
pub enum StreamFrame<'a> {
    /// Encoded protobuf stream message.
    Message(&'a [u8]),
    /// Terminal contract-owned failure.
    Failure(CallFailure),
}

/// Encodes `method_len:u16be | context_len:u32be | method | context | body`.
/// The operation stream FIN is the outer delimiter.
pub fn encode_request_frame(
    method: &str,
    context: &CallContext,
    body: &[u8],
) -> Result<Vec<u8>, FrameError> {
    validate_method(method)?;
    validate_body(body)?;
    let context = context.encode_to_vec();
    if context.len() > MAX_CALL_CONTEXT {
        return Err(FrameError::Invalid(format!(
            "call context is {} bytes; maximum is {MAX_CALL_CONTEXT}",
            context.len()
        )));
    }
    let method_len = u16::try_from(method.len())
        .map_err(|_| FrameError::Invalid("method path exceeds u16".to_string()))?;
    let context_len = u32::try_from(context.len())
        .map_err(|_| FrameError::Invalid("call context exceeds u32".to_string()))?;
    let mut frame = Vec::with_capacity(6 + method.len() + context.len() + body.len());
    frame.extend_from_slice(&method_len.to_be_bytes());
    frame.extend_from_slice(&context_len.to_be_bytes());
    frame.extend_from_slice(method.as_bytes());
    frame.extend_from_slice(&context);
    frame.extend_from_slice(body);
    Ok(frame)
}

/// Decodes a complete FIN-delimited request frame.
pub fn decode_request_frame(frame: &[u8]) -> Result<RequestFrame<'_>, FrameError> {
    if frame.len() < 6 {
        return Err(FrameError::Invalid(
            "request prelude is truncated".to_string(),
        ));
    }
    let method_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let context_len = u32::from_be_bytes([frame[2], frame[3], frame[4], frame[5]]) as usize;
    if method_len == 0 || method_len > MAX_METHOD_PATH || context_len > MAX_CALL_CONTEXT {
        return Err(FrameError::Invalid(
            "request prelude declares an invalid length".to_string(),
        ));
    }
    let context_start = 6_usize
        .checked_add(method_len)
        .ok_or_else(|| FrameError::Invalid("request length overflow".to_string()))?;
    let body_start = context_start
        .checked_add(context_len)
        .ok_or_else(|| FrameError::Invalid("request length overflow".to_string()))?;
    if body_start > frame.len() {
        return Err(FrameError::Invalid(
            "request frame is truncated".to_string(),
        ));
    }
    let method = std::str::from_utf8(&frame[6..context_start])
        .map_err(|_| FrameError::Invalid("method path is not UTF-8".to_string()))?;
    validate_method(method)?;
    let body = &frame[body_start..];
    validate_body(body)?;
    Ok(RequestFrame {
        method,
        context: CallContext::decode(&frame[context_start..body_start])?,
        body,
    })
}

/// Encodes a successful unary response; stream FIN delimits the body.
pub fn encode_success_response(body: &[u8]) -> Result<Vec<u8>, FrameError> {
    validate_body(body)?;
    let mut frame = Vec::with_capacity(1 + body.len());
    frame.push(RESPONSE_SUCCESS);
    frame.extend_from_slice(body);
    Ok(frame)
}

/// Encodes a contract-owned unary failure; stream FIN delimits the envelope.
pub fn encode_failure_response(failure: &CallFailure) -> Result<Vec<u8>, FrameError> {
    let body = failure.encode_to_vec();
    validate_body(&body)?;
    let mut frame = Vec::with_capacity(1 + body.len());
    frame.push(RESPONSE_FAILURE);
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decodes a complete FIN-delimited unary response frame.
pub fn decode_response_frame(frame: &[u8]) -> Result<ResponseFrame<'_>, FrameError> {
    let (&outcome, body) = frame
        .split_first()
        .ok_or_else(|| FrameError::Invalid("response frame is empty".to_string()))?;
    validate_body(body)?;
    match outcome {
        RESPONSE_SUCCESS => Ok(ResponseFrame::Success(body)),
        RESPONSE_FAILURE => Ok(ResponseFrame::Failure(CallFailure::decode(body)?)),
        value => Err(FrameError::Invalid(format!(
            "unknown response outcome {value}"
        ))),
    }
}

/// Encodes one protobuf message for a streaming operation.
pub fn encode_stream_message(body: &[u8]) -> Result<Vec<u8>, FrameError> {
    encode_stream_item(STREAM_MESSAGE, body)
}

/// Encodes one terminal failure for a streaming operation.
pub fn encode_stream_failure(failure: &CallFailure) -> Result<Vec<u8>, FrameError> {
    encode_stream_item(STREAM_FAILURE, &failure.encode_to_vec())
}

/// Decodes one item from a streaming receive buffer.
///
/// Returns `Ok(None)` until the buffer contains the complete declared item.
/// The consumed length lets callers retain any following frames already read.
pub fn decode_stream_frame(buffer: &[u8]) -> Result<Option<(StreamFrame<'_>, usize)>, FrameError> {
    if buffer.len() < STREAM_HEADER {
        return Ok(None);
    }
    let kind = buffer[0];
    let body_len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    if body_len > MAX_CONTROL_BODY {
        return Err(FrameError::Invalid(format!(
            "stream item is {body_len} bytes; maximum is {MAX_CONTROL_BODY}"
        )));
    }
    let consumed = STREAM_HEADER
        .checked_add(body_len)
        .ok_or_else(|| FrameError::Invalid("stream item length overflow".to_string()))?;
    if buffer.len() < consumed {
        return Ok(None);
    }
    let body = &buffer[STREAM_HEADER..consumed];
    let frame = match kind {
        STREAM_MESSAGE => StreamFrame::Message(body),
        STREAM_FAILURE => StreamFrame::Failure(CallFailure::decode(body)?),
        value => {
            return Err(FrameError::Invalid(format!(
                "unknown stream item kind {value}"
            )));
        }
    };
    Ok(Some((frame, consumed)))
}

fn encode_stream_item(kind: u8, body: &[u8]) -> Result<Vec<u8>, FrameError> {
    validate_body(body)?;
    let body_len = u32::try_from(body.len())
        .map_err(|_| FrameError::Invalid("stream item exceeds u32".to_string()))?;
    let mut frame = Vec::with_capacity(STREAM_HEADER + body.len());
    frame.push(kind);
    frame.extend_from_slice(&body_len.to_be_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

fn validate_method(method: &str) -> Result<(), FrameError> {
    if method.is_empty() || !method.starts_with('/') || method.len() > MAX_METHOD_PATH {
        return Err(FrameError::Invalid(
            "method path must begin with '/' and fit the method-path limit".to_string(),
        ));
    }
    Ok(())
}

fn validate_body(body: &[u8]) -> Result<(), FrameError> {
    if body.len() > MAX_CONTROL_BODY {
        return Err(FrameError::Invalid(format!(
            "control body is {} bytes; maximum is {MAX_CONTROL_BODY}",
            body.len()
        )));
    }
    Ok(())
}

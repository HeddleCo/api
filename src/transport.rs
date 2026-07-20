// SPDX-License-Identifier: Apache-2.0

use crate::heddle::api::v1alpha1::{
    CallContext, DeploymentTarget, RetryBehavior, RpcEffect, ServiceMaturity, SigningTier,
};

/// Production ALPN for the first transport-neutral hosted-call protocol.
pub const HOSTED_ALPN_V1: &[u8] = b"heddle-api/1";

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

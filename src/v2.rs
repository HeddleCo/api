//! Shared v2 client behavior. Transport adapters retain key and connection ownership.
pub mod client;
use crate::StreamingShape;
use crate::heddle::api::v1alpha1::{
    AuthorizationAccess, DeploymentTarget, RetryBehavior, RpcEffect, ServiceMaturity, SigningTier,
};
use crate::heddle::api::v2alpha1::{StreamDataKind, StreamFrame, stream_frame};

include!(concat!(env!("OUT_DIR"), "/heddle_api_v2_methods.rs"));

/// Upper bound for an opaque observation cursor; independent of payload limits.
pub const MAX_CURSOR_BYTES: usize = 4096;

/// Invalid stream framing must never advance a client's durable observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StreamProtocolError {
    #[error("non-contiguous stream sequence")]
    Sequence,
    #[error("stream query binding mismatch")]
    Binding,
    #[error("stream resumed from an unexpected cursor")]
    Resume,
    #[error("invalid stream phase")]
    Phase,
    #[error("payload does not match the frame kind")]
    Payload,
    #[error("invalid or oversized checkpoint cursor")]
    Cursor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Opening,
    Snapshot,
    Live,
    Reset,
    Complete,
}

/// Instructions for the typed view reducer. Apply staged data atomically at
/// Commit, and persist the cursor only after that reducer succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationAction {
    BeginSnapshot,
    Resumed,
    Stage(StreamDataKind),
    Commit,
    Heartbeat,
    Reset,
    Complete,
}

#[derive(Debug, thiserror::Error)]
pub enum ObservationApplyError<E> {
    #[error("stream protocol failed: {0}")]
    Protocol(#[from] StreamProtocolError),
    #[error("view reducer failed: {0}")]
    Reducer(E),
}

/// Cursor and lifecycle tracker; typed consumers own staged view data.
#[derive(Clone)]
pub struct ObservationState {
    binding_digest: [u8; 32],
    cursor: Vec<u8>,
    sequence: u64,
    phase: Phase,
    pending: bool,
}

impl ObservationState {
    /// Advances this tracker only after the view reducer succeeds. At Commit,
    /// the reducer must atomically apply staged data and persist the supplied
    /// cursor. A failed reducer leaves the tracker at its previous checkpoint.
    pub async fn apply<E, F, Fut>(
        &mut self,
        frame: &StreamFrame,
        has_payload: bool,
        reducer: F,
    ) -> Result<ObservationAction, ObservationApplyError<E>>
    where
        F: FnOnce(ObservationAction, Vec<u8>) -> Fut,
        Fut: std::future::Future<Output = Result<(), E>>,
    {
        let mut next = self.clone();
        let action = next.accept(frame, has_payload)?;
        reducer(action, next.cursor.clone())
            .await
            .map_err(ObservationApplyError::Reducer)?;
        *self = next;
        Ok(action)
    }

    pub fn new(binding_digest: [u8; 32], cursor: Vec<u8>) -> Self {
        Self {
            binding_digest,
            cursor,
            sequence: 0,
            phase: Phase::Opening,
            pending: false,
        }
    }

    pub fn cursor(&self) -> &[u8] {
        &self.cursor
    }

    pub fn is_complete(&self) -> bool {
        self.phase == Phase::Complete
    }

    /// Validate a frame before changing lifecycle state. A rejected frame leaves
    /// the state unchanged. Transport adapters enforce negotiated byte budgets
    /// before decoding; callers validate the method-specific typed payload.
    ///
    /// For reducers that can fail, run this on a clone, apply the returned action,
    /// then replace the original tracker only if the reducer succeeds.
    pub fn accept(
        &mut self,
        frame: &StreamFrame,
        has_payload: bool,
    ) -> Result<ObservationAction, StreamProtocolError> {
        use stream_frame::Body;
        if matches!(self.phase, Phase::Reset | Phase::Complete) {
            return Err(StreamProtocolError::Phase);
        }
        if self.sequence.checked_add(1) != Some(frame.sequence) {
            return Err(StreamProtocolError::Sequence);
        }
        let body = frame.body.as_ref().ok_or(StreamProtocolError::Phase)?;
        if has_payload != matches!(body, Body::Data(_)) {
            return Err(StreamProtocolError::Payload);
        }
        let action = match body {
            Body::Open(open) => {
                if self.phase != Phase::Opening {
                    return Err(StreamProtocolError::Phase);
                }
                if open.binding_digest.as_slice() != self.binding_digest {
                    return Err(StreamProtocolError::Binding);
                }
                if open.resumed_from != self.cursor {
                    return Err(StreamProtocolError::Resume);
                }
                if self.cursor.len() > MAX_CURSOR_BYTES {
                    return Err(StreamProtocolError::Cursor);
                }
                if self.cursor.is_empty() {
                    self.phase = Phase::Snapshot;
                    ObservationAction::BeginSnapshot
                } else {
                    self.phase = Phase::Live;
                    ObservationAction::Resumed
                }
            }
            Body::Data(data) => {
                let kind =
                    StreamDataKind::try_from(data.kind).map_err(|_| StreamProtocolError::Phase)?;
                let valid = match self.phase {
                    Phase::Snapshot => kind == StreamDataKind::Snapshot,
                    Phase::Live => matches!(kind, StreamDataKind::Upsert | StreamDataKind::Remove),
                    _ => false,
                };
                if !valid {
                    return Err(StreamProtocolError::Phase);
                }
                self.pending = true;
                ObservationAction::Stage(kind)
            }
            Body::Checkpoint(checkpoint) => {
                if !matches!(self.phase, Phase::Snapshot | Phase::Live)
                    || checkpoint.snapshot_complete != (self.phase == Phase::Snapshot)
                {
                    return Err(StreamProtocolError::Phase);
                }
                if checkpoint.previous_cursor != self.cursor
                    || checkpoint.cursor.is_empty()
                    || checkpoint.cursor.len() > MAX_CURSOR_BYTES
                    || checkpoint.cursor == self.cursor
                {
                    return Err(StreamProtocolError::Cursor);
                }
                self.cursor.clone_from(&checkpoint.cursor);
                self.phase = Phase::Live;
                self.pending = false;
                ObservationAction::Commit
            }
            Body::Reset(_) => {
                self.phase = Phase::Reset;
                self.cursor.clear();
                self.pending = false;
                ObservationAction::Reset
            }
            Body::Complete(complete) => {
                if self.phase != Phase::Live || self.pending {
                    return Err(StreamProtocolError::Phase);
                }
                if complete.cursor != self.cursor {
                    return Err(StreamProtocolError::Cursor);
                }
                self.phase = Phase::Complete;
                ObservationAction::Complete
            }
            Body::Heartbeat(_) => {
                if self.phase == Phase::Opening {
                    return Err(StreamProtocolError::Phase);
                }
                ObservationAction::Heartbeat
            }
        };
        self.sequence = frame.sequence;
        Ok(action)
    }
}

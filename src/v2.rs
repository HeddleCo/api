//! Shared v2 client behavior. Transport adapters retain key and connection ownership.
use crate::heddle::api::v2alpha1::StreamFrame;

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
}

/// Cursor and lifecycle tracker; typed consumers own staged view data.
pub struct ObservationState {
    cursor: Vec<u8>,
}

impl ObservationState {
    pub fn new(_binding_digest: [u8; 32], cursor: Vec<u8>) -> Self {
        Self { cursor }
    }

    pub fn cursor(&self) -> &[u8] {
        &self.cursor
    }

    pub fn is_complete(&self) -> bool {
        false
    }

    pub fn accept(&mut self, _frame: &StreamFrame, _has_payload: bool) -> Result<(), StreamProtocolError> {
        Ok(())
    }
}

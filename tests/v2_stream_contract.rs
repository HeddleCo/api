//! Behavioral conformance for the shared v2 observation protocol.
use heddle_api::v2::{ObservationState, StreamProtocolError};
use heddle_api::heddle::api::v2alpha1::{
    StreamCheckpoint, StreamComplete, StreamData, StreamDataKind, StreamFrame,
    StreamOpen, stream_frame,
};

fn frame(sequence: u64, body: stream_frame::Body) -> StreamFrame {
    StreamFrame { sequence, body: Some(body) }
}

fn open(resumed_from: &[u8]) -> stream_frame::Body {
    stream_frame::Body::Open(StreamOpen {
        binding_digest: vec![7; 32],
        resumed_from: resumed_from.to_vec(),
        ..Default::default()
    })
}

fn checkpoint(cursor: &[u8], previous: &[u8], snapshot: bool) -> stream_frame::Body {
    stream_frame::Body::Checkpoint(StreamCheckpoint {
        cursor: cursor.to_vec(), previous_cursor: previous.to_vec(),
        snapshot_complete: snapshot, page: None,
    })
}

#[test]
fn capture_reply_loss_resumes_only_committed_observations() {
    let mut state = ObservationState::new([7; 32], Vec::new());
    state.accept(&frame(1, open(&[])), false).expect("open snapshot");
    state.accept(&frame(2, stream_frame::Body::Data(StreamData {
        kind: StreamDataKind::Snapshot as i32,
    })), true).expect("stage initial thread");
    assert_eq!(state.cursor(), b"", "partial snapshot is not resumable");
    state.accept(&frame(3, checkpoint(b"s0", b"", true)), false).expect("commit snapshot");
    state.accept(&frame(4, stream_frame::Body::Data(StreamData {
        kind: StreamDataKind::Upsert as i32,
    })), true).expect("stage captured revision");
    assert_eq!(state.cursor(), b"s0", "lost update must replay from committed state");
    let mut resumed = ObservationState::new([7; 32], state.cursor().to_vec());
    resumed.accept(&frame(1, open(b"s0")), false).expect("resume accepted");
    resumed.accept(&frame(2, stream_frame::Body::Data(StreamData {
        kind: StreamDataKind::Upsert as i32,
    })), true).expect("replayed revision");
    resumed.accept(&frame(3, checkpoint(b"s1", b"s0", false)), false).expect("commit replay");
    assert_eq!(resumed.cursor(), b"s1");
}

#[test]
fn missing_update_frame_does_not_advance_cursor() {
    let mut state = ObservationState::new([7; 32], Vec::new());
    state.accept(&frame(1, open(&[])), false).expect("open");
    assert_eq!(state.accept(&frame(3, checkpoint(b"s0", b"", true)), false),
        Err(StreamProtocolError::Sequence));
    assert_eq!(state.cursor(), b"");
}

#[test]
fn cursor_cannot_cross_query_bindings_or_be_silently_replaced() {
    let mut wrong_query = ObservationState::new([8; 32], Vec::new());
    assert_eq!(wrong_query.accept(&frame(1, open(&[])), false),
        Err(StreamProtocolError::Binding));
    let mut state = ObservationState::new([7; 32], b"s0".to_vec());
    assert_eq!(state.accept(&frame(1, open(b"other")), false),
        Err(StreamProtocolError::Resume));
}

#[test]
fn end_before_snapshot_boundary_is_incomplete() {
    let mut state = ObservationState::new([7; 32], Vec::new());
    state.accept(&frame(1, open(&[])), false).expect("open");
    assert_eq!(state.accept(&frame(2, stream_frame::Body::Complete(StreamComplete {
        cursor: Vec::new(),
    })), false), Err(StreamProtocolError::Phase));
    assert!(!state.is_complete());
}

#[test]
fn controls_cannot_smuggle_unaccounted_payloads() {
    let mut state = ObservationState::new([7; 32], Vec::new());
    assert_eq!(state.accept(&frame(1, open(&[])), true), Err(StreamProtocolError::Payload));
}

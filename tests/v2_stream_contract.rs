//! Behavioral conformance for the shared v2 observation protocol.
use heddle_api::heddle::api::v2alpha1::{
    StreamCheckpoint, StreamComplete, StreamData, StreamDataKind, StreamFrame, StreamOpen,
    stream_frame,
};
use heddle_api::v2::{ObservationState, StreamProtocolError};

#[test]
fn shared_stream_wire_vectors_match_rust_codec() {
    use heddle_api::framing::{
        decode_stream_frame, encode_stream_failure, encode_stream_message, encode_stream_raw_body,
    };
    use heddle_api::heddle::api::v1alpha1::CallFailure;
    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/v2-stream-wire.json"))
            .expect("shared fixtures");
    assert!(
        !vectors.is_empty(),
        "wire parity cannot pass with no vectors"
    );
    for vector in vectors {
        let kind = vector["kind"].as_str().expect("vector kind");
        let encoded = match kind {
            "message" => encode_stream_message(
                &hex::decode(vector["body_hex"].as_str().expect("body")).expect("hex body"),
            )
            .expect("message frame"),
            "failure" => encode_stream_failure(&CallFailure {
                code: vector["code"].as_i64().expect("code") as i32,
                message: vector["message"].as_str().expect("message").into(),
                error: None,
            })
            .expect("failure frame"),
            "raw_body" => encode_stream_raw_body(
                vector["length"]
                    .as_str()
                    .expect("length")
                    .parse()
                    .expect("u64 length"),
            )
            .expect("raw header"),
            _ => panic!("unknown fixture kind"),
        };
        assert_eq!(
            hex::encode(&encoded),
            vector["frame_hex"].as_str().expect("wire bytes")
        );
        for cut in 0..encoded.len() {
            assert!(
                decode_stream_frame(&encoded[..cut])
                    .expect("valid prefix")
                    .is_none()
            );
        }
        assert_eq!(
            decode_stream_frame(&encoded)
                .expect("frame")
                .expect("complete frame")
                .1,
            encoded.len()
        );
    }
}

#[test]
fn oversized_cursor_cannot_replace_a_committed_checkpoint() {
    let mut state = ObservationState::new([7; 32], b"s0".to_vec());
    state.accept(&frame(1, open(b"s0")), false).expect("resume");
    assert_eq!(
        state.accept(&frame(2, checkpoint(&vec![1; 4097], b"s0", false)), false),
        Err(StreamProtocolError::Cursor)
    );
    assert_eq!(state.cursor(), b"s0");
}

fn frame(sequence: u64, body: stream_frame::Body) -> StreamFrame {
    StreamFrame {
        sequence,
        body: Some(body),
    }
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
        cursor: cursor.to_vec(),
        previous_cursor: previous.to_vec(),
        snapshot_complete: snapshot,
        page: None,
    })
}

#[test]
fn capture_reply_loss_resumes_only_committed_observations() {
    let mut state = ObservationState::new([7; 32], Vec::new());
    state
        .accept(&frame(1, open(&[])), false)
        .expect("open snapshot");
    state
        .accept(
            &frame(
                2,
                stream_frame::Body::Data(StreamData {
                    kind: StreamDataKind::Snapshot as i32,
                }),
            ),
            true,
        )
        .expect("stage initial thread");
    assert_eq!(state.cursor(), b"", "partial snapshot is not resumable");
    state
        .accept(&frame(3, checkpoint(b"s0", b"", true)), false)
        .expect("commit snapshot");
    state
        .accept(
            &frame(
                4,
                stream_frame::Body::Data(StreamData {
                    kind: StreamDataKind::Upsert as i32,
                }),
            ),
            true,
        )
        .expect("stage captured revision");
    assert_eq!(
        state.cursor(),
        b"s0",
        "lost update must replay from committed state"
    );
    let mut resumed = ObservationState::new([7; 32], state.cursor().to_vec());
    resumed
        .accept(&frame(1, open(b"s0")), false)
        .expect("resume accepted");
    resumed
        .accept(
            &frame(
                2,
                stream_frame::Body::Data(StreamData {
                    kind: StreamDataKind::Upsert as i32,
                }),
            ),
            true,
        )
        .expect("replayed revision");
    resumed
        .accept(&frame(3, checkpoint(b"s1", b"s0", false)), false)
        .expect("commit replay");
    assert_eq!(resumed.cursor(), b"s1");
}

#[test]
fn missing_update_frame_does_not_advance_cursor() {
    let mut state = ObservationState::new([7; 32], Vec::new());
    state.accept(&frame(1, open(&[])), false).expect("open");
    assert_eq!(
        state.accept(&frame(3, checkpoint(b"s0", b"", true)), false),
        Err(StreamProtocolError::Sequence)
    );
    assert_eq!(state.cursor(), b"");
}

#[test]
fn cursor_cannot_cross_query_bindings_or_be_silently_replaced() {
    let mut wrong_query = ObservationState::new([8; 32], Vec::new());
    assert_eq!(
        wrong_query.accept(&frame(1, open(&[])), false),
        Err(StreamProtocolError::Binding)
    );
    let mut state = ObservationState::new([7; 32], b"s0".to_vec());
    assert_eq!(
        state.accept(&frame(1, open(b"other")), false),
        Err(StreamProtocolError::Resume)
    );
}

#[test]
fn end_before_snapshot_boundary_is_incomplete() {
    let mut state = ObservationState::new([7; 32], Vec::new());
    state.accept(&frame(1, open(&[])), false).expect("open");
    assert_eq!(
        state.accept(
            &frame(
                2,
                stream_frame::Body::Complete(StreamComplete { cursor: Vec::new() })
            ),
            false
        ),
        Err(StreamProtocolError::Phase)
    );
    assert!(!state.is_complete());
}

#[test]
fn controls_cannot_smuggle_unaccounted_payloads() {
    let mut state = ObservationState::new([7; 32], Vec::new());
    assert_eq!(
        state.accept(&frame(1, open(&[])), true),
        Err(StreamProtocolError::Payload)
    );
}

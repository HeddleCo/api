//! Native clients use generated typed methods, with no network runtime in this crate.
use std::{
    collections::VecDeque,
    future::{Future, ready},
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

use heddle_api::heddle::api::v2alpha1::{
    ObserveThreadsRequest, StartThreadRequest, ThreadListEvent, ThreadMutationResponse,
    ThreadOverview, thread_list_event,
};
use heddle_api::v2::{
    MethodDescriptor,
    client::{Client, ClientError, MessageReader, MessageWriter, RpcTransport},
    rpc,
};
use prost::Message;

#[derive(Clone, Default)]
struct TestTransport {
    calls: Arc<Mutex<Vec<String>>>,
    cancelled: Arc<AtomicBool>,
}

struct TestReader {
    messages: VecDeque<Vec<u8>>,
    cancelled: Arc<AtomicBool>,
}

impl MessageReader for TestReader {
    type Error = io::Error;
    fn next(&mut self) -> impl Future<Output = Result<Option<Vec<u8>>, io::Error>> {
        ready(Ok(self.messages.pop_front()))
    }
    fn cancel(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

struct TestWriter;

#[test]
fn adapter_extracts_operation_identity_from_v2_descriptor() {
    use heddle_api::v2::client::Rpc;
    let request = StartThreadRequest {
        client_operation_id: "start-1".into(),
        ..Default::default()
    };
    assert_eq!(
        rpc::ThreadServiceStartThread::METHOD
            .client_operation_id(&request.encode_to_vec())
            .expect("metadata"),
        Some("start-1")
    );
    assert_eq!(
        rpc::ThreadServiceObserveThreads::METHOD
            .client_operation_id(&ObserveThreadsRequest::default().encode_to_vec())
            .expect("read metadata"),
        None
    );
}

#[test]
fn blob_source_is_exclusive_and_preserves_an_exact_hash() {
    use heddle_api::heddle::api::v2alpha1::{BlobRead, blob_read};
    let request = BlobRead {
        source: Some(blob_read::Source::ObjectHash(vec![7; 32])),
        offset: 11,
        length: 17,
    };
    assert_eq!(
        BlobRead::decode(request.encode_to_vec().as_slice()).expect("blob source"),
        request
    );
}
impl MessageWriter for TestWriter {
    type Error = io::Error;
    fn send(&mut self, _: Vec<u8>) -> impl Future<Output = Result<(), io::Error>> {
        ready(Ok(()))
    }
    fn finish(&mut self) -> impl Future<Output = Result<(), io::Error>> {
        ready(Ok(()))
    }
    fn abort(&mut self) {}
}

impl RpcTransport for TestTransport {
    type Error = io::Error;
    type Reader = TestReader;
    type Writer = TestWriter;
    fn unary(
        &self,
        method: &'static MethodDescriptor,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, io::Error>> {
        self.calls
            .lock()
            .expect("trace mutex")
            .push(method.path.into());
        let request = StartThreadRequest::decode(bytes.as_slice()).expect("typed request");
        assert_eq!(request.client_operation_id, "original-op");
        ready(Ok(ThreadMutationResponse {
            thread: Some(ThreadOverview {
                name: request.name,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()))
    }
    fn observe(
        &self,
        method: &'static MethodDescriptor,
        _: Vec<u8>,
    ) -> impl Future<Output = Result<TestReader, io::Error>> {
        self.calls
            .lock()
            .expect("trace mutex")
            .push(method.path.into());
        let event = ThreadListEvent {
            frame: None,
            payload: Some(thread_list_event::Payload::Thread(ThreadOverview {
                name: "first".into(),
                ..Default::default()
            })),
        };
        ready(Ok(TestReader {
            messages: VecDeque::from([event.encode_to_vec(), event.encode_to_vec()]),
            cancelled: self.cancelled.clone(),
        }))
    }
    fn exchange(
        &self,
        _: &'static MethodDescriptor,
        _: Vec<u8>,
    ) -> impl Future<Output = Result<(TestWriter, TestReader), io::Error>> {
        ready(Err(io::Error::other("unused test transport route")))
    }
}

fn completed<F: Future + Send>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test transport futures complete synchronously"),
    }
}

#[test]
fn typed_mutation_preserves_operation_identity_and_response() {
    let transport = TestTransport::default();
    let trace = transport.calls.clone();
    let client = Client::new(
        transport,
        ["/heddle.api.v2alpha1.ThreadService/StartThread".into()],
    );
    let response = completed(
        client.call::<rpc::ThreadServiceStartThread>(&StartThreadRequest {
            client_operation_id: "original-op".into(),
            name: "intent".into(),
            ..Default::default()
        }),
    )
    .expect("typed call");
    assert_eq!(response.thread.expect("resulting thread").name, "intent");
    assert_eq!(trace.lock().expect("trace mutex").len(), 1);
}

#[test]
fn unknown_handler_and_missing_operation_id_never_reach_transport() {
    let transport = TestTransport::default();
    let trace = transport.calls.clone();
    let unsupported = Client::new(transport.clone(), []);
    assert!(matches!(
        completed(
            unsupported.call::<rpc::ThreadServiceStartThread>(&StartThreadRequest::default())
        ),
        Err(ClientError::NotImplemented(_))
    ));
    let supported = Client::new(
        transport,
        ["/heddle.api.v2alpha1.ThreadService/StartThread".into()],
    );
    assert!(matches!(
        completed(supported.call::<rpc::ThreadServiceStartThread>(&StartThreadRequest::default())),
        Err(ClientError::MissingOperationId(_))
    ));
    assert!(trace.lock().expect("trace mutex").is_empty());
}

#[test]
fn dropping_a_live_observation_cancels_only_its_stream() {
    let transport = TestTransport::default();
    let cancelled = transport.cancelled.clone();
    let client = Client::new(
        transport,
        ["/heddle.api.v2alpha1.ThreadService/ObserveThreads".into()],
    );
    let mut events = completed(
        client.observe::<rpc::ThreadServiceObserveThreads>(&ObserveThreadsRequest::default()),
    )
    .expect("open observation");
    assert!(completed(events.next()).expect("first item").is_some());
    assert!(!cancelled.load(Ordering::SeqCst));
    drop(events);
    assert!(cancelled.load(Ordering::SeqCst));
}

#[test]
fn explicit_cancellation_ends_a_live_observation_without_draining_it() {
    let transport = TestTransport::default();
    let cancelled = transport.cancelled.clone();
    let client = Client::new(
        transport,
        ["/heddle.api.v2alpha1.ThreadService/ObserveThreads".into()],
    );
    let mut events = completed(
        client.observe::<rpc::ThreadServiceObserveThreads>(&ObserveThreadsRequest::default()),
    )
    .expect("observation");
    events.cancel();
    events.cancel();
    assert!(cancelled.load(Ordering::SeqCst));
    assert!(
        completed(events.next())
            .expect("cancelled stream")
            .is_none()
    );
}

#[test]
fn failed_reducer_leaves_the_last_resumable_checkpoint() {
    use heddle_api::heddle::api::v2alpha1::{
        StreamCheckpoint, StreamFrame, StreamOpen, stream_frame,
    };
    use heddle_api::v2::{ObservationApplyError, ObservationState};
    let mut state = ObservationState::new([7; 32], Vec::new());
    state
        .accept(
            &StreamFrame {
                sequence: 1,
                body: Some(stream_frame::Body::Open(StreamOpen {
                    binding_digest: vec![7; 32],
                    ..Default::default()
                })),
            },
            false,
        )
        .expect("open");
    let checkpoint = StreamFrame {
        sequence: 2,
        body: Some(stream_frame::Body::Checkpoint(StreamCheckpoint {
            cursor: b"s0".to_vec(),
            snapshot_complete: true,
            ..Default::default()
        })),
    };
    let result = completed(state.apply(&checkpoint, false, |_, _| {
        ready(Err(io::Error::other("store unavailable")))
    }));
    assert!(matches!(result, Err(ObservationApplyError::Reducer(_))));
    assert_eq!(state.cursor(), b"");
    completed(state.apply(&checkpoint, false, |_, cursor| {
        assert_eq!(cursor, b"s0");
        ready(Ok::<_, io::Error>(()))
    }))
    .expect("apply checkpoint");
    assert_eq!(state.cursor(), b"s0");
}

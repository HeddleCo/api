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

use heddle_api::heddle::api::v1alpha2::{
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
    use heddle_api::heddle::api::v1alpha2::{BlobRead, blob_read};
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
        assert_eq!(
            request
                .thread_genesis
                .as_ref()
                .expect("signed genesis retained")
                .canonical_record,
            [1, 2, 3]
        );
        ready(Ok(ThreadMutationResponse {
            thread: Some(ThreadOverview {
                name: "derived from signed genesis".into(),
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
        ["/heddle.api.v1alpha2.ThreadService/StartThread".into()],
    );
    let response = completed(
        client.call::<rpc::ThreadServiceStartThread>(&StartThreadRequest {
            client_operation_id: "original-op".into(),
            thread_genesis: Some(heddle_api::heddle::api::v1alpha2::SignedRecord {
                format: "heddle-thread-genesis-v1".into(),
                canonical_record: vec![1, 2, 3],
                ..Default::default()
            }),
            ..Default::default()
        }),
    )
    .expect("typed call");
    assert_eq!(
        response.thread.expect("resulting thread").name,
        "derived from signed genesis"
    );
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
        ["/heddle.api.v1alpha2.ThreadService/StartThread".into()],
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
        ["/heddle.api.v1alpha2.ThreadService/ObserveThreads".into()],
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
        ["/heddle.api.v1alpha2.ThreadService/ObserveThreads".into()],
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
    use heddle_api::heddle::api::v1alpha2::{
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
                    accepted_budget: Some(heddle_api::v2::GUARANTEED_READ_BUDGET),
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

#[test]
fn old_peer_advertising_import_methods_never_reaches_transport() {
    use heddle_api::heddle::api::{common::ProtocolCompatibility, v1alpha2::*};
    let paths = [
        "ImportSource",
        "RetryImportSource",
        "SynchronizeRemote",
        "PrepareImportJob",
        "CommitImportJob",
        "CancelImportJob",
        "GetHostedWitnessHistoryProof",
        "GetImportJobState",
    ];
    for protocol in [
        None,
        Some(ProtocolCompatibility {
            protocol_version: 1,
            mandatory_features: vec![1],
        }),
        Some(ProtocolCompatibility {
            protocol_version: 2,
            mandatory_features: vec![],
        }),
        Some(ProtocolCompatibility {
            protocol_version: 2,
            mandatory_features: vec![1, 3],
        }),
    ] {
        let trace = TestTransport::default();
        let calls = trace.calls.clone();
        let mut client = Client::new(
            GateTransport {
                frames: vec![],
                trace,
            },
            paths.map(|name| format!("/heddle.api.v1alpha2.IntegrationService/{name}")),
        );
        if let Some(protocol) = protocol {
            client = client.with_protocol(protocol);
        }
        macro_rules! rejects {
            ($rpc:ty, $request:ty) => {
                assert!(matches!(completed(client.call::<$rpc>(&<$request>::default())),
                    Err(ClientError::Protocol(path)) if path == <$rpc as heddle_api::v2::client::Rpc>::METHOD.path));
            };
        }
        rejects!(
            rpc::IntegrationServiceGetImportJobState,
            GetImportJobStateRequest
        );
        rejects!(rpc::IntegrationServiceImportSource, ImportSourceRequest);
        rejects!(
            rpc::IntegrationServiceRetryImportSource,
            RetryImportSourceRequest
        );
        rejects!(
            rpc::IntegrationServiceSynchronizeRemote,
            SynchronizeRemoteRequest
        );
        rejects!(
            rpc::IntegrationServicePrepareImportJob,
            PrepareImportJobRequest
        );
        rejects!(
            rpc::IntegrationServiceCommitImportJob,
            CommitImportJobRequest
        );
        rejects!(
            rpc::IntegrationServiceCancelImportJob,
            CancelImportJobRequest
        );
        rejects!(
            rpc::IntegrationServiceGetHostedWitnessHistoryProof,
            GetHostedWitnessHistoryProofRequest
        );
        assert!(calls.lock().expect("transport calls").is_empty());
    }
}

#[derive(Clone)]
struct GateTransport {
    frames: Vec<Vec<u8>>,
    trace: TestTransport,
}
impl RpcTransport for GateTransport {
    type Error = io::Error;
    type Reader = TestReader;
    type Writer = TestWriter;
    fn unary(
        &self,
        method: &'static MethodDescriptor,
        _: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, io::Error>> {
        self.trace
            .calls
            .lock()
            .expect("trace")
            .push(method.path.into());
        ready(Ok(Vec::new()))
    }
    fn observe(
        &self,
        method: &'static MethodDescriptor,
        _: Vec<u8>,
    ) -> impl Future<Output = Result<TestReader, io::Error>> {
        self.trace
            .calls
            .lock()
            .expect("trace")
            .push(method.path.into());
        ready(Ok(TestReader {
            messages: self.frames.clone().into(),
            cancelled: self.trace.cancelled.clone(),
        }))
    }
    fn exchange(
        &self,
        method: &'static MethodDescriptor,
        _: Vec<u8>,
    ) -> impl Future<Output = Result<(TestWriter, TestReader), io::Error>> {
        self.trace
            .calls
            .lock()
            .expect("trace")
            .push(method.path.into());
        ready(Ok((
            TestWriter,
            TestReader {
                messages: self.frames.clone().into(),
                cancelled: self.trace.cancelled.clone(),
            },
        )))
    }
}
#[test]
fn sync_without_hybrid_encodes_openings_and_accepts_ready() {
    use heddle_api::heddle::api::{common::ProtocolCompatibility, v1alpha2::*};
    for protocol in [
        None,
        Some(ProtocolCompatibility {
            protocol_version: 1,
            mandatory_features: vec![],
        }),
        Some(ProtocolCompatibility {
            protocol_version: 2,
            mandatory_features: vec![],
        }),
        Some(ProtocolCompatibility {
            protocol_version: 2,
            mandatory_features: vec![1],
        }),
    ] {
        macro_rules! exchange {
            ($rpc:ty, $request:expr, $response:expr) => {{
                use heddle_api::v2::client::Rpc;
                let response = $response;
                let trace = TestTransport::default();
                let calls = trace.calls.clone();
                let mut client = Client::new(
                    GateTransport {
                        frames: vec![response.encode_to_vec()],
                        trace,
                    },
                    [<$rpc>::METHOD.path.into()],
                );
                if let Some(protocol) = protocol.clone() {
                    client = client.with_protocol(protocol);
                }
                let (mut sender, mut messages) = completed(client.exchange::<$rpc>(&$request))
                    .expect("ordinary Sync opening without mandatory HYBRID");
                completed(sender.send(&$request))
                    .expect("subsequent frame without mandatory HYBRID");
                assert_eq!(
                    completed(messages.next()).expect("ordinary Sync ready"),
                    Some(response)
                );
                assert_eq!(*calls.lock().expect("trace"), [<$rpc>::METHOD.path]);
            }};
        }
        exchange!(
            rpc::SyncServiceFetch,
            FetchClientFrame {
                body: Some(fetch_client_frame::Body::Open(FetchOpen {
                    protocol: protocol.clone(),
                    ..Default::default()
                }))
            },
            FetchServerFrame {
                body: Some(fetch_server_frame::Body::Ready(TransferReady {
                    protocol: protocol.clone(),
                    ..Default::default()
                }))
            }
        );
        exchange!(
            rpc::SyncServicePublishContent,
            PublishContentClientFrame {
                client_operation_id: "publish-1".into(),
                body: Some(publish_content_client_frame::Body::Open(
                    PublishContentOpen {
                        protocol: protocol.clone(),
                        ..Default::default()
                    }
                ))
            },
            PublishContentServerFrame {
                body: Some(publish_content_server_frame::Body::Ready(
                    TransferReady::default()
                ))
            }
        );
        exchange!(
            rpc::SyncServiceReplicateThread,
            ReplicateThreadRequest {
                body: Some(replicate_thread_request::Body::Open(ReplicationOpen {
                    protocol: protocol.clone(),
                    ..Default::default()
                }))
            },
            ReplicateThreadResponse {
                body: Some(replicate_thread_response::Body::Ready(ReplicationReady {
                    protocol: protocol.clone(),
                    ..Default::default()
                }))
            }
        );
    }
}

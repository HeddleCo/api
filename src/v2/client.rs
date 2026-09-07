//! Typed, statically dispatched clients over caller-owned transport and signers.
use std::{collections::BTreeSet, future::Future, marker::PhantomData};

use prost::Message;

use super::MethodDescriptor;

pub trait Rpc {
    type Request: Message;
    type Response: Message + Default;
    const METHOD: &'static MethodDescriptor;
}
pub trait UnaryRpc: Rpc {}
pub trait ServerStreamingRpc: Rpc {}
pub trait ClientStreamingRpc: Rpc {}
pub trait BidirectionalRpc: Rpc {}

/// Frames are already transport-decoded protobuf messages. Implementations
/// enforce negotiated byte limits before allocating/decoding a frame body.
pub trait MessageReader: Send {
    type Error: std::error::Error + Send + Sync + 'static;
    fn next(&mut self) -> impl Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send;
    /// Stops observation; it does not cancel a durable server operation.
    fn cancel(&mut self);
}

pub trait MessageWriter: Send {
    type Error: std::error::Error + Send + Sync + 'static;
    fn send(&mut self, message: Vec<u8>) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn finish(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn abort(&mut self);
}

/// Owns endpoint selection, credentials, exact-request signing, deadlines and
/// Iroh framing. No automatic write retry or cross-endpoint failover is implied.
/// A streaming implementation pulls input and output under transport flow control.
pub trait RpcTransport: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;
    type Reader: MessageReader<Error = Self::Error>;
    type Writer: MessageWriter<Error = Self::Error>;
    fn unary(
        &self,
        method: &'static MethodDescriptor,
        request: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send;
    fn observe(
        &self,
        method: &'static MethodDescriptor,
        request: Vec<u8>,
    ) -> impl Future<Output = Result<Self::Reader, Self::Error>> + Send;
    fn exchange(
        &self,
        method: &'static MethodDescriptor,
        opening: Vec<u8>,
    ) -> impl Future<Output = Result<(Self::Writer, Self::Reader), Self::Error>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError<E: std::error::Error> {
    #[error("endpoint does not implement {0}")]
    NotImplemented(&'static str),
    #[error("{0} requires a stable client operation ID")]
    MissingOperationId(&'static str),
    #[error("invalid request metadata: {0}")]
    Metadata(#[from] crate::RequestMetadataError),
    #[error("transport failure: {0}")]
    Transport(E),
    #[error("invalid protobuf response: {0}")]
    Decode(#[from] prost::DecodeError),
}

pub struct Client<T> {
    transport: T,
    implemented: BTreeSet<String>,
}

impl<T: RpcTransport> Client<T> {
    /// implemented is the authenticated endpoint's advertised handler set, not
    /// ALL_METHODS or the proto's maturity declarations.
    pub fn new(transport: T, implemented: impl IntoIterator<Item = String>) -> Self {
        Self {
            transport,
            implemented: implemented.into_iter().collect(),
        }
    }

    fn encode<M: Rpc>(&self, request: &M::Request) -> Result<Vec<u8>, ClientError<T::Error>> {
        let method = M::METHOD;
        if !self.implemented.contains(method.path) {
            return Err(ClientError::NotImplemented(method.path));
        }
        let bytes = request.encode_to_vec();
        if method.client_operation_id_required {
            let Some(field) = method.client_operation_id_field_number else {
                return Err(ClientError::MissingOperationId(method.path));
            };
            let id = crate::transport::protobuf_string_field(&bytes, field)?;
            if id.is_none_or(|value| value.trim().is_empty()) {
                return Err(ClientError::MissingOperationId(method.path));
            }
        }
        Ok(bytes)
    }

    pub async fn call<M: UnaryRpc>(
        &self,
        request: &M::Request,
    ) -> Result<M::Response, ClientError<T::Error>> {
        let bytes = self
            .transport
            .unary(M::METHOD, self.encode::<M>(request)?)
            .await
            .map_err(ClientError::Transport)?;
        Ok(M::Response::decode(bytes.as_slice())?)
    }

    pub async fn observe<M: ServerStreamingRpc>(
        &self,
        request: &M::Request,
    ) -> Result<Messages<T::Reader, M::Response>, ClientError<T::Error>> {
        let reader = self
            .transport
            .observe(M::METHOD, self.encode::<M>(request)?)
            .await
            .map_err(ClientError::Transport)?;
        Ok(Messages {
            reader,
            done: false,
            message: PhantomData,
        })
    }

    /// Returns independently borrowable halves so receives cannot block sends.
    pub async fn exchange<M: BidirectionalRpc>(
        &self,
        opening: &M::Request,
    ) -> Result<
        (
            Sender<T::Writer, M::Request>,
            Messages<T::Reader, M::Response>,
        ),
        ClientError<T::Error>,
    > {
        let (writer, reader) = self
            .transport
            .exchange(M::METHOD, self.encode::<M>(opening)?)
            .await
            .map_err(ClientError::Transport)?;
        Ok((
            Sender {
                writer,
                finished: false,
                message: PhantomData,
            },
            Messages {
                reader,
                done: false,
                message: PhantomData,
            },
        ))
    }
}

pub struct Messages<R: MessageReader, O> {
    reader: R,
    done: bool,
    message: PhantomData<O>,
}

impl<R: MessageReader, O: Message + Default> Messages<R, O> {
    pub async fn next(&mut self) -> Result<Option<O>, ClientError<R::Error>> {
        if self.done {
            return Ok(None);
        }
        let decoded = match self.reader.next().await {
            Ok(Some(bytes)) => O::decode(bytes.as_slice())
                .map(Some)
                .map_err(ClientError::Decode),
            Ok(None) => {
                self.done = true;
                Ok(None)
            }
            Err(error) => Err(ClientError::Transport(error)),
        };
        if decoded.is_err() {
            self.reader.cancel();
            self.done = true;
        }
        decoded
    }
}

impl<R: MessageReader, O> Drop for Messages<R, O> {
    fn drop(&mut self) {
        if !self.done {
            self.reader.cancel();
        }
    }
}

pub struct Sender<W: MessageWriter, I> {
    writer: W,
    finished: bool,
    message: PhantomData<I>,
}

impl<W: MessageWriter, I: Message> Sender<W, I> {
    pub async fn send(&mut self, message: &I) -> Result<(), W::Error> {
        self.writer.send(message.encode_to_vec()).await
    }
    pub async fn finish(mut self) -> Result<(), W::Error> {
        self.writer.finish().await?;
        self.finished = true;
        Ok(())
    }
}

impl<W: MessageWriter, I> Drop for Sender<W, I> {
    fn drop(&mut self) {
        if !self.finished {
            self.writer.abort();
        }
    }
}

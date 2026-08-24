//! Transport layer for Strike48 Connector SDK.
//!
//! Provides abstraction over gRPC and WebSocket transports.
//! All transports implement the same trait, allowing seamless switching.
//!
//! # Architecture
//!
//! ```text
//! ConnectorRunner
//!       ↓
//!    Transport (trait)
//!       ↓
//! ┌─────┴─────┐
//! ↓           ↓
//! GrpcTransport    WebSocketTransport
//! (tonic/HTTP2)    (tokio-tungstenite/Phoenix)
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use strike48_connector::transport::{create_transport, TransportType, TransportOptions};
//!
//! let options = TransportOptions {
//!     host: "localhost:4000".to_string(),
//!     use_tls: false,
//!     connect_timeout_ms: Some(5000),
//!     default_timeout_ms: Some(30000),
//! };
//!
//! // Auto-select transport
//! let mut transport = create_transport(TransportType::WebSocket, options);
//! transport.connect().await?;
//!
//! // Send and receive using channels
//! let (tx, rx) = transport.start_stream().await?;
//! tx.send(message).await?;
//! while let Some(msg) = rx.recv().await {
//!     // handle message
//! }
//! ```

pub(crate) mod grpc;
pub mod proxy;
mod websocket;

pub use grpc::GrpcTransport;
pub use websocket::WebSocketTransport;

use crate::error::Result;
use async_trait::async_trait;
use std::fmt;
use strike48_proto::proto::StreamMessage;
use tokio::sync::mpsc;

/// Transport type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportType {
    /// Native gRPC over HTTP/2 (default, best performance)
    #[default]
    Grpc,
    /// WebSocket over HTTP/1.1 (corporate proxy compatible)
    WebSocket,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportType::Grpc => write!(f, "gRPC"),
            TransportType::WebSocket => write!(f, "WebSocket"),
        }
    }
}

/// Transport configuration options.
#[derive(Debug, Clone)]
pub struct TransportOptions {
    /// Strike48 server host (e.g., "connectors-poc-us.strike48.com:443")
    pub host: String,
    /// Use TLS for connection
    pub use_tls: bool,
    /// Connection timeout in milliseconds (default: 10000)
    pub connect_timeout_ms: Option<u64>,
    /// Default operation timeout in milliseconds (default: 30000)
    pub default_timeout_ms: Option<u64>,
    /// Channel capacity for message backpressure (default: 1024)
    /// Set to None for unbounded channels (not recommended for production)
    pub channel_capacity: Option<usize>,
    /// HTTP CONNECT proxy to tunnel through. `None` = direct connection.
    pub proxy: Option<proxy::ProxyConfig>,
}

/// Transport trait - abstraction for gRPC and WebSocket.
///
/// All transports implement this trait, allowing ConnectorRunner
/// to work identically regardless of underlying protocol.
///
/// Key principle: Transports are PURE message passthrough.
/// No business logic, no auth - just move proto messages.
///
/// # Channel-based API
///
/// The `start_stream` method returns channels for bidirectional communication:
/// - `tx` channel: Send messages to the server
/// - `rx` channel: Receive messages from the server
///
/// This provides a unified API that works the same way for both
/// gRPC bidirectional streaming and WebSocket connections.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Get the transport type identifier.
    #[allow(dead_code)]
    fn transport_type(&self) -> TransportType;

    /// Connect to the Strike48 server.
    ///
    /// Establishes the underlying connection (TCP, TLS handshake, etc.)
    /// but does not start the message stream yet.
    async fn connect(&mut self) -> Result<()>;

    /// Start bidirectional message stream.
    ///
    /// Returns channels for sending and receiving protobuf messages.
    /// The transport handles protocol-specific details internally.
    ///
    /// # Arguments
    ///
    /// - `initial_message`: Optional message to send immediately when starting the stream.
    ///   For gRPC, this is required to prevent deadlock - the server waits for a message
    ///   before sending a response.
    ///
    /// # Returns
    ///
    /// - `tx`: Send channel for outgoing messages
    /// - `rx`: Receive channel for incoming messages
    async fn start_stream(
        &mut self,
        initial_message: Option<StreamMessage>,
    ) -> Result<(
        mpsc::UnboundedSender<StreamMessage>,
        mpsc::UnboundedReceiver<StreamMessage>,
    )>;

    /// Check if transport is connected.
    #[allow(dead_code)]
    fn is_connected(&self) -> bool;

    /// Disconnect from the server.
    async fn disconnect(&mut self) -> Result<()>;
}

/// Create a new transport based on the specified type.
pub fn create_transport(
    transport_type: TransportType,
    options: TransportOptions,
) -> Box<dyn Transport> {
    match transport_type {
        TransportType::Grpc => Box::new(GrpcTransport::new(options)),
        TransportType::WebSocket => Box::new(WebSocketTransport::new(options)),
    }
}

/// Create wrapper that converts bounded channels to unbounded API.
///
/// This maintains API compatibility while using bounded channels internally.
/// The wrapper spawns tasks that forward messages between bounded and unbounded
/// channels, applying backpressure when the internal bounded channel is full.
///
/// # Why unbounded API?
///
/// The public API uses unbounded channels for simplicity, but internally we use
/// bounded channels with configurable capacity for memory safety. This wrapper
/// bridges the two, allowing callers to use the simpler unbounded API while
/// maintaining backpressure internally.
pub(crate) fn create_unbounded_wrapper(
    bounded_tx: mpsc::Sender<StreamMessage>,
    bounded_rx: mpsc::Receiver<StreamMessage>,
) -> (
    mpsc::UnboundedSender<StreamMessage>,
    mpsc::UnboundedReceiver<StreamMessage>,
    Vec<tokio::task::JoinHandle<()>>,
) {
    use tracing::debug;

    let (unbounded_tx, mut unbounded_rx_inner) = mpsc::unbounded_channel::<StreamMessage>();
    let (unbounded_tx_out, unbounded_rx) = mpsc::unbounded_channel::<StreamMessage>();

    let h1 = tokio::spawn(async move {
        while let Some(msg) = unbounded_rx_inner.recv().await {
            if bounded_tx.send(msg).await.is_err() {
                debug!("Bounded channel closed, stopping forwarder");
                break;
            }
        }
    });

    let mut bounded_rx = bounded_rx;
    let h2 = tokio::spawn(async move {
        while let Some(msg) = bounded_rx.recv().await {
            if unbounded_tx_out.send(msg).is_err() {
                debug!("Unbounded channel closed, stopping forwarder");
                break;
            }
        }
    });

    (unbounded_tx, unbounded_rx, vec![h1, h2])
}

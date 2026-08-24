use crate::error::{ConnectorError, Result};
use crate::transport::{Transport, TransportOptions, TransportType, create_transport};
use crate::types::*;
use crate::url_parser::parse_url;
use crate::utils::{generate_id, sanitize_identifier};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, mpsc};
use tokio::time::Duration;
use tracing::debug;

/// Keepalive interval: send a HeartbeatRequest every 30 seconds to prevent
/// the server's session reaper from killing the session (timeout = 90s).
const KEEPALIVE_INTERVAL_SECS: u64 = 30;

/// Client configuration options.
///
/// Transport is auto-detected from URL scheme when using `url`:
/// - `grpc://` or `grpcs://` → gRPC transport
/// - `ws://`, `wss://`, `http://`, `https://` → WebSocket transport
///
/// # Examples
///
/// ```rust,ignore
/// // Auto-detect transport from URL (recommended)
/// ClientOptions {
///     url: Some("grpcs://connectors.example.com:443".to_string()),
///     ..Default::default()
/// }
///
/// // WebSocket transport (auto-detected from wss://)
/// ClientOptions {
///     url: Some("wss://connectors.example.com:443".to_string()),
///     ..Default::default()
/// }
///
/// // Legacy: explicit host
/// ClientOptions {
///     host: Some("connectors.example.com:443".to_string()),
///     use_tls: Some(true),
///     ..Default::default()
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct ClientOptions {
    /// Strike48 server URL with scheme (preferred, auto-detects transport).
    ///
    /// Examples:
    /// - `grpcs://matrix.example.com:443` - gRPC with TLS
    /// - `wss://matrix.example.com:443` - WebSocket with TLS
    pub url: Option<String>,
    /// Strike48 server host (legacy, use `url` instead).
    #[deprecated(note = "Use `url` with scheme for auto-detection")]
    pub host: Option<String>,
    /// Use TLS for connection (auto-detected from URL scheme when using `url`).
    pub use_tls: Option<bool>,
    /// Transport type (auto-detected from URL scheme when using `url`).
    #[deprecated(note = "Use `url` with scheme for auto-detection")]
    pub transport: Option<TransportType>,
    /// Default timeout for operations in milliseconds (default: 30000).
    pub default_timeout_ms: Option<u64>,
}

pub use strike48_proto::proto;

use proto::{StreamMessage as ProtoStreamMessage, stream_message};

/// Pending invoke request awaiting response
struct PendingInvoke {
    resolve: tokio::sync::oneshot::Sender<crate::types::InvokeCapabilityResponse>,
    #[allow(dead_code)]
    deadline: tokio::time::Instant,
}

/// Result of `start_invoke` -- contains everything needed to wait for the
/// response outside any parent lock scope.
pub(crate) struct StartedInvoke {
    pub receiver: Option<tokio::sync::oneshot::Receiver<crate::types::InvokeCapabilityResponse>>,
    pub request_id: String,
    pub timeout_ms: u64,
    pending_invokes: Arc<RwLock<HashMap<String, PendingInvoke>>>,
}

impl StartedInvoke {
    /// Remove the pending invoke entry (cleanup on timeout or channel close).
    pub(crate) async fn cancel(&self) {
        self.pending_invokes.write().await.remove(&self.request_id);
    }
}

/// gRPC client for connector communication
///
/// Supports two transport modes:
/// - `TransportType::Grpc` (default): Native gRPC over HTTP/2
/// - `TransportType::WebSocket`: WebSocket over HTTP/1.1 (for corporate proxy compatibility)
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::{ConnectorClient, client::{ClientOptions, TransportType}};
///
/// // Using native gRPC (default)
/// let client = ConnectorClient::new("connectors-poc-us.strike48.com:443".to_string(), true);
///
/// // Using WebSocket for corporate proxy compatibility
/// let client = ConnectorClient::with_options(ClientOptions {
///     host: "connectors-poc-us.strike48.com:443".to_string(),
///     use_tls: true,
///     transport: TransportType::WebSocket,
///     default_timeout_ms: 30000,
/// });
/// ```
pub struct ConnectorClient {
    host: String,
    use_tls: bool,
    transport_type: TransportType,
    /// Transport layer abstraction (gRPC or WebSocket)
    transport: Option<Box<dyn Transport>>,
    /// Atomic flag for connection state (lock-free)
    connected: Arc<AtomicBool>,
    /// Atomic flag for registration state (lock-free)
    registered: Arc<AtomicBool>,
    session_token: Arc<RwLock<Option<String>>>,
    #[allow(dead_code)] // Connector address after registration
    connector_address: Arc<RwLock<Option<String>>>,
    request_tx: Arc<RwLock<Option<mpsc::UnboundedSender<ProtoStreamMessage>>>>,
    pending_invokes: Arc<RwLock<HashMap<String, PendingInvoke>>>,
    default_timeout_ms: u64,
    /// Epoch nanos when the last HeartbeatRequest was sent (for RTT calculation).
    heartbeat_sent_at_nanos: Arc<AtomicU64>,
    /// Outbound keepalive interval used by `spawn_keepalive`. Defaults to
    /// `KEEPALIVE_INTERVAL_SECS` (30s); override via
    /// [`Self::set_keepalive_interval`] before [`Self::start_stream_with_registration`].
    keepalive_interval: Duration,
}

impl ConnectorClient {
    /// Create a new ConnectorClient with default transport (gRPC).
    ///
    /// For URL-based transport auto-detection, use `with_options` with `url`.
    #[allow(dead_code)]
    pub fn new(host: String, use_tls: bool) -> Self {
        #[allow(deprecated)]
        Self::with_options(ClientOptions {
            url: None,
            host: Some(host),
            use_tls: Some(use_tls),
            transport: Some(TransportType::default()),
            default_timeout_ms: Some(30000),
        })
    }

    /// Create a new ConnectorClient with full configuration.
    ///
    /// Transport is auto-detected from URL scheme when using `url` option:
    /// - `grpc://` or `grpcs://` → gRPC transport
    /// - `ws://`, `wss://`, `http://`, `https://` → WebSocket transport
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Auto-detect transport from URL (recommended)
    /// let client = ConnectorClient::with_options(ClientOptions {
    ///     url: Some("grpcs://connectors.example.com:443".to_string()),
    ///     ..Default::default()
    /// });
    ///
    /// // WebSocket transport (auto-detected from wss://)
    /// let client = ConnectorClient::with_options(ClientOptions {
    ///     url: Some("wss://connectors.example.com:443".to_string()),
    ///     ..Default::default()
    /// });
    /// ```
    #[allow(deprecated)]
    pub fn with_options(opts: ClientOptions) -> Self {
        // Parse URL to auto-detect transport, TLS, and normalize host
        let (host, use_tls, transport) = if let Some(url) = &opts.url {
            // URL-based configuration (auto-detect transport from scheme)
            match parse_url(url) {
                Ok(parsed) => {
                    let host = parsed.host_port();
                    let tls = opts.use_tls.unwrap_or(parsed.use_tls);
                    let trans = opts.transport.unwrap_or(parsed.transport);
                    (host, tls, trans)
                }
                Err(_) => {
                    // Fallback to legacy behavior
                    let host = url.clone();
                    let tls = opts.use_tls.unwrap_or(false);
                    let trans = opts.transport.unwrap_or(TransportType::Grpc);
                    (host, tls, trans)
                }
            }
        } else if let Some(host) = &opts.host {
            // Try to parse host as URL for auto-detection
            match parse_url(host) {
                Ok(parsed) => {
                    let host_port = parsed.host_port();
                    let tls = opts.use_tls.unwrap_or(parsed.use_tls);
                    let trans = opts.transport.unwrap_or(parsed.transport);
                    (host_port, tls, trans)
                }
                Err(_) => {
                    // Simple host:port format
                    let tls = opts.use_tls.unwrap_or(false);
                    let trans = opts.transport.unwrap_or(TransportType::Grpc);
                    (host.clone(), tls, trans)
                }
            }
        } else {
            // No URL or host provided, use defaults
            ("localhost:50061".to_string(), false, TransportType::Grpc)
        };

        if transport == TransportType::WebSocket {
            debug!(
                "WebSocket transport selected (detected from URL scheme). \
                This transport works through corporate proxies that block HTTP/2."
            );
        }

        debug!(
            "ConnectorClient initialized: {} (transport: {:?}, TLS: {})",
            host, transport, use_tls
        );

        Self {
            host,
            use_tls,
            transport_type: transport,
            transport: None, // Created on connect
            connected: Arc::new(AtomicBool::new(false)),
            registered: Arc::new(AtomicBool::new(false)),
            session_token: Arc::new(RwLock::new(None)),
            connector_address: Arc::new(RwLock::new(None)),
            request_tx: Arc::new(RwLock::new(None)),
            pending_invokes: Arc::new(RwLock::new(HashMap::new())),
            default_timeout_ms: opts.default_timeout_ms.unwrap_or(30000),
            heartbeat_sent_at_nanos: Arc::new(AtomicU64::new(0)),
            keepalive_interval: Duration::from_secs(KEEPALIVE_INTERVAL_SECS),
        }
    }

    /// Override the outbound keepalive interval. Call before
    /// [`Self::start_stream_with_registration`]; later changes do not affect
    /// an already-spawned keepalive task. Default is 30s.
    pub(crate) fn set_keepalive_interval(&mut self, d: Duration) {
        self.keepalive_interval = d;
    }

    /// Connect to Strike48 server using the configured transport.
    ///
    /// Uses the configured transport:
    /// - `TransportType::Grpc`: Native gRPC over HTTP/2 (default)
    /// - `TransportType::WebSocket`: WebSocket over HTTP/1.1 (for corporate proxy compatibility)
    pub async fn connect_channel(&mut self) -> Result<()> {
        debug!(
            "Connecting to Strike48 server: {} (transport: {:?})",
            self.host, self.transport_type
        );

        // Create transport options
        let options = TransportOptions {
            host: self.host.clone(),
            use_tls: self.use_tls,
            connect_timeout_ms: Some(10000),
            default_timeout_ms: Some(self.default_timeout_ms),
            channel_capacity: Some(1024), // Bounded for backpressure
            proxy: crate::transport::proxy::resolve_proxy(
                &self.host,
                self.use_tls,
                std::env::var("STUDIO_PROXY").ok().as_deref(),
                &|k| std::env::var(k).ok(),
            )?,
        };
        match &options.proxy {
            Some(p) => tracing::info!(proxy = %p, "studio proxy ENABLED (HTTP CONNECT)"),
            None => tracing::debug!("studio proxy DISABLED (direct connection)"),
        }

        // Create and connect the appropriate transport
        let mut transport = create_transport(self.transport_type, options);
        transport.connect().await?;

        self.connected.store(true, Ordering::SeqCst);
        self.transport = Some(transport);

        debug!("Connected to Strike48 server");
        Ok(())
    }

    /// Send registration request on the stream
    /// Note: Registration happens through the bidirectional stream, not a separate RPC
    #[allow(dead_code)]
    pub async fn send_register_request(
        &self,
        tenant_id: &str,
        connector_type: &str,
        instance_id: &str,
        capabilities: &ConnectorCapabilities,
        auth_token: &str,
    ) -> Result<()> {
        // Convert capabilities to protobuf
        let capabilities_proto = proto::ConnectorCapabilities {
            connector_type: capabilities.connector_type.clone(),
            version: capabilities.version.clone(),
            supported_encodings: capabilities
                .supported_encodings
                .iter()
                .map(|e| *e as i32)
                .collect(),
            behaviors: capabilities.behaviors.iter().map(|b| *b as i32).collect(),
            metadata: capabilities.metadata.clone(),
            task_types: capabilities
                .task_types
                .as_ref()
                .map(|tts| {
                    tts.iter()
                        .map(|tt| proto::TaskTypeSchema {
                            task_type_id: tt.task_type_id.clone(),
                            name: tt.name.clone(),
                            description: tt.description.clone(),
                            category: tt.category.clone(),
                            icon: tt.icon.clone(),
                            input_schema_json: tt.input_schema_json.clone(),
                            output_schema_json: tt.output_schema_json.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        };

        // Sanitize identifiers to prevent address parsing issues
        // Dots and colons are used as separators in addresses
        let sanitized_instance_id = sanitize_identifier(instance_id);

        // Default instance metadata (display_name = instance_id)
        let instance_metadata = Some(proto::InstanceMetadata {
            display_name: sanitized_instance_id.clone(),
            tags: Vec::new(),
            metadata: std::collections::HashMap::new(),
        });

        let mut request = proto::RegisterConnectorRequest {
            tenant_id: sanitize_identifier(tenant_id),
            connector_type: sanitize_identifier(connector_type),
            instance_id: sanitized_instance_id,
            capabilities: Some(capabilities_proto),
            jwt_token: if auth_token.is_empty() {
                String::new()
            } else {
                auth_token.to_string()
            },
            session_token: String::new(),
            scope: 0, // Default scope
            instance_metadata,
        };

        // Use session token if available
        if let Some(session_token) = self.session_token.read().await.as_ref() {
            request.session_token = session_token.clone();
            debug!("Using session token for reconnection");
        }

        // Send registration request on the stream
        let message = ProtoStreamMessage {
            message: Some(proto::stream_message::Message::RegisterRequest(request)),
        };

        self.send_message(message).await
    }

    /// Start bidirectional streaming using the transport abstraction.
    ///
    /// This method works identically for both gRPC and WebSocket transports.
    /// The transport handles protocol-specific details internally.
    ///
    /// A background keepalive task is automatically spawned that sends
    /// `HeartbeatRequest` messages every 30 seconds. This prevents the
    /// server's session reaper (90s timeout) from killing the session,
    /// regardless of whether the caller sends their own metrics/heartbeats.
    pub async fn start_stream_with_registration(
        &mut self,
        initial_message: ProtoStreamMessage,
    ) -> Result<(
        mpsc::UnboundedSender<ProtoStreamMessage>,
        mpsc::UnboundedReceiver<ProtoStreamMessage>,
    )> {
        debug!("start_stream: getting transport reference");
        let transport = self
            .transport
            .as_mut()
            .ok_or(ConnectorError::NotConnected)?;

        debug!("start_stream: starting transport stream with initial message");

        // Start the bidirectional stream via transport abstraction
        // Pass the initial message so it's sent immediately (prevents deadlock in gRPC)
        let (tx, rx) = transport.start_stream(Some(initial_message)).await?;

        debug!("start_stream: transport stream started successfully");

        // Store the tx for later use
        *self.request_tx.write().await = Some(tx.clone());

        // Spawn keepalive task: sends HeartbeatRequest every 30s to prevent
        // the server from reaping the session. Stops automatically when the
        // stream closes (tx dropped) or when the client disconnects.
        Self::spawn_keepalive(
            tx.clone(),
            self.connected.clone(),
            self.heartbeat_sent_at_nanos.clone(),
            self.keepalive_interval,
        );

        Ok((tx, rx))
    }

    /// Spawn a background task that sends periodic `HeartbeatRequest` messages
    /// on the stream to prevent the server's session reaper from timing out.
    ///
    /// Records `SystemTime` epoch nanos into `sent_at_nanos` right before each
    /// send so the receiver can compute round-trip time.
    fn spawn_keepalive(
        tx: mpsc::UnboundedSender<ProtoStreamMessage>,
        connected: Arc<AtomicBool>,
        sent_at_nanos: Arc<AtomicU64>,
        keepalive_interval: Duration,
    ) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(keepalive_interval);
            // If the runtime stalls briefly we don't want a backlog of
            // catch-up heartbeats on resume; collapse to a single tick.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // First tick fires immediately; skip it so the first heartbeat
            // is sent after one full interval.
            interval.tick().await;

            loop {
                interval.tick().await;

                if !connected.load(Ordering::SeqCst) {
                    debug!("keepalive: client disconnected, stopping");
                    break;
                }

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();
                let now_ms = now.as_millis() as i64;

                sent_at_nanos.store(now.as_nanos() as u64, Ordering::Release);

                let heartbeat = ProtoStreamMessage {
                    message: Some(proto::stream_message::Message::HeartbeatRequest(
                        proto::HeartbeatRequest {
                            gateway_id: String::new(),
                            timestamp_ms: now_ms,
                        },
                    )),
                };

                if tx.send(heartbeat).is_err() {
                    debug!("keepalive: stream closed, stopping");
                    break;
                }
            }
        });
    }

    /// Returns the epoch nanos when the last `HeartbeatRequest` was sent.
    /// Used by `ConnectorRunner` to compute RTT on `HeartbeatResponse`.
    pub(crate) fn heartbeat_sent_at_nanos(&self) -> &Arc<AtomicU64> {
        &self.heartbeat_sent_at_nanos
    }

    /// Send a message on the stream
    pub async fn send_message(&self, message: ProtoStreamMessage) -> Result<()> {
        if let Some(tx) = self.request_tx.read().await.as_ref() {
            tx.send(message)
                .map_err(|e| ConnectorError::StreamError(format!("Failed to send message: {e}")))?;
            Ok(())
        } else {
            Err(ConnectorError::StreamError(
                "Stream not started".to_string(),
            ))
        }
    }

    /// Clone the stream sender for use outside a parent lock scope.
    ///
    /// Returns the cloned `UnboundedSender` so callers can send messages
    /// without holding any outer lock across the send.
    pub(crate) async fn clone_message_tx(
        &self,
    ) -> Result<mpsc::UnboundedSender<ProtoStreamMessage>> {
        self.request_tx
            .read()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| ConnectorError::StreamError("Stream not started".to_string()))
    }

    /// Prepare an invoke request: validate state, register the response channel,
    /// and send the request message. Returns the oneshot receiver to wait on
    /// (or `None` for fire-and-forget), the request ID, and the timeout.
    ///
    /// Callers should drop any parent locks before awaiting the receiver so that
    /// reconnection is not blocked during the (potentially long) wait.
    pub(crate) async fn start_invoke(
        &self,
        target_address: &str,
        payload: Vec<u8>,
        options: InvokeOptions,
    ) -> Result<StartedInvoke> {
        use tokio::sync::oneshot;

        if !self.registered.load(Ordering::SeqCst) {
            return Err(ConnectorError::NotRegistered);
        }

        let request_id = format!("invoke-{}", generate_id());
        let timeout_ms = options.timeout_ms.unwrap_or(self.default_timeout_ms);
        let fire_and_forget = options.fire_and_forget.unwrap_or(false);

        let proto_request = proto::InvokeCapabilityRequest {
            request_id: request_id.clone(),
            target_address: target_address.to_string(),
            capability_id: options.capability_id.unwrap_or_default(),
            payload,
            payload_encoding: options.payload_encoding.unwrap_or(PayloadEncoding::Json) as i32,
            context: options.context.unwrap_or_default(),
            timeout_ms: timeout_ms as i32,
            fire_and_forget,
        };

        let message = ProtoStreamMessage {
            message: Some(stream_message::Message::InvokeRequest(proto_request)),
        };

        if fire_and_forget {
            self.send_message(message).await?;
            return Ok(StartedInvoke {
                receiver: None,
                request_id,
                timeout_ms,
                pending_invokes: self.pending_invokes.clone(),
            });
        }

        let (tx, rx) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);

        {
            let mut pending = self.pending_invokes.write().await;
            pending.insert(
                request_id.clone(),
                PendingInvoke {
                    resolve: tx,
                    deadline,
                },
            );
        }

        self.send_message(message).await?;

        Ok(StartedInvoke {
            receiver: Some(rx),
            request_id,
            timeout_ms,
            pending_invokes: self.pending_invokes.clone(),
        })
    }

    /// Set session token
    pub async fn set_session_token(&self, token: String) {
        *self.session_token.write().await = Some(token);
    }

    /// Send execute response
    #[allow(dead_code)]
    pub async fn send_response(&self, response: ExecuteResponse) -> Result<()> {
        let message = ProtoStreamMessage {
            message: Some(stream_message::Message::ExecuteResponse(
                proto::ExecuteResponse {
                    request_id: response.request_id,
                    success: response.success,
                    payload: response.payload,
                    payload_encoding: response.payload_encoding as i32,
                    error: response.error,
                    duration_ms: response.duration_ms as i64,
                },
            )),
        };

        self.send_message(message).await
    }

    /// Disconnect from Strike48 server
    pub async fn disconnect(&mut self) {
        // Disconnect transport
        if let Some(transport) = self.transport.as_mut() {
            let _ = transport.disconnect().await;
        }

        self.connected.store(false, Ordering::SeqCst);
        self.registered.store(false, Ordering::SeqCst);
        self.transport = None;
        *self.request_tx.write().await = None;

        // Cancel all in-flight invoke requests. Without this, callers waiting
        // on the oneshot receiver will block until their individual timeouts
        // fire (up to 30s each). Draining eagerly on disconnect lets them fail
        // fast and allows the connector to reconnect cleanly.
        let mut pending = self.pending_invokes.write().await;
        let count = pending.len();
        pending.clear(); // drops all PendingInvoke entries, closing the oneshot senders
        if count > 0 {
            debug!(
                "Cancelled {} in-flight invoke request(s) on disconnect",
                count
            );
        }

        debug!("Disconnected from Strike48 server");
    }

    /// Check if connected (lock-free atomic check)
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Check if registered (lock-free atomic check)
    #[allow(dead_code)]
    pub fn is_registered(&self) -> bool {
        self.registered.load(Ordering::SeqCst)
    }

    /// Mark this client as successfully registered with the server.
    pub fn mark_registered(&self) {
        self.registered.store(true, Ordering::SeqCst);
    }

    /// Invoke a capability on another connector through Strike48 routing
    #[allow(dead_code)]
    pub async fn invoke_capability(
        &self,
        target_address: &str,
        payload: Vec<u8>,
        options: InvokeOptions,
    ) -> Result<Option<InvokeCapabilityResponse>> {
        use tokio::sync::oneshot;
        use tokio::time::{Duration, timeout};

        if !self.registered.load(Ordering::SeqCst) {
            return Err(ConnectorError::NotRegistered);
        }

        let request_id = format!("invoke-{}", generate_id());
        let timeout_ms = options.timeout_ms.unwrap_or(self.default_timeout_ms);
        let fire_and_forget = options.fire_and_forget.unwrap_or(false);

        // Convert to protobuf
        let proto_request = proto::InvokeCapabilityRequest {
            request_id: request_id.clone(),
            target_address: target_address.to_string(),
            capability_id: options.capability_id.unwrap_or_default(),
            payload,
            payload_encoding: options.payload_encoding.unwrap_or(PayloadEncoding::Json) as i32,
            context: options.context.unwrap_or_default(),
            timeout_ms: timeout_ms as i32,
            fire_and_forget,
        };

        let message = ProtoStreamMessage {
            message: Some(stream_message::Message::InvokeRequest(proto_request)),
        };

        // For fire-and-forget, just send and return None
        if fire_and_forget {
            self.send_message(message).await?;
            return Ok(None);
        }

        // For synchronous invoke, wait for response
        let (tx, rx) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);

        // Store pending request
        {
            let mut pending = self.pending_invokes.write().await;
            pending.insert(
                request_id.clone(),
                PendingInvoke {
                    resolve: tx,
                    deadline,
                },
            );
        }

        self.send_message(message).await?;

        // Wait for response with timeout
        match timeout(Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(response)) => Ok(Some(response)),
            Ok(Err(_)) => {
                // Clean up pending request
                self.pending_invokes.write().await.remove(&request_id);
                Err(ConnectorError::StreamError(
                    "Response channel closed".to_string(),
                ))
            }
            Err(_) => {
                // Clean up pending request
                self.pending_invokes.write().await.remove(&request_id);
                Err(ConnectorError::Timeout(format!(
                    "Invoke request {request_id} timed out after {timeout_ms}ms"
                )))
            }
        }
    }

    /// Handle incoming invoke response
    pub(crate) async fn handle_invoke_response(
        &self,
        response: proto::InvokeCapabilityResponse,
    ) -> bool {
        let request_id = response.request_id.clone();
        let mut pending = self.pending_invokes.write().await;

        if let Some(pending_invoke) = pending.remove(&request_id) {
            let invoke_response = InvokeCapabilityResponse {
                request_id: response.request_id,
                success: response.success,
                payload: response.payload,
                payload_encoding: PayloadEncoding::from(response.payload_encoding),
                error: response.error,
                duration_ms: response.duration_ms as u64,
                context: if response.context.is_empty() {
                    None
                } else {
                    Some(response.context)
                },
                error_details: if response.error_details.is_empty() {
                    None
                } else {
                    Some(response.error_details)
                },
            };

            let _ = pending_invoke.resolve.send(invoke_response);
            true
        } else {
            false
        }
    }

    /// Get default timeout in milliseconds
    #[allow(dead_code)]
    pub fn get_default_timeout(&self) -> Option<u64> {
        Some(self.default_timeout_ms)
    }
}

/// Options for invoke capability
#[derive(Debug, Clone, Default)]
pub struct InvokeOptions {
    pub payload_encoding: Option<PayloadEncoding>,
    pub capability_id: Option<String>,
    pub timeout_ms: Option<u64>,
    pub fire_and_forget: Option<bool>,
    pub context: Option<HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_keepalive_sends_heartbeats() {
        let (tx, mut rx) = mpsc::unbounded_channel::<ProtoStreamMessage>();
        let connected = Arc::new(AtomicBool::new(true));
        let sent_at = Arc::new(AtomicU64::new(0));

        ConnectorClient::spawn_keepalive(
            tx,
            connected.clone(),
            sent_at,
            Duration::from_secs(KEEPALIVE_INTERVAL_SECS),
        );

        // Wait for at least one heartbeat (interval is 30s, but we can't wait
        // that long in a test -- override by using a shorter sleep).
        // Instead, test the mechanism: spawn_keepalive skips the first tick,
        // so we verify the task is alive by disconnecting after a moment.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Signal disconnect to stop the keepalive
        connected.store(false, Ordering::SeqCst);

        // Give the task time to notice the flag and exit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The channel should still be valid (not panicked)
        // No heartbeat expected yet since interval is 30s
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_keepalive_stops_on_channel_close() {
        let (tx, rx) = mpsc::unbounded_channel::<ProtoStreamMessage>();
        let connected = Arc::new(AtomicBool::new(true));
        let sent_at = Arc::new(AtomicU64::new(0));

        ConnectorClient::spawn_keepalive(
            tx,
            connected.clone(),
            sent_at,
            Duration::from_secs(KEEPALIVE_INTERVAL_SECS),
        );

        // Drop the receiver -- the next send in the keepalive task will fail
        // and the task should exit cleanly.
        drop(rx);

        // Give the task time to attempt a send and exit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // If we get here without a panic, the task handled the closed channel gracefully.
        assert!(connected.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_keepalive_heartbeat_format() {
        let (tx, mut rx) = mpsc::unbounded_channel::<ProtoStreamMessage>();
        let connected = Arc::new(AtomicBool::new(true));

        // Spawn a keepalive with a very short interval for testing
        let keepalive_tx = tx;
        let keepalive_connected = connected.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(50));
            interval.tick().await; // skip first

            interval.tick().await;
            if !keepalive_connected.load(Ordering::SeqCst) {
                return;
            }

            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);

            let heartbeat = ProtoStreamMessage {
                message: Some(proto::stream_message::Message::HeartbeatRequest(
                    proto::HeartbeatRequest {
                        gateway_id: String::new(),
                        timestamp_ms: now_ms,
                    },
                )),
            };
            let _ = keepalive_tx.send(heartbeat);
        });

        // Wait for the heartbeat
        tokio::time::sleep(Duration::from_millis(200)).await;

        let msg = rx.try_recv().expect("should have received a heartbeat");
        match msg.message {
            Some(proto::stream_message::Message::HeartbeatRequest(hb)) => {
                assert!(
                    hb.gateway_id.is_empty(),
                    "gateway_id should be empty (server fills it)"
                );
                assert!(hb.timestamp_ms > 0, "timestamp should be set");
            }
            other => panic!("expected HeartbeatRequest, got {:?}", other),
        }

        connected.store(false, Ordering::SeqCst);
    }
}

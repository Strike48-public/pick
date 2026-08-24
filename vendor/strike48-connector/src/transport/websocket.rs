//! WebSocket Transport for Strike48 Connector SDK.
//!
//! WebSocket over HTTP/1.1 - works through corporate proxies that block HTTP/2.
//! Uses Phoenix Channels with JSON transport and base64-encoded protobuf data.
//!
//! Protocol:
//! - Connect to /socket/connector/websocket?vsn=2.0.0
//! - Join "connector:lobby" channel
//! - Send/receive "proto" events with Base64-encoded protobuf data
//! - Phoenix message format: [join_ref, ref, topic, event, payload]
//! - Heartbeat: Client must send [null, ref, "phoenix", "heartbeat", {}] every 30s

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use tokio_tungstenite::{
    Connector, client_async_tls_with_config, tungstenite::Message,
    tungstenite::client::IntoClientRequest,
};
use tracing::{debug, error, trace, warn};

use super::proxy::{ProxyStream, connect_through_proxy};
use super::{Transport, TransportOptions, TransportType, create_unbounded_wrapper};
use crate::error::{ConnectorError, Result};
use strike48_proto::proto::StreamMessage;

/// Default channel capacity for bounded message channels.
const DEFAULT_CHANNEL_CAPACITY: usize = 1024;

/// Strip the port from a `host:port` string when it's the well-known default
/// for the scheme (80 for HTTP/WS, 443 for HTTPS/WSS).
/// This keeps the HTTP Host header clean for hostname-based gateway routing.
fn strip_default_port(host_port: &str, use_tls: bool) -> String {
    let default_port: u16 = if use_tls { 443 } else { 80 };

    if let Some((host, port_str)) = host_port.rsplit_once(':')
        && let Ok(port) = port_str.parse::<u16>()
        && port == default_port
    {
        return host.to_string();
    }

    host_port.to_string()
}

/// Split a PEM file into individual `BEGIN…END` certificate blocks (inclusive
/// of the markers), so each can be parsed separately. Non-certificate content
/// between blocks is ignored.
fn split_pem_certs(pem: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = String::from_utf8_lossy(pem);
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start..];
        if let Some(end_rel) = after.find(END) {
            let end = end_rel + END.len();
            out.push(after.as_bytes()[..end].to_vec());
            rest = &after[end..];
        } else {
            break;
        }
    }
    out
}

/// Phoenix heartbeat interval in milliseconds.
/// Phoenix default is 30s timeout, we send every 25s to have margin.
const PHOENIX_HEARTBEAT_INTERVAL_MS: u64 = 25000;

/// WebSocket Transport implementation.
///
/// Uses Phoenix Channels over WebSocket for connector communication.
/// Messages are base64-encoded protobuf over JSON transport.
///
/// Endpoint: /socket/connector/websocket?vsn=2.0.0
/// Channel: connector:lobby
/// Event: "proto" with payload `{"data": "<base64-encoded-protobuf>"}`
pub struct WebSocketTransport {
    options: TransportOptions,
    connected: Arc<AtomicBool>,
    /// Channel capacity for backpressure (default: 1024)
    channel_capacity: usize,

    // Phoenix protocol state (atomic for lock-free access)
    join_ref: Arc<AtomicU32>,
    msg_ref: Arc<AtomicU32>,

    /// Handles for spawned background tasks so we can abort them on disconnect.
    task_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl WebSocketTransport {
    /// Create a new WebSocket transport.
    pub fn new(options: TransportOptions) -> Self {
        debug!(
            "WebSocketTransport created: {} (TLS: {})",
            options.host, options.use_tls
        );

        Self {
            channel_capacity: options.channel_capacity.unwrap_or(DEFAULT_CHANNEL_CAPACITY),
            options,
            connected: Arc::new(AtomicBool::new(false)),
            join_ref: Arc::new(AtomicU32::new(0)),
            msg_ref: Arc::new(AtomicU32::new(0)),
            task_handles: Vec::new(),
        }
    }

    /// Build a TLS connector honoring the SDK's standard TLS knobs.
    ///
    /// - `MATRIX_TLS_INSECURE=true` → accept any certificate (dev only).
    /// - `MATRIX_TLS_CA_CERT=/path` → trust this extra CA in addition to the
    ///   system roots. Required for TLS-inspecting (MITM) corporate proxies and
    ///   private/custom-CA studio deployments. Mirrors the gRPC transport.
    /// - otherwise → system default roots.
    fn build_tls_connector(&self) -> Option<Connector> {
        if !self.options.use_tls {
            return None;
        }

        let tls_insecure = std::env::var("MATRIX_TLS_INSECURE")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        if tls_insecure {
            warn!(
                "TLS certificate verification DISABLED (MATRIX_TLS_INSECURE=true). Do NOT use in production!"
            );
            match native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .build()
            {
                Ok(c) => return Some(Connector::NativeTls(c)),
                Err(e) => {
                    // Degrade gracefully (mirrors the custom-CA branch below)
                    // instead of aborting the process on a platform TLS failure.
                    warn!(error = %e, "could not build insecure TLS connector; using system roots");
                    return None;
                }
            }
        }

        if let Ok(ca_path) = std::env::var("MATRIX_TLS_CA_CERT") {
            match Self::native_tls_with_ca(&ca_path) {
                Ok(c) => return Some(Connector::NativeTls(c)),
                Err(e) => {
                    warn!(
                        error = %e,
                        "could not load MATRIX_TLS_CA_CERT for WebSocket TLS; using system roots"
                    );
                }
            }
        }

        // Use default system TLS (validates certificates).
        None
    }

    /// Build a native-tls connector that trusts the system roots PLUS every CA
    /// in the PEM file at `ca_path`. The file may contain MULTIPLE PEM
    /// certificates (a CA plus intermediates, or several roots) — native-tls'
    /// `Certificate::from_pem` parses only one, so we split on the PEM
    /// boundaries and add each.
    fn native_tls_with_ca(ca_path: &str) -> Result<native_tls::TlsConnector> {
        let pem = std::fs::read(ca_path).map_err(|e| {
            ConnectorError::ConnectionError(format!("failed to read CA cert {ca_path}: {e}"))
        })?;

        let mut builder = native_tls::TlsConnector::builder();
        let mut added = 0usize;
        // Split into individual PEM blocks (`-----BEGIN ...-----` … `-----END ...-----`).
        for block in split_pem_certs(&pem) {
            let cert = native_tls::Certificate::from_pem(&block).map_err(|e| {
                ConnectorError::ConnectionError(format!("invalid CA cert in {ca_path}: {e}"))
            })?;
            builder.add_root_certificate(cert);
            added += 1;
        }
        if added == 0 {
            return Err(ConnectorError::ConnectionError(format!(
                "no PEM certificates found in {ca_path}"
            )));
        }
        builder.build().map_err(|e| {
            ConnectorError::ConnectionError(format!("failed to build TLS connector: {e}"))
        })
    }

    /// Build WebSocket URL from options.
    ///
    /// Uses `self.options.host` as-is (already resolved by the URL parser).
    /// Omits the port when it matches the scheme default so that the Host header
    /// stays clean for hostname-based gateway routing (e.g. `*.example.com`).
    fn build_ws_url(&self) -> String {
        let scheme = if self.options.use_tls { "wss" } else { "ws" };

        let authority = strip_default_port(&self.options.host, self.options.use_tls);

        format!("{scheme}://{authority}/socket/connector/websocket?vsn=2.0.0")
    }

    /// Resolve the target `(host, port)` from `self.options.host`, defaulting
    /// the port to the scheme default when absent.
    fn target_host_port(&self) -> (String, u16) {
        let default_port = if self.options.use_tls { 443 } else { 80 };
        let host = strip_default_port(&self.options.host, self.options.use_tls);
        let (h, port) = crate::transport::proxy::split_host_port(&host);
        (h, port.unwrap_or(default_port))
    }

    /// Establish the byte stream to studio, tunneling through the proxy if one
    /// is configured. Returns a stream ready for the TLS/WS upgrade (a plain TCP
    /// stream for a direct connection, or a tunnel stream — itself possibly
    /// TLS-to-proxy — when proxied). The whole dial (incl. the proxy CONNECT
    /// handshake) is bounded by `connect_timeout_ms` so a stalled proxy can't
    /// wedge the reconnect loop.
    async fn dial_tcp(&self, connect_timeout_ms: u64) -> Result<ProxyStream> {
        let (target_host, target_port) = self.target_host_port();
        match &self.options.proxy {
            Some(cfg) => {
                connect_through_proxy(cfg, &target_host, target_port, connect_timeout_ms).await
            }
            None => {
                let tcp = timeout(
                    Duration::from_millis(connect_timeout_ms),
                    tokio::net::TcpStream::connect(format!("{target_host}:{target_port}")),
                )
                .await
                .map_err(|_| ConnectorError::Timeout("TCP connect timeout".to_string()))?
                .map_err(|e| ConnectorError::ConnectionError(format!("TCP connect failed: {e}")))?;
                Ok(Box::new(tcp) as ProxyStream)
            }
        }
    }

    /// Wait for Phoenix channel join confirmation with proper timeout.
    async fn wait_for_join_confirmation<S>(read: &mut S, timeout_ms: u64) -> Result<()>
    where
        S: StreamExt<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
            + Unpin,
    {
        let deadline = Duration::from_millis(timeout_ms);

        loop {
            match timeout(deadline, read.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    // Parse Phoenix message: [join_ref, ref, topic, event, payload]
                    if let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(&text)
                        && parsed.len() >= 5
                    {
                        let event = parsed[3].as_str().unwrap_or("");
                        let payload = &parsed[4];

                        if event == "phx_reply"
                            && let Some(status) = payload
                                .as_object()
                                .and_then(|p| p.get("status"))
                                .and_then(|s| s.as_str())
                        {
                            if status == "ok" {
                                debug!("Phoenix join confirmed");
                                return Ok(());
                            } else if status == "error" {
                                return Err(ConnectorError::ConnectionError(format!(
                                    "Phoenix join failed: {payload:?}"
                                )));
                            }
                        }
                    }
                }
                Ok(Some(Ok(_))) => {
                    // Ignore other message types during join
                    continue;
                }
                Ok(Some(Err(e))) => {
                    return Err(ConnectorError::ConnectionError(format!(
                        "WebSocket error during join: {e}"
                    )));
                }
                Ok(None) => {
                    return Err(ConnectorError::ConnectionError(
                        "WebSocket closed during join".to_string(),
                    ));
                }
                Err(_) => {
                    return Err(ConnectorError::Timeout(
                        "Timeout waiting for Phoenix join confirmation".to_string(),
                    ));
                }
            }
        }
    }

    /// Decode base64-encoded protobuf data to StreamMessage.
    fn decode_proto_message(data: &str) -> Option<StreamMessage> {
        // Try base64 decode first
        let proto_bytes = match BASE64.decode(data) {
            Ok(bytes) => bytes,
            Err(_) => {
                // Fallback to hex decode for backwards compatibility
                match hex::decode(data) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!("Failed to decode proto data: {}", e);
                        return None;
                    }
                }
            }
        };

        // Parse protobuf
        match StreamMessage::decode(proto_bytes.as_slice()) {
            Ok(msg) => Some(msg),
            Err(e) => {
                error!("Failed to parse protobuf message: {}", e);
                None
            }
        }
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    #[allow(dead_code)]
    fn transport_type(&self) -> TransportType {
        TransportType::WebSocket
    }

    async fn connect(&mut self) -> Result<()> {
        let url = self.build_ws_url();
        let connect_timeout = self.options.connect_timeout_ms.unwrap_or(10000);
        let tls_connector = self.build_tls_connector();

        debug!("Connecting to WebSocket at {}", url);

        // Connect with timeout. Dial (optionally through the proxy) then run the
        // TLS/WS upgrade over the resulting stream so the TARGET cert is validated.
        let tcp = self.dial_tcp(connect_timeout).await?;
        let request = url
            .as_str()
            .into_client_request()
            .map_err(|e| ConnectorError::ConnectionError(format!("bad ws request: {e}")))?;
        let (ws_stream, _) = timeout(
            Duration::from_millis(connect_timeout),
            client_async_tls_with_config(request, tcp, None, tls_connector),
        )
        .await
        .map_err(|_| ConnectorError::Timeout("WebSocket connection timeout".to_string()))?
        .map_err(|e| ConnectorError::ConnectionError(format!("WebSocket connect failed: {e}")))?;

        let (mut write, mut read) = ws_stream.split();

        // Join the Phoenix channel with proper confirmation
        let jr = self.join_ref.fetch_add(1, Ordering::SeqCst) + 1;
        let mr = self.msg_ref.fetch_add(1, Ordering::SeqCst) + 1;

        let join_msg = serde_json::json!([
            jr.to_string(),
            mr.to_string(),
            "connector:lobby",
            "phx_join",
            {}
        ]);

        debug!("Sending phx_join: {}", join_msg);
        write
            .send(Message::Text(join_msg.to_string().into()))
            .await
            .map_err(|e| ConnectorError::ConnectionError(format!("Failed to send join: {e}")))?;

        // Wait for proper join confirmation (not just a sleep!)
        Self::wait_for_join_confirmation(&mut read, 5000).await?;

        self.connected.store(true, Ordering::SeqCst);
        debug!("WebSocket transport connected and joined connector:lobby");

        Ok(())
    }

    async fn start_stream(
        &mut self,
        initial_message: Option<StreamMessage>,
    ) -> Result<(
        mpsc::UnboundedSender<StreamMessage>,
        mpsc::UnboundedReceiver<StreamMessage>,
    )> {
        let url = self.build_ws_url();
        let connect_timeout_ms = self.options.connect_timeout_ms.unwrap_or(10000);

        debug!("Starting WebSocket stream at {}", url);

        // Connect to WebSocket with the same timeout used in connect() so a
        // stalled TCP handshake (server mid-restart) doesn't block the reconnect
        // loop indefinitely.
        let tls_connector = self.build_tls_connector();
        let tcp = self.dial_tcp(connect_timeout_ms).await?;
        let request = url
            .as_str()
            .into_client_request()
            .map_err(|e| ConnectorError::ConnectionError(format!("bad ws request: {e}")))?;
        let (ws_stream, _) = timeout(
            Duration::from_millis(connect_timeout_ms),
            client_async_tls_with_config(request, tcp, None, tls_connector),
        )
        .await
        .map_err(|_| ConnectorError::Timeout("WebSocket stream connection timeout".to_string()))?
        .map_err(|e| ConnectorError::ConnectionError(format!("WebSocket connect failed: {e}")))?;

        let (mut write, mut read) = ws_stream.split();

        // Create BOUNDED channels for backpressure
        let (proto_tx, mut proto_rx) = mpsc::channel::<StreamMessage>(self.channel_capacity);
        let (response_tx, response_rx) = mpsc::channel::<StreamMessage>(self.channel_capacity);

        let join_ref = self.join_ref.clone();
        let msg_ref = self.msg_ref.clone();
        let connected = self.connected.clone();

        // Join the channel first and wait for confirmation
        let jr = join_ref.fetch_add(1, Ordering::SeqCst) + 1;
        let mr = msg_ref.fetch_add(1, Ordering::SeqCst) + 1;

        let join_msg = serde_json::json!([
            jr.to_string(),
            mr.to_string(),
            "connector:lobby",
            "phx_join",
            {}
        ]);

        debug!("Sending phx_join: {}", join_msg);
        write
            .send(Message::Text(join_msg.to_string().into()))
            .await
            .map_err(|e| ConnectorError::ConnectionError(format!("Failed to send join: {e}")))?;

        // Wait for join confirmation properly
        Self::wait_for_join_confirmation(&mut read, 5000).await?;

        // Mark the transport "connected" the moment phx_join succeeds.
        // The Phoenix heartbeat task spawned below is gated on this flag
        // and bails on its first tick if it's still false — without this
        // store, channels opened via `start_stream` (the path the multi-
        // connector runner uses) never emit Phoenix heartbeats and the
        // server's idle-channel watchdog drops them with code 1002 about
        // two minutes after join. The single-connector `connect()` path
        // sets the same flag for the same reason; this keeps the two
        // paths consistent.
        self.connected.store(true, Ordering::SeqCst);

        // Create internal channel for WebSocket writes (proto + heartbeat)
        // This allows multiple senders (proto forwarder, heartbeat) to write to the WebSocket
        let (ws_tx, mut ws_rx) = mpsc::channel::<String>(64);

        // Send initial message if provided
        if let Some(msg) = initial_message {
            debug!("WS TX: Sending initial message");
            let proto_bytes = msg.encode_to_vec();
            let b64_data = BASE64.encode(&proto_bytes);

            let mr = msg_ref.fetch_add(1, Ordering::SeqCst) + 1;
            let jr = join_ref.load(Ordering::SeqCst);

            let phoenix_msg = serde_json::json!([
                jr.to_string(),
                mr.to_string(),
                "connector:lobby",
                "proto",
                {"data": b64_data}
            ]);

            write
                .send(Message::Text(phoenix_msg.to_string().into()))
                .await
                .map_err(|e| {
                    ConnectorError::StreamError(format!("Failed to send initial message: {e}"))
                })?;
        }

        // Abort any lingering tasks from a previous stream before spawning new ones.
        self.abort_tasks();

        // Spawn WebSocket writer task - reads from internal channel and sends to WebSocket
        let connected_writer = connected.clone();
        let writer_handle = tokio::spawn(async move {
            while let Some(msg_text) = ws_rx.recv().await {
                if let Err(e) = write.send(Message::Text(msg_text.into())).await {
                    error!("WebSocket write failed: {}", e);
                    connected_writer.store(false, Ordering::SeqCst);
                    break;
                }
            }
            debug!("WebSocket writer task ended");
        });

        // Spawn proto forwarder task - converts proto messages to Phoenix format
        let join_ref_proto = join_ref.clone();
        let msg_ref_proto = msg_ref.clone();
        let ws_tx_proto = ws_tx.clone();
        let forwarder_handle = tokio::spawn(async move {
            while let Some(msg) = proto_rx.recv().await {
                // Encode message to protobuf binary
                let proto_bytes = msg.encode_to_vec();
                let b64_data = BASE64.encode(&proto_bytes);

                // Increment ref atomically
                let mr = msg_ref_proto.fetch_add(1, Ordering::SeqCst) + 1;
                let jr = join_ref_proto.load(Ordering::SeqCst);

                // Phoenix message: [join_ref, ref, topic, event, payload]
                let phoenix_msg = serde_json::json!([
                    jr.to_string(),
                    mr.to_string(),
                    "connector:lobby",
                    "proto",
                    {"data": b64_data}
                ]);

                trace!("WS TX proto ({} bytes)", proto_bytes.len());
                if ws_tx_proto.send(phoenix_msg.to_string()).await.is_err() {
                    debug!("Proto forwarder: ws_tx closed");
                    break;
                }
            }
            debug!("Proto forwarder task ended");
        });

        // Spawn Phoenix heartbeat task - sends heartbeat every 25 seconds
        let msg_ref_heartbeat = msg_ref.clone();
        let ws_tx_heartbeat = ws_tx.clone();
        let connected_heartbeat = connected.clone();
        let heartbeat_handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_millis(PHOENIX_HEARTBEAT_INTERVAL_MS));
            interval.tick().await; // Skip first immediate tick

            loop {
                interval.tick().await;

                if !connected_heartbeat.load(Ordering::SeqCst) {
                    trace!("Heartbeat task: not connected, stopping");
                    break;
                }

                let mr = msg_ref_heartbeat.fetch_add(1, Ordering::SeqCst) + 1;

                // Phoenix heartbeat: [null, ref, "phoenix", "heartbeat", {}]
                let heartbeat = serde_json::json!([
                    serde_json::Value::Null,
                    mr.to_string(),
                    "phoenix",
                    "heartbeat",
                    {}
                ]);

                trace!("Sending Phoenix heartbeat (ref: {})", mr);
                if ws_tx_heartbeat.send(heartbeat.to_string()).await.is_err() {
                    trace!("Heartbeat task: ws_tx closed");
                    break;
                }
            }
            trace!("Heartbeat task ended");
        });

        // Spawn reader task - parses Phoenix format to proto messages
        let ws_tx_reader = ws_tx; // Move remaining ws_tx to reader for heartbeat replies
        let reader_handle = tokio::spawn(async move {
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        trace!("WS RX: {}", text);

                        // Parse Phoenix message: [join_ref, ref, topic, event, payload]
                        if let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(&text)
                            && parsed.len() >= 5
                        {
                            let topic = parsed[2].as_str().unwrap_or("");
                            let event = parsed[3].as_str().unwrap_or("");
                            let payload = &parsed[4];

                            match event {
                                // Handle server-initiated heartbeat - respond immediately
                                "heartbeat" if topic == "phoenix" => {
                                    trace!("Responding to server heartbeat");
                                    let join_ref = &parsed[0];
                                    let ref_val = &parsed[1];

                                    let reply = serde_json::json!([
                                        join_ref,
                                        ref_val,
                                        "phoenix",
                                        "phx_reply",
                                        {"status": "ok", "response": {}}
                                    ]);

                                    if ws_tx_reader.send(reply.to_string()).await.is_err() {
                                        trace!("Reader: ws_tx closed");
                                        break;
                                    }
                                }
                                "phx_reply" => {
                                    if let Some(payload_obj) = payload.as_object() {
                                        let status = payload_obj
                                            .get("status")
                                            .and_then(|s| s.as_str())
                                            .unwrap_or("");

                                        if status == "ok" {
                                            trace!("Phoenix reply OK");

                                            // Check if reply contains proto data
                                            if let Some(response) = payload_obj.get("response")
                                                && let Some(data) = response
                                                    .as_object()
                                                    .and_then(|r| r.get("data"))
                                                    .and_then(|d| d.as_str())
                                                && let Some(proto_msg) =
                                                    WebSocketTransport::decode_proto_message(data)
                                            {
                                                trace!("Decoded proto from phx_reply");
                                                // Use blocking send for backpressure
                                                if response_tx.send(proto_msg).await.is_err() {
                                                    warn!("Response channel closed");
                                                    break;
                                                }
                                            }
                                        } else if status == "error" {
                                            let is_channel_dead = payload_obj
                                                .get("response")
                                                .and_then(|r| r.as_object())
                                                .and_then(|r| r.get("reason"))
                                                .and_then(|r| r.as_str())
                                                .is_some_and(|reason| reason == "unmatched topic");

                                            if is_channel_dead {
                                                warn!(
                                                    "Channel process no longer exists \
                                                     (unmatched topic). Closing stream \
                                                     to trigger reconnect."
                                                );
                                                connected.store(false, Ordering::SeqCst);
                                                break;
                                            }
                                            error!("Phoenix reply error: {:?}", payload_obj);
                                        }
                                    }
                                }
                                "proto" => {
                                    // Incoming proto message from server
                                    if let Some(data) = payload
                                        .as_object()
                                        .and_then(|p| p.get("data"))
                                        .and_then(|d| d.as_str())
                                        && let Some(proto_msg) =
                                            WebSocketTransport::decode_proto_message(data)
                                    {
                                        trace!("Received proto message via 'proto' event");
                                        // Use blocking send for backpressure
                                        if response_tx.send(proto_msg).await.is_err() {
                                            warn!("Response channel closed");
                                            break;
                                        }
                                    }
                                }
                                "phx_error" => {
                                    warn!(
                                        "Phoenix channel process terminated (phx_error): {:?}. \
                                         Closing stream to trigger reconnect.",
                                        payload
                                    );
                                    connected.store(false, Ordering::SeqCst);
                                    break;
                                }
                                "phx_close" => {
                                    warn!("Phoenix channel closed");
                                    connected.store(false, Ordering::SeqCst);
                                    break;
                                }
                                _ => {
                                    debug!("Unhandled Phoenix event: {}", event);
                                }
                            }
                        }
                    }
                    Ok(Message::Binary(data)) => {
                        trace!("Received binary message ({} bytes)", data.len());
                        // Try to decode as raw protobuf
                        if let Ok(proto_msg) = StreamMessage::decode(&data[..])
                            && response_tx.send(proto_msg).await.is_err()
                        {
                            warn!("Response channel closed");
                            break;
                        }
                    }
                    Ok(Message::Close(frame)) => {
                        if let Some(cf) = &frame {
                            warn!(
                                "WebSocket closed by server: code={}, reason={}",
                                cf.code, cf.reason
                            );
                        } else {
                            debug!("WebSocket closed (no close frame)");
                        }
                        connected.store(false, Ordering::SeqCst);
                        break;
                    }
                    Ok(Message::Ping(_)) => {
                        trace!("Received ping");
                    }
                    Ok(Message::Pong(_)) => {
                        trace!("Received pong");
                    }
                    Ok(Message::Frame(_)) => {
                        // Raw frame, ignore
                    }
                    Err(e) => {
                        error!("WebSocket error: {}", e);
                        connected.store(false, Ordering::SeqCst);
                        break;
                    }
                }
            }
            debug!("WebSocket reader task ended");
        });

        self.task_handles = vec![
            writer_handle,
            forwarder_handle,
            heartbeat_handle,
            reader_handle,
        ];

        debug!("WebSocket bidirectional stream started");

        let (unbounded_tx, unbounded_rx, wrapper_handles) =
            create_unbounded_wrapper(proto_tx, response_rx);
        self.task_handles.extend(wrapper_handles);

        Ok((unbounded_tx, unbounded_rx))
    }

    #[allow(dead_code)]
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    async fn disconnect(&mut self) -> Result<()> {
        debug!("Disconnecting WebSocket transport");
        self.connected.store(false, Ordering::SeqCst);
        self.abort_tasks();
        Ok(())
    }
}

impl WebSocketTransport {
    /// Abort all spawned background tasks (writer, forwarder, heartbeat, reader).
    /// Called on disconnect and before starting a new stream to prevent leaked tasks
    /// from a previous connection from spamming "Response channel closed" warnings.
    fn abort_tasks(&mut self) {
        for handle in self.task_handles.drain(..) {
            handle.abort();
        }
    }
}

impl Drop for WebSocketTransport {
    fn drop(&mut self) {
        self.abort_tasks();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::proxy::{ProxyConfig, ProxyScheme};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn opts(host: &str, proxy: Option<ProxyConfig>) -> TransportOptions {
        TransportOptions {
            host: host.to_string(),
            use_tls: false,
            connect_timeout_ms: Some(2000),
            default_timeout_ms: None,
            channel_capacity: Some(16),
            proxy,
        }
    }

    #[test]
    fn target_host_port_defaults_port() {
        let t = WebSocketTransport::new(opts("studio.example", None));
        assert_eq!(t.target_host_port(), ("studio.example".to_string(), 80));
    }

    #[test]
    fn target_host_port_parses_explicit_port() {
        let t = WebSocketTransport::new(opts("studio.example:9000", None));
        assert_eq!(t.target_host_port(), ("studio.example".to_string(), 9000));
    }

    /// `dial_tcp` must route through the proxy: it should send a CONNECT for the
    /// target host and return the tunneled stream.
    #[tokio::test]
    async fn dial_tcp_routes_through_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let saw_connect = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw = saw_connect.clone();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            if req.starts_with("CONNECT studio.example:80 HTTP/1.1\r\n") {
                saw.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            // hold the tunnel open briefly
            let _ = s.read(&mut buf).await;
        });

        let cfg = ProxyConfig {
            scheme: ProxyScheme::Http,
            host: "127.0.0.1".into(),
            port: proxy_addr.port(),
            auth: None,
        };
        let t = WebSocketTransport::new(opts("studio.example", Some(cfg)));
        // dial_tcp must succeed by going through the proxy: studio.example does
        // not resolve here, so a direct dial would fail. The proxy also must
        // have received a CONNECT for the target.
        let _stream = t.dial_tcp(2000).await.unwrap();
        assert!(saw_connect.load(std::sync::atomic::Ordering::SeqCst));
    }
}

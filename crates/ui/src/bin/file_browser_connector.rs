//! File Browser Connector for Strike48
//!
//! This binary runs the file browser as a Strike48 APP connector,
//! using Dioxus liveview with HTTP + WebSocket proxy.
//!
//! Architecture:
//! - Dioxus liveview server runs on localhost:3031
//!   - /liveview - HTML page with JS client
//!   - /ws - WebSocket for live updates
//! - Strike48 connector proxies requests to the liveview server
//!   - HTTP requests: ExecuteRequest → proxy to Dioxus
//!   - WebSocket: WsOpenRequest/WsFrame → proxy to Dioxus /ws

use axum::Router;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dashmap::DashMap;
use dioxus::prelude::*;
use dioxus_liveview::LiveviewRouter as _;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use strike48_connector::{
    AppManifest, AppPageRequest, AppPageResponse, BodyEncoding, ConnectorBehavior, ConnectorClient,
    ConnectorConfig, NavigationConfig, PayloadEncoding,
};
use strike48_proto::proto::{
    self, stream_message::Message, ConnectorCapabilities, ExecuteResponse,
    RegisterConnectorRequest, StreamMessage, WebSocketCloseRequest, WebSocketFrame,
    WebSocketFrameType, WebSocketOpenRequest, WebSocketOpenResponse,
};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

use pentest_ui::FileBrowser;

/// Port for the internal Dioxus liveview server
const DIOXUS_PORT: u16 = 3031;

/// Workspace path (configurable via env var)
fn get_workspace_path() -> String {
    std::env::var("WORKSPACE_PATH").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{}/workspace", home)
    })
}

/// Proxy HTTP requests to the Dioxus backend server
async fn proxy_to_dioxus(path: &str, _params: &HashMap<String, String>) -> AppPageResponse {
    let target_path = if path == "/" || path.is_empty() {
        "/liveview"
    } else {
        path
    };

    let url = format!("http://127.0.0.1:{}{}", DIOXUS_PORT, target_path);
    tracing::debug!("Proxying {} -> {}", path, url);

    match reqwest::get(&url).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("text/html")
                .to_string();

            match resp.bytes().await {
                Ok(body) => {
                    let mut body_str = String::from_utf8_lossy(&body).to_string();

                    if content_type.contains("html") {
                        body_str = rewrite_dioxus_websocket_url(&body_str);
                    }

                    AppPageResponse {
                        content_type,
                        body: body_str,
                        status,
                        encoding: BodyEncoding::Utf8,
                        headers: HashMap::new(),
                    }
                }
                Err(e) => AppPageResponse::error(502, format!("Error reading response: {}", e)),
            }
        }
        Err(e) => {
            tracing::error!("Failed to proxy request to {}: {}", url, e);
            AppPageResponse::error(502, format!("Backend unavailable: {}", e))
        }
    }
}

/// Inject Phoenix Socket shim for Strike48 WebSocket proxy
fn rewrite_dioxus_websocket_url(html: &str) -> String {
    let phoenix_shim = r#"<script>
// Strike48 Phoenix Socket Shim for Dioxus LiveView
(function() {
  console.log('[Strike48WsShim] Installing WebSocket shim...');

  const PHX_VSN = '2.0.0';
  const SOCKET_STATES = {connecting: 0, open: 1, closing: 2, closed: 3};

  const NativeWebSocket = window.WebSocket;
  window.__STRIKE48_NATIVE_WEBSOCKET__ = NativeWebSocket;

  class Strike48WebSocket {
    constructor(url) {
      this.url = url;
      this.readyState = SOCKET_STATES.connecting;
      this.onopen = null;
      this.onclose = null;
      this.onerror = null;
      this.onmessage = null;
      this._ref = 0;
      this._joinRef = null;
      this.binaryType = 'blob';
      this._eventListeners = {open: [], close: [], error: [], message: []};

      const urlObj = new URL(url, window.location.origin);
      const isLiveViewWs = urlObj.pathname.includes('/ws') || urlObj.pathname.includes('/live');

      if (!isLiveViewWs) {
        console.log('[Strike48WsShim] Non-LiveView WebSocket, using native:', url);
        return new NativeWebSocket(url);
      }

      this._wsPath = urlObj.pathname;
      console.log('[Strike48WsShim] LiveView WebSocket detected, path:', this._wsPath);
      this._waitForStrike48AndConnect();
    }

    _waitForStrike48AndConnect() {
      const check = () => {
        if (window.__MATRIX_SESSION_TOKEN__ && window.__MATRIX_APP_ADDRESS__) {
          console.log('[Strike48WsShim] Strike48 ready, connecting...');
          this._connectToStrike48();
        } else {
          setTimeout(check, 50);
        }
      };
      check();
    }

    _connectToStrike48() {
      const token = window.__MATRIX_SESSION_TOKEN__;
      const appAddress = window.__MATRIX_APP_ADDRESS__;

      let host = window.location.host;
      const baseTag = document.querySelector('base');
      if (baseTag && baseTag.href) {
        try {
          const baseUrl = new URL(baseTag.href);
          host = baseUrl.host;
        } catch (e) {}
      }

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const phoenixUrl = protocol + '//' + host +
        '/api/app/ws/websocket?__st=' + encodeURIComponent(token) +
        '&app=' + encodeURIComponent(appAddress) +
        '&vsn=' + PHX_VSN;

      console.log('[Strike48WsShim] Connecting to Phoenix socket:', phoenixUrl);

      this._socket = new NativeWebSocket(phoenixUrl);
      this._socket.binaryType = 'arraybuffer';

      this._socket.onopen = () => {
        console.log('[Strike48WsShim] Phoenix socket connected, joining channel');
        this._joinChannel();
      };

      this._socket.onclose = (event) => {
        this.readyState = SOCKET_STATES.closed;
        if (this._heartbeatInterval) clearInterval(this._heartbeatInterval);
        this._dispatchEvent('close', event);
      };

      this._socket.onerror = (event) => {
        this._dispatchEvent('error', event);
      };

      this._socket.onmessage = (event) => {
        this._handlePhoenixMessage(event.data);
      };
    }

    _joinChannel() {
      this._joinRef = String(++this._ref);
      const topic = 'app_ws:' + this._wsPath;
      const joinMsg = JSON.stringify([this._joinRef, String(++this._ref), topic, 'phx_join', {}]);
      console.log('[Strike48WsShim] Joining channel:', topic);
      this._socket.send(joinMsg);
    }

    _handlePhoenixMessage(data) {
      let msg;
      try { msg = JSON.parse(data); } catch (e) { return; }

      const [joinRef, ref, topic, event, payload] = msg;

      if (event === 'phx_reply' && joinRef === this._joinRef) {
        if (payload.status === 'ok') {
          console.log('[Strike48WsShim] Channel joined successfully');
          this.readyState = SOCKET_STATES.open;
          this._startHeartbeat();
          this._dispatchEvent('open', {type: 'open'});
        } else {
          this._dispatchEvent('error', new Error('Channel join failed'));
        }
      } else if (event === 'frame') {
        const frameData = payload.data;
        let messageData;
        try {
          const binary = atob(frameData);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
          }
          messageData = bytes.buffer;
        } catch (e) {
          messageData = frameData;
        }
        this._dispatchEvent('message', {data: messageData, type: 'message'});
      } else if (event === 'close' || event === 'phx_close') {
        this.readyState = SOCKET_STATES.closed;
        this._dispatchEvent('close', {code: 1000, reason: 'closed'});
      } else if (event === 'phx_error') {
        this._dispatchEvent('error', new Error('Channel error'));
      }
    }

    _startHeartbeat() {
      this._heartbeatInterval = setInterval(() => {
        if (this.readyState !== SOCKET_STATES.open) return;
        const heartbeat = JSON.stringify([null, String(++this._ref), 'phoenix', 'heartbeat', {}]);
        this._socket.send(heartbeat);
      }, 30000);
    }

    send(data) {
      if (this.readyState !== SOCKET_STATES.open) return;

      const topic = 'app_ws:' + this._wsPath;
      let framePayload;

      if (data instanceof ArrayBuffer || data instanceof Uint8Array) {
        const bytes = new Uint8Array(data);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        framePayload = {data: btoa(binary), type: 'binary'};
      } else {
        const str = String(data);
        const bytes = new TextEncoder().encode(str);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        framePayload = {data: btoa(binary), type: 'text'};
      }

      const msg = JSON.stringify([this._joinRef, String(++this._ref), topic, 'frame', framePayload]);
      this._socket.send(msg);
    }

    close(code, reason) {
      if (this.readyState === SOCKET_STATES.closed) return;
      this.readyState = SOCKET_STATES.closing;
      if (this._heartbeatInterval) clearInterval(this._heartbeatInterval);
      this._socket.close(code || 1000, reason || '');
    }

    addEventListener(type, listener) {
      this._eventListeners[type] = this._eventListeners[type] || [];
      this._eventListeners[type].push(listener);
    }

    removeEventListener(type, listener) {
      if (this._eventListeners[type]) {
        this._eventListeners[type] = this._eventListeners[type].filter(l => l !== listener);
      }
    }

    _dispatchEvent(type, event) {
      const handler = this['on' + type];
      if (handler) handler.call(this, event);
      if (this._eventListeners[type]) {
        this._eventListeners[type].forEach(l => l.call(this, event));
      }
    }
  }

  window.WebSocket = Strike48WebSocket;
  console.log('[Strike48WsShim] WebSocket constructor replaced');
})();
</script>"#;

    let replacement_fn = r#"function __dioxusGetWsUrl(path) {
      let loc = window.location;
      let new_url = loc.protocol === "https:" ? "wss:" : "ws:";
      new_url += "//" + loc.host + path;
      console.log('[Dioxus] WebSocket URL:', new_url);
      return new_url;
    }"#;

    let re = regex::Regex::new(
        r#"function __dioxusGetWsUrl\(path\) \{[\s\S]*?new_url \+= "\/\/" \+ loc\.host \+ path;[\s\S]*?return new_url;[\s\S]*?\}"#
    ).unwrap();

    let mut result = html.to_string();

    if re.is_match(html) {
        tracing::info!("Rewriting Dioxus WebSocket URL function and injecting Phoenix shim");
        result = re.replace(&result, replacement_fn).to_string();

        if let Some(head_end) = result.find("</head>") {
            result.insert_str(head_end, phoenix_shim);
        } else if let Some(body_start) = result.find("<body") {
            result.insert_str(body_start, phoenix_shim);
        }
    }

    result
}

/// The Dioxus App component that wraps FileBrowser
#[component]
fn FileBrowserApp() -> Element {
    let workspace = get_workspace_path();
    rsx! {
        FileBrowser { workspace_path: workspace }
    }
}

/// Start the Dioxus liveview server
async fn start_dioxus_server() {
    use axum::routing::get;

    tracing::info!("Starting Dioxus liveview server on port {}", DIOXUS_PORT);

    let router = Router::new()
        .with_app("/", FileBrowserApp)
        .route("/health", get(|| async { "OK" }));

    let addr: SocketAddr = ([127, 0, 0, 1], DIOXUS_PORT).into();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    tracing::info!("Dioxus liveview server listening on http://{}", addr);

    axum::serve(listener, router.into_make_service())
        .await
        .unwrap();
}

/// WebSocket connection state
struct WsConnectionState {
    to_backend_tx: mpsc::Sender<Vec<u8>>,
}

/// Main connector that handles the gRPC stream directly
struct FileBrowserConnector {
    ws_connections: Arc<DashMap<String, WsConnectionState>>,
    matrix_tx: mpsc::UnboundedSender<StreamMessage>,
}

impl FileBrowserConnector {
    fn new(matrix_tx: mpsc::UnboundedSender<StreamMessage>) -> Self {
        Self {
            ws_connections: Arc::new(DashMap::new()),
            matrix_tx,
        }
    }

    async fn handle_execute(&self, req: proto::ExecuteRequest) {
        let request_id = req.request_id.clone();

        let page_request: AppPageRequest =
            serde_json::from_slice(&req.payload).unwrap_or_else(|_| AppPageRequest {
                path: "/".to_string(),
                params: HashMap::new(),
            });

        let response = proxy_to_dioxus(&page_request.path, &page_request.params).await;
        let payload = serde_json::to_vec(&response).unwrap_or_default();

        let response_msg = StreamMessage {
            message: Some(Message::ExecuteResponse(ExecuteResponse {
                request_id,
                success: true,
                payload,
                payload_encoding: PayloadEncoding::Json as i32,
                error: String::new(),
                duration_ms: 0,
            })),
        };

        if let Err(e) = self.matrix_tx.send(response_msg) {
            tracing::error!("Failed to send execute response: {}", e);
        }
    }

    async fn handle_ws_open(&self, req: WebSocketOpenRequest) {
        let connection_id = req.connection_id.clone();

        let ws_path = if req.path.is_empty() {
            "/ws"
        } else {
            &req.path
        };
        let ws_url = if req.query_string.is_empty() {
            format!("ws://127.0.0.1:{}{}", DIOXUS_PORT, ws_path)
        } else {
            format!(
                "ws://127.0.0.1:{}{}?{}",
                DIOXUS_PORT, ws_path, req.query_string
            )
        };

        tracing::info!("Opening WebSocket to backend: {}", ws_url);

        match connect_async(&ws_url).await {
            Ok((ws_stream, _)) => {
                tracing::info!("WebSocket connected for connection_id: {}", connection_id);

                let (mut ws_sink, mut ws_source) = ws_stream.split();
                let (to_backend_tx, mut to_backend_rx) = mpsc::channel::<Vec<u8>>(100);

                self.ws_connections
                    .insert(connection_id.clone(), WsConnectionState { to_backend_tx });

                let response = StreamMessage {
                    message: Some(Message::WsOpenResponse(WebSocketOpenResponse {
                        connection_id: connection_id.clone(),
                        success: true,
                        error: String::new(),
                    })),
                };
                let _ = self.matrix_tx.send(response);

                let conn_id_write = connection_id.clone();
                tokio::spawn(async move {
                    while let Some(data) = to_backend_rx.recv().await {
                        let decoded = match String::from_utf8(data.clone()) {
                            Ok(base64_str) => BASE64.decode(&base64_str).unwrap_or(data),
                            Err(_) => data,
                        };

                        let msg = WsMessage::Binary(decoded.into());
                        if let Err(e) = ws_sink.send(msg).await {
                            tracing::error!("Error sending to backend WS {}: {}", conn_id_write, e);
                            break;
                        }
                    }
                });

                let conn_id_read = connection_id.clone();
                let matrix_tx = self.matrix_tx.clone();
                let ws_connections = self.ws_connections.clone();
                tokio::spawn(async move {
                    while let Some(msg_result) = ws_source.next().await {
                        match msg_result {
                            Ok(msg) => {
                                let (frame_type, data) = match msg {
                                    WsMessage::Text(text) => (
                                        WebSocketFrameType::WebsocketFrameTypeText,
                                        text.as_bytes().to_vec(),
                                    ),
                                    WsMessage::Binary(data) => (
                                        WebSocketFrameType::WebsocketFrameTypeBinary,
                                        data.to_vec(),
                                    ),
                                    WsMessage::Ping(data) => {
                                        (WebSocketFrameType::WebsocketFrameTypePing, data.to_vec())
                                    }
                                    WsMessage::Pong(data) => {
                                        (WebSocketFrameType::WebsocketFrameTypePong, data.to_vec())
                                    }
                                    WsMessage::Close(_) => {
                                        tracing::info!("Backend WS closed for {}", conn_id_read);
                                        break;
                                    }
                                    WsMessage::Frame(_) => continue,
                                };

                                let encoded_data = BASE64.encode(&data);

                                let frame = StreamMessage {
                                    message: Some(Message::WsFrame(WebSocketFrame {
                                        connection_id: conn_id_read.clone(),
                                        frame_type: frame_type as i32,
                                        data: encoded_data.into_bytes(),
                                    })),
                                };

                                if let Err(e) = matrix_tx.send(frame) {
                                    tracing::error!("Error sending frame to Strike48: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Error reading from backend WS {}: {}",
                                    conn_id_read,
                                    e
                                );
                                break;
                            }
                        }
                    }
                    ws_connections.remove(&conn_id_read);
                });
            }
            Err(e) => {
                tracing::error!("Failed to connect to backend WS: {}", e);
                let response = StreamMessage {
                    message: Some(Message::WsOpenResponse(WebSocketOpenResponse {
                        connection_id,
                        success: false,
                        error: format!("Failed to connect: {}", e),
                    })),
                };
                let _ = self.matrix_tx.send(response);
            }
        }
    }

    async fn handle_ws_frame(&self, frame: WebSocketFrame) {
        if let Some(conn) = self.ws_connections.get(&frame.connection_id) {
            if let Err(e) = conn.to_backend_tx.send(frame.data).await {
                tracing::error!("Error forwarding frame to backend: {}", e);
            }
        }
    }

    fn handle_ws_close(&self, req: WebSocketCloseRequest) {
        tracing::info!("Closing WebSocket: {}", req.connection_id);
        self.ws_connections.remove(&req.connection_id);
    }
}

/// Build the registration message
fn build_registration_message(config: &ConnectorConfig) -> StreamMessage {
    let manifest = AppManifest::new("Workspace Files", "/")
        .description("Browse the connector workspace filesystem")
        .icon("hero-folder-open")
        .navigation(NavigationConfig::nested(&["Apps"]));

    let manifest_json = serde_json::to_string(&manifest).unwrap_or_default();

    let mut metadata = HashMap::new();
    metadata.insert("app_manifest".to_string(), manifest_json);
    metadata.insert("timeout_ms".to_string(), "10000".to_string());

    let capabilities = ConnectorCapabilities {
        connector_type: "app-file-browser".to_string(),
        version: "1.0.0".to_string(),
        supported_encodings: vec![PayloadEncoding::Json as i32],
        behaviors: vec![ConnectorBehavior::App as i32],
        metadata,
        task_types: vec![],
    };

    let register_request = RegisterConnectorRequest {
        tenant_id: config.tenant_id.clone(),
        connector_type: "app-file-browser".to_string(),
        instance_id: config.instance_id.clone(),
        capabilities: Some(capabilities),
        jwt_token: config.auth_token.clone(),
        session_token: String::new(),
        scope: 0,
        instance_metadata: None,
    };

    StreamMessage {
        message: Some(Message::RegisterRequest(register_request)),
    }
}

/// Run the connector message loop
async fn run_message_loop(
    connector: Arc<FileBrowserConnector>,
    mut rx: mpsc::UnboundedReceiver<StreamMessage>,
    shutdown: &AtomicBool,
) {
    // Note: keepalive heartbeats are handled by the SDK's
    // start_stream_with_registration (sends HeartbeatRequest every 30s).

    loop {
        if shutdown.load(Ordering::SeqCst) {
            tracing::info!("Shutdown requested, exiting message loop");
            return;
        }

        tokio::select! {
            biased;

            // Periodic shutdown check
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                if shutdown.load(Ordering::SeqCst) {
                    return;
                }
            }

            msg_opt = rx.recv() => {
                let Some(msg) = msg_opt else {
                    tracing::info!("Stream closed by server");
                    return;
                };

                match msg.message {
                    Some(Message::RegisterResponse(resp)) => {
                        if resp.success {
                            tracing::info!("Registered successfully: {}", resp.connector_arn);
                        } else {
                            tracing::error!("Registration failed: {}", resp.error);
                            return;
                        }
                    }
                    Some(Message::ExecuteRequest(req)) => {
                        tracing::info!("Received ExecuteRequest: {}", req.request_id);
                        let connector = connector.clone();
                        tokio::spawn(async move {
                            connector.handle_execute(req).await;
                        });
                    }
                    Some(Message::WsOpenRequest(req)) => {
                        tracing::info!("Received WsOpenRequest: {} path={}", req.connection_id, req.path);
                        let connector = connector.clone();
                        tokio::spawn(async move {
                            connector.handle_ws_open(req).await;
                        });
                    }
                    Some(Message::WsFrame(frame)) => {
                        connector.handle_ws_frame(frame).await;
                    }
                    Some(Message::WsCloseRequest(req)) => {
                        connector.handle_ws_close(req);
                    }
                    _ => {}
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    tracing::info!("Starting File Browser Connector");
    tracing::info!("================================");
    tracing::info!("Workspace path: {}", get_workspace_path());

    // Create workspace directory if it doesn't exist
    let workspace = get_workspace_path();
    if !std::path::Path::new(&workspace).exists() {
        std::fs::create_dir_all(&workspace)?;
        tracing::info!("Created workspace directory: {}", workspace);
    }

    // Start Dioxus liveview server in background
    let dioxus_handle = tokio::spawn(start_dioxus_server());

    // Wait for server to start
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Verify server is running
    match reqwest::get(format!("http://127.0.0.1:{}/health", DIOXUS_PORT)).await {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!("Dioxus liveview server is ready");
        }
        _ => {
            tracing::error!("Failed to connect to Dioxus server");
        }
    }

    // Build config from environment
    let mut config = ConnectorConfig::from_env();
    config.connector_type = "app-file-browser".to_string();

    if let Ok(instance_id) = std::env::var("INSTANCE_ID") {
        config.instance_id = instance_id;
    }

    tracing::info!("Registering with Strike48 as APP connector...");
    tracing::info!("  - Host: {}", config.host);
    tracing::info!("  - Tenant: {}", config.tenant_id);
    tracing::info!("  - Instance: {}", config.instance_id);

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Received shutdown signal (Ctrl+C)");
        shutdown_clone.store(true, Ordering::SeqCst);
    });

    // Connection loop
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        // Create client and connect
        let mut client = ConnectorClient::new(config.host.clone(), config.use_tls);

        if let Err(e) = client.connect_channel().await {
            tracing::error!("Failed to connect: {}", e);
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            continue;
        }

        tracing::info!("Connected to Strike48, starting stream...");

        // Build registration message
        let registration_msg = build_registration_message(&config);

        // Start bidirectional stream
        let (tx, rx) = match client
            .start_stream_with_registration(registration_msg)
            .await
        {
            Ok(streams) => streams,
            Err(e) => {
                tracing::error!("Failed to start stream: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        // Create connector with outbound channel
        let connector = Arc::new(FileBrowserConnector::new(tx));

        tracing::info!("Waiting for registration response...");

        // Run message loop
        run_message_loop(connector, rx, &shutdown).await;

        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        tracing::info!("Connection closed, reconnecting...");
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    tracing::info!("Connector shutting down...");
    dioxus_handle.abort();
    tracing::info!("Shutdown complete");

    Ok(())
}

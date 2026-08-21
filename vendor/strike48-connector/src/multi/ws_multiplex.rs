//! WebSocket multiplexing: many logical connectors sharing one Phoenix socket.
//!
//! When [`crate::MultiConnectorRunner`] runs over [`TransportType::WebSocket`]
//! with multiple registrations, every registration that shares a `tenant_id`
//! is folded onto a single underlying [`crate::transport::WebSocketTransport`]
//! (one TCP connection, one Phoenix `connector:lobby` channel). Different
//! tenants always get separate sockets — cross-tenant isolation is a hard
//! security boundary.
//!
//! ## How dispatch works
//!
//! Outbound is trivial: every per-handle runner pushes `StreamMessage`s into
//! a single bounded `mpsc::Sender` that drives the shared socket's writer.
//! The Phoenix transport already serialises writes.
//!
//! Inbound runs through one demux task per socket:
//!
//! - `register_response` → keyed by the response's own `connector_arn` (built
//!   from `matrix:tenant:type:instance`).
//! - `execute_request` / `invoke_request` → keyed by `context["connector_arn"]`
//!   stamped by the server. With exactly one handle on the socket the
//!   ARN is allowed to be missing (back-compat with old single-connector
//!   sockets); with more than one handle, an unmatched ARN drops the frame
//!   and logs.
//! - `execute_response` / `invoke_response` → routed by `request_id` against
//!   the socket-level pending map (`request_id → handle`).
//! - `credentials_issued` / `approval_notification` / `register_response`-style
//!   one-shots → routed via the same pending-register table that owns the
//!   first `register_response`. With one handle they always go to it.
//! - heartbeat replies and other connection-level frames are owned by the
//!   socket and don't reach handles.
//!
//! ## Lifecycle
//!
//! - One [`WsMultiplexSocket`] per tenant per [`MultiConnectorRunner::run`].
//! - When the socket drops, every handle re-enters its own register-and-
//!   drive loop; the socket itself transparently reconnects via the same
//!   reconnect path `WebSocketTransport` already uses.
//! - When a handle exits (shutdown / unrecoverable register failure), the
//!   socket reaps its routing entries and continues serving the rest. When
//!   the last handle exits, the socket task winds down on its own.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use rand::{Rng, thread_rng};
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc, oneshot};

use crate::connector::{BaseConnector, ConnectorConfig};
use crate::error::{ConnectorError, Result};
use crate::logger::Logger;
use crate::multi::registration_runner::{REJECTIONS_BEFORE_TOKEN_DROP, auth_mint_budget};
use crate::multi::{MultiTransportOptions, RegistrationKey};
use crate::transport::{Transport, TransportOptions, TransportType, WebSocketTransport};
use crate::types::{ConnectorMetrics, ExecuteRequest as SdkExecuteRequest, PayloadEncoding};
use crate::utils::{deserialize_payload, error_response, sanitize_identifier, serialize_payload};

use strike48_proto::proto::{
    self, ConnectorCapabilities, HeartbeatRequest, HeartbeatResponse, InstanceMetadata,
    RegisterConnectorRequest, StreamMessage, stream_message,
};

/// Outbound mpsc capacity per shared socket. Sized so that bursts from one
/// handle can't deadlock writers for the others.
const SHARED_OUTBOUND_CAPACITY: usize = 256;

/// Granularity for shutdown-aware sleeps so reconnect backoff can be
/// interrupted promptly.
const SHUTDOWN_POLL: Duration = Duration::from_millis(50);

/// Default app-level heartbeat cadence. Mirrors
/// [`crate::multi::registration_runner::HEARTBEAT_INTERVAL`]. Phoenix-level
/// pings keep the WS pipe alive, but Matrix's per-channel idle watchdog
/// fires on app-level silence — so we send a periodic `HeartbeatRequest`
/// from the socket so it covers every handle on it at once.
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

// =============================================================================
// Shared per-socket state
// =============================================================================

/// Per-handle inbound channels and metadata held by the shared socket. The
/// demux task looks up entries here when routing inbound frames. One entry
/// is registered before each handle's first `register_request` is sent and
/// removed when the handle exits.
struct HandleEntry {
    key: RegistrationKey,
    /// Inbound frames addressed to this handle (execute_request,
    /// invoke_request, execute_response/invoke_response by request_id,
    /// credentials_issued / approval_notification routed by gateway_id).
    inbound_tx: mpsc::Sender<StreamMessage>,
    /// Sender for the one-shot first register_response so the handle's
    /// register-and-drive loop can `await` it. Cleared after the first
    /// successful register; subsequent in-stream re-registrations flow
    /// through `inbound_tx` like any other frame.
    pending_register: Mutex<Option<oneshot::Sender<proto::RegisterConnectorResponse>>>,
}

/// State the demux task needs to route inbound messages. Wrapped in an `Arc`
/// so handles can register/unregister themselves without owning the socket.
pub(crate) struct WsMultiplexSocket {
    pub tenant_id: String,
    /// Outbound writer fed by every handle. The socket task forwards into
    /// the underlying `WebSocketTransport`.
    outbound_tx: mpsc::Sender<StreamMessage>,
    /// `arn → handle` (e.g. `matrix:tenant:type:instance`). Populated when a
    /// `register_response` is observed; lookup target for `execute_request`
    /// and `invoke_request` inbound dispatch.
    by_arn: RwLock<HashMap<String, Arc<HandleEntry>>>,
    /// `tenant.type.instance → handle`. Populated synchronously when the
    /// handle is admitted; targets for inbound frames that arrive before
    /// the first `register_response` (most importantly the response itself
    /// and `credentials_issued`).
    by_dot: RwLock<HashMap<String, Arc<HandleEntry>>>,
    /// `request_id → handle` for outbound `execute_request` / `invoke_request`
    /// emitted by handles. Populated by the handle right before it sends;
    /// drained when the matching response routes back.
    by_request_id: RwLock<HashMap<String, Arc<HandleEntry>>>,
    shutdown: Arc<AtomicBool>,
    /// Last time any frame was observed from the server. The socket task
    /// uses this as a soft proof-of-life.
    last_inbound: Mutex<Instant>,
    /// Per-socket handler cap (configured via
    /// [`MultiTransportOptions::max_handlers_per_socket`]). The cap mirrors
    /// the Phoenix-channel handler cap on the server; we enforce it locally
    /// so users get a typed error instead of a delayed server-side rejection.
    max_handlers: usize,
    /// Set the first time any handle on this socket gets a successful
    /// register_response. Read by `run_tenant_group` to decide whether the
    /// socket actually started doing useful work — if no handle ever
    /// registered, we don't reset the socket-level reconnect attempt
    /// counter, otherwise a server that admits the WS handshake but rejects
    /// every register would loop with zero backoff.
    register_acked: Arc<AtomicBool>,
}

impl WsMultiplexSocket {
    fn new(
        tenant_id: String,
        outbound_tx: mpsc::Sender<StreamMessage>,
        max_handlers: usize,
    ) -> Self {
        Self {
            tenant_id,
            outbound_tx,
            by_arn: RwLock::new(HashMap::new()),
            by_dot: RwLock::new(HashMap::new()),
            by_request_id: RwLock::new(HashMap::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            last_inbound: Mutex::new(Instant::now()),
            max_handlers: max_handlers.max(1),
            register_acked: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Cap check + admit a handle. Returns the registered entry on success;
    /// `Err(InvalidConfig)` if admitting would push us past the configured
    /// per-socket handler cap.
    async fn admit(
        self: &Arc<Self>,
        key: RegistrationKey,
        inbound_tx: mpsc::Sender<StreamMessage>,
        pending_register: oneshot::Sender<proto::RegisterConnectorResponse>,
    ) -> Result<Arc<HandleEntry>> {
        let dot = key.to_string();
        let mut by_dot = self.by_dot.write().await;
        if by_dot.len() >= self.max_handlers {
            return Err(ConnectorError::InvalidConfig(format!(
                "ws multiplex: cannot admit registration {dot}; \
                 per-socket handler cap of {} reached for tenant '{}'",
                self.max_handlers, self.tenant_id
            )));
        }
        if by_dot.contains_key(&dot) {
            return Err(ConnectorError::InvalidConfig(format!(
                "ws multiplex: registration {dot} is already admitted on this socket"
            )));
        }
        let entry = Arc::new(HandleEntry {
            key,
            inbound_tx,
            pending_register: Mutex::new(Some(pending_register)),
        });
        by_dot.insert(dot, entry.clone());
        Ok(entry)
    }

    async fn evict(&self, key: &RegistrationKey, arn: Option<&str>) {
        let dot = key.to_string();
        self.by_dot.write().await.remove(&dot);
        if let Some(arn) = arn {
            self.by_arn.write().await.remove(arn);
        }
        // Drain any request_id entries owned by this handle. We don't have
        // an index by handle so this is O(N) over outstanding requests;
        // in practice the table has at most ~hundreds of entries.
        let mut by_id = self.by_request_id.write().await;
        by_id.retain(|_, h| h.key != *key);
    }

    /// Single-handle convenience used by the inbound demux fallback rule.
    async fn sole_handle(&self) -> Option<Arc<HandleEntry>> {
        let by_dot = self.by_dot.read().await;
        if by_dot.len() == 1 {
            by_dot.values().next().cloned()
        } else {
            None
        }
    }

    /// Defensive lookup for inbound frames whose dot-form key does not
    /// exactly match what we admitted: scan `by_dot` for entries whose
    /// `instance_id` matches `target`. Returns `Some` only when exactly
    /// one entry matches — a unique `instance_id` is enough to route
    /// safely even when the server canonicalises `connector_type` to a
    /// different value than we registered with (e.g. stripping a vendor
    /// prefix). With multiple matches we refuse to guess and let the
    /// caller drop the frame.
    async fn unique_by_instance_id(&self, target: &str) -> Option<Arc<HandleEntry>> {
        if target.is_empty() {
            return None;
        }
        let by_dot = self.by_dot.read().await;
        let mut matches = by_dot
            .values()
            .filter(|entry| entry.key.instance_id == target);
        let first = matches.next()?.clone();
        if matches.next().is_some() {
            return None;
        }
        Some(first)
    }

    /// Bind a new arn for a handle. Idempotent.
    async fn bind_arn(&self, arn: String, handle: Arc<HandleEntry>) {
        self.by_arn.write().await.insert(arn, handle);
    }

    /// Reserved for future SDK-initiated outbound `invoke_request` /
    /// `execute_request` paths that need to track their own request_id for
    /// response correlation. Currently the connector implementations do not
    /// emit such requests on this code path; keep this hook so the wiring
    /// stays close to the gRPC runner.
    #[allow(dead_code)]
    async fn track_request_id(&self, request_id: String, handle: Arc<HandleEntry>) {
        self.by_request_id.write().await.insert(request_id, handle);
    }

    #[allow(dead_code)]
    fn outbound(&self) -> mpsc::Sender<StreamMessage> {
        self.outbound_tx.clone()
    }
}

// =============================================================================
// Socket task: owns the WebSocketTransport, runs the demux and writer loops
// =============================================================================

/// Open a shared multiplex socket for `tenant_id` and start its demux loop.
/// Returns the socket state plus the JoinHandle for the demux task.
async fn open_socket(
    tenant_id: &str,
    opts: &MultiTransportOptions,
    runner_shutdown: Arc<AtomicBool>,
) -> Result<(Arc<WsMultiplexSocket>, tokio::task::JoinHandle<()>)> {
    let proxy = crate::transport::proxy::resolve_proxy(
        &opts.host,
        opts.use_tls,
        std::env::var("STUDIO_PROXY").ok().as_deref(),
        &|k| std::env::var(k).ok(),
    )?;
    if let Some(p) = &proxy {
        // Announce once per process at info (open_socket runs per reconnect, so
        // an unconditional info here would spam). Subsequent reopens log at debug.
        static PROXY_ANNOUNCED: AtomicBool = AtomicBool::new(false);
        if !PROXY_ANNOUNCED.swap(true, Ordering::Relaxed) {
            tracing::info!(proxy = %p, tenant = %tenant_id, "studio proxy ENABLED (HTTP CONNECT)");
        } else {
            tracing::debug!(proxy = %p, tenant = %tenant_id, "studio proxy ENABLED (HTTP CONNECT)");
        }
    }
    let transport_opts = TransportOptions {
        host: opts.host.clone(),
        use_tls: opts.use_tls,
        connect_timeout_ms: Some(opts.connect_timeout_ms),
        default_timeout_ms: None,
        channel_capacity: Some(SHARED_OUTBOUND_CAPACITY),
        proxy,
    };
    let mut transport = WebSocketTransport::new(transport_opts);

    // Note: we deliberately skip `transport.connect()` and go straight to
    // `start_stream()`. The websocket transport's `connect()` opens a TCP
    // connection that is then *discarded*; `start_stream()` opens a fresh
    // one. Calling both would dial the server twice per tenant — visible to
    // tests as two `sockets_accepted`. The first registration through this
    // socket sends its own register_request; there's no socket-level
    // payload to deliver here.
    let (writer_tx, mut reader_rx) = transport.start_stream(None).await?;

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<StreamMessage>(SHARED_OUTBOUND_CAPACITY);
    let socket = Arc::new(WsMultiplexSocket::new(
        tenant_id.to_string(),
        outbound_tx,
        opts.max_handlers_per_socket,
    ));

    // Bridge the socket's per-handle outbound mpsc into the transport's
    // unbounded sender. The bridge exits when either side closes.
    let bridge_handle = {
        let writer_tx = writer_tx.clone();
        tokio::spawn(async move {
            while let Some(msg) = outbound_rx.recv().await {
                if writer_tx.send(msg).is_err() {
                    break;
                }
            }
        })
    };

    // App-level keepalive. Phoenix-level pings already keep the WS pipe
    // alive, but Matrix runs a per-channel idle watchdog on top —
    // observed to drop the channel with code 1002 after ~2min of no
    // app-level traffic. Send a `HeartbeatRequest` at `heartbeat_interval`
    // (default 30s, well under the observed 120s threshold). One task
    // per socket — every handle on the socket benefits from it.
    //
    // We deliberately do NOT enforce an inbound-silence timeout here.
    // Pipe-level liveness is the transport's job (Phoenix WS ping/pong
    // closes the reader on a dead pipe), and a server that admits the
    // outbound heartbeat without ever echoing it is still a healthy
    // peer for our purposes — preemptively tearing the socket down on
    // app-level silence false-positives a fully working channel into a
    // disconnect storm.
    let heartbeat_handle = {
        let socket_for_hb = socket.clone();
        let runner_shutdown = runner_shutdown.clone();
        let interval_dur = opts
            .heartbeat_interval
            .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval_dur);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Drop the immediate first tick; we just opened the socket.
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = tokio::time::sleep(SHUTDOWN_POLL) => {
                        if runner_shutdown.load(Ordering::SeqCst)
                            || socket_for_hb.shutdown.load(Ordering::SeqCst)
                        {
                            return;
                        }
                        continue;
                    }
                }
                if runner_shutdown.load(Ordering::SeqCst)
                    || socket_for_hb.shutdown.load(Ordering::SeqCst)
                {
                    return;
                }
                let hb = StreamMessage {
                    message: Some(stream_message::Message::HeartbeatRequest(
                        HeartbeatRequest {
                            gateway_id: String::new(),
                            timestamp_ms: now_ms(),
                        },
                    )),
                };
                if socket_for_hb.outbound_tx.send(hb).await.is_err() {
                    // Outbound bridge gone — socket is winding down.
                    return;
                }
            }
        })
    };

    // Demux loop. Owned by this task; routes inbound frames to per-handle
    // queues and forwards heartbeat replies on its own. Holding the
    // transport keeps the connection alive for the life of the loop;
    // dropping the transport at the end disconnects.
    let socket_clone = socket.clone();
    let heartbeat_for_demux = heartbeat_handle.abort_handle();
    let demux = tokio::spawn(async move {
        let logger = Logger::new("multi/ws");
        // Keep the transport alive for the duration of the demux loop;
        // dropping it will close the WebSocket on the way out.
        let _transport_keepalive = transport;

        while let Some(msg) = reader_rx.recv().await {
            *socket_clone.last_inbound.lock().await = Instant::now();

            if runner_shutdown.load(Ordering::SeqCst)
                || socket_clone.shutdown.load(Ordering::SeqCst)
            {
                break;
            }

            dispatch_inbound_to_handle(&socket_clone, msg, &logger).await;
        }

        socket_clone.shutdown.store(true, Ordering::SeqCst);
        // Once the reader loop exits, broadcast EOF to every admitted
        // handle by dropping their inbound senders.
        let mut by_dot = socket_clone.by_dot.write().await;
        by_dot.clear();
        socket_clone.by_arn.write().await.clear();
        socket_clone.by_request_id.write().await.clear();
        bridge_handle.abort();
        heartbeat_for_demux.abort();
    });

    Ok((socket, demux))
}

/// Route a single inbound frame to the correct handle (or to the socket-
/// level handler for connection-scoped frames). Drops + logs frames that
/// can't be routed.
async fn dispatch_inbound_to_handle(
    socket: &Arc<WsMultiplexSocket>,
    msg: StreamMessage,
    logger: &Logger,
) {
    match msg.message.as_ref() {
        Some(stream_message::Message::HeartbeatRequest(_)) => {
            // Server-initiated heartbeat: reply directly from the socket.
            // The transport already responds to Phoenix-level pings; this
            // covers the application-level proto heartbeat used by gRPC.
            let resp = StreamMessage {
                message: Some(stream_message::Message::HeartbeatResponse(
                    HeartbeatResponse {
                        gateway_id: String::new(),
                        timestamp_ms: now_ms(),
                        should_reconnect: false,
                    },
                )),
            };
            let _ = socket.outbound_tx.send(resp).await;
        }
        Some(stream_message::Message::HeartbeatResponse(_)) => {
            // Connection-level liveness; the per-socket reader updates
            // last_inbound for us. No per-handle action.
        }
        Some(stream_message::Message::RegisterResponse(resp)) => {
            // First-register: deliver via the pending oneshot if there is
            // one. The handle was admitted by its dot-form key; rebuild
            // the same dot form from the response's ARN.
            //
            // Fallback chain when the dot-form key from the ARN doesn't
            // match `by_dot` (typically because the server canonicalises
            // `connector_type` to a different value than the SDK
            // registered with):
            //   1. Match by `instance_id` alone (ARN's last segment).
            //      `instance_id` is unique per registration on a socket,
            //      so a single match routes deterministically without
            //      relying on `connector_type` agreement with the server.
            //   2. `sole_handle()` — only when exactly one handle is
            //      admitted, the legacy single-connector back-compat path.
            let parsed = arn_parts(&resp.connector_arn);
            let dot = parsed.as_ref().map(|p| format!("{}.{}.{}", p.0, p.1, p.2));
            let instance_from_arn = parsed.as_ref().map(|p| p.2);

            let mut handle: Option<Arc<HandleEntry>> = None;
            if let Some(d) = &dot {
                handle = socket.by_dot.read().await.get(d).cloned();
            }
            if handle.is_none()
                && let Some(inst) = instance_from_arn
            {
                handle = socket.unique_by_instance_id(inst).await;
                if handle.is_some() {
                    logger.debug(&format!(
                        "ws multiplex: register_response for arn '{}' \
                         routed by instance_id fallback (tenant '{}')",
                        resp.connector_arn, socket.tenant_id
                    ));
                }
            }
            if handle.is_none() {
                handle = socket.sole_handle().await;
            }
            let handle = match handle {
                Some(h) => h,
                None => {
                    if dot.is_none() {
                        logger.warn(&format!(
                            "ws multiplex: register_response with malformed arn '{}' \
                             dropped (tenant '{}')",
                            resp.connector_arn, socket.tenant_id
                        ));
                    } else {
                        logger.warn(&format!(
                            "ws multiplex: register_response for unknown arn '{}' \
                             dropped (tenant '{}')",
                            resp.connector_arn, socket.tenant_id
                        ));
                    }
                    return;
                }
            };

            // Bind ARN → handle on success so subsequent execute_request /
            // invoke_request frames can route by ARN.
            if resp.success && !resp.connector_arn.is_empty() {
                socket
                    .bind_arn(resp.connector_arn.clone(), handle.clone())
                    .await;
            }

            let mut pending = handle.pending_register.lock().await;
            if let Some(tx) = pending.take() {
                // First register_response: hand it to the awaiting runner.
                let _ = tx.send(resp.clone());
                return;
            }
            drop(pending);

            // Subsequent in-stream register_response (e.g. post-OTT): forward
            // through the inbound queue so the runner observes it on the
            // same loop as everything else.
            forward_to_handle(&handle, msg, logger).await;
        }
        Some(stream_message::Message::ExecuteRequest(req)) => {
            let arn = req.context.get("connector_arn").map(String::as_str);
            route_inbound_by_arn(socket, msg.clone(), arn, "execute_request", logger).await;
        }
        Some(stream_message::Message::InvokeRequest(req)) => {
            let arn = req.context.get("connector_arn").map(String::as_str);
            route_inbound_by_arn(socket, msg.clone(), arn, "invoke_request", logger).await;
        }
        Some(stream_message::Message::ExecuteResponse(resp)) => {
            route_inbound_by_request_id(
                socket,
                msg.clone(),
                &resp.request_id,
                "execute_response",
                logger,
            )
            .await;
        }
        Some(stream_message::Message::InvokeResponse(resp)) => {
            route_inbound_by_request_id(
                socket,
                msg.clone(),
                &resp.request_id,
                "invoke_response",
                logger,
            )
            .await;
        }
        Some(stream_message::Message::CredentialsIssued(creds)) => {
            // The server stamps `gateway_id = tenant.type.instance` exactly
            // like our `by_dot` keys, so we can route deterministically
            // even with N>1 simultaneous bring-ups on one socket.
            let gid = creds.gateway_id.clone();
            route_inbound_by_gateway_id(socket, msg.clone(), &gid, "credentials_issued", logger)
                .await;
        }
        Some(stream_message::Message::ApprovalNotification(notif)) => {
            let gid = notif.gateway_id.clone();
            route_inbound_by_gateway_id(socket, msg.clone(), &gid, "approval_notification", logger)
                .await;
        }
        Some(other) => {
            // Forward unknown / un-routed variants to a sole handle if any;
            // otherwise log + drop.
            if let Some(handle) = socket.sole_handle().await {
                forward_to_handle(&handle, msg.clone(), logger).await;
            } else {
                logger.debug(&format!(
                    "ws multiplex: unrouted inbound variant {:?} dropped (tenant '{}')",
                    std::mem::discriminant(other),
                    socket.tenant_id
                ));
            }
        }
        None => {
            logger.debug("ws multiplex: empty inbound message");
        }
    }
}

async fn route_inbound_by_arn(
    socket: &Arc<WsMultiplexSocket>,
    msg: StreamMessage,
    arn: Option<&str>,
    label: &'static str,
    logger: &Logger,
) {
    if let Some(arn) = arn {
        let map = socket.by_arn.read().await;
        if let Some(handle) = map.get(arn).cloned() {
            drop(map);
            forward_to_handle(&handle, msg, logger).await;
            return;
        }
        // ARN was given but doesn't match. We deliberately do NOT fall back
        // to sole_handle here: if a handle just exited and exactly one
        // survivor remains, we'd misroute the frame to it. An addressed
        // frame with no matching admitted handle is a server/SDK skew —
        // drop it and log.
        logger.warn(&format!(
            "ws multiplex: {label} with unmatched connector_arn={arn:?} dropped (tenant '{}', \
             {} handles admitted)",
            socket.tenant_id,
            socket.by_dot.read().await.len()
        ));
        return;
    }
    // Address absent (legacy single-connector socket): deliver to the sole
    // handle if present. This is the back-compat path the brief calls out
    // as REQUIRED for unmodified single-connector deployments.
    if let Some(handle) = socket.sole_handle().await {
        forward_to_handle(&handle, msg, logger).await;
        return;
    }
    logger.warn(&format!(
        "ws multiplex: {label} without connector_arn dropped (tenant '{}', \
         {} handles admitted)",
        socket.tenant_id,
        socket.by_dot.read().await.len()
    ));
}

async fn route_inbound_by_request_id(
    socket: &Arc<WsMultiplexSocket>,
    msg: StreamMessage,
    request_id: &str,
    label: &'static str,
    logger: &Logger,
) {
    if !request_id.is_empty() {
        if let Some(handle) = socket.by_request_id.write().await.remove(request_id) {
            forward_to_handle(&handle, msg, logger).await;
            return;
        }
        // Same rationale as route_inbound_by_arn: the addressed handle
        // probably exited; fall-through to sole_handle would misroute.
        logger.warn(&format!(
            "ws multiplex: {label} request_id={request_id:?} matched no outstanding handle \
             (tenant '{}')",
            socket.tenant_id
        ));
        return;
    }
    // Address absent (rare; usually a malformed response): legacy
    // back-compat — deliver to sole handle if present.
    if let Some(handle) = socket.sole_handle().await {
        forward_to_handle(&handle, msg, logger).await;
        return;
    }
    logger.warn(&format!(
        "ws multiplex: {label} without request_id dropped (tenant '{}')",
        socket.tenant_id
    ));
}

/// Route a frame addressed by the proto-level `gateway_id` field
/// (`tenant.type.instance`, identical to our `by_dot` keys). Used for
/// `CredentialsIssued` and `ApprovalNotification`, which historically the
/// SDK routed by "whoever is currently registering"; that approach
/// collapsed under N>1 simultaneous bring-ups on one socket.
async fn route_inbound_by_gateway_id(
    socket: &Arc<WsMultiplexSocket>,
    msg: StreamMessage,
    gateway_id: &str,
    label: &'static str,
    logger: &Logger,
) {
    if !gateway_id.is_empty() {
        let map = socket.by_dot.read().await;
        if let Some(handle) = map.get(gateway_id).cloned() {
            drop(map);
            forward_to_handle(&handle, msg, logger).await;
            return;
        }
        logger.warn(&format!(
            "ws multiplex: {label} for unknown gateway_id={gateway_id:?} dropped (tenant '{}', \
             {} handles admitted)",
            socket.tenant_id,
            socket.by_dot.read().await.len()
        ));
        return;
    }
    // Older servers may omit gateway_id. Fall back to the sole-handle
    // back-compat path; with multiple admitted handles drop and log.
    if let Some(handle) = socket.sole_handle().await {
        forward_to_handle(&handle, msg, logger).await;
        return;
    }
    logger.warn(&format!(
        "ws multiplex: {label} without gateway_id dropped (tenant '{}', \
         {} handles admitted; cannot disambiguate)",
        socket.tenant_id,
        socket.by_dot.read().await.len()
    ));
}

async fn forward_to_handle(handle: &Arc<HandleEntry>, msg: StreamMessage, logger: &Logger) {
    if handle.inbound_tx.send(msg).await.is_err() {
        logger.debug(&format!(
            "ws multiplex: handle {} inbound channel closed; frame dropped",
            handle.key
        ));
    }
}

/// Parse ARN form `matrix:tenant:type:instance` into its three identity
/// components. Returns `None` for malformed ARNs (missing `matrix:`
/// prefix or fewer than four colon-separated segments). The fourth split
/// is bounded so any extra colons inside `instance` stay grouped with it.
fn arn_parts(arn: &str) -> Option<(&str, &str, &str)> {
    let parts: Vec<&str> = arn.splitn(4, ':').collect();
    if parts.len() < 4 || parts[0] != "matrix" {
        return None;
    }
    Some((parts[1], parts[2], parts[3]))
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// =============================================================================
// WsMultiplexHandle: per-registration runner using a shared socket
// =============================================================================

/// One logical registration backed by a shared [`WsMultiplexSocket`]. Mirrors
/// the gRPC [`crate::multi::registration_runner::RegistrationRunner`] surface
/// without owning a transport: outbound goes through the socket's writer,
/// inbound is delivered via a handle-private mpsc fed by the demux task.
pub(crate) struct WsMultiplexHandle {
    pub key: RegistrationKey,
    pub config: Arc<RwLock<ConnectorConfig>>,
    pub connector: Arc<dyn BaseConnector>,
    pub socket: Arc<WsMultiplexSocket>,
    pub shutdown: Arc<AtomicBool>,
    pub metrics: Arc<Mutex<ConnectorMetrics>>,
    pub opts: MultiTransportOptions,
    pub request_semaphore: Arc<Semaphore>,
    /// Per-handle session token. Mirrors the gRPC runner: persists across
    /// in-stream re-registers (post-OTT) so the server can identify this
    /// instance. None until the first successful register.
    pub session_token: Arc<RwLock<Option<String>>>,
    /// Count of consecutive registration *rejections* (not transient errors)
    /// since the last successful register. Once it reaches
    /// [`REJECTIONS_BEFORE_TOKEN_DROP`] the cached session token is dropped and
    /// auth is re-minted so the next attempt re-registers from scratch. Mirrors
    /// the gRPC runner's `consecutive_rejections`; see that field for the full
    /// rationale (K=2 absorbs a spurious rejection; reset on any success).
    pub consecutive_rejections: Arc<AtomicU32>,
}

impl WsMultiplexHandle {
    pub async fn run(self) -> Result<()> {
        let logger = Logger::new("multi/ws/handle");
        if self.shutdown.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Pre-approval auth: if this connector was approved in a previous run,
        // its Keycloak client_id + private key are persisted on disk. Load them
        // and mint a private_key_jwt into `config.auth_token` so the *initial*
        // register on this socket is already authenticated and the server skips
        // the pending-approval flow. Without this, a restarted connector
        // registers anonymously and is re-queued for approval even though it
        // already holds valid credentials. Mirrors Priority 3 of the
        // single-connector `ConnectorRunner::initialize_auth`.
        self.prime_auth_from_saved_credentials(&logger).await;

        let mut attempt: u32 = 0;
        let mut current_arn: Option<String> = None;
        let mut ever_registered = false;

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                self.socket.evict(&self.key, current_arn.as_deref()).await;
                return Ok(());
            }

            // The socket may have died (reader EOF, server kicked us). If
            // so, end the handle: the multi-runner-level reconnect path
            // will reopen a fresh socket and respawn handles.
            if self.socket.shutdown.load(Ordering::SeqCst) {
                logger.debug(&format!(
                    "ws multiplex handle {}: socket shut down, exiting",
                    self.key
                ));
                self.socket.evict(&self.key, current_arn.as_deref()).await;
                return Ok(());
            }

            let (inbound_tx, inbound_rx) = mpsc::channel::<StreamMessage>(64);
            let (register_tx, register_rx) = oneshot::channel::<proto::RegisterConnectorResponse>();

            let entry = match self
                .socket
                .admit(self.key.clone(), inbound_tx, register_tx)
                .await
            {
                Ok(e) => e,
                Err(e) => {
                    logger.error(
                        &format!(
                            "ws multiplex handle {}: admission rejected by socket",
                            self.key
                        ),
                        &e.to_string(),
                    );
                    return Err(e);
                }
            };

            // Build and send the register_request. We do not propagate
            // sanitization errors to the wire — `sanitize_identifier`
            // already rewrites forbidden chars; we just surface the
            // original config in the runner config field for telemetry.
            let register_msg = {
                let cfg = self.config.read().await;
                let token = self.session_token.read().await.clone().unwrap_or_default();
                build_register_message_with_token(&cfg, self.connector.as_ref(), &token)
            };
            if self.socket.outbound_tx.send(register_msg).await.is_err() {
                logger.warn(&format!(
                    "ws multiplex handle {}: outbound closed before register_request could be sent",
                    self.key
                ));
                self.socket.evict(&self.key, current_arn.as_deref()).await;
                return self.maybe_backoff(&logger, &mut attempt).await;
            }

            // Wait for the first register_response. With per-handle
            // CredentialsIssued/ApprovalNotification routing (by
            // `gateway_id`), N handles can be in this state concurrently
            // without races.
            let response_deadline =
                Duration::from_millis(self.opts.connect_timeout_ms.max(1)).saturating_mul(3);
            let resp = match wait_for_register_response(
                register_rx,
                &self.shutdown,
                &self.socket,
                response_deadline,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    logger.warn(&format!(
                        "ws multiplex handle {}: register failed: {e}",
                        self.key
                    ));
                    self.socket.evict(&self.key, current_arn.as_deref()).await;
                    if self.shutdown.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    if !self.opts.reconnect_enabled {
                        return Ok(());
                    }
                    attempt = attempt.saturating_add(1);
                    let backoff = compute_backoff(&self.opts, attempt);
                    {
                        let mut m = self.metrics.lock().await;
                        m.reconnection_attempts += 1;
                        m.current_backoff_ms = backoff.as_millis() as u64;
                    }
                    if !sleep_with_shutdown(backoff, &self.shutdown, Some(&self.socket.shutdown))
                        .await
                    {
                        return Ok(());
                    }
                    continue;
                }
            };

            if !resp.success {
                logger.warn(&format!(
                    "ws multiplex handle {}: register rejected: status='{}' error='{}'",
                    self.key, resp.status, resp.error
                ));
                // An in-band `success=false` is a credential rejection (the WS
                // analogue of the gRPC `RegistrationError`) — the usual cause
                // is a cached session token that no longer validates after a
                // Matrix redeploy rotates its session-signing secret. After
                // REJECTIONS_BEFORE_TOKEN_DROP consecutive rejections, drop the
                // token and re-mint auth so the next attempt re-registers from
                // scratch instead of replaying a credential the server keeps
                // refusing. Shares the counter with the in-stream re-register
                // path below.
                if self
                    .note_rejection_and_maybe_reset_credentials(&logger)
                    .await
                {
                    logger.warn(&format!(
                        "ws multiplex handle {}: reset rejected credentials after \
                         {REJECTIONS_BEFORE_TOKEN_DROP} consecutive rejections; \
                         re-registering from scratch",
                        self.key
                    ));
                }
                self.socket.evict(&self.key, current_arn.as_deref()).await;
                if !self.opts.reconnect_enabled {
                    return Ok(());
                }
                attempt = attempt.saturating_add(1);
                let backoff = compute_backoff(&self.opts, attempt);
                {
                    let mut m = self.metrics.lock().await;
                    m.reconnection_attempts += 1;
                    m.current_backoff_ms = backoff.as_millis() as u64;
                }
                if !sleep_with_shutdown(backoff, &self.shutdown, Some(&self.socket.shutdown)).await
                {
                    return Ok(());
                }
                continue;
            }

            // Successful register: persist session token + arn, drive the loop.
            self.note_registration_success();
            current_arn = Some(resp.connector_arn.clone());
            if !resp.session_token.is_empty() {
                *self.session_token.write().await = Some(resp.session_token.clone());
            }
            {
                let mut m = self.metrics.lock().await;
                m.last_connected_at_ms = Some(now_ms() as u64);
                m.current_backoff_ms = 0;
                if ever_registered {
                    m.successful_reconnects += 1;
                }
            }
            ever_registered = true;
            // Tell run_tenant_group that this socket has actually started
            // doing useful work. Until at least one handle reaches this
            // point, the socket-level reconnect counter does not reset, so
            // a server that admits the WS but rejects every register
            // doesn't give us a zero-backoff busy loop.
            self.socket.register_acked.store(true, Ordering::SeqCst);
            attempt = 0;
            logger.info(&format!(
                "ws multiplex handle {}: registered (arn={})",
                self.key, resp.connector_arn
            ));

            self.drive_inbound(inbound_rx, &entry, &logger).await;

            self.socket.evict(&self.key, current_arn.as_deref()).await;
            current_arn = None;

            if self.shutdown.load(Ordering::SeqCst) {
                return Ok(());
            }
            if self.socket.shutdown.load(Ordering::SeqCst) {
                // Socket died; the multi-runner respawns handles after
                // reopening the socket. Just exit.
                return Ok(());
            }
            if !self.opts.reconnect_enabled {
                return Ok(());
            }

            attempt = attempt.saturating_add(1);
            let backoff = compute_backoff(&self.opts, attempt);
            {
                let mut m = self.metrics.lock().await;
                m.total_disconnects += 1;
                m.last_disconnected_at_ms = Some(now_ms() as u64);
                m.last_disconnect_reason = Some("ws-stream-ended".to_string());
                m.reconnection_attempts += 1;
                m.current_backoff_ms = backoff.as_millis() as u64;
            }
            if !sleep_with_shutdown(backoff, &self.shutdown, Some(&self.socket.shutdown)).await {
                return Ok(());
            }
        }
    }

    async fn maybe_backoff(&self, logger: &Logger, attempt: &mut u32) -> Result<()> {
        if !self.opts.reconnect_enabled {
            return Ok(());
        }
        *attempt = attempt.saturating_add(1);
        let backoff = compute_backoff(&self.opts, *attempt);
        logger.warn(&format!(
            "ws multiplex handle {}: outbound channel lost; retrying in {}ms (attempt {})",
            self.key,
            backoff.as_millis(),
            attempt
        ));
        if !sleep_with_shutdown(backoff, &self.shutdown, Some(&self.socket.shutdown)).await {
            return Ok(());
        }
        Ok(())
    }

    /// Load previously-saved credentials (Keycloak `client_id` + private key,
    /// persisted under `~/.strike48`) and mint a `private_key_jwt` into
    /// `config.auth_token`, so the first `RegisterConnectorRequest` of this run
    /// is already authenticated and the server skips pending approval.
    ///
    /// Best-effort and idempotent: if `auth_token` is already set, no saved
    /// credentials exist, or the JWT mint fails, it leaves `auth_token`
    /// untouched and the handle falls back to the normal
    /// pending-approval → `CredentialsIssued` flow. Mirrors Priority 3 of the
    /// single-connector `ConnectorRunner::initialize_auth`.
    async fn prime_auth_from_saved_credentials(&self, logger: &Logger) {
        if !self.config.read().await.auth_token.is_empty() {
            return;
        }
        self.mint_auth_from_saved_credentials(logger).await;
    }

    /// Mint a fresh `private_key_jwt` from saved keypair credentials into
    /// `config.auth_token`, **overwriting** any existing value. Unlike
    /// [`Self::prime_auth_from_saved_credentials`] (a no-op when `auth_token`
    /// is already set), this always re-mints — used at the rejection threshold
    /// so a stale JWT is refreshed before re-registering. Leaves `auth_token`
    /// untouched when no saved credentials exist (OTT-only connectors), so we
    /// never downgrade a possibly-valid OTT credential. Mirrors the gRPC
    /// runner's method of the same name.
    ///
    /// Time-bounded by [`auth_mint_budget`] — see that function for why an
    /// unbounded inline mint would stall the reconnect loop.
    async fn mint_auth_from_saved_credentials(&self, logger: &Logger) {
        let (instance_id, connector_type) = (
            self.config.read().await.instance_id.clone(),
            self.connector.connector_type().to_string(),
        );

        let mut provider =
            crate::auth::OttProvider::new(Some(connector_type.clone()), Some(instance_id.clone()));

        let Some(saved) = provider.load_saved_credentials(&connector_type, Some(&instance_id))
        else {
            logger.info(&format!(
                "ws multiplex handle {}: no saved credentials; using pending-approval flow",
                self.key
            ));
            return;
        };

        let budget = auth_mint_budget(&self.opts);
        match tokio::time::timeout(budget, provider.get_token()).await {
            Ok(Ok(jwt)) => {
                self.config.write().await.auth_token = jwt;
                logger.info(&format!(
                    "ws multiplex handle {}: primed auth from saved credentials (client_id={})",
                    self.key, saved.client_id
                ));
            }
            Ok(Err(e)) => {
                logger.warn(&format!(
                    "ws multiplex handle {}: saved credentials present but JWT mint failed ({e}); \
                     falling back to pending-approval flow",
                    self.key
                ));
            }
            Err(_) => {
                logger.warn(&format!(
                    "ws multiplex handle {}: JWT mint timed out after {}ms; leaving auth_token \
                     unchanged and letting the reconnect loop retry",
                    self.key,
                    budget.as_millis()
                ));
            }
        }
    }

    /// Record a registration *rejection* and, at
    /// [`REJECTIONS_BEFORE_TOKEN_DROP`] consecutive rejections, reset
    /// credentials (drop the cached session token + re-mint auth) so the next
    /// register is net-new. Returns whether the threshold was reached on this
    /// call (true even when there was no token to drop, so a stale-JWT loop
    /// still logs each cycle). Mirrors the gRPC runner's
    /// `note_rejection_and_maybe_reset_credentials`; the counter is shared
    /// across the initial-register and in-stream re-register paths.
    async fn note_rejection_and_maybe_reset_credentials(&self, logger: &Logger) -> bool {
        let count = self.consecutive_rejections.fetch_add(1, Ordering::SeqCst) + 1;
        if count < REJECTIONS_BEFORE_TOKEN_DROP {
            logger.debug(&format!(
                "ws multiplex handle {}: registration rejection \
                 {count}/{REJECTIONS_BEFORE_TOKEN_DROP} (retaining cached credentials)",
                self.key
            ));
            return false;
        }
        self.consecutive_rejections.store(0, Ordering::SeqCst);
        let dropped_token = self.session_token.write().await.take().is_some();
        logger.debug(&format!(
            "ws multiplex handle {}: rejection threshold reached \
             (dropped_session_token={dropped_token}); re-minting auth from saved credentials",
            self.key
        ));
        self.mint_auth_from_saved_credentials(logger).await;
        true
    }

    /// Reset the consecutive-rejection counter after a successful register.
    /// Mirrors the gRPC runner's `note_registration_success`.
    fn note_registration_success(&self) {
        self.consecutive_rejections.store(0, Ordering::SeqCst);
    }

    /// Inbound drive loop for a registered handle. Runs until the handle's
    /// inbound channel closes (socket EOF), shutdown fires, or the loop hits
    /// an in-stream re-register failure.
    ///
    /// We poll `self.socket.shutdown` alongside the runner-wide
    /// `self.shutdown` because the demux task signals socket death by
    /// setting that flag and clearing `by_dot` — but the handle's local
    /// `Arc<HandleEntry>` keeps `inbound_tx` alive, so `inbound_rx.recv()`
    /// would otherwise never return `None` after a transport-level
    /// `Connection reset` and the outer reconnect loop in
    /// `run_tenant_group` would never fire.
    async fn drive_inbound(
        &self,
        mut inbound_rx: mpsc::Receiver<StreamMessage>,
        entry: &Arc<HandleEntry>,
        logger: &Logger,
    ) {
        loop {
            if self.shutdown.load(Ordering::SeqCst) || self.socket.shutdown.load(Ordering::SeqCst) {
                return;
            }

            tokio::select! {
                msg_opt = inbound_rx.recv() => {
                    match msg_opt {
                        Some(msg) => {
                            self.dispatch_inbound(msg, entry, logger).await;
                        }
                        None => {
                            return;
                        }
                    }
                }
                _ = tokio::time::sleep(SHUTDOWN_POLL) => {}
            }
        }
    }

    async fn dispatch_inbound(
        &self,
        msg: StreamMessage,
        entry: &Arc<HandleEntry>,
        logger: &Logger,
    ) {
        match msg.message {
            Some(stream_message::Message::ExecuteRequest(req)) => {
                let request = SdkExecuteRequest {
                    request_id: req.request_id.clone(),
                    payload: req.payload,
                    payload_encoding: PayloadEncoding::from(req.payload_encoding),
                    context: req.context,
                    capability_id: if req.capability_id.is_empty() {
                        None
                    } else {
                        Some(req.capability_id)
                    },
                };

                let connector = self.connector.clone();
                let metrics = self.metrics.clone();
                let outbound = self.socket.outbound_tx.clone();
                let key = self.key.clone();
                let semaphore = self.request_semaphore.clone();
                let exec_logger = Logger::new("multi/ws/handle/execute");

                tokio::spawn(async move {
                    let permit = match semaphore.acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            exec_logger.debug(&format!(
                                "ws multiplex handle {key}: request semaphore closed"
                            ));
                            return;
                        }
                    };
                    if let Err(e) =
                        handle_execute(connector, request, outbound, metrics, &exec_logger, &key)
                            .await
                    {
                        exec_logger.error(
                            &format!("ws multiplex handle {key}: execute dispatch failed"),
                            &e.to_string(),
                        );
                    }
                    drop(permit);
                });
            }
            Some(stream_message::Message::RegisterResponse(resp)) => {
                if resp.success {
                    self.note_registration_success();
                    if !resp.session_token.is_empty() {
                        *self.session_token.write().await = Some(resp.session_token.clone());
                    }
                    if !resp.connector_arn.is_empty() {
                        self.socket
                            .bind_arn(resp.connector_arn.clone(), entry.clone())
                            .await;
                    }
                    logger.info(&format!(
                        "ws multiplex handle {}: in-stream re-register succeeded (arn={})",
                        self.key, resp.connector_arn
                    ));
                } else {
                    logger.warn(&format!(
                        "ws multiplex handle {}: in-stream re-register failed: status='{}' error='{}'",
                        self.key, resp.status, resp.error
                    ));
                    // Rejected re-registration: after REJECTIONS_BEFORE_TOKEN_DROP
                    // consecutive rejections, drop the cached session token and
                    // re-mint auth so the reconnect after this stream tears down
                    // re-registers from scratch instead of replaying the
                    // credential the server just refused. Shares the counter
                    // with the initial-register path.
                    if self
                        .note_rejection_and_maybe_reset_credentials(logger)
                        .await
                    {
                        logger.warn(&format!(
                            "ws multiplex handle {}: reset rejected credentials after \
                             {REJECTIONS_BEFORE_TOKEN_DROP} consecutive rejections \
                             (in-stream re-register)",
                            self.key
                        ));
                    }
                }
            }
            Some(stream_message::Message::CredentialsIssued(creds)) => {
                // Run the OTT/JWT exchange + in-stream re-register on a
                // separate task. The exchange does outbound HTTP to the
                // OTT issuer and Matrix's auth endpoint, both of which can
                // stall on a misbehaving network. If we awaited it here,
                // a stalled request would pin `drive_inbound` and the
                // handle could not observe socket EOF (sender drop) when
                // the server closes the WS — the outer reconnect loop
                // would never fire.
                let key = self.key.clone();
                let config = self.config.clone();
                let connector = self.connector.clone();
                let socket = self.socket.clone();
                let session_token = self.session_token.clone();
                let opts = self.opts.clone();
                let shutdown = self.shutdown.clone();
                let creds_logger = Logger::new("multi/ws/handle/creds");
                tokio::spawn(async move {
                    handle_credentials_issued(
                        key,
                        config,
                        connector,
                        socket,
                        session_token,
                        opts,
                        shutdown,
                        creds,
                        creds_logger,
                    )
                    .await;
                });
            }
            Some(stream_message::Message::ApprovalNotification(notif)) => {
                let status = proto::RegistrationStatus::try_from(notif.status);
                match status {
                    Ok(proto::RegistrationStatus::Approved) => {
                        logger.info(&format!(
                            "ws multiplex handle {}: approved (CredentialsIssued imminent)",
                            self.key
                        ));
                    }
                    Ok(proto::RegistrationStatus::Pending) => {
                        logger.info(&format!(
                            "ws multiplex handle {}: pending approval — {}",
                            self.key,
                            if notif.message.is_empty() {
                                "awaiting admin"
                            } else {
                                &notif.message
                            }
                        ));
                    }
                    Ok(proto::RegistrationStatus::Rejected) => {
                        logger.warn(&format!(
                            "ws multiplex handle {}: REJECTED — {}",
                            self.key,
                            if notif.message.is_empty() {
                                "no reason"
                            } else {
                                &notif.message
                            }
                        ));
                    }
                    _ => {}
                }
            }
            Some(stream_message::Message::HeartbeatRequest(_)) => {
                let resp = StreamMessage {
                    message: Some(stream_message::Message::HeartbeatResponse(
                        HeartbeatResponse {
                            gateway_id: String::new(),
                            timestamp_ms: now_ms(),
                            should_reconnect: false,
                        },
                    )),
                };
                let _ = self.socket.outbound_tx.send(resp).await;
            }
            other => {
                logger.debug(&format!(
                    "ws multiplex handle {}: ignoring inbound variant {:?}",
                    self.key,
                    other.as_ref().map(std::mem::discriminant)
                ));
            }
        }
    }
}

/// Handle a `CredentialsIssued` from the gateway: register the local
/// public key against the OTT, exchange for a JWT, then send an in-stream
/// re-register so the gateway promotes the registration from `pending` to
/// `approved`.
///
/// Runs as its own spawned task so a slow OTT issuer or Matrix auth
/// endpoint cannot block `drive_inbound` (which is what observes socket
/// EOF on server-initiated close). HTTP calls are bounded by
/// `connect_timeout_ms * 3` as a defence-in-depth ceiling so a
/// misbehaving peer can't pin this task forever either.
#[allow(clippy::too_many_arguments)]
async fn handle_credentials_issued(
    key: RegistrationKey,
    config: Arc<RwLock<ConnectorConfig>>,
    connector: Arc<dyn BaseConnector>,
    socket: Arc<WsMultiplexSocket>,
    session_token: Arc<RwLock<Option<String>>>,
    opts: MultiTransportOptions,
    shutdown: Arc<AtomicBool>,
    creds: proto::CredentialsIssued,
    logger: Logger,
) {
    if creds.ott.is_empty() {
        logger.warn(&format!(
            "ws multiplex handle {key}: CredentialsIssued without OTT",
        ));
        return;
    }
    if creds.matrix_api_url.is_empty() {
        logger.warn(&format!(
            "ws multiplex handle {key}: CredentialsIssued without matrix_api_url",
        ));
        return;
    }

    // Bound each HTTP step. `connect_timeout_ms` is the single-attempt
    // budget; we allow 3× to cover the OTT request's connect+TLS+request+
    // server-side processing on a slow cross-region link.
    let http_budget = Duration::from_millis(
        opts.connect_timeout_ms
            .saturating_mul(3)
            .max(opts.connect_timeout_ms),
    );

    // Retry the post-approval credential exchange indefinitely with capped
    // exponential backoff. Unlike the single-connector runner — which retries
    // the whole exchange implicitly via its socket-drop → reconnect → fresh
    // CredentialsIssued cycle — this handle shares its socket with other
    // connectors and must NOT tear it down on its own failure. So a failed
    // OTT/JWT exchange has no reconnect to ride; it would dead-end and leave
    // the connector approved-but-credential-less on a live socket. Looping
    // here is the only path back to a working session, and it lets the
    // connector self-heal once a transient server/network fault (or a fixed
    // server misconfiguration) clears — without an operator restart.
    //
    // Termination: success, or either the runner-level `shutdown` or the
    // per-socket `socket.shutdown` flag flips (socket died → the handle's
    // outer reconnect loop rebuilds the socket and a fresh CredentialsIssued
    // spawns a new exchange). `sleep_with_shutdown` polls both, so backoff is
    // interrupted promptly on either.
    let mut attempt: u32 = 0;
    loop {
        if shutdown.load(Ordering::SeqCst) || socket.shutdown.load(Ordering::SeqCst) {
            logger.debug(&format!(
                "ws multiplex handle {key}: credential exchange abandoned (shutdown/socket closed)"
            ));
            return;
        }

        match try_credential_exchange(
            &key,
            &config,
            connector.as_ref(),
            &socket,
            &session_token,
            http_budget,
            &creds,
            &logger,
        )
        .await
        {
            Ok(()) => {
                if attempt > 0 {
                    logger.info(&format!(
                        "ws multiplex handle {key}: credential exchange succeeded after {attempt} retr{}",
                        if attempt == 1 { "y" } else { "ies" }
                    ));
                }
                return;
            }
            Err(reason) => {
                attempt = attempt.saturating_add(1);
                let backoff = compute_backoff(&opts, attempt);
                logger.warn(&format!(
                    "ws multiplex handle {key}: credential exchange failed ({reason}); \
                     retrying in {}ms (attempt {attempt})",
                    backoff.as_millis()
                ));
                if !sleep_with_shutdown(backoff, &shutdown, Some(&socket.shutdown)).await {
                    // shutdown / socket death observed during backoff
                    return;
                }
            }
        }
    }
}

/// One attempt at the post-approval credential exchange: OTT public-key
/// registration → JWT mint → in-stream re-register. Returns `Err(reason)` on
/// any failure (incl. the re-register send) so the caller can back off and
/// retry. A fresh `OttProvider` is built per attempt because the keypair +
/// Keycloak client_id are scoped to this approval cycle.
#[allow(clippy::too_many_arguments)]
async fn try_credential_exchange(
    key: &RegistrationKey,
    config: &Arc<RwLock<ConnectorConfig>>,
    connector: &dyn BaseConnector,
    socket: &Arc<WsMultiplexSocket>,
    session_token: &Arc<RwLock<Option<String>>>,
    http_budget: Duration,
    creds: &proto::CredentialsIssued,
    logger: &Logger,
) -> std::result::Result<(), String> {
    let (instance_id, connector_type) = (
        config.read().await.instance_id.clone(),
        connector.connector_type().to_string(),
    );

    let mut provider =
        crate::auth::OttProvider::new(Some(connector_type.clone()), Some(instance_id.clone()));
    let register_fut = provider.register_public_key_with_ott_data(
        &creds.ott,
        &creds.matrix_api_url,
        &creds.register_url,
        &connector_type,
        Some(&instance_id),
    );
    match tokio::time::timeout(http_budget, register_fut).await {
        Ok(Ok(_creds)) => {}
        Ok(Err(e)) => return Err(format!("OTT public-key registration failed: {e}")),
        Err(_) => {
            return Err(format!(
                "OTT public-key registration timed out after {}ms",
                http_budget.as_millis()
            ));
        }
    }

    let jwt = match tokio::time::timeout(http_budget, provider.get_token()).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return Err(format!("post-OTT JWT exchange failed: {e}")),
        Err(_) => {
            return Err(format!(
                "post-OTT JWT exchange timed out after {}ms",
                http_budget.as_millis()
            ));
        }
    };

    config.write().await.auth_token = jwt;
    let cfg = config.read().await.clone();
    let token = session_token.read().await.clone().unwrap_or_default();
    let msg = build_register_message_with_token(&cfg, connector, &token);
    if socket.outbound_tx.send(msg).await.is_err() {
        // Socket closed right at the re-register point — treat as a retryable
        // failure so a momentary hiccup doesn't strand an approved connector.
        return Err("socket closed before in-stream re-register sent".to_string());
    }
    logger.debug(&format!(
        "ws multiplex handle {key}: in-stream re-register sent after credential exchange"
    ));
    Ok(())
}

// =============================================================================
// Helpers shared with registration_runner-style code
// =============================================================================

fn build_register_message_with_token(
    config: &ConnectorConfig,
    connector: &dyn BaseConnector,
    session_token: &str,
) -> StreamMessage {
    // Start from build_registration_metadata so behavior-required keys
    // (notably `tool_schemas` for Tool connectors) are auto-injected the
    // same way the gRPC path does. Operator-supplied `config.metadata`
    // overlays on top — same precedence as the connector's own metadata().
    let mut metadata = crate::connector::build_registration_metadata(connector);
    for (k, v) in &config.metadata {
        metadata.insert(k.clone(), v.clone());
    }
    crate::sdk_metadata::merge_into(
        &mut metadata,
        &config.transport_type.to_string(),
        config.use_tls,
    );

    let capabilities_proto = ConnectorCapabilities {
        connector_type: connector.connector_type().to_string(),
        version: connector.version().to_string(),
        supported_encodings: connector
            .supported_encodings()
            .iter()
            .map(|e| *e as i32)
            .collect(),
        behaviors: connector.behaviors().iter().map(|b| *b as i32).collect(),
        metadata: metadata.clone(),
        task_types: {
            let caps = connector.capabilities();
            if caps.is_empty() {
                Vec::new()
            } else {
                caps.iter()
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
            }
        },
    };

    let sanitized_instance_id = sanitize_identifier(&config.instance_id);
    let instance_metadata = Some(InstanceMetadata {
        display_name: config
            .display_name
            .clone()
            .unwrap_or_else(|| sanitized_instance_id.clone()),
        tags: config.tags.clone(),
        metadata,
    });

    let register = RegisterConnectorRequest {
        tenant_id: sanitize_identifier(&config.tenant_id),
        connector_type: sanitize_identifier(connector.connector_type()),
        instance_id: sanitized_instance_id,
        capabilities: Some(capabilities_proto),
        jwt_token: config.auth_token.clone(),
        session_token: session_token.to_string(),
        scope: 0,
        instance_metadata,
    };

    StreamMessage {
        message: Some(stream_message::Message::RegisterRequest(register)),
    }
}

async fn handle_execute(
    connector: Arc<dyn BaseConnector>,
    request: SdkExecuteRequest,
    outbound: mpsc::Sender<StreamMessage>,
    metrics: Arc<Mutex<ConnectorMetrics>>,
    logger: &Logger,
    key: &RegistrationKey,
) -> Result<()> {
    let start = Instant::now();
    {
        let mut m = metrics.lock().await;
        m.requests_received += 1;
        m.bytes_received += request.payload.len() as u64;
        m.last_request_at_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    }

    let request_id = request.request_id.clone();

    let response = match deserialize_payload::<serde_json::Value>(
        &request.payload,
        request.payload_encoding,
    ) {
        Ok(payload) => match connector
            .execute_with_context(payload, request.capability_id.as_deref(), &request.context)
            .await
        {
            Ok(value) => match serialize_payload(&value, PayloadEncoding::Json) {
                Ok(bytes) => proto::ExecuteResponse {
                    request_id,
                    success: true,
                    payload: bytes.clone(),
                    payload_encoding: PayloadEncoding::Json as i32,
                    error: String::new(),
                    duration_ms: start.elapsed().as_millis() as i64,
                },
                Err(e) => {
                    logger.error(
                        &format!("ws multiplex handle {key}: serialize failed"),
                        &e.to_string(),
                    );
                    let mut m = metrics.lock().await;
                    m.requests_failed += 1;
                    proto::ExecuteResponse {
                        request_id,
                        success: false,
                        payload: error_response(&e.to_string()).unwrap_or_default(),
                        payload_encoding: PayloadEncoding::Json as i32,
                        error: e.to_string(),
                        duration_ms: start.elapsed().as_millis() as i64,
                    }
                }
            },
            Err(e) => {
                logger.error(
                    &format!("ws multiplex handle {key}: execute failed"),
                    &e.to_string(),
                );
                let mut m = metrics.lock().await;
                m.requests_failed += 1;
                proto::ExecuteResponse {
                    request_id,
                    success: false,
                    payload: error_response(&e.to_string()).unwrap_or_default(),
                    payload_encoding: PayloadEncoding::Json as i32,
                    error: e.to_string(),
                    duration_ms: start.elapsed().as_millis() as i64,
                }
            }
        },
        Err(e) => {
            logger.error(
                &format!("ws multiplex handle {key}: deserialize failed"),
                &e.to_string(),
            );
            let mut m = metrics.lock().await;
            m.requests_failed += 1;
            proto::ExecuteResponse {
                request_id,
                success: false,
                payload: error_response(&e.to_string()).unwrap_or_default(),
                payload_encoding: PayloadEncoding::Json as i32,
                error: e.to_string(),
                duration_ms: start.elapsed().as_millis() as i64,
            }
        }
    };

    {
        let mut m = metrics.lock().await;
        if response.success {
            m.requests_processed += 1;
            m.bytes_sent += response.payload.len() as u64;
        }
        m.total_duration_ms += response.duration_ms.max(0) as u64;
    }

    let msg = StreamMessage {
        message: Some(stream_message::Message::ExecuteResponse(response)),
    };
    if outbound.send(msg).await.is_err() {
        return Err(ConnectorError::StreamError(
            "ws multiplex outbound closed".to_string(),
        ));
    }
    Ok(())
}

async fn wait_for_register_response(
    register_rx: oneshot::Receiver<proto::RegisterConnectorResponse>,
    shutdown: &Arc<AtomicBool>,
    socket: &Arc<WsMultiplexSocket>,
    deadline: Duration,
) -> Result<proto::RegisterConnectorResponse> {
    let mut register_rx = register_rx;
    let start = Instant::now();
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return Err(ConnectorError::StreamError(
                "shutdown while awaiting register response".to_string(),
            ));
        }
        if socket.shutdown.load(Ordering::SeqCst) {
            return Err(ConnectorError::StreamError(
                "socket closed while awaiting register response".to_string(),
            ));
        }
        if start.elapsed() >= deadline {
            return Err(ConnectorError::Timeout(
                "register response did not arrive in time".to_string(),
            ));
        }

        let remaining = deadline.saturating_sub(start.elapsed()).min(SHUTDOWN_POLL);
        match tokio::time::timeout(remaining, &mut register_rx).await {
            Ok(Ok(resp)) => return Ok(resp),
            Ok(Err(_)) => {
                return Err(ConnectorError::StreamError(
                    "register response sender dropped".to_string(),
                ));
            }
            Err(_) => continue,
        }
    }
}

fn compute_backoff(opts: &MultiTransportOptions, attempt: u32) -> Duration {
    let base = opts.reconnect_delay_ms;
    let max = opts.max_backoff_delay_ms;
    let exp = (attempt.saturating_sub(1)).min(20);
    let scaled = base.saturating_mul(1u64 << exp);
    let jitter = if opts.reconnect_jitter_ms > 0 {
        thread_rng().gen_range(0..=opts.reconnect_jitter_ms)
    } else {
        0
    };
    let with_jitter = scaled.saturating_add(jitter);
    Duration::from_millis(with_jitter.min(max))
}

/// Sleep for `total`, but return early (with `false`) the moment either
/// the runner-level `shutdown` flag flips or the optional `socket_shutdown`
/// flag flips. The socket flag is what unblocks post-disconnect backoff
/// when the server has hung up — without it, a 60s backoff would still
/// run to completion even though the socket is already dead.
async fn sleep_with_shutdown(
    total: Duration,
    shutdown: &Arc<AtomicBool>,
    socket_shutdown: Option<&Arc<AtomicBool>>,
) -> bool {
    let deadline = Instant::now() + total;
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return false;
        }
        if let Some(s) = socket_shutdown
            && s.load(Ordering::SeqCst)
        {
            return false;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        let step = remaining.min(SHUTDOWN_POLL);
        tokio::time::sleep(step).await;
    }
}

// =============================================================================
// Public driver: groups N registrations by tenant onto shared sockets
// =============================================================================

pub(crate) struct WsMultiplexDriver {
    pub opts: MultiTransportOptions,
    pub shutdown: Arc<AtomicBool>,
}

pub(crate) struct WsMultiplexEntry {
    pub key: RegistrationKey,
    pub config: ConnectorConfig,
    pub connector: Arc<dyn BaseConnector>,
    pub metrics: Arc<Mutex<ConnectorMetrics>>,
}

impl WsMultiplexDriver {
    pub(crate) async fn run(self, entries: Vec<WsMultiplexEntry>) -> Result<()> {
        let logger = Logger::new("multi/ws/driver");

        // Group by sanitized tenant_id (the dot-form address uses sanitized
        // form). Cross-tenant entries always end up on different sockets
        // — that is a hard isolation invariant.
        let mut groups: HashMap<String, Vec<WsMultiplexEntry>> = HashMap::new();
        for entry in entries {
            let sanitized = sanitize_identifier(&entry.config.tenant_id);
            groups.entry(sanitized).or_default().push(entry);
        }

        let mut tenant_tasks = Vec::with_capacity(groups.len());
        for (tenant_sanitized, group) in groups {
            let opts = self.opts.clone();
            let shutdown = self.shutdown.clone();
            let logger = Logger::new("multi/ws/driver");
            tenant_tasks.push(tokio::spawn(async move {
                run_tenant_group(tenant_sanitized, group, opts, shutdown, logger).await
            }));
        }

        for t in tenant_tasks {
            match t.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => logger.warn(&format!("tenant group exited with error: {e}")),
                Err(e) => logger.error("tenant group task panicked", &e.to_string()),
            }
        }
        Ok(())
    }
}

async fn run_tenant_group(
    tenant_sanitized: String,
    entries: Vec<WsMultiplexEntry>,
    opts: MultiTransportOptions,
    shutdown: Arc<AtomicBool>,
    logger: Logger,
) -> Result<()> {
    // Outer reconnect loop: when a shared socket dies we rebuild it and
    // respawn every handle.
    let mut socket_attempt: u32 = 0;
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return Ok(());
        }

        let (socket, demux_handle) =
            match open_socket(&tenant_sanitized, &opts, shutdown.clone()).await {
                Ok(pair) => pair,
                Err(e) => {
                    logger.warn(&format!(
                        "ws multiplex tenant '{tenant_sanitized}': open_socket failed: {e}"
                    ));
                    if !opts.reconnect_enabled {
                        return Err(e);
                    }
                    socket_attempt = socket_attempt.saturating_add(1);
                    let backoff = compute_backoff(&opts, socket_attempt);
                    // No socket exists yet — pass None.
                    if !sleep_with_shutdown(backoff, &shutdown, None).await {
                        return Ok(());
                    }
                    continue;
                }
            };
        // We do NOT reset socket_attempt here: a server that admits the WS
        // handshake but then rejects every register would otherwise give us
        // a zero-backoff busy loop. The reset only happens after we
        // observe at least one successful register on the new socket
        // (handles set `socket.register_acked` on success). See finding #3.

        // Spawn one handle task per registration. Each handle gets its own
        // semaphore (sized from opts) and its own session-token slot.
        let mut handle_tasks = Vec::with_capacity(entries.len());
        for entry in &entries {
            let opts = opts.clone();
            let shutdown = shutdown.clone();
            let socket = socket.clone();
            let key = entry.key.clone();
            let metrics = entry.metrics.clone();
            let connector = entry.connector.clone();
            let mut config = entry.config.clone();
            // Pin transport-level fields to the runner's options so the
            // handle's view matches the socket it's bound to.
            config.transport_type = TransportType::WebSocket;
            config.host = opts.host.clone();
            config.use_tls = opts.use_tls;
            let handle = WsMultiplexHandle {
                key,
                config: Arc::new(RwLock::new(config)),
                connector,
                socket,
                shutdown,
                metrics,
                opts: opts.clone(),
                request_semaphore: Arc::new(Semaphore::new(opts.max_concurrent_requests.max(1))),
                session_token: Arc::new(RwLock::new(None)),
                consecutive_rejections: Arc::new(AtomicU32::new(0)),
            };
            handle_tasks.push(tokio::spawn(async move { handle.run().await }));
        }

        for t in handle_tasks {
            match t.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => logger.warn(&format!(
                    "ws multiplex handle exited with error (tenant '{tenant_sanitized}'): {e}"
                )),
                Err(e) => logger.error(
                    &format!("ws multiplex handle task panicked (tenant '{tenant_sanitized}')"),
                    &e.to_string(),
                ),
            }
        }

        // All handles finished (shutdown or socket EOF). Tear down the
        // demux task and decide whether to rebuild the socket.
        socket.shutdown.store(true, Ordering::SeqCst);
        demux_handle.abort();
        let _ = demux_handle.await;

        if shutdown.load(Ordering::SeqCst) || !opts.reconnect_enabled {
            return Ok(());
        }

        // Only treat this as a "successful socket worth restarting" if at
        // least one handle actually registered. Otherwise an admit-then-
        // reject server (or a misconfigured one) would loop forever at
        // socket_attempt=0. By gating the reset on register_acked we keep
        // the exponential backoff growing across consecutive zero-handle
        // sockets.
        if socket.register_acked.load(Ordering::SeqCst) {
            socket_attempt = 0;
        }

        socket_attempt = socket_attempt.saturating_add(1);
        let backoff = compute_backoff(&opts, socket_attempt);
        logger.warn(&format!(
            "ws multiplex tenant '{tenant_sanitized}': all handles ended; reopening socket in {}ms",
            backoff.as_millis()
        ));
        // The just-torn-down socket is dead; the next loop iteration
        // opens a fresh one. Pass None so the inter-socket backoff isn't
        // short-circuited.
        if !sleep_with_shutdown(backoff, &shutdown, None).await {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arn_parts_round_trip() {
        assert_eq!(
            arn_parts("matrix:demo-org:echo:echo-1"),
            Some(("demo-org", "echo", "echo-1"))
        );
        assert_eq!(arn_parts("matrix:t:c:i"), Some(("t", "c", "i")));
        // Trailing colons in the instance segment are preserved via splitn(4,…).
        assert_eq!(
            arn_parts("matrix:t:c:weird:instance"),
            Some(("t", "c", "weird:instance"))
        );
    }

    #[test]
    fn arn_parts_rejects_non_matrix() {
        assert!(arn_parts("foo:t:c:i").is_none());
        assert!(arn_parts("matrix:t:c").is_none());
        assert!(arn_parts("").is_none());
    }

    fn key(instance: &str) -> RegistrationKey {
        RegistrationKey {
            tenant_id: "t".into(),
            connector_type: "c".into(),
            instance_id: instance.into(),
        }
    }

    #[tokio::test]
    async fn admit_respects_configured_cap() {
        let (tx, _rx) = mpsc::channel(1);
        let socket = Arc::new(WsMultiplexSocket::new("t".into(), tx, 3));

        for i in 0..3 {
            let (in_tx, _in_rx) = mpsc::channel(1);
            let (reg_tx, _reg_rx) = oneshot::channel();
            socket
                .admit(key(&format!("inst-{i}")), in_tx, reg_tx)
                .await
                .expect("admit");
        }

        let (in_tx, _in_rx) = mpsc::channel(1);
        let (reg_tx, _reg_rx) = oneshot::channel();
        let err = socket
            .admit(key("inst-3"), in_tx, reg_tx)
            .await
            .map(|_| ())
            .expect_err("4th admit should be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("handler cap of 3"),
            "error should name the configured cap, got: {msg}"
        );
    }

    #[tokio::test]
    async fn admit_rejects_duplicate_keys() {
        let (tx, _rx) = mpsc::channel(1);
        let socket = Arc::new(WsMultiplexSocket::new("t".into(), tx, 8));

        let (in_tx, _in_rx) = mpsc::channel(1);
        let (reg_tx, _reg_rx) = oneshot::channel();
        socket
            .admit(key("inst-0"), in_tx, reg_tx)
            .await
            .expect("first admit");

        let (in_tx2, _in_rx2) = mpsc::channel(1);
        let (reg_tx2, _reg_rx2) = oneshot::channel();
        let err = socket
            .admit(key("inst-0"), in_tx2, reg_tx2)
            .await
            .map(|_| ())
            .expect_err("duplicate should be rejected");
        assert!(err.to_string().contains("already admitted"));
    }

    #[test]
    fn compute_backoff_caps_at_max() {
        let opts = MultiTransportOptions {
            reconnect_delay_ms: 100,
            max_backoff_delay_ms: 5_000,
            reconnect_jitter_ms: 0,
            ..MultiTransportOptions::default()
        };
        // Attempt 21 would otherwise be 100 * 2^20 ≫ max.
        let backoff = compute_backoff(&opts, 21);
        assert_eq!(backoff, Duration::from_millis(5_000));
    }

    /// Helper: admit a handle and return its entry plus the inbound rx so
    /// tests can assert what frames the handle would have received.
    async fn admit_with_rx(
        socket: &Arc<WsMultiplexSocket>,
        instance: &str,
    ) -> (Arc<HandleEntry>, mpsc::Receiver<StreamMessage>) {
        let (in_tx, in_rx) = mpsc::channel(8);
        let (reg_tx, _reg_rx) = oneshot::channel();
        let entry = socket
            .admit(key(instance), in_tx, reg_tx)
            .await
            .expect("admit");
        (entry, in_rx)
    }

    /// Finding #1: with N handles concurrently mid-bring-up on one
    /// socket, the server's `CredentialsIssued` and `ApprovalNotification`
    /// frames must route to the correct handle even though
    /// `RegisterResponse` for those handles has not been observed yet.
    /// The proto carries `gateway_id = tenant.type.instance` exactly
    /// matching our `by_dot` keys, so this is deterministic.
    #[tokio::test]
    async fn credentials_issued_routes_by_gateway_id() {
        let (out_tx, _out_rx) = mpsc::channel(8);
        let socket = Arc::new(WsMultiplexSocket::new("t".into(), out_tx, 8));

        let (_entry_a, mut rx_a) = admit_with_rx(&socket, "inst-a").await;
        let (_entry_b, mut rx_b) = admit_with_rx(&socket, "inst-b").await;

        let logger = Logger::new("test");
        let creds = StreamMessage {
            message: Some(stream_message::Message::CredentialsIssued(
                proto::CredentialsIssued {
                    gateway_id: "t.c.inst-a".to_string(),
                    ..Default::default()
                },
            )),
        };
        route_inbound_by_gateway_id(&socket, creds, "t.c.inst-a", "credentials_issued", &logger)
            .await;

        // Handle A is the addressee; handle B must not see the frame.
        assert!(rx_a.try_recv().is_ok(), "addressed handle must receive");
        assert!(
            rx_b.try_recv().is_err(),
            "other handle MUST NOT receive credentials addressed elsewhere"
        );
    }

    /// Finding #1 follow-on: an unknown `gateway_id` is dropped instead
    /// of being misrouted to a survivor — same rule as
    /// [`unmatched_arn_does_not_fall_back_to_sole_survivor`].
    #[tokio::test]
    async fn credentials_issued_unknown_gateway_drops() {
        let (out_tx, _out_rx) = mpsc::channel(8);
        let socket = Arc::new(WsMultiplexSocket::new("t".into(), out_tx, 8));
        let (_entry, mut rx) = admit_with_rx(&socket, "inst-survivor").await;

        let logger = Logger::new("test");
        let creds = StreamMessage {
            message: Some(stream_message::Message::CredentialsIssued(
                proto::CredentialsIssued {
                    gateway_id: "t.c.inst-evicted".to_string(),
                    ..Default::default()
                },
            )),
        };
        route_inbound_by_gateway_id(
            &socket,
            creds,
            "t.c.inst-evicted",
            "credentials_issued",
            &logger,
        )
        .await;
        assert!(
            rx.try_recv().is_err(),
            "credentials for unknown gateway must be dropped, not delivered"
        );
    }

    /// Finding #2: when an inbound frame is addressed to a specific ARN
    /// or request_id but the addressee was just evicted, the SDK must NOT
    /// fall back to "sole survivor" routing. Doing so misroutes frames
    /// from a dead handle into a different live handle.
    #[tokio::test]
    async fn unmatched_arn_does_not_fall_back_to_sole_survivor() {
        let (out_tx, _out_rx) = mpsc::channel(8);
        let socket = Arc::new(WsMultiplexSocket::new("t".into(), out_tx, 8));

        // Survivor handle exists but was never bound to ARN-X.
        let (_entry_survivor, mut rx_survivor) = admit_with_rx(&socket, "inst-survivor").await;

        let logger = Logger::new("test");
        let exec_msg = StreamMessage {
            message: Some(stream_message::Message::ExecuteRequest(
                proto::ExecuteRequest {
                    request_id: "req-1".into(),
                    ..Default::default()
                },
            )),
        };
        // Frame is addressed to a handle that never registered (or just
        // exited): with the bug, this would have been delivered to the
        // sole survivor.
        route_inbound_by_arn(
            &socket,
            exec_msg,
            Some("matrix:t:c:inst-evicted"),
            "execute_request",
            &logger,
        )
        .await;

        assert!(
            rx_survivor.try_recv().is_err(),
            "addressed-but-unmatched ARN MUST be dropped, not delivered to survivor"
        );
    }

    /// Finding #2 continued: when no ARN is supplied at all and there is
    /// exactly one admitted handle, the back-compat sole-handle fallback
    /// MUST still fire (single-connector deployments depend on this).
    #[tokio::test]
    async fn missing_arn_with_sole_handle_falls_back() {
        let (out_tx, _out_rx) = mpsc::channel(8);
        let socket = Arc::new(WsMultiplexSocket::new("t".into(), out_tx, 8));
        let (_entry, mut rx) = admit_with_rx(&socket, "inst-only").await;

        let logger = Logger::new("test");
        let exec_msg = StreamMessage {
            message: Some(stream_message::Message::ExecuteRequest(
                proto::ExecuteRequest::default(),
            )),
        };
        route_inbound_by_arn(&socket, exec_msg, None, "execute_request", &logger).await;
        assert!(
            rx.try_recv().is_ok(),
            "no-ARN frame must reach sole admitted handle"
        );
    }

    /// `register_response` whose ARN's `connector_type` segment is a
    /// canonicalised form (e.g. server stripped a vendor prefix) must
    /// still route to the awaiting handle when its `instance_id`
    /// uniquely identifies the registration on the socket. Without this
    /// fallback every per-handle register stalls until timeout.
    #[tokio::test]
    async fn register_response_routes_by_instance_id_when_type_canonicalised() {
        let (out_tx, _out_rx) = mpsc::channel(8);
        let socket = Arc::new(WsMultiplexSocket::new("t".into(), out_tx, 8));

        // Handle was admitted with connector_type "construct-jira-mcp" but
        // the server canonicalises that to bare "jira-mcp" in the ARN it
        // returns. The instance_id is unchanged ("host-jira-mcp").
        let (in_tx, _in_rx) = mpsc::channel(8);
        let (reg_tx, reg_rx) = oneshot::channel();
        let admitted_key = RegistrationKey {
            tenant_id: "t".into(),
            connector_type: "construct-jira-mcp".into(),
            instance_id: "host-jira-mcp".into(),
        };
        socket
            .admit(admitted_key, in_tx, reg_tx)
            .await
            .expect("admit");

        // A second handle exists on the same socket, distinct instance_id,
        // so the legacy `sole_handle()` fallback would not have fired.
        let (in_tx2, _in_rx2) = mpsc::channel(8);
        let (reg_tx2, _reg_rx2) = oneshot::channel();
        let other_key = RegistrationKey {
            tenant_id: "t".into(),
            connector_type: "construct-other".into(),
            instance_id: "host-other".into(),
        };
        socket
            .admit(other_key, in_tx2, reg_tx2)
            .await
            .expect("admit");

        let logger = Logger::new("test");
        let resp_msg = StreamMessage {
            message: Some(stream_message::Message::RegisterResponse(
                proto::RegisterConnectorResponse {
                    success: true,
                    connector_arn: "matrix:t:jira-mcp:host-jira-mcp".into(),
                    ..Default::default()
                },
            )),
        };
        dispatch_inbound_to_handle(&socket, resp_msg, &logger).await;

        let delivered = reg_rx.await.expect("pending oneshot fulfilled");
        assert!(delivered.success);
        assert_eq!(delivered.connector_arn, "matrix:t:jira-mcp:host-jira-mcp");
    }

    /// Even with the instance-id fallback, an ARN whose `instance_id`
    /// matches multiple admitted handles must NOT be routed — that would
    /// be a guess. Such frames are dropped.
    #[tokio::test]
    async fn register_response_with_ambiguous_instance_id_drops() {
        let (out_tx, _out_rx) = mpsc::channel(8);
        let socket = Arc::new(WsMultiplexSocket::new("t".into(), out_tx, 8));

        // Two handles share the same instance_id under different types.
        // (Pathological config, but the SDK must refuse to guess.)
        let (in_tx_a, _in_rx_a) = mpsc::channel(8);
        let (reg_tx_a, mut reg_rx_a) = oneshot::channel();
        socket
            .admit(
                RegistrationKey {
                    tenant_id: "t".into(),
                    connector_type: "type-a".into(),
                    instance_id: "shared-inst".into(),
                },
                in_tx_a,
                reg_tx_a,
            )
            .await
            .expect("admit");
        let (in_tx_b, _in_rx_b) = mpsc::channel(8);
        let (reg_tx_b, mut reg_rx_b) = oneshot::channel();
        socket
            .admit(
                RegistrationKey {
                    tenant_id: "t".into(),
                    connector_type: "type-b".into(),
                    instance_id: "shared-inst".into(),
                },
                in_tx_b,
                reg_tx_b,
            )
            .await
            .expect("admit");

        let logger = Logger::new("test");
        let resp_msg = StreamMessage {
            message: Some(stream_message::Message::RegisterResponse(
                proto::RegisterConnectorResponse {
                    success: true,
                    connector_arn: "matrix:t:type-mystery:shared-inst".into(),
                    ..Default::default()
                },
            )),
        };
        dispatch_inbound_to_handle(&socket, resp_msg, &logger).await;

        // Neither pending oneshot may have been fulfilled — ambiguous
        // instance_id MUST drop, not pick one arbitrarily.
        assert!(reg_rx_a.try_recv().is_err());
        assert!(reg_rx_b.try_recv().is_err());
    }

    // --- post-approval credential-exchange resilience -----------------------

    struct CredsNoopConn;
    impl BaseConnector for CredsNoopConn {
        fn connector_type(&self) -> &str {
            "test_conn"
        }
        fn version(&self) -> &str {
            "0.0.0"
        }
        fn execute(
            &self,
            _: serde_json::Value,
            _: Option<&str>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>,
        > {
            Box::pin(async { Ok(serde_json::json!({})) })
        }
    }

    fn creds_test_socket() -> Arc<WsMultiplexSocket> {
        let (out_tx, _out_rx) = mpsc::channel(8);
        Arc::new(WsMultiplexSocket::new("t".into(), out_tx, 8))
    }

    fn creds_key() -> RegistrationKey {
        RegistrationKey {
            tenant_id: "t".into(),
            connector_type: "test_conn".into(),
            instance_id: "inst-1".into(),
        }
    }

    /// A malformed CredentialsIssued (missing OTT) must return immediately —
    /// never enter the retry loop. Guards against retrying un-retryable
    /// protocol errors forever.
    #[tokio::test]
    async fn credential_exchange_missing_ott_returns_immediately() {
        let socket = creds_test_socket();
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            handle_credentials_issued(
                creds_key(),
                Arc::new(RwLock::new(crate::connector::ConnectorConfig::default())),
                Arc::new(CredsNoopConn),
                socket,
                Arc::new(RwLock::new(None)),
                MultiTransportOptions::default(),
                Arc::new(AtomicBool::new(false)),
                proto::CredentialsIssued::default(), // empty ott + api_url
                Logger::new("test"),
            ),
        )
        .await;
        assert!(
            res.is_ok(),
            "must return immediately on missing OTT, not loop"
        );
    }

    /// If shutdown is already set, the retry loop must exit on its first
    /// iteration without attempting any HTTP — proving the loop honours the
    /// shutdown flag rather than spinning/blocking.
    #[tokio::test]
    async fn credential_exchange_aborts_when_shutdown_set() {
        let socket = creds_test_socket();
        // Valid-looking creds so the empty-field guards don't short-circuit;
        // shutdown must be what stops it before any network attempt.
        let creds = proto::CredentialsIssued {
            ott: "tok".into(),
            matrix_api_url: "https://example.test".into(),
            ..Default::default()
        };
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            handle_credentials_issued(
                creds_key(),
                Arc::new(RwLock::new(crate::connector::ConnectorConfig::default())),
                Arc::new(CredsNoopConn),
                socket,
                Arc::new(RwLock::new(None)),
                MultiTransportOptions::default(),
                Arc::new(AtomicBool::new(true)), // shutdown already set
                creds,
                Logger::new("test"),
            ),
        )
        .await;
        assert!(
            res.is_ok(),
            "must abort promptly when shutdown is set, not attempt the exchange"
        );
    }

    /// Same as above but via the per-socket shutdown flag (socket died):
    /// the loop must also exit on `socket.shutdown`, not just the runner flag.
    #[tokio::test]
    async fn credential_exchange_aborts_when_socket_shutdown_set() {
        let socket = creds_test_socket();
        socket.shutdown.store(true, Ordering::SeqCst);
        let creds = proto::CredentialsIssued {
            ott: "tok".into(),
            matrix_api_url: "https://example.test".into(),
            ..Default::default()
        };
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            handle_credentials_issued(
                creds_key(),
                Arc::new(RwLock::new(crate::connector::ConnectorConfig::default())),
                Arc::new(CredsNoopConn),
                socket,
                Arc::new(RwLock::new(None)),
                MultiTransportOptions::default(),
                Arc::new(AtomicBool::new(false)),
                creds,
                Logger::new("test"),
            ),
        )
        .await;
        assert!(
            res.is_ok(),
            "must abort promptly when socket.shutdown is set"
        );
    }

    // --- session-token clearing on rejected registration (WS) --------------

    /// Build a bare `WsMultiplexHandle` for exercising the rejection-reset
    /// logic in isolation. The test connector's identity (`test_conn` /
    /// `inst-1`) has no saved credentials on disk, so the threshold-reached
    /// credential re-mint is a no-op here — these tests exercise the
    /// session-token drop and threshold reporting.
    fn make_ws_handle_for_reset_tests() -> WsMultiplexHandle {
        WsMultiplexHandle {
            key: creds_key(),
            config: Arc::new(RwLock::new(crate::connector::ConnectorConfig::default())),
            connector: Arc::new(CredsNoopConn),
            socket: creds_test_socket(),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(Mutex::new(ConnectorMetrics::default())),
            opts: MultiTransportOptions::default(),
            request_semaphore: Arc::new(Semaphore::new(8)),
            session_token: Arc::new(RwLock::new(None)),
            consecutive_rejections: Arc::new(AtomicU32::new(0)),
        }
    }

    #[tokio::test]
    async fn ws_note_rejection_drops_token_only_after_k_consecutive() {
        // A single rejection must NOT drop the token; the Kth consecutive one
        // must. Mirrors the gRPC runner's guarantee on the WS transport.
        let handle = make_ws_handle_for_reset_tests();
        let logger = Logger::new("test");
        *handle.session_token.write().await = Some("stale-token".into());

        for _ in 1..REJECTIONS_BEFORE_TOKEN_DROP {
            assert!(
                !handle
                    .note_rejection_and_maybe_reset_credentials(&logger)
                    .await,
                "must not reset before {REJECTIONS_BEFORE_TOKEN_DROP} rejections"
            );
            assert!(
                handle.session_token.read().await.is_some(),
                "token must survive a sub-threshold rejection"
            );
        }

        assert!(
            handle
                .note_rejection_and_maybe_reset_credentials(&logger)
                .await,
            "must reset on the {REJECTIONS_BEFORE_TOKEN_DROP}th consecutive rejection"
        );
        assert!(
            handle.session_token.read().await.is_none(),
            "token must be cleared once the threshold is reached"
        );
    }

    #[tokio::test]
    async fn ws_mint_auth_leaves_token_untouched_without_saved_credentials() {
        // Mirrors the gRPC runner's guard: the no-saved-credentials path must
        // not clobber an existing (OTT-issued) auth_token, and must return
        // promptly rather than blocking the reconnect loop on the network.
        let handle = make_ws_handle_for_reset_tests();
        let logger = Logger::new("test");
        handle.config.write().await.auth_token = "ott-issued-jwt".into();

        tokio::time::timeout(
            Duration::from_secs(5),
            handle.mint_auth_from_saved_credentials(&logger),
        )
        .await
        .expect("mint must return promptly when there are no saved credentials");

        assert_eq!(
            handle.config.read().await.auth_token,
            "ott-issued-jwt",
            "an OTT-issued auth_token must survive a mint with no keypair on disk"
        );
    }

    #[tokio::test]
    async fn ws_note_success_resets_rejection_counter() {
        // A success between rejections resets the counter so an isolated later
        // rejection never inherits stale count.
        let handle = make_ws_handle_for_reset_tests();
        let logger = Logger::new("test");
        *handle.session_token.write().await = Some("tok".into());

        assert!(
            !handle
                .note_rejection_and_maybe_reset_credentials(&logger)
                .await
        );
        handle.note_registration_success();

        assert!(
            !handle
                .note_rejection_and_maybe_reset_credentials(&logger)
                .await,
            "counter must have reset on success"
        );
        assert!(
            handle.session_token.read().await.is_some(),
            "token must survive when success reset the counter between rejections"
        );
    }

    #[tokio::test]
    async fn ws_dispatch_in_stream_reregister_clears_token_after_threshold() {
        // Regression: repeated rejected in-stream re-registers must eventually
        // drop the cached session token so the reconnect after teardown
        // re-registers from scratch instead of replaying a refused token.
        let handle = make_ws_handle_for_reset_tests();
        let logger = Logger::new("test");
        *handle.session_token.write().await = Some("stale-token".into());

        let (entry, _rx) = admit_with_rx(&handle.socket, "inst-1").await;

        for i in 1..=REJECTIONS_BEFORE_TOKEN_DROP {
            handle
                .dispatch_inbound(register_response(false, 3), &entry, &logger)
                .await;
            let cleared = handle.session_token.read().await.is_none();
            if i < REJECTIONS_BEFORE_TOKEN_DROP {
                assert!(!cleared, "token must survive rejection {i}");
            } else {
                assert!(cleared, "token must clear on rejection {i}");
            }
        }
    }

    #[tokio::test]
    async fn ws_dispatch_in_stream_reregister_success_keeps_token() {
        // Symmetric guard: a successful in-stream re-register persists the
        // freshly issued token and resets the rejection counter.
        let handle = make_ws_handle_for_reset_tests();
        let logger = Logger::new("test");
        *handle.session_token.write().await = Some("old-token".into());

        let (entry, _rx) = admit_with_rx(&handle.socket, "inst-1").await;

        handle
            .dispatch_inbound(register_response(true, 0), &entry, &logger)
            .await;
        assert_eq!(
            handle.session_token.read().await.as_deref(),
            Some("fresh-token"),
            "successful re-register must persist the freshly issued session token"
        );
    }

    fn register_response(success: bool, status: i32) -> StreamMessage {
        StreamMessage {
            message: Some(stream_message::Message::RegisterResponse(
                proto::RegisterConnectorResponse {
                    success,
                    address: String::new(),
                    error: if success {
                        String::new()
                    } else {
                        "Registration failed".into()
                    },
                    connector_arn: String::new(),
                    status,
                    session_token: if success {
                        "fresh-token".into()
                    } else {
                        String::new()
                    },
                    oidc_config: None,
                },
            )),
        }
    }
}

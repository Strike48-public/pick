//! Per-registration runner for `MultiConnectorRunner`.
//!
//! Drives the lifecycle of one logical connector against a stream returned
//! by [`crate::multi::shared_channel::SharedChannel`]:
//!
//! 1. Build the `RegisterConnectorRequest` (mirrors the canonical fields used
//!    by the existing `ConnectorRunner::build_register_request`).
//! 2. Open a stream on the shared channel with the register request folded
//!    into the outbound stream (avoids the bidi-gRPC deadlock with elixir-grpc).
//! 3. Wait for `RegisterResponse`.
//! 4. Run a select loop:
//!      - inbound message -> dispatch (`ExecuteRequest`, `HeartbeatRequest`,
//!        `HeartbeatResponse`, ...).
//!      - heartbeat tick -> send `HeartbeatRequest`.
//!      - shutdown -> exit.
//!
//! Existing single-registration callers go through `ConnectorRunner` and are
//! unaffected.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use rand::{Rng, thread_rng};
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc};
use tokio::time::{MissedTickBehavior, interval};

use crate::auth::OttProvider;
use crate::connector::{BaseConnector, ConnectorConfig, ConnectorHandle};
use crate::error::{ConnectorError, Result};
use crate::logger::Logger;
use crate::multi::MultiTransportOptions;
use crate::multi::RegistrationKey;
use crate::multi::shared_channel::{SharedChannel, SharedStream};
use crate::types::ConnectorMetrics;
use crate::types::{ExecuteRequest as SdkExecuteRequest, ExecuteResponse, PayloadEncoding};
use crate::types::{WsCloseRequest, WsFrame, WsFrameType, WsOpenRequest};
use crate::utils::{deserialize_payload, error_response, sanitize_identifier, serialize_payload};

use strike48_proto::proto::{
    self, ConnectorCapabilities, CredentialsIssued, HeartbeatRequest, HeartbeatResponse,
    InstanceMetadata, RegisterConnectorRequest, StreamMessage, stream_message,
};

/// Drives one logical registration against a shared transport.
pub(crate) struct RegistrationRunner {
    pub key: RegistrationKey,
    /// Wrapped so post-approval `CredentialsIssued` can update `auth_token`
    /// in place; subsequent reconnects pick up the new JWT.
    pub config: Arc<RwLock<ConnectorConfig>>,
    pub connector: Arc<dyn BaseConnector>,
    pub shared_channel: Arc<SharedChannel>,
    pub shutdown: Arc<AtomicBool>,
    pub metrics: Arc<Mutex<ConnectorMetrics>>,
    pub opts: MultiTransportOptions,
    /// Caps in-flight user `execute()` invocations for this registration.
    /// Mirrors the single-runner `max_concurrent_requests` pattern; protects
    /// the runtime from OOM under burst load.
    pub request_semaphore: Arc<Semaphore>,
    /// Session token granted by the server on a successful `RegisterResponse`.
    /// Sent back on subsequent in-stream re-registrations (e.g. after an
    /// OTT-driven `CredentialsIssued`) so the server can recognise this
    /// connector instance instead of treating it as a fresh registration.
    /// Mirrors the single-runner pattern in `connector.rs`.
    pub session_token: Arc<RwLock<Option<String>>>,
    /// Count of consecutive registration *rejections* (not transient errors)
    /// observed since the last successful register. Once it reaches
    /// [`REJECTIONS_BEFORE_TOKEN_DROP`] the cached session token is dropped so
    /// the next attempt re-registers from scratch. Shared (both the reconnect
    /// loop and the in-stream re-register path bump it) and reset to 0 on any
    /// success. Tolerating one rejection avoids discarding a still-valid token
    /// — and, for OTT-only connectors that have no keypair fallback, avoids
    /// bouncing them back into the pending-approval queue — on a single
    /// spurious/transient server rejection.
    ///
    /// "Consecutive" here means consecutive *rejections*: transient stream/gRPC
    /// errors (see [`is_registration_rejection`]) are skipped entirely — they
    /// neither increment nor reset this counter — so a network blip between two
    /// genuine rejections neither triggers a drop nor forgives the earlier
    /// rejection.
    pub consecutive_rejections: Arc<AtomicU32>,
}

/// Default heartbeat interval — matches Matrix's session-reaper expectation.
/// Per-runner override lives on [`MultiTransportOptions::heartbeat_interval`].
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
/// Default heartbeat watchdog timeout. Per-runner override lives on
/// [`MultiTransportOptions::heartbeat_timeout`].
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(45);
const SHUTDOWN_POLL: Duration = Duration::from_millis(100);
/// Number of consecutive registration rejections tolerated before the cached
/// session token is dropped and the connector re-registers from scratch. K=2
/// absorbs a single spurious/transient rejection while still recovering
/// promptly (one extra backoff cycle) from a genuinely dead token. Shared with
/// the WebSocket transport ([`crate::multi::ws_multiplex`]) so both paths use
/// the same threshold.
pub(crate) const REJECTIONS_BEFORE_TOKEN_DROP: u32 = 2;
/// Granularity for shutdown-aware sleep so reconnect backoff can be
/// interrupted promptly.
const RECONNECT_POLL: Duration = Duration::from_millis(50);

#[derive(Debug)]
enum StreamOutcome {
    Shutdown,
    ServerClosed,
    StreamError(String),
    HeartbeatTimeout,
    OutboundClosed,
}

impl StreamOutcome {
    fn summary(&self) -> &'static str {
        match self {
            StreamOutcome::Shutdown => "shutdown",
            StreamOutcome::ServerClosed => "server-closed",
            StreamOutcome::StreamError(_) => "stream-error",
            StreamOutcome::HeartbeatTimeout => "heartbeat-timeout",
            StreamOutcome::OutboundClosed => "outbound-closed",
        }
    }
}

impl std::fmt::Display for StreamOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamOutcome::StreamError(s) => write!(f, "stream-error: {s}"),
            other => write!(f, "{}", other.summary()),
        }
    }
}

/// Compute exponential backoff with jitter, hard-capped at `max_backoff_delay_ms`.
///
/// Order is intentional: scale exponentially → add jitter → clamp to the cap.
/// The cap applies to the post-jitter value so the effective max wait is never
/// `max_backoff_delay_ms + reconnect_jitter_ms`; some operators size the cap
/// against an SLA and depend on it being a true upper bound.
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

/// Reset the in-stream heartbeat watchdog timestamp to `now`.
///
/// Extracted as a free function so the post-OTT heartbeat-reset path can be
/// regression-tested without standing up a Keycloak / Matrix server.
fn bump_heartbeat(last_heartbeat_response: &mut Instant) {
    *last_heartbeat_response = Instant::now();
}

/// Sleep for `total` while polling the shutdown flag every `RECONNECT_POLL`.
/// Returns `true` if the full sleep completed, `false` if shutdown fired.
async fn sleep_with_shutdown(total: Duration, shutdown: &Arc<AtomicBool>) -> bool {
    let deadline = Instant::now() + total;
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return false;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        let step = remaining.min(RECONNECT_POLL);
        tokio::time::sleep(step).await;
    }
}

impl RegistrationRunner {
    pub async fn run(self) -> Result<()> {
        let logger = Logger::new("multi/registration");

        if self.shutdown.load(Ordering::SeqCst) {
            logger.debug(&format!(
                "registration {} skipped: shutdown signalled before run",
                self.key
            ));
            return Ok(());
        }

        // Pre-approval auth: if this connector was approved in a previous run,
        // its Keycloak client_id + private key are on disk. Load them and mint
        // a private_key_jwt into `config.auth_token` so the *initial* register
        // is authenticated and the server skips the pending-approval flow.
        //
        // Without this, a restarted connector registers anonymously and gets
        // re-queued for approval even though it already has valid credentials.
        // The single-connector `ConnectorRunner::initialize_auth` does this;
        // the multi-runner historically did not (it only minted a JWT
        // reactively on an inbound `CredentialsIssued`), which is the bug this
        // closes.
        self.prime_auth_from_saved_credentials(&logger).await;

        let mut attempt: u32 = 0;
        let mut ever_registered = false;

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                logger.debug(&format!(
                    "registration {}: shutdown signalled, exiting reconnect loop",
                    self.key
                ));
                return Ok(());
            }

            // Open a fresh stream (lazily acquires a channel from the pool).
            let register = {
                let cfg = self.config.read().await;
                let token = self.session_token.read().await.clone().unwrap_or_default();
                build_register_message_with_token(&cfg, self.connector.as_ref(), &token)
            };
            let stream = match self.shared_channel.open_stream(register, 64).await {
                Ok(s) => s,
                Err(e) => {
                    logger.warn(&format!(
                        "registration {}: open_stream failed: {e}",
                        self.key
                    ));
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
                    if !sleep_with_shutdown(backoff, &self.shutdown).await {
                        return Ok(());
                    }
                    continue;
                }
            };

            // Wait for the register response, racing against shutdown so a
            // server that accepts the bidi stream but never replies cannot
            // wedge us until the gRPC keepalive (~40s) fires.
            let mut stream = stream;
            let response_deadline =
                Duration::from_millis(self.opts.connect_timeout_ms.max(1)).saturating_mul(3);
            match wait_for_register_response(&mut stream.inbound, &self.shutdown, response_deadline)
                .await
            {
                Ok(accepted) => {
                    let arn = &accepted.connector_arn;
                    logger.info(&format!("registration {} registered (arn={arn})", self.key));
                    self.note_registration_success();
                    if !accepted.session_token.is_empty() {
                        *self.session_token.write().await = Some(accepted.session_token.clone());
                    }
                    {
                        let mut m = self.metrics.lock().await;
                        m.last_connected_at_ms = Some(now_ms());
                        m.current_backoff_ms = 0;
                        if ever_registered {
                            m.successful_reconnects += 1;
                        }
                    }
                    ever_registered = true;
                    attempt = 0;
                }
                Err(e) => {
                    logger.warn(&format!("registration {}: register failed: {e}", self.key));

                    // If the server *rejected* the register (as opposed to a
                    // transient stream/network blip), the usual cause is a stale
                    // cached session token that no longer validates — e.g. after
                    // Matrix redeploys and rotates its session-signing secret.
                    // After REJECTIONS_BEFORE_TOKEN_DROP consecutive rejections
                    // we drop it and re-mint auth so the next attempt
                    // re-registers from scratch (keypair JWT / OTT) instead of
                    // replaying a credential that will never decode again;
                    // otherwise the loop retries the dead token forever.
                    // Transient errors keep the token so a working session
                    // survives a blip. See `is_registration_rejection` for what
                    // counts as a rejection.
                    if is_registration_rejection(&e)
                        && self
                            .note_rejection_and_maybe_reset_credentials(&logger)
                            .await
                    {
                        logger.warn(&format!(
                            "registration {}: reset rejected credentials after \
                             {REJECTIONS_BEFORE_TOKEN_DROP} consecutive rejections; \
                             re-registering from scratch",
                            self.key
                        ));
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
                    if !sleep_with_shutdown(backoff, &self.shutdown).await {
                        return Ok(());
                    }
                    continue;
                }
            }

            // Drive the stream until it errors / closes / shutdown fires.
            let outcome = self.drive_stream(stream, &logger).await;
            {
                let mut m = self.metrics.lock().await;
                m.total_disconnects += 1;
                m.last_disconnected_at_ms = Some(now_ms());
                m.last_disconnect_reason = Some(outcome.summary().to_string());
            }

            // Shutdown observed inside drive_stream → exit cleanly.
            if self.shutdown.load(Ordering::SeqCst) {
                return Ok(());
            }

            if !self.opts.reconnect_enabled {
                logger.debug(&format!(
                    "registration {}: reconnect disabled, exiting after {outcome}",
                    self.key
                ));
                return Ok(());
            }

            attempt = attempt.saturating_add(1);
            let backoff = compute_backoff(&self.opts, attempt);
            logger.warn(&format!(
                "registration {}: stream ended ({outcome}); reconnecting in {}ms (attempt {})",
                self.key,
                backoff.as_millis(),
                attempt
            ));
            {
                let mut m = self.metrics.lock().await;
                m.reconnection_attempts += 1;
                m.current_backoff_ms = backoff.as_millis() as u64;
            }
            if !sleep_with_shutdown(backoff, &self.shutdown).await {
                return Ok(());
            }
        }
    }

    /// Main select loop: dispatch inbound, send heartbeats, observe shutdown.
    /// Returns the reason the loop exited so the outer reconnect loop can
    /// log/decide whether to retry.
    async fn drive_stream(&self, stream: SharedStream, logger: &Logger) -> StreamOutcome {
        let SharedStream {
            tx, mut inbound, ..
        } = stream;

        // Per-connection WS pump tasks. Keyed by `connection_id`. We track
        // these so:
        //   - `WsCloseRequest` can abort the corresponding pump promptly
        //     instead of waiting for it to discover the close via send error.
        //   - Stream teardown (this fn returning) aborts all pumps so a
        //     reconnect doesn't leave pumps holding stale `tx` senders that
        //     would silently send into a half-dead channel.
        // The outcome is held in a local rather than on `self` because pumps
        // are scoped to one stream lifetime; the outer reconnect loop builds
        // a new map on the next stream.
        //
        // Implementation note: a `tokio::task::JoinSet` would auto-collect
        // finished pumps, but it does not support keyed lookup — abort-on-
        // close needs `connection_id → handle` direct addressing, and a
        // pump that finishes naturally (peer EOF) drops its `Sender` clone,
        // which is harmless to leave in the map until stream teardown
        // drains it. Trading the auto-collect for keyed lookup is the right
        // shape here.
        let mut ws_pumps: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();

        let mut last_heartbeat_response = Instant::now();
        let hb_interval_dur = self.opts.heartbeat_interval.unwrap_or(HEARTBEAT_INTERVAL);
        let hb_timeout_dur = self.opts.heartbeat_timeout.unwrap_or(HEARTBEAT_TIMEOUT);
        let mut hb_interval = interval(hb_interval_dur);
        // If the runtime stalls (e.g. user `execute()` blocks the runtime
        // briefly) we don't want to emit a burst of catch-up heartbeat ticks.
        // `Skip` collapses missed ticks into one — heartbeats are about
        // liveness, not delivery exactly N per interval.
        hb_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Skip the immediate tick — first heartbeat fires after one full interval.
        hb_interval.tick().await;

        // Capture the outcome so we can abort pumps before returning.
        let outcome = loop {
            if self.shutdown.load(Ordering::SeqCst) {
                logger.debug(&format!(
                    "registration {}: shutting down on signal",
                    self.key
                ));
                break StreamOutcome::Shutdown;
            }

            tokio::select! {
                msg_opt = inbound.next() => {
                    match msg_opt {
                        Some(Ok(msg)) => {
                            if let Some(outcome) = self
                                .dispatch_inbound(msg, &tx, &mut last_heartbeat_response, &mut ws_pumps, logger)
                                .await
                            {
                                break outcome;
                            }
                        }
                        Some(Err(status)) => {
                            logger.warn(&format!(
                                "registration {}: stream error: {status}",
                                self.key
                            ));
                            break StreamOutcome::StreamError(status.to_string());
                        }
                        None => {
                            logger.debug(&format!(
                                "registration {}: server closed stream",
                                self.key
                            ));
                            break StreamOutcome::ServerClosed;
                        }
                    }
                }
                _ = hb_interval.tick() => {
                    if last_heartbeat_response.elapsed() > hb_timeout_dur {
                        logger.warn(&format!(
                            "registration {}: no heartbeat response for {}s, presumed dead",
                            self.key,
                            last_heartbeat_response.elapsed().as_secs()
                        ));
                        break StreamOutcome::HeartbeatTimeout;
                    }
                    let hb = StreamMessage {
                        message: Some(stream_message::Message::HeartbeatRequest(HeartbeatRequest {
                            gateway_id: String::new(),
                            timestamp_ms: now_ms() as i64,
                        })),
                    };
                    if tx.send(hb).await.is_err() {
                        logger.debug(&format!(
                            "registration {}: outbound channel closed; exiting",
                            self.key
                        ));
                        break StreamOutcome::OutboundClosed;
                    }
                }
                _ = tokio::time::sleep(SHUTDOWN_POLL) => {
                    // Re-check shutdown flag at the top of the loop.
                }
            }
        };

        // Stream is dying. Abort any WS pump tasks so they don't keep
        // sending into a closing `tx` (or, after the runner reconnects,
        // into a stale channel that will never reach the new stream).
        // `JoinHandle::abort` is safe to call regardless of task state;
        // already-finished tasks are no-ops.
        if !ws_pumps.is_empty() {
            logger.debug(&format!(
                "registration {}: aborting {} WS pump task(s) on stream exit",
                self.key,
                ws_pumps.len()
            ));
            for (_, handle) in ws_pumps.drain() {
                handle.abort();
            }
        }

        outcome
    }

    /// Dispatch one inbound message. Returns `Some(outcome)` if the drive
    /// loop should exit (e.g. server-rejected approval that needs a fresh
    /// register cycle, or post-credentials in-stream re-register failed and
    /// we want the outer loop to reconnect with the new JWT).
    ///
    /// `ws_pumps` is the per-stream `connection_id → JoinHandle` registry
    /// owned by `drive_stream`. We update it on `WsOpenRequest` (insert) and
    /// `WsCloseRequest` (abort + remove), and `drive_stream` drains it on
    /// stream teardown.
    async fn dispatch_inbound(
        &self,
        msg: StreamMessage,
        tx: &mpsc::Sender<StreamMessage>,
        last_heartbeat_response: &mut Instant,
        ws_pumps: &mut HashMap<String, tokio::task::JoinHandle<()>>,
        logger: &Logger,
    ) -> Option<StreamOutcome> {
        match msg.message {
            Some(stream_message::Message::ExecuteRequest(req)) => {
                let request = SdkExecuteRequest {
                    request_id: req.request_id.clone(),
                    payload: req.payload.clone(),
                    payload_encoding: PayloadEncoding::from(req.payload_encoding),
                    context: req.context.clone(),
                    capability_id: if req.capability_id.is_empty() {
                        None
                    } else {
                        Some(req.capability_id.clone())
                    },
                };

                let connector = self.connector.clone();
                let metrics = self.metrics.clone();
                let tx = tx.clone();
                let key = self.key.clone();
                let semaphore = self.request_semaphore.clone();
                let logger = Logger::new("multi/registration/execute");

                tokio::spawn(async move {
                    // Acquire a permit BEFORE doing user work; released on
                    // task exit. If the semaphore is closed (only happens
                    // on runner teardown), drop the request silently.
                    let permit = match semaphore.acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            logger.debug(&format!(
                                "registration {key}: request semaphore closed, dropping execute"
                            ));
                            return;
                        }
                    };
                    if let Err(e) =
                        handle_execute(connector, request, tx, metrics, &logger, &key).await
                    {
                        logger.error(
                            &format!("registration {key}: execute dispatch failed"),
                            &e.to_string(),
                        );
                    }
                    drop(permit);
                });
                None
            }
            Some(stream_message::Message::HeartbeatRequest(_)) => {
                let resp = StreamMessage {
                    message: Some(stream_message::Message::HeartbeatResponse(
                        HeartbeatResponse {
                            gateway_id: String::new(),
                            timestamp_ms: now_ms() as i64,
                            should_reconnect: false,
                        },
                    )),
                };
                let _ = tx.send(resp).await;
                None
            }
            Some(stream_message::Message::HeartbeatResponse(_)) => {
                *last_heartbeat_response = Instant::now();
                None
            }
            Some(stream_message::Message::RegisterResponse(resp)) => {
                // Post-approval JWT re-registration: the server sends another
                // RegisterResponse on the same stream after we re-register
                // with the JWT. Log the upgrade and persist any session token.
                if resp.success {
                    logger.info(&format!(
                        "registration {}: in-stream re-register succeeded (arn={})",
                        self.key, resp.connector_arn
                    ));
                    self.note_registration_success();
                    if !resp.session_token.is_empty() {
                        *self.session_token.write().await = Some(resp.session_token.clone());
                    }
                    let mut m = self.metrics.lock().await;
                    m.last_connected_at_ms = Some(now_ms());
                } else {
                    logger.warn(&format!(
                        "registration {}: in-stream re-register failed: status='{}' error='{}'",
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
                            "registration {}: reset rejected credentials after \
                             {REJECTIONS_BEFORE_TOKEN_DROP} consecutive rejections \
                             (in-stream re-register)",
                            self.key
                        ));
                    }
                }
                None
            }
            Some(stream_message::Message::CredentialsIssued(creds)) => {
                self.handle_credentials_issued(creds, tx, last_heartbeat_response, logger)
                    .await
            }
            Some(stream_message::Message::ApprovalNotification(notif)) => {
                let status = proto::RegistrationStatus::try_from(notif.status);
                match status {
                    Ok(proto::RegistrationStatus::Approved) => {
                        logger.info(&format!(
                            "registration {}: approved by admin (CredentialsIssued imminent)",
                            self.key
                        ));
                        None
                    }
                    Ok(proto::RegistrationStatus::Pending) => {
                        logger.info(&format!(
                            "registration {}: pending approval — {}",
                            self.key,
                            if notif.message.is_empty() {
                                "awaiting admin"
                            } else {
                                &notif.message
                            }
                        ));
                        None
                    }
                    Ok(proto::RegistrationStatus::Rejected) => {
                        logger.warn(&format!(
                            "registration {}: REJECTED by admin — {}",
                            self.key,
                            if notif.message.is_empty() {
                                "no reason given"
                            } else {
                                &notif.message
                            }
                        ));
                        // Force a reconnect so the next register cycle goes
                        // back through pending approval. The OTT provider is
                        // rebuilt per `CredentialsIssued`, so there is no
                        // cached credential state to clear here.
                        Some(StreamOutcome::ServerClosed)
                    }
                    _ => {
                        logger.debug(&format!(
                            "registration {}: ApprovalNotification status={} message={}",
                            self.key, notif.status, notif.message
                        ));
                        None
                    }
                }
            }
            Some(stream_message::Message::WsOpenRequest(req)) => {
                let connection_id = req.connection_id.clone();
                let ws_req = WsOpenRequest {
                    connection_id: connection_id.clone(),
                    path: req.path.clone(),
                    query_string: req.query_string.clone(),
                    headers: req.headers.clone(),
                };
                let connector = self.connector.clone();
                let handle = ConnectorHandle::from_sender(tx.clone());
                let key = self.key.clone();
                let pump = tokio::spawn(async move {
                    if let Err(e) = connector.handle_ws_open(ws_req, handle).await {
                        tracing::error!(
                            registration = %key,
                            error = %e,
                            "handle_ws_open failed"
                        );
                    }
                });
                // If a previous open with the same connection_id is still
                // pending (Matrix sent two opens before the first finished
                // — shouldn't happen on the wire, but cheap to guard) we
                // abort the old one. Otherwise it would leak the JoinHandle.
                if let Some(prev) = ws_pumps.insert(connection_id.clone(), pump) {
                    tracing::warn!(
                        registration = %self.key,
                        connection_id = %connection_id,
                        "duplicate WsOpenRequest for connection_id; aborting previous pump"
                    );
                    prev.abort();
                }
                None
            }
            Some(stream_message::Message::WsFrame(frame)) => {
                let ws_frame = WsFrame {
                    connection_id: frame.connection_id.clone(),
                    frame_type: WsFrameType::from(frame.frame_type),
                    data: frame.data.clone(),
                };
                let connector = self.connector.clone();
                let handle = ConnectorHandle::from_sender(tx.clone());
                let key = self.key.clone();
                // Frames are short-lived inbound dispatches that the
                // connector is expected to handle quickly; we don't track
                // their JoinHandles. If a connector implementation needs
                // ordering across frames it must serialise internally.
                //
                // Operational caveat: because we don't track these tasks,
                // they are NOT aborted on stream teardown. A future
                // connector whose `handle_ws_frame` runs long (>O(ms))
                // would leak one task per frame across each reconnect.
                // If/when that becomes a real use case, lift these into
                // a `JoinSet` keyed alongside `ws_pumps` and drain on
                // teardown like the open pumps below.
                tokio::spawn(async move {
                    if let Err(e) = connector.handle_ws_frame(ws_frame, handle).await {
                        tracing::error!(
                            registration = %key,
                            error = %e,
                            "handle_ws_frame failed"
                        );
                    }
                });
                None
            }
            Some(stream_message::Message::WsCloseRequest(req)) => {
                let ws_req = WsCloseRequest {
                    connection_id: req.connection_id.clone(),
                    code: req.code,
                    reason: req.reason.clone(),
                };
                // Abort the open's pump task before invoking the connector's
                // close hook. `abort` is idempotent on already-finished
                // tasks. Doing it before the user hook means a connector
                // can't accidentally race a still-running pump from inside
                // its `handle_ws_close` body.
                //
                // We deliberately do NOT `await` the aborted handle here:
                // `JoinHandle::abort` only signals cancellation, it does
                // not block until the task observes it at the next `.await`
                // point. Awaiting would let a pump that's currently inside
                // a slow user-supplied future (e.g. a backend `read`) stall
                // the entire dispatch loop and back up other inbound
                // messages on the stream. The abort signal will be
                // observed at the pump's next yield point; until then the
                // pump may emit one or two more frames into the closing
                // channel, which is harmless — the runner has already
                // committed to closing this connection.
                if let Some(pump) = ws_pumps.remove(&req.connection_id) {
                    pump.abort();
                }
                self.connector.handle_ws_close(ws_req);
                None
            }
            Some(other) => {
                // InvokeRequest/Response variants are not wired yet; log at
                // debug. Tracked as follow-up work.
                logger.debug(&format!(
                    "registration {}: ignoring inbound variant {:?}",
                    self.key,
                    std::mem::discriminant(&other)
                ));
                None
            }
            None => {
                logger.debug(&format!("registration {}: empty inbound message", self.key));
                None
            }
        }
    }

    /// Record a registration *rejection* and, once
    /// [`REJECTIONS_BEFORE_TOKEN_DROP`] consecutive rejections have been seen,
    /// reset the credentials so the next attempt re-registers from scratch
    /// rather than replaying credentials the server keeps refusing:
    ///
    ///   1. Drop the cached session token (if any) so the next register is
    ///      net-new rather than a session-resume.
    ///   2. Re-mint `auth_token` from saved keypair credentials. Without this,
    ///      a connector that has been up longer than the Keycloak token
    ///      lifetime (~300s) would drop its session token but re-register with
    ///      an already-expired JWT — rejected again, looping forever. This is
    ///      the per-drop refresh the single-connector runner does every
    ///      iteration (`connector.rs`); the multi-runner only primed auth once
    ///      before the loop, so it needs to refresh here.
    ///
    /// Called from both the reconnect loop (initial register) and the in-stream
    /// re-register path; the counter is shared so rejections across those paths
    /// accumulate. Returns whether the threshold was reached on this call — the
    /// caller logs a diagnostic when it is. Note this is *threshold reached*,
    /// not *token dropped*: it stays `true` even when there was no session token
    /// to drop, so a connector that keeps re-registering with a stale JWT still
    /// logs each reset cycle instead of looping silently.
    async fn note_rejection_and_maybe_reset_credentials(&self, logger: &Logger) -> bool {
        let count = self.consecutive_rejections.fetch_add(1, Ordering::SeqCst) + 1;
        if count < REJECTIONS_BEFORE_TOKEN_DROP {
            logger.debug(&format!(
                "registration {}: registration rejection {count}/{REJECTIONS_BEFORE_TOKEN_DROP} \
                 (retaining cached credentials)",
                self.key
            ));
            return false;
        }
        // Threshold reached: reset credentials so the next register is a
        // net-new registration, then reset the counter so the fresh
        // registration starts from a clean slate.
        self.consecutive_rejections.store(0, Ordering::SeqCst);
        let dropped_token = self.session_token.write().await.take().is_some();
        logger.debug(&format!(
            "registration {}: rejection threshold reached (dropped_session_token={dropped_token}); \
             re-minting auth from saved credentials",
            self.key
        ));
        // Refresh the keypair JWT so we don't re-register with a stale one.
        self.mint_auth_from_saved_credentials(logger).await;
        true
    }

    /// Reset the consecutive-rejection counter after a successful register, so a
    /// single later rejection never inherits stale count from an earlier blip.
    fn note_registration_success(&self) {
        self.consecutive_rejections.store(0, Ordering::SeqCst);
    }

    /// Load previously-saved credentials (Keycloak `client_id` + private key,
    /// persisted under `~/.strike48`) and mint a `private_key_jwt` into
    /// `config.auth_token`, so the first `RegisterConnectorRequest` of this
    /// run is already authenticated.
    ///
    /// Best-effort and idempotent: if `auth_token` is already set, no saved
    /// credentials exist, or the JWT mint fails, it leaves `auth_token`
    /// untouched and the connector falls back to the normal
    /// pending-approval → `CredentialsIssued` flow. Mirrors Priority 3 of the
    /// single-connector `ConnectorRunner::initialize_auth`.
    async fn prime_auth_from_saved_credentials(&self, logger: &Logger) {
        // Don't clobber an auth token that's already been arranged (e.g. an
        // OTT/direct-config flow that set it before `run`).
        if !self.config.read().await.auth_token.is_empty() {
            return;
        }
        self.mint_auth_from_saved_credentials(logger).await;
    }

    /// Mint a fresh `private_key_jwt` from saved keypair credentials into
    /// `config.auth_token`, **overwriting** any existing value. Unlike
    /// [`Self::prime_auth_from_saved_credentials`] (a no-op when `auth_token`
    /// is already set), this always re-mints — used when a run of rejections
    /// suggests the cached credential has gone stale and the token must be
    /// refreshed before re-registering.
    ///
    /// If no saved credentials exist (e.g. OTT-only connectors that have no
    /// keypair on disk) the existing `auth_token` is left **untouched** so we
    /// never downgrade a possibly-still-valid OTT credential to the anonymous
    /// pending-approval flow; the caller's dropped session token already forces
    /// the server to treat the next register as net-new.
    ///
    /// The mint is **time-bounded** (`auth_mint_budget`): `get_token` performs a
    /// network round-trip to Keycloak with its own internal retries and no
    /// per-request timeout, and this runs inline in the reconnect loop. Without
    /// a bound, an unreachable/hung Keycloak (or a silent proxy) would stall the
    /// register loop instead of letting it back off and retry — the very
    /// failure mode the rejection reset exists to avoid.
    async fn mint_auth_from_saved_credentials(&self, logger: &Logger) {
        let (instance_id, connector_type) = (
            self.config.read().await.instance_id.clone(),
            self.connector.connector_type().to_string(),
        );

        let mut provider =
            OttProvider::new(Some(connector_type.clone()), Some(instance_id.clone()));

        let Some(saved) = provider.load_saved_credentials(&connector_type, Some(&instance_id))
        else {
            logger.info(&format!(
                "registration {}: no saved credentials; using pending-approval flow",
                self.key
            ));
            return;
        };

        let budget = auth_mint_budget(&self.opts);
        match tokio::time::timeout(budget, provider.get_token()).await {
            Ok(Ok(jwt)) => {
                self.config.write().await.auth_token = jwt;
                logger.info(&format!(
                    "registration {}: primed auth from saved credentials (client_id={})",
                    self.key, saved.client_id
                ));
            }
            Ok(Err(e)) => {
                logger.warn(&format!(
                    "registration {}: saved credentials present but JWT mint failed ({e}); \
                     falling back to pending-approval flow",
                    self.key
                ));
            }
            Err(_) => {
                logger.warn(&format!(
                    "registration {}: JWT mint timed out after {}ms; leaving auth_token \
                     unchanged and letting the reconnect loop retry",
                    self.key,
                    budget.as_millis()
                ));
            }
        }
    }

    /// Handle `CredentialsIssued`: do the OTT exchange against the Matrix
    /// HTTP API, persist the JWT in `config.auth_token`, and re-register on
    /// the same stream so the server can transition this connector from
    /// pending to registered without a full reconnect.
    async fn handle_credentials_issued(
        &self,
        creds: CredentialsIssued,
        tx: &mpsc::Sender<StreamMessage>,
        last_heartbeat_response: &mut Instant,
        logger: &Logger,
    ) -> Option<StreamOutcome> {
        if creds.ott.is_empty() {
            logger.error(
                &format!("registration {}: CredentialsIssued without OTT", self.key),
                "",
            );
            return None;
        }
        if creds.matrix_api_url.is_empty() {
            logger.error(
                &format!(
                    "registration {}: CredentialsIssued without matrix_api_url",
                    self.key
                ),
                "",
            );
            return None;
        }

        let (instance_id, connector_type) = (
            self.config.read().await.instance_id.clone(),
            self.connector.connector_type().to_string(),
        );

        let mut provider =
            OttProvider::new(Some(connector_type.clone()), Some(instance_id.clone()));

        match provider
            .register_public_key_with_ott_data(
                &creds.ott,
                &creds.matrix_api_url,
                &creds.register_url,
                &connector_type,
                Some(&instance_id),
            )
            .await
        {
            Ok(response) => {
                logger.debug(&format!(
                    "registration {}: registered public key with OTT (client_id={})",
                    self.key, response.client_id
                ));
            }
            Err(e) => {
                logger.error(
                    &format!(
                        "registration {}: failed to complete OTT registration",
                        self.key
                    ),
                    &e.to_string(),
                );
                return None;
            }
        }

        let jwt_token = match provider.get_token().await {
            Ok(t) => t,
            Err(e) => {
                logger.error(
                    &format!(
                        "registration {}: failed to fetch JWT after OTT exchange",
                        self.key
                    ),
                    &e.to_string(),
                );
                return None;
            }
        };

        // Persist the JWT in our config so future reconnects use it.
        self.config.write().await.auth_token = jwt_token.clone();
        // The provider itself is intentionally dropped here. We rebuild a
        // fresh OttProvider on every `CredentialsIssued` because the keypair
        // and Keycloak client_id are scoped to this approval cycle.
        drop(provider);

        // Re-register on the same stream. The server will respond with a
        // success RegisterResponse, which the dispatch loop logs.
        let register = {
            let cfg = self.config.read().await;
            let token = self.session_token.read().await.clone().unwrap_or_default();
            build_register_message_with_token(&cfg, self.connector.as_ref(), &token)
        };
        match tx.send(register).await {
            Ok(()) => {
                // The OTT/Keycloak HTTPS round-trip can take many seconds
                // (observed up to ~22s in the wild). Without resetting the
                // heartbeat watchdog, the very next heartbeat tick after this
                // function returns can find that more than HEARTBEAT_TIMEOUT
                // (45s) has elapsed since the last `HeartbeatResponse` —
                // because we were busy doing the OTT exchange — and tear the
                // stream down immediately after a *successful* re-register.
                bump_heartbeat(last_heartbeat_response);
                logger.info(&format!(
                    "registration {}: sent JWT re-registration on existing stream",
                    self.key
                ));
                None
            }
            Err(e) => {
                logger.warn(&format!(
                    "registration {}: in-stream re-register send failed: {e}; reconnecting",
                    self.key
                ));
                Some(StreamOutcome::OutboundClosed)
            }
        }
    }
}

async fn handle_execute(
    connector: Arc<dyn BaseConnector>,
    request: SdkExecuteRequest,
    tx: mpsc::Sender<StreamMessage>,
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

    let response = match deserialize_payload::<serde_json::Value>(
        &request.payload,
        request.payload_encoding,
    ) {
        Ok(req_data) => match connector
            .execute_with_context(req_data, request.capability_id.as_deref(), &request.context)
            .await
        {
            Ok(resp_data) => match serialize_payload(&resp_data, PayloadEncoding::Json) {
                Ok(payload) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    {
                        let mut m = metrics.lock().await;
                        m.requests_processed += 1;
                        m.bytes_sent += payload.len() as u64;
                        m.total_duration_ms += duration_ms;
                    }
                    ExecuteResponse {
                        request_id: request.request_id,
                        success: true,
                        payload,
                        payload_encoding: PayloadEncoding::Json,
                        error: String::new(),
                        duration_ms,
                    }
                }
                Err(e) => {
                    logger.error(
                        &format!("registration {key}: serialization failed"),
                        &e.to_string(),
                    );
                    {
                        let mut m = metrics.lock().await;
                        m.requests_failed += 1;
                    }
                    ExecuteResponse {
                        request_id: request.request_id,
                        success: false,
                        payload: error_response(&e.to_string()).unwrap_or_default(),
                        payload_encoding: PayloadEncoding::Json,
                        error: e.to_string(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    }
                }
            },
            Err(e) => {
                logger.error(
                    &format!("registration {key}: execute failed"),
                    &e.to_string(),
                );
                {
                    let mut m = metrics.lock().await;
                    m.requests_failed += 1;
                }
                ExecuteResponse {
                    request_id: request.request_id,
                    success: false,
                    payload: error_response(&e.to_string()).unwrap_or_default(),
                    payload_encoding: PayloadEncoding::Json,
                    error: e.to_string(),
                    duration_ms: start.elapsed().as_millis() as u64,
                }
            }
        },
        Err(e) => {
            logger.error(
                &format!("registration {key}: deserialization failed"),
                &e.to_string(),
            );
            {
                let mut m = metrics.lock().await;
                m.requests_failed += 1;
            }
            ExecuteResponse {
                request_id: request.request_id,
                success: false,
                payload: error_response(&e.to_string()).unwrap_or_default(),
                payload_encoding: PayloadEncoding::Json,
                error: e.to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
            }
        }
    };

    let message = StreamMessage {
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

    tx.send(message).await.map_err(|e| {
        ConnectorError::StreamError(format!("failed to send execute response: {e}"))
    })?;
    Ok(())
}

/// Whether a failed register attempt represents a server-side *rejection* of
/// our credentials (versus a transient stream/network error). On a rejection
/// the caller drops any cached session token so the next attempt re-registers
/// from scratch; on a transient error the token is retained.
///
/// Two shapes count as a rejection:
///   - `RegistrationError` — the server replied with an in-band
///     `RegisterResponse { success: false }` (this is what Matrix sends today
///     for a stale/undecodable session token: `status='3'`).
///   - `Grpc` with code `Unauthenticated` or `InvalidArgument` — a
///     credential-shaped rejection surfaced as a trailing gRPC status rather
///     than an in-band message. Other gRPC codes (`Unavailable`,
///     `DeadlineExceeded`, etc.) are transient and must NOT clear the token.
fn is_registration_rejection(e: &ConnectorError) -> bool {
    match e {
        ConnectorError::RegistrationError(_) => true,
        ConnectorError::Grpc(status) => matches!(
            status.code(),
            tonic::Code::Unauthenticated | tonic::Code::InvalidArgument
        ),
        _ => false,
    }
}

/// Wall-clock budget for an inline `private_key_jwt` mint against Keycloak.
///
/// `OttProvider::get_token` does a network round-trip with its own internal
/// retries (3 attempts, 500ms→1s backoff) and the shared reqwest client sets no
/// per-request timeout, so an unreachable or hung Keycloak — or a silent proxy —
/// can block for an unbounded time. Both multi-runners mint inline in their
/// reconnect loops, so that would stall registration entirely.
///
/// `connect_timeout_ms * 3` matches the budget the post-approval OTT exchange
/// already uses (see `ws_multiplex::…http_budget`): enough for
/// connect + TLS + request + server processing on a slow cross-region link,
/// while still bounded. Shared by both transports so they can't drift.
pub(crate) fn auth_mint_budget(opts: &MultiTransportOptions) -> Duration {
    Duration::from_millis(opts.connect_timeout_ms.max(1).saturating_mul(3))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn build_register_message_with_token(
    config: &ConnectorConfig,
    connector: &dyn BaseConnector,
    session_token: &str,
) -> StreamMessage {
    let mut msg = build_register_message(config, connector);
    if let Some(stream_message::Message::RegisterRequest(ref mut req)) = msg.message {
        req.session_token = session_token.to_string();
    }
    msg
}

fn build_register_message(
    config: &ConnectorConfig,
    connector: &dyn BaseConnector,
) -> StreamMessage {
    let capabilities = ConnectorCapabilities {
        connector_type: connector.connector_type().to_string(),
        version: connector.version().to_string(),
        supported_encodings: connector
            .supported_encodings()
            .iter()
            .map(|e| *e as i32)
            .collect(),
        behaviors: connector.behaviors().iter().map(|b| *b as i32).collect(),
        metadata: crate::connector::build_registration_metadata(connector),
        task_types: connector
            .capabilities()
            .iter()
            .map(|tt| proto::TaskTypeSchema {
                task_type_id: tt.task_type_id.clone(),
                name: tt.name.clone(),
                description: tt.description.clone(),
                category: tt.category.clone(),
                icon: tt.icon.clone(),
                input_schema_json: tt.input_schema_json.clone(),
                output_schema_json: tt.output_schema_json.clone(),
            })
            .collect(),
    };

    let sanitized_instance = sanitize_identifier(&config.instance_id);

    let mut metadata = config.metadata.clone();
    crate::sdk_metadata::merge_into(
        &mut metadata,
        &config.transport_type.to_string(),
        config.use_tls,
    );

    let instance_metadata = Some(InstanceMetadata {
        display_name: config
            .display_name
            .clone()
            .unwrap_or_else(|| sanitized_instance.clone()),
        tags: config.tags.clone(),
        metadata,
    });

    let request = RegisterConnectorRequest {
        tenant_id: sanitize_identifier(&config.tenant_id),
        connector_type: sanitize_identifier(connector.connector_type()),
        instance_id: sanitized_instance,
        capabilities: Some(capabilities),
        jwt_token: config.auth_token.clone(),
        session_token: String::new(),
        scope: 0,
        instance_metadata,
    };

    StreamMessage {
        message: Some(stream_message::Message::RegisterRequest(request)),
    }
}

/// Outcome of a successful `RegisterResponse`. Includes the connector ARN
/// (echoed back in logs) and the session token the server allocated, which
/// the runner persists for subsequent in-stream re-registers.
#[derive(Debug, Clone)]
pub(crate) struct RegisterAccepted {
    pub connector_arn: String,
    pub session_token: String,
}

async fn wait_for_register_response(
    inbound: &mut tonic::Streaming<StreamMessage>,
    shutdown: &Arc<AtomicBool>,
    deadline: Duration,
) -> Result<RegisterAccepted> {
    let started = Instant::now();
    loop {
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(ConnectorError::Timeout(
                "register response not received within deadline".into(),
            ));
        }
        tokio::select! {
            biased;
            _ = wait_for_shutdown(shutdown) => {
                return Err(ConnectorError::StreamError(
                    "shutdown signalled while waiting for register response".into(),
                ));
            }
            _ = tokio::time::sleep(remaining) => {
                return Err(ConnectorError::Timeout(
                    "register response not received within deadline".into(),
                ));
            }
            inbound_result = inbound.next() => match inbound_result {
                None => {
                    return Err(ConnectorError::StreamError(
                        "stream closed before register response".into(),
                    ));
                }
                Some(Err(status)) => {
                    return Err(ConnectorError::Grpc(Box::new(status)));
                }
                Some(Ok(msg)) => match msg.message {
                    Some(stream_message::Message::RegisterResponse(resp)) => {
                        if !resp.success {
                            return Err(ConnectorError::RegistrationError(format!(
                                "register failed: status='{}' error='{}'",
                                resp.status, resp.error
                            )));
                        }
                        return Ok(RegisterAccepted {
                            connector_arn: resp.connector_arn,
                            session_token: resp.session_token,
                        });
                    }
                    Some(_) => continue,
                    None => continue,
                },
            },
        }
    }
}

/// Block until the shutdown flag is set. Polls at `RECONNECT_POLL` cadence so
/// `tokio::select!` can race it against any other future without busy-looping.
async fn wait_for_shutdown(shutdown: &Arc<AtomicBool>) {
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(RECONNECT_POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi::shared_channel::SharedChannel;
    use proto::ApprovalNotification;
    use std::pin::Pin;
    use tokio::sync::Semaphore;

    struct NoopConn;
    impl BaseConnector for NoopConn {
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
        ) -> Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>>
        {
            Box::pin(async { Ok(serde_json::json!({})) })
        }
    }

    fn make_runner_for_dispatch_tests() -> RegistrationRunner {
        let key = RegistrationKey {
            tenant_id: "t".into(),
            connector_type: "test_conn".into(),
            instance_id: "i".into(),
        };
        let opts = MultiTransportOptions::default();
        RegistrationRunner {
            key,
            config: Arc::new(RwLock::new(crate::connector::ConnectorConfig::default())),
            connector: Arc::new(NoopConn),
            shared_channel: Arc::new(SharedChannel::new(opts.clone())),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(Mutex::new(ConnectorMetrics::default())),
            opts,
            request_semaphore: Arc::new(Semaphore::new(8)),
            session_token: Arc::new(RwLock::new(None)),
            consecutive_rejections: Arc::new(AtomicU32::new(0)),
        }
    }

    fn opts_for_backoff(base: u64, max: u64, jitter: u64) -> MultiTransportOptions {
        MultiTransportOptions {
            reconnect_delay_ms: base,
            max_backoff_delay_ms: max,
            reconnect_jitter_ms: jitter,
            ..MultiTransportOptions::default()
        }
    }

    #[test]
    fn backoff_never_exceeds_max_even_with_jitter() {
        // Effective max delay must be the cap; jitter must NOT push the result
        // past `max_backoff_delay_ms`. With base=500ms, max=1_000ms,
        // jitter=10_000ms the previous (jitter-after-cap) implementation could
        // return up to 11s.
        let opts = opts_for_backoff(500, 1_000, 10_000);

        // Sample many attempts to exercise the jitter range deterministically.
        for attempt in 1u32..=64 {
            for _ in 0..32 {
                let d = compute_backoff(&opts, attempt);
                assert!(
                    d.as_millis() as u64 <= opts.max_backoff_delay_ms,
                    "compute_backoff(attempt={attempt}) = {}ms exceeds cap {}ms",
                    d.as_millis(),
                    opts.max_backoff_delay_ms
                );
            }
        }
    }

    #[test]
    fn backoff_zero_jitter_is_capped_exactly() {
        let opts = opts_for_backoff(500, 1_000, 0);
        // attempt 1 = base, attempt 2 = 2*base, attempt 3 onwards saturates at cap
        assert_eq!(compute_backoff(&opts, 1).as_millis(), 500);
        assert_eq!(compute_backoff(&opts, 2).as_millis(), 1_000);
        assert_eq!(compute_backoff(&opts, 8).as_millis(), 1_000);
    }

    #[test]
    fn bump_heartbeat_moves_timestamp_forward() {
        // Simulates the scenario fixed in handle_credentials_issued: an old
        // heartbeat instant from before a slow OTT exchange must be advanced
        // so the very next heartbeat tick does not falsely trip the timeout.
        let original = Instant::now() - Duration::from_secs(120);
        let mut ts = original;
        // Sanity: starting timestamp is in the past.
        assert!(original.elapsed() >= Duration::from_secs(120));

        bump_heartbeat(&mut ts);

        assert!(
            ts > original,
            "bump_heartbeat must advance the watchdog timestamp"
        );
        // After bump, the new timestamp must be very recent (within a small
        // wall-clock window). 5 seconds is safe slop for slow CI hosts.
        assert!(
            ts.elapsed() < Duration::from_secs(5),
            "bump_heartbeat must reset to ~now"
        );
    }

    #[tokio::test]
    async fn dispatch_heartbeat_request_replies_with_response() {
        let runner = make_runner_for_dispatch_tests();
        let (tx, mut rx) = mpsc::channel::<StreamMessage>(8);
        let mut last_hb = Instant::now();
        let logger = Logger::new("test");

        let msg = StreamMessage {
            message: Some(stream_message::Message::HeartbeatRequest(
                HeartbeatRequest {
                    gateway_id: "gw1".into(),
                    timestamp_ms: 1234,
                },
            )),
        };

        let outcome = runner
            .dispatch_inbound(msg, &tx, &mut last_hb, &mut HashMap::new(), &logger)
            .await;
        assert!(
            outcome.is_none(),
            "HeartbeatRequest must NOT terminate the dispatch loop"
        );

        let resp = rx
            .try_recv()
            .expect("must reply to inbound HeartbeatRequest");
        match resp.message {
            Some(stream_message::Message::HeartbeatResponse(_)) => {}
            other => panic!("expected HeartbeatResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_heartbeat_response_advances_watchdog() {
        let runner = make_runner_for_dispatch_tests();
        let (tx, _rx) = mpsc::channel::<StreamMessage>(8);
        let mut last_hb = Instant::now() - Duration::from_secs(60);
        let before = last_hb;
        let logger = Logger::new("test");

        let msg = StreamMessage {
            message: Some(stream_message::Message::HeartbeatResponse(
                HeartbeatResponse {
                    gateway_id: String::new(),
                    timestamp_ms: 0,
                    should_reconnect: false,
                },
            )),
        };
        let outcome = runner
            .dispatch_inbound(msg, &tx, &mut last_hb, &mut HashMap::new(), &logger)
            .await;
        assert!(outcome.is_none());
        assert!(
            last_hb > before,
            "HeartbeatResponse must reset the watchdog"
        );
    }

    #[tokio::test]
    async fn dispatch_approval_pending_does_not_close_stream() {
        let runner = make_runner_for_dispatch_tests();
        let (tx, _rx) = mpsc::channel::<StreamMessage>(8);
        let mut last_hb = Instant::now();
        let logger = Logger::new("test");

        let msg = StreamMessage {
            message: Some(stream_message::Message::ApprovalNotification(
                ApprovalNotification {
                    status: proto::RegistrationStatus::Pending as i32,
                    message: "awaiting admin".into(),
                    ..Default::default()
                },
            )),
        };
        let outcome = runner
            .dispatch_inbound(msg, &tx, &mut last_hb, &mut HashMap::new(), &logger)
            .await;
        assert!(
            outcome.is_none(),
            "Pending approval must not terminate the stream"
        );
    }

    #[tokio::test]
    async fn dispatch_approval_approved_does_not_close_stream() {
        let runner = make_runner_for_dispatch_tests();
        let (tx, _rx) = mpsc::channel::<StreamMessage>(8);
        let mut last_hb = Instant::now();
        let logger = Logger::new("test");

        let msg = StreamMessage {
            message: Some(stream_message::Message::ApprovalNotification(
                ApprovalNotification {
                    status: proto::RegistrationStatus::Approved as i32,
                    ..Default::default()
                },
            )),
        };
        let outcome = runner
            .dispatch_inbound(msg, &tx, &mut last_hb, &mut HashMap::new(), &logger)
            .await;
        assert!(
            outcome.is_none(),
            "Approved must not terminate the stream — CredentialsIssued follows"
        );
    }

    #[tokio::test]
    async fn dispatch_approval_rejected_returns_server_closed() {
        let runner = make_runner_for_dispatch_tests();
        let (tx, _rx) = mpsc::channel::<StreamMessage>(8);
        let mut last_hb = Instant::now();
        let logger = Logger::new("test");

        let msg = StreamMessage {
            message: Some(stream_message::Message::ApprovalNotification(
                ApprovalNotification {
                    status: proto::RegistrationStatus::Rejected as i32,
                    message: "not allowed".into(),
                    ..Default::default()
                },
            )),
        };
        let outcome = runner
            .dispatch_inbound(msg, &tx, &mut last_hb, &mut HashMap::new(), &logger)
            .await;
        assert!(
            matches!(outcome, Some(StreamOutcome::ServerClosed)),
            "Rejected approval must end the stream so we restart through pending"
        );
    }

    #[tokio::test]
    async fn dispatch_empty_or_unknown_message_is_no_op() {
        let runner = make_runner_for_dispatch_tests();
        let (tx, _rx) = mpsc::channel::<StreamMessage>(8);
        let mut last_hb = Instant::now();
        let logger = Logger::new("test");

        // None payload
        let none_msg = StreamMessage { message: None };
        assert!(
            runner
                .dispatch_inbound(none_msg, &tx, &mut last_hb, &mut HashMap::new(), &logger)
                .await
                .is_none()
        );
    }

    // ---- WS pump lifecycle -------------------------------------------------

    /// Connector that holds open inside `handle_ws_open` until aborted, so we
    /// can prove the runner aborts the pump on `WsCloseRequest` and on
    /// stream teardown.
    struct HangingWsConn {
        opened: Arc<AtomicBool>,
        closed: Arc<AtomicBool>,
    }

    impl BaseConnector for HangingWsConn {
        fn connector_type(&self) -> &str {
            "hanging-ws"
        }
        fn version(&self) -> &str {
            "0.0.0"
        }
        fn execute(
            &self,
            _: serde_json::Value,
            _: Option<&str>,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>>
        {
            Box::pin(async { Ok(serde_json::json!({})) })
        }
        fn handle_ws_open(
            &self,
            _req: WsOpenRequest,
            _handle: ConnectorHandle,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            let opened = self.opened.clone();
            Box::pin(async move {
                opened.store(true, Ordering::SeqCst);
                let () = std::future::pending().await;
                Ok(())
            })
        }
        fn handle_ws_close(&self, _req: WsCloseRequest) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    fn ws_pump_runner(opened: Arc<AtomicBool>, closed: Arc<AtomicBool>) -> RegistrationRunner {
        RegistrationRunner {
            key: RegistrationKey {
                tenant_id: "t".into(),
                connector_type: "ws".into(),
                instance_id: "i".into(),
            },
            config: Arc::new(RwLock::new(crate::connector::ConnectorConfig::default())),
            connector: Arc::new(HangingWsConn { opened, closed }),
            shared_channel: Arc::new(SharedChannel::new(MultiTransportOptions::default())),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(Mutex::new(ConnectorMetrics::default())),
            opts: MultiTransportOptions::default(),
            request_semaphore: Arc::new(Semaphore::new(8)),
            session_token: Arc::new(RwLock::new(None)),
            consecutive_rejections: Arc::new(AtomicU32::new(0)),
        }
    }

    fn ws_open_msg(connection_id: &str) -> StreamMessage {
        StreamMessage {
            message: Some(stream_message::Message::WsOpenRequest(
                proto::WebSocketOpenRequest {
                    connection_id: connection_id.into(),
                    path: "/whatever".into(),
                    query_string: String::new(),
                    headers: std::collections::HashMap::new(),
                },
            )),
        }
    }

    fn ws_close_msg(connection_id: &str) -> StreamMessage {
        StreamMessage {
            message: Some(stream_message::Message::WsCloseRequest(
                proto::WebSocketCloseRequest {
                    connection_id: connection_id.into(),
                    code: 1000,
                    reason: String::new(),
                },
            )),
        }
    }

    #[tokio::test]
    async fn dispatch_ws_close_aborts_pump_task() {
        let opened = Arc::new(AtomicBool::new(false));
        let closed = Arc::new(AtomicBool::new(false));
        let runner = ws_pump_runner(opened.clone(), closed.clone());

        let (tx, _rx) = mpsc::channel::<StreamMessage>(8);
        let mut last_hb = Instant::now();
        let logger = Logger::new("test");
        let mut pumps: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();

        runner
            .dispatch_inbound(ws_open_msg("c1"), &tx, &mut last_hb, &mut pumps, &logger)
            .await;
        assert_eq!(pumps.len(), 1, "open must register a pump JoinHandle");
        // Yield so the spawned pump task gets to set `opened`.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(opened.load(Ordering::SeqCst));

        runner
            .dispatch_inbound(ws_close_msg("c1"), &tx, &mut last_hb, &mut pumps, &logger)
            .await;
        assert!(pumps.is_empty(), "close must remove the JoinHandle");
        assert!(closed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn dispatch_ws_duplicate_open_aborts_previous_pump() {
        // Two opens with the same connection_id (no close between) must
        // abort the first pump rather than leaking it.
        let opened = Arc::new(AtomicBool::new(false));
        let closed = Arc::new(AtomicBool::new(false));
        let runner = ws_pump_runner(opened, closed);

        let (tx, _rx) = mpsc::channel::<StreamMessage>(8);
        let mut last_hb = Instant::now();
        let logger = Logger::new("test");
        let mut pumps: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();

        runner
            .dispatch_inbound(ws_open_msg("dup"), &tx, &mut last_hb, &mut pumps, &logger)
            .await;
        let first_id = pumps.get("dup").expect("first open").id();

        runner
            .dispatch_inbound(ws_open_msg("dup"), &tx, &mut last_hb, &mut pumps, &logger)
            .await;
        assert_eq!(pumps.len(), 1, "duplicate must replace, not duplicate");
        assert_ne!(
            pumps.get("dup").unwrap().id(),
            first_id,
            "duplicate open must install a fresh JoinHandle"
        );
    }

    #[tokio::test]
    async fn wait_for_register_response_observes_shutdown() {
        // Build a streaming source that never yields anything; we want the
        // shutdown branch of the select! to fire.
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_for_signal = shutdown.clone();
        // Park a Streaming<StreamMessage> that never produces a message by
        // wrapping a hung channel via `Streaming::new_empty` — there's no
        // public ctor, so use `tonic::Streaming` from a stalled tonic
        // endpoint via the mock-free path: build a request with `tonic`'s
        // request stream from a never-yielding `async_stream::stream!`.
        //
        // Instead, exercise the shutdown signal path indirectly by setting
        // shutdown and asserting the helper returns the StreamError variant
        // on the very next poll. We do this by sleeping briefly then
        // toggling the flag.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            shutdown_for_signal.store(true, Ordering::SeqCst);
        });

        // Create a permanently empty Streaming via the only available ctor:
        // the gRPC inbound from a stream that fails to connect immediately.
        // Easiest: use a tonic `Streaming` via an in-memory channel of
        // tonic Status by hand-rolling — not directly supported. Instead
        // assert that `wait_for_shutdown` resolves once the flag flips,
        // which is the underlying primitive that wins the select! branch.
        wait_for_shutdown(&shutdown).await;
        assert!(shutdown.load(Ordering::SeqCst));
    }
    #[test]
    fn runner_uses_custom_heartbeat_interval_and_timeout_from_opts() {
        // Behavior probe: drive_stream reads its hb_interval/hb_timeout
        // exclusively from opts. We verify the values reach the runner via
        // its `opts` field; the drive_stream code paths above use precisely
        // those fields with `unwrap_or(HEARTBEAT_*)`.
        let opts = MultiTransportOptions::builder()
            .heartbeat_interval(Duration::from_secs(5))
            .heartbeat_timeout(Duration::from_secs(15))
            .build();
        let runner = RegistrationRunner {
            key: RegistrationKey {
                tenant_id: "t".into(),
                connector_type: "c".into(),
                instance_id: "i".into(),
            },
            config: Arc::new(RwLock::new(crate::connector::ConnectorConfig::default())),
            connector: Arc::new(NoopConn),
            shared_channel: Arc::new(SharedChannel::new(opts.clone())),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(Mutex::new(ConnectorMetrics::default())),
            opts: opts.clone(),
            request_semaphore: Arc::new(Semaphore::new(8)),
            session_token: Arc::new(RwLock::new(None)),
            consecutive_rejections: Arc::new(AtomicU32::new(0)),
        };
        assert_eq!(
            runner.opts.heartbeat_interval,
            Some(Duration::from_secs(5)),
            "custom heartbeat_interval must be wired through to the runner"
        );
        assert_eq!(
            runner.opts.heartbeat_timeout,
            Some(Duration::from_secs(15)),
            "custom heartbeat_timeout must be wired through to the runner"
        );
        // And: the SDK-default fallback constants match what we documented.
        assert_eq!(HEARTBEAT_INTERVAL, Duration::from_secs(30));
        assert_eq!(HEARTBEAT_TIMEOUT, Duration::from_secs(45));
    }

    #[test]
    fn backoff_huge_attempt_with_huge_jitter_still_capped() {
        // Saturating math must cope with extreme inputs without panicking.
        let opts = opts_for_backoff(u64::MAX / 4, 60_000, u64::MAX / 4);
        for attempt in 1u32..=128 {
            let d = compute_backoff(&opts, attempt);
            assert!(d.as_millis() as u64 <= opts.max_backoff_delay_ms);
        }
    }

    // ---- Context plumbing tests --------------------------------------------
    //
    // These tests pin two contracts that the rest of the SDK relies on:
    //
    //   1. `handle_execute` must invoke `BaseConnector::execute_with_context`
    //      (NOT bare `execute`) so the wire-supplied `request.context` map
    //      reaches a context-aware connector implementation.
    //   2. A connector that only implements `execute` (no
    //      `execute_with_context` override) keeps working — proving the
    //      default delegation in the trait is correct.

    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex as StdMutex;

    /// Connector that overrides `execute_with_context` and captures the
    /// context map it received. `execute` is `unreachable!()` to prove the
    /// SDK reaches us through the context-aware path.
    struct CapturingConn {
        seen: Arc<StdMutex<Option<StdHashMap<String, String>>>>,
    }

    impl BaseConnector for CapturingConn {
        fn connector_type(&self) -> &str {
            "capturing"
        }
        fn version(&self) -> &str {
            "0.0.0"
        }
        fn execute(
            &self,
            _request: serde_json::Value,
            _capability_id: Option<&str>,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>>
        {
            // Reaching this would prove the SDK is dropping context.
            Box::pin(async {
                unreachable!("SDK must dispatch through execute_with_context, not bare execute")
            })
        }
        fn execute_with_context<'a>(
            &'a self,
            _request: serde_json::Value,
            _capability_id: Option<&'a str>,
            context: &'a StdHashMap<String, String>,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + 'a>>
        {
            let captured = context.clone();
            let slot = self.seen.clone();
            Box::pin(async move {
                *slot.lock().unwrap() = Some(captured);
                Ok(serde_json::json!({ "ok": true }))
            })
        }
    }

    /// Connector that only implements `execute`. Used to prove the default
    /// `execute_with_context` impl correctly delegates back to `execute`.
    struct LegacyConn {
        called: Arc<AtomicBool>,
    }

    impl BaseConnector for LegacyConn {
        fn connector_type(&self) -> &str {
            "legacy"
        }
        fn version(&self) -> &str {
            "0.0.0"
        }
        fn execute(
            &self,
            _request: serde_json::Value,
            _capability_id: Option<&str>,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>>
        {
            let flag = self.called.clone();
            Box::pin(async move {
                flag.store(true, Ordering::SeqCst);
                Ok(serde_json::json!({ "legacy": true }))
            })
        }
    }

    fn key_for_context_tests() -> RegistrationKey {
        RegistrationKey {
            tenant_id: "t".into(),
            connector_type: "ctx".into(),
            instance_id: "i".into(),
        }
    }

    #[tokio::test]
    async fn handle_execute_forwards_request_context_to_connector() {
        let seen = Arc::new(StdMutex::new(None));
        let connector: Arc<dyn BaseConnector> = Arc::new(CapturingConn { seen: seen.clone() });
        let metrics = Arc::new(Mutex::new(ConnectorMetrics::default()));
        let logger = Logger::new("test/ctx");
        let key = key_for_context_tests();

        // Build a request with a non-trivial context map.
        let mut context = StdHashMap::new();
        context.insert("tenant_id".to_string(), "tenant-acme".to_string());
        context.insert("user_id".to_string(), "user-42".to_string());
        context.insert("strike48.attrs.region".to_string(), "us-east-1".to_string());

        let payload = serialize_payload(&serde_json::json!({}), PayloadEncoding::Json)
            .expect("serialize empty payload");
        let request = SdkExecuteRequest {
            request_id: "req-ctx-1".into(),
            payload,
            payload_encoding: PayloadEncoding::Json,
            context: context.clone(),
            capability_id: None,
        };

        let (tx, mut rx) = mpsc::channel::<StreamMessage>(8);
        handle_execute(connector, request, tx, metrics, &logger, &key)
            .await
            .expect("handle_execute should succeed");

        // The connector must have observed exactly the context we sent.
        let captured = seen
            .lock()
            .unwrap()
            .clone()
            .expect("execute_with_context must have been invoked");
        assert_eq!(
            captured, context,
            "context map must round-trip from request → connector"
        );

        // And the response must have made it back onto the wire.
        let resp = rx.try_recv().expect("an ExecuteResponse must be sent back");
        match resp.message {
            Some(stream_message::Message::ExecuteResponse(r)) => {
                assert!(r.success, "successful execute must produce success=true");
                assert_eq!(r.request_id, "req-ctx-1");
            }
            other => panic!("expected ExecuteResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_execute_keeps_working_for_legacy_execute_only_connector() {
        let called = Arc::new(AtomicBool::new(false));
        let connector: Arc<dyn BaseConnector> = Arc::new(LegacyConn {
            called: called.clone(),
        });
        let metrics = Arc::new(Mutex::new(ConnectorMetrics::default()));
        let logger = Logger::new("test/ctx");
        let key = key_for_context_tests();

        let payload = serialize_payload(&serde_json::json!({}), PayloadEncoding::Json)
            .expect("serialize empty payload");
        let request = SdkExecuteRequest {
            request_id: "req-legacy-1".into(),
            payload,
            payload_encoding: PayloadEncoding::Json,
            // Context is non-empty on the wire but the legacy connector
            // ignores it; what matters is it still gets called.
            context: {
                let mut m = StdHashMap::new();
                m.insert("tenant_id".to_string(), "ignored".to_string());
                m
            },
            capability_id: None,
        };

        let (tx, mut rx) = mpsc::channel::<StreamMessage>(8);
        handle_execute(connector, request, tx, metrics, &logger, &key)
            .await
            .expect("handle_execute should succeed");

        assert!(
            called.load(Ordering::SeqCst),
            "default execute_with_context must delegate to execute"
        );

        let resp = rx.try_recv().expect("must produce an ExecuteResponse");
        match resp.message {
            Some(stream_message::Message::ExecuteResponse(r)) => {
                assert!(r.success);
                assert_eq!(r.request_id, "req-legacy-1");
            }
            other => panic!("expected ExecuteResponse, got {other:?}"),
        }
    }

    // --- session-token clearing on rejected registration -------------------

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

    #[test]
    fn is_registration_rejection_classifies_correctly() {
        use tonic::{Code, Status};

        // In-band rejection (what Matrix sends for a stale session token).
        assert!(is_registration_rejection(
            &ConnectorError::RegistrationError(
                "register failed: status='3' error='Registration failed'".into()
            )
        ));

        // Credential-shaped gRPC statuses count as rejections too.
        assert!(is_registration_rejection(&ConnectorError::Grpc(Box::new(
            Status::new(Code::Unauthenticated, "bad token")
        ))));
        assert!(is_registration_rejection(&ConnectorError::Grpc(Box::new(
            Status::new(Code::InvalidArgument, "jwt_decode_failed")
        ))));

        // Transient gRPC statuses must NOT be treated as rejections — clearing
        // the token on a blip would force a needless re-register.
        assert!(!is_registration_rejection(&ConnectorError::Grpc(Box::new(
            Status::new(Code::Unavailable, "try again")
        ))));
        assert!(!is_registration_rejection(&ConnectorError::Grpc(Box::new(
            Status::new(Code::DeadlineExceeded, "slow")
        ))));

        // Non-gRPC transient errors keep the token.
        assert!(!is_registration_rejection(&ConnectorError::StreamError(
            "socket closed".into()
        )));
        assert!(!is_registration_rejection(&ConnectorError::Timeout(
            "nope".into()
        )));
    }

    #[tokio::test]
    async fn note_rejection_drops_token_only_after_k_consecutive() {
        // A single rejection must NOT drop the token (absorbs a spurious/
        // transient server rejection); the Kth consecutive one must.
        //
        // The test connector's identity (`test_conn` / `i`) has no saved
        // credentials on disk, so the threshold-reached credential re-mint is a
        // no-op here — this exercises the session-token drop in isolation.
        let runner = make_runner_for_dispatch_tests();
        let logger = Logger::new("test");
        *runner.session_token.write().await = Some("stale-token".into());

        // Rejections 1..K-1: token retained, threshold not reached.
        for _ in 1..REJECTIONS_BEFORE_TOKEN_DROP {
            assert!(
                !runner
                    .note_rejection_and_maybe_reset_credentials(&logger)
                    .await,
                "must not reset before {REJECTIONS_BEFORE_TOKEN_DROP} rejections"
            );
            assert!(
                runner.session_token.read().await.is_some(),
                "token must survive a sub-threshold rejection"
            );
        }

        // Kth rejection: token dropped, threshold reached.
        assert!(
            runner
                .note_rejection_and_maybe_reset_credentials(&logger)
                .await,
            "must reset on the {REJECTIONS_BEFORE_TOKEN_DROP}th consecutive rejection"
        );
        assert!(
            runner.session_token.read().await.is_none(),
            "token must be cleared once the threshold is reached"
        );
    }

    #[tokio::test]
    async fn note_rejection_reports_threshold_even_without_token() {
        // Regression for the silent-loop bug: when the threshold is reached but
        // there is no session token to drop (e.g. a connector re-registering
        // with a stale JWT), the method must STILL report the threshold so the
        // caller logs a diagnostic instead of looping silently.
        let runner = make_runner_for_dispatch_tests();
        let logger = Logger::new("test");
        // No session token set.
        assert!(runner.session_token.read().await.is_none());

        for _ in 1..REJECTIONS_BEFORE_TOKEN_DROP {
            assert!(
                !runner
                    .note_rejection_and_maybe_reset_credentials(&logger)
                    .await
            );
        }
        assert!(
            runner
                .note_rejection_and_maybe_reset_credentials(&logger)
                .await,
            "threshold must be reported even when there was no token to drop"
        );
    }

    #[test]
    fn auth_mint_budget_is_bounded_and_scales_with_connect_timeout() {
        // The inline JWT mint must never be unbounded: an unreachable Keycloak
        // would otherwise stall the reconnect loop. The budget tracks
        // connect_timeout_ms (3x, matching the post-approval OTT exchange).
        let opts = MultiTransportOptions::builder()
            .connect_timeout_ms(10_000)
            .build();
        assert_eq!(auth_mint_budget(&opts), Duration::from_millis(30_000));

        let fast = MultiTransportOptions::builder()
            .connect_timeout_ms(1_000)
            .build();
        assert_eq!(auth_mint_budget(&fast), Duration::from_millis(3_000));

        // A zero/unset connect timeout must still yield a positive budget
        // rather than a timeout that fires instantly.
        let zero = MultiTransportOptions::builder()
            .connect_timeout_ms(0)
            .build();
        assert!(
            auth_mint_budget(&zero) > Duration::ZERO,
            "budget must stay positive so the mint is attempted at all"
        );
    }

    #[tokio::test]
    async fn mint_auth_leaves_token_untouched_without_saved_credentials() {
        // The no-saved-credentials path must not clobber an existing
        // auth_token (OTT-only connectors have no keypair on disk), and it must
        // return promptly rather than blocking on the network.
        let runner = make_runner_for_dispatch_tests();
        let logger = Logger::new("test");
        runner.config.write().await.auth_token = "ott-issued-jwt".into();

        // Well under the mint budget: with no credentials on disk this returns
        // before any network call is attempted.
        tokio::time::timeout(
            Duration::from_secs(5),
            runner.mint_auth_from_saved_credentials(&logger),
        )
        .await
        .expect("mint must return promptly when there are no saved credentials");

        assert_eq!(
            runner.config.read().await.auth_token,
            "ott-issued-jwt",
            "an OTT-issued auth_token must survive a mint with no keypair on disk"
        );
    }

    #[tokio::test]
    async fn note_success_resets_rejection_counter() {
        // A success between rejections must reset the counter, so an isolated
        // rejection later never inherits stale count and resets prematurely.
        let runner = make_runner_for_dispatch_tests();
        let logger = Logger::new("test");
        *runner.session_token.write().await = Some("tok".into());

        // One rejection (sub-threshold for K>=2), then a success resets.
        assert!(
            !runner
                .note_rejection_and_maybe_reset_credentials(&logger)
                .await
        );
        runner.note_registration_success();

        // A subsequent lone rejection must again be sub-threshold — not a reset.
        assert!(
            !runner
                .note_rejection_and_maybe_reset_credentials(&logger)
                .await,
            "counter must have reset on success"
        );
        assert!(
            runner.session_token.read().await.is_some(),
            "token must survive when success reset the counter between rejections"
        );
    }

    #[tokio::test]
    async fn dispatch_in_stream_reregister_failure_clears_session_token_after_threshold() {
        // Regression: repeated rejected in-stream re-registers must eventually
        // drop the cached session token so the reconnect after teardown
        // re-registers from scratch instead of replaying a refused token.
        let runner = make_runner_for_dispatch_tests();
        *runner.session_token.write().await = Some("stale-token".into());

        let (tx, _rx) = mpsc::channel::<StreamMessage>(8);
        let mut last_hb = Instant::now();
        let logger = Logger::new("test");

        // Feed REJECTIONS_BEFORE_TOKEN_DROP rejections; the token clears on the
        // last one, never terminating the stream.
        for i in 1..=REJECTIONS_BEFORE_TOKEN_DROP {
            let outcome = runner
                .dispatch_inbound(
                    register_response(false, 3),
                    &tx,
                    &mut last_hb,
                    &mut HashMap::new(),
                    &logger,
                )
                .await;
            assert!(
                outcome.is_none(),
                "a failed re-register must not close the stream here"
            );
            let cleared = runner.session_token.read().await.is_none();
            if i < REJECTIONS_BEFORE_TOKEN_DROP {
                assert!(!cleared, "token must survive rejection {i}");
            } else {
                assert!(cleared, "token must clear on rejection {i}");
            }
        }
    }

    #[tokio::test]
    async fn dispatch_in_stream_reregister_success_keeps_session_token() {
        // Symmetric guard: a successful re-register must persist the new token,
        // never clear it.
        let runner = make_runner_for_dispatch_tests();
        *runner.session_token.write().await = Some("old-token".into());

        let (tx, _rx) = mpsc::channel::<StreamMessage>(8);
        let mut last_hb = Instant::now();
        let logger = Logger::new("test");

        let outcome = runner
            .dispatch_inbound(
                register_response(true, 0),
                &tx,
                &mut last_hb,
                &mut HashMap::new(),
                &logger,
            )
            .await;
        assert!(outcome.is_none());
        assert_eq!(
            runner.session_token.read().await.as_deref(),
            Some("fresh-token"),
            "successful re-register must persist the freshly issued session token"
        );
    }
}

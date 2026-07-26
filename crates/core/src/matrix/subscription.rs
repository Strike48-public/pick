//! Async WebSocket transport for the Absinthe `conversationEvents` subscription.
//!
//! This module owns the live socket lifecycle: connect, Phoenix join, GraphQL
//! subscribe, periodic heartbeat, and reconnect-with-backoff. It consumes the
//! pure protocol helpers in [`crate::matrix::phoenix_sub`] and emits a typed
//! event stream plus a connection-state watch channel.

use std::sync::Arc;
use std::time::Duration;

use futures::{Sink, SinkExt, Stream, StreamExt};
use serde_json::Value;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::matrix::phoenix_sub::{
    build_ws_url, create_heartbeat, create_join, create_subscription, extract_event, parse_event,
    ConversationStreamEvent,
};

type WsError = tokio_tungstenite::tungstenite::Error;

/// Heartbeat cadence. Phoenix drops idle sockets; keep it well under the
/// server timeout.
const HEARTBEAT_INTERVAL_SECS: u64 = 25;
/// Upper bound on a single connect attempt, and on the wait for each
/// `phx_reply` ok, so a silent server can never hang the supervisor.
const CONNECT_TIMEOUT_SECS: u64 = 10;
/// Maximum frames to read while waiting for a specific `phx_reply` before
/// giving up (belt-and-suspenders alongside the timeout).
const MAX_REPLY_READS: usize = 20;
/// After this many consecutive failed connects (never reached `Live`), surface
/// [`ConnectionState::Failed`] while continuing to retry at the backoff cap.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;
/// Backoff cap in milliseconds.
const BACKOFF_CAP_MS: u64 = 5000;

/// Connection lifecycle, mirrored to the consumer via a watch channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// A connect attempt is in progress and we have not yet subscribed.
    Connecting,
    /// Joined + subscribed; events are flowing.
    Live,
    /// The socket dropped; a reconnect is scheduled.
    Reconnecting,
    /// Too many consecutive failed connects. Still retrying under the hood.
    Failed,
}

/// Exponential backoff with a fixed cap: 500, 1000, 2000, 4000, 5000 (cap) ms.
struct Backoff {
    step: u32,
}

impl Backoff {
    fn new() -> Self {
        Self { step: 0 }
    }

    fn next_delay_ms(&mut self) -> u64 {
        let delay = match self.step {
            0 => 500,
            1 => 1000,
            2 => 2000,
            3 => 4000,
            _ => BACKOFF_CAP_MS,
        };
        self.step = self.step.saturating_add(1);
        delay
    }

    fn reset(&mut self) {
        self.step = 0;
    }
}

/// A [`JoinHandle`] that aborts its task when dropped, so switching
/// conversations tears the socket down deterministically.
pub struct AbortOnDrop(pub JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Handle to a live conversation subscription.
pub struct ConversationSubscription {
    /// Typed events as they arrive. Dropping this receiver tears the socket down.
    pub events: mpsc::UnboundedReceiver<ConversationStreamEvent>,
    /// Current connection state.
    pub state: watch::Receiver<ConnectionState>,
    /// Aborts the supervisor task on drop.
    pub _handle: AbortOnDrop,
}

/// Outcome of a single connect-and-run cycle, used to drive backoff.
enum ConnectOutcome {
    /// The events receiver was dropped; the supervisor should exit.
    ConsumerGone,
    /// The connect/join/subscribe handshake never reached `Live`.
    FailedBeforeLive,
    /// We were `Live` and then the socket dropped.
    DisconnectedAfterLive,
}

/// Subscribe to the `conversationEvents` stream for `conversation_id`.
///
/// `token_fn` is invoked on every (re)connect so each attempt uses a fresh
/// auth token. `insecure_tls` maps to `danger_accept_invalid_certs` on the
/// native-tls connector (dev clusters with self-signed chains only).
pub fn subscribe_conversation(
    api_url: String,
    conversation_id: String,
    insecure_tls: bool,
    token_fn: Arc<dyn Fn() -> String + Send + Sync>,
) -> ConversationSubscription {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (state_tx, state_rx) = watch::channel(ConnectionState::Connecting);

    let handle = tokio::spawn(supervisor(
        api_url,
        conversation_id,
        insecure_tls,
        token_fn,
        event_tx,
        state_tx,
    ));

    ConversationSubscription {
        events: event_rx,
        state: state_rx,
        _handle: AbortOnDrop(handle),
    }
}

/// Supervisor loop: connect, run until the socket drops, back off, repeat.
async fn supervisor(
    api_url: String,
    conversation_id: String,
    insecure_tls: bool,
    token_fn: Arc<dyn Fn() -> String + Send + Sync>,
    event_tx: mpsc::UnboundedSender<ConversationStreamEvent>,
    state_tx: watch::Sender<ConnectionState>,
) {
    let mut backoff = Backoff::new();
    let mut consecutive_failures: u32 = 0;
    let mut ref_counter: u64 = 0;

    loop {
        if event_tx.is_closed() {
            return;
        }

        // Reflect the attempt about to happen.
        let attempt_state = if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            ConnectionState::Failed
        } else if consecutive_failures == 0 {
            ConnectionState::Connecting
        } else {
            ConnectionState::Reconnecting
        };
        let _ = state_tx.send(attempt_state);

        let outcome = connect_and_run(
            &api_url,
            &conversation_id,
            insecure_tls,
            &token_fn,
            &event_tx,
            &state_tx,
            &mut ref_counter,
        )
        .await;

        let delay_ms = match outcome {
            ConnectOutcome::ConsumerGone => return,
            ConnectOutcome::DisconnectedAfterLive => {
                // A healthy connection dropped: reset failure tracking and
                // reconnect quickly.
                consecutive_failures = 0;
                backoff.reset();
                let _ = state_tx.send(ConnectionState::Reconnecting);
                backoff.next_delay_ms()
            }
            ConnectOutcome::FailedBeforeLive => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    let _ = state_tx.send(ConnectionState::Failed);
                    BACKOFF_CAP_MS
                } else {
                    let _ = state_tx.send(ConnectionState::Reconnecting);
                    backoff.next_delay_ms()
                }
            }
        };

        // Sleep before reconnecting, but bail out immediately if the consumer
        // has gone away.
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
            _ = event_tx.closed() => return,
        }
    }
}

/// Connect, join, subscribe, then pump the socket until it drops.
async fn connect_and_run(
    api_url: &str,
    conversation_id: &str,
    insecure_tls: bool,
    token_fn: &Arc<dyn Fn() -> String + Send + Sync>,
    event_tx: &mpsc::UnboundedSender<ConversationStreamEvent>,
    state_tx: &watch::Sender<ConnectionState>,
    ref_counter: &mut u64,
) -> ConnectOutcome {
    let token = token_fn();
    let url = build_ws_url(api_url, &token);

    let connector = match native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(insecure_tls)
        .build()
    {
        Ok(tls) => tokio_tungstenite::Connector::NativeTls(tls),
        Err(e) => {
            tracing::warn!("subscription: failed to build TLS connector: {e}");
            return ConnectOutcome::FailedBeforeLive;
        }
    };

    let connect_fut =
        tokio_tungstenite::connect_async_tls_with_config(&url, None, false, Some(connector));
    let ws = match tokio::time::timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS), connect_fut).await
    {
        Ok(Ok((ws, _resp))) => ws,
        Ok(Err(e)) => {
            tracing::warn!("subscription: connect error: {e}");
            return ConnectOutcome::FailedBeforeLive;
        }
        Err(_) => {
            tracing::warn!("subscription: connect timed out");
            return ConnectOutcome::FailedBeforeLive;
        }
    };

    let (mut write, mut read) = ws.split();

    // Phoenix join on the Absinthe control topic.
    *ref_counter += 1;
    let join_ref = ref_counter.to_string();
    if let Err(e) = send_json(&mut write, &create_join(&join_ref)).await {
        tracing::warn!("subscription: join send failed: {e}");
        return ConnectOutcome::FailedBeforeLive;
    }
    if !await_reply_ok(&mut read, &join_ref).await {
        tracing::warn!("subscription: join was not acknowledged");
        return ConnectOutcome::FailedBeforeLive;
    }

    // GraphQL subscribe as a `doc` frame.
    *ref_counter += 1;
    let sub_ref = ref_counter.to_string();
    if let Err(e) = send_json(&mut write, &create_subscription(conversation_id, &sub_ref)).await {
        tracing::warn!("subscription: subscribe send failed: {e}");
        return ConnectOutcome::FailedBeforeLive;
    }
    if !await_reply_ok(&mut read, &sub_ref).await {
        tracing::warn!("subscription: subscribe was not acknowledged");
        return ConnectOutcome::FailedBeforeLive;
    }

    let _ = state_tx.send(ConnectionState::Live);

    // Single-task pump: read frames and fire heartbeats on the same loop so we
    // never contend for the write half across tasks.
    let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
    // Skip the immediate first tick so the first heartbeat lands one interval out.
    heartbeat.tick().await;

    loop {
        tokio::select! {
            maybe_msg = read.next() => {
                match maybe_msg {
                    Some(Ok(WsMessage::Text(text))) => {
                        match serde_json::from_str::<Value>(&text) {
                            Ok(value) => {
                                if let Some(raw_event) = extract_event(&value) {
                                    let event = parse_event(&raw_event);
                                    if event_tx.send(event).is_err() {
                                        return ConnectOutcome::ConsumerGone;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::debug!("subscription: skipping undecodable frame: {e}");
                            }
                        }
                    }
                    Some(Ok(WsMessage::Close(_))) => {
                        tracing::info!("subscription: server closed the socket");
                        return ConnectOutcome::DisconnectedAfterLive;
                    }
                    // Ping/Pong/Binary/Frame: nothing to forward.
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        tracing::warn!("subscription: read error: {e}");
                        return ConnectOutcome::DisconnectedAfterLive;
                    }
                    None => {
                        tracing::info!("subscription: stream ended");
                        return ConnectOutcome::DisconnectedAfterLive;
                    }
                }
            }
            _ = heartbeat.tick() => {
                *ref_counter += 1;
                let hb_ref = ref_counter.to_string();
                if let Err(e) = send_json(&mut write, &create_heartbeat(&hb_ref)).await {
                    tracing::warn!("subscription: heartbeat send failed: {e}");
                    return ConnectOutcome::DisconnectedAfterLive;
                }
            }
        }
    }
}

/// Serialize `value` to a text frame and send it.
async fn send_json<S>(write: &mut S, value: &Value) -> Result<(), WsError>
where
    S: Sink<WsMessage, Error = WsError> + Unpin,
{
    let text = serde_json::to_string(value).unwrap_or_default();
    write.send(WsMessage::Text(text.into())).await
}

/// Read frames until a `phx_reply` with `expected_ref` arrives, returning
/// whether its status is `ok`. Bounded by both a read count and an overall
/// timeout so a silent or chatty server cannot hang the handshake.
async fn await_reply_ok<S>(read: &mut S, expected_ref: &str) -> bool
where
    S: Stream<Item = Result<WsMessage, WsError>> + Unpin,
{
    let wait = async {
        let mut attempts = 0usize;
        while attempts < MAX_REPLY_READS {
            attempts += 1;
            match read.next().await {
                Some(Ok(WsMessage::Text(text))) => {
                    let Ok(value) = serde_json::from_str::<Value>(&text) else {
                        continue;
                    };
                    if value.get("event").and_then(Value::as_str) != Some("phx_reply") {
                        continue;
                    }
                    // Match the ref when present; tolerate servers that omit it.
                    let ref_matches = value
                        .get("ref")
                        .and_then(Value::as_str)
                        .map(|r| r == expected_ref)
                        .unwrap_or(true);
                    if !ref_matches {
                        continue;
                    }
                    let status = value
                        .get("payload")
                        .and_then(|p| p.get("status"))
                        .and_then(Value::as_str);
                    return status == Some("ok");
                }
                Some(Ok(WsMessage::Close(_))) | None => return false,
                Some(Err(_)) => return false,
                // Ignore ping/pong/binary while waiting.
                Some(Ok(_)) => continue,
            }
        }
        false
    };

    tokio::time::timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS), wait)
        .await
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_sequence_caps() {
        let mut b = Backoff::new();
        let ds: Vec<u64> = (0..6).map(|_| b.next_delay_ms()).collect();
        assert_eq!(ds[0], 500);
        assert!(ds.iter().all(|d| *d <= 5000));
        assert!(ds[5] == 5000); // capped
    }
}

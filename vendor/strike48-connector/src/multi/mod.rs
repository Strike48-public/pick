//! Multi-registration connector runner.
//!
//! Lets one host process register `N` independently-approvable connectors
//! against a single Matrix server while sharing the underlying transport:
//!
//! - **gRPC**: one TCP+TLS connection, N HTTP/2 streams (one per registration).
//!   Lazily opens additional channels when `max_streams_per_channel` is hit.
//! - **WebSocket**: one TCP+TLS connection per tenant, all registrations on
//!   that tenant share a single Phoenix `connector:lobby` channel. Inbound
//!   `execute_request` / `invoke_request` frames are demuxed by the
//!   `context["connector_arn"]` the server stamps on them; outbound
//!   responses correlate by `request_id`. Cross-tenant registrations always
//!   land on separate sockets — that is a hard isolation boundary.
//!
//! From the Matrix server's point of view, each registration is a normal
//! `Connect` RPC. There are zero server-side changes.
//!
//! ## Reconnect behaviour
//!
//! The runner has two layers of reconnect, owned by different actors:
//!
//! - **Stream-level (per registration)**: implemented in the internal
//!   `registration_runner` module. When a stream ends (server closes, network
//!   blip, heartbeat timeout) the runner sleeps with exponential backoff +
//!   jitter (caps at `MultiTransportOptions::reconnect_max_delay_ms`) and
//!   opens a fresh stream over the existing channel. Fully shutdown-aware
//!   — never blocks shutdown for more than one backoff slice. Each
//!   reconnect bumps the registration's `successful_reconnects` /
//!   `total_disconnects` metrics.
//!
//! - **Channel-level (per HTTP/2 connection, gRPC only)**: delegated to
//!   `tonic::transport::Channel`. The channel is configured with HTTP/2
//!   keepalive and dialled **eagerly** via `endpoint.connect().await` the
//!   first time a registration needs it. tonic auto-recovers on transient
//!   TCP / TLS failures by re-dialing internally on the next request; the
//!   SDK does **not** explicitly recreate channels today.
//!
//!   In practice this means: if the underlying TCP connection breaks, all
//!   N registrations using that channel will see their streams close. The
//!   per-registration loop opens a fresh stream, which in turn forces the
//!   channel to redial. End state: connections recover transparently
//!   without involvement from this module.
//!
//!   If a channel ever goes **permanently dead** (e.g. DNS now points to
//!   an unreachable host and the lazy redial keeps failing), every
//!   registration on that channel will spend its time backing off. The
//!   [`MultiConnectorRunner::shutdown_handle`] still works, but recovery
//!   for the current process is best-effort. A future improvement would
//!   be to track per-channel consecutive-failure counts and rebuild the
//!   channel after a threshold; tracked under
//!   `connector-sdk-rust-channel-reconnect-policy`.
//!
//! ## Backward compatibility
//!
//! This module is **purely additive**. The existing single-registration
//! [`crate::ConnectorRunner`] API and behaviour are unchanged.
//!
//! ## Example
//!
//! ```no_run
//! # async fn run() -> strike48_connector::Result<()> {
//! use std::sync::Arc;
//! use strike48_connector::{
//!     BaseConnector, ConnectorConfig, ConnectorRegistration, MultiConnectorRunner,
//!     MultiTransportOptions, Result, TransportType,
//! };
//!
//! struct Echo;
//! impl BaseConnector for Echo {
//!     fn connector_type(&self) -> &str { "echo" }
//!     fn version(&self) -> &str { "1.0.0" }
//!     fn execute(
//!         &self,
//!         req: serde_json::Value,
//!         _: Option<&str>,
//!     ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>> {
//!         Box::pin(async move { Ok(req) })
//!     }
//! }
//!
//! let opts = MultiTransportOptions::builder()
//!     .host("localhost:50061")
//!     .transport_type(TransportType::Grpc)
//!     .build();
//!
//! let registrations = (0..3).map(|i| {
//!     ConnectorRegistration::new(
//!         ConnectorConfig {
//!             tenant_id: "demo-org".into(),
//!             connector_type: "echo".into(),
//!             instance_id: format!("echo-{i}"),
//!             ..ConnectorConfig::default()
//!         },
//!         Echo,
//!     )
//! }).collect::<Vec<_>>();
//!
//! let runner = MultiConnectorRunner::new(opts, registrations);
//! let _shutdown = runner.shutdown_handle();
//! runner.run().await?;
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use tokio::sync::{Mutex, RwLock, Semaphore};

use crate::connector::{BaseConnector, ConnectorConfig, ShutdownHandle};
use crate::error::{ConnectorError, Result};
use crate::logger::Logger;
use crate::transport::TransportType;
use crate::types::ConnectorMetrics;

mod registration_runner;
mod shared_channel;
mod ws_multiplex;

use registration_runner::RegistrationRunner;
use shared_channel::SharedChannel;
use ws_multiplex::{WsMultiplexDriver, WsMultiplexEntry};

// =============================================================================
// Public types
// =============================================================================

/// Transport-level configuration shared by every registration in a
/// [`MultiConnectorRunner`]. Per-registration identity (tenant, type, instance,
/// auth token, ...) lives on each [`ConnectorRegistration`]'s [`ConnectorConfig`].
///
/// Marked `#[non_exhaustive]` so future fields can be added without breaking
/// downstream struct-literal construction. Use
/// [`MultiTransportOptions::builder`] (preferred) or
/// `MultiTransportOptions { ..MultiTransportOptions::default() }`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MultiTransportOptions {
    /// Server host:port (e.g. `localhost:50061` for gRPC, `localhost:4000` for WS).
    pub host: String,
    /// Whether to use TLS for the transport.
    pub use_tls: bool,
    /// Transport scheme.
    pub transport_type: TransportType,

    /// Soft cap on concurrent gRPC streams per channel before the runner
    /// opens an additional channel. Defaults to `80` to leave headroom under
    /// the typical Cowboy/RFC 7540 default of 100. Ignored for WebSocket.
    pub max_streams_per_channel: usize,

    /// Initial connect timeout (ms). Default 10_000.
    pub connect_timeout_ms: u64,

    /// Enable channel-level reconnect on transport failure. Default `true`.
    pub reconnect_enabled: bool,
    /// Base reconnect backoff (ms). Default 500.
    pub reconnect_delay_ms: u64,
    /// Max reconnect backoff (ms). Default 60_000.
    pub max_backoff_delay_ms: u64,
    /// Reconnect jitter (ms). Default 500.
    pub reconnect_jitter_ms: u64,

    /// Per-registration maximum number of in-flight `ExecuteRequest`s being
    /// processed by the user `BaseConnector::execute()` callback. When the
    /// limit is reached, additional `ExecuteRequest`s queue on a semaphore
    /// until a permit is released. Mirrors
    /// [`crate::ConnectorConfig::max_concurrent_requests`] for the
    /// single-runner path. Default `100`.
    pub max_concurrent_requests: usize,

    /// Per-registration outbound heartbeat interval. `None` (default) means
    /// use the SDK default of 30s, which matches the Matrix server's
    /// session-reaper expectation.
    ///
    /// Only tune this when running against a Matrix deployment with a
    /// non-default heartbeat configuration, or for flaky-network testing.
    pub heartbeat_interval: Option<Duration>,

    /// Per-registration heartbeat watchdog timeout. If no `HeartbeatResponse`
    /// arrives within this window the runner declares the stream dead and
    /// reconnects. `None` (default) means use the SDK default of 45s.
    ///
    /// Only tune this when running against a Matrix deployment with a
    /// non-default heartbeat configuration, or for flaky-network testing.
    pub heartbeat_timeout: Option<Duration>,

    /// PEM-encoded CA certificate to trust for the outbound TLS connection,
    /// in addition to the system roots. Set this to reach an endpoint fronted
    /// by a private or self-signed CA. `None` (default) uses only the system
    /// trust store. Ignored when `use_tls` is false.
    pub tls_ca_pem: Option<Vec<u8>>,

    /// Skip TLS certificate verification entirely for the outbound connection.
    /// `false` (default) validates against the system roots plus `tls_ca_pem`.
    /// Takes precedence over `tls_ca_pem` when both are set. Intended only for
    /// dev/test against a known endpoint with an untrusted certificate; never
    /// enable in production. Ignored when `use_tls` is false.
    pub tls_insecure: bool,

    /// Maximum number of admitted handles per shared WebSocket multiplex
    /// socket (i.e. per Phoenix `connector:lobby` channel for one tenant).
    /// The 513th `admit()` for the same tenant returns
    /// `ConnectorError::InvalidConfig` synchronously, so users see a typed
    /// error instead of a delayed server-side rejection. Default `512`.
    ///
    /// Match this to the value the Matrix server is configured with —
    /// admitting more than the server allows just defers the failure to
    /// register-time. Ignored for gRPC.
    pub max_handlers_per_socket: usize,
}

impl MultiTransportOptions {
    /// Start a builder with sensible defaults (gRPC, plaintext, localhost:50061).
    pub fn builder() -> MultiTransportOptionsBuilder {
        MultiTransportOptionsBuilder::default()
    }
}

impl Default for MultiTransportOptions {
    fn default() -> Self {
        Self {
            host: "localhost:50061".to_string(),
            use_tls: false,
            transport_type: TransportType::Grpc,
            max_streams_per_channel: 80,
            connect_timeout_ms: 10_000,
            reconnect_enabled: true,
            reconnect_delay_ms: 500,
            max_backoff_delay_ms: 60_000,
            reconnect_jitter_ms: 500,
            max_concurrent_requests: 100,
            heartbeat_interval: None,
            heartbeat_timeout: None,
            tls_ca_pem: None,
            tls_insecure: false,
            max_handlers_per_socket: 512,
        }
    }
}

/// Validate a heartbeat (interval, timeout) pair and emit a `tracing::warn!`
/// if the timeout is shorter than the interval — that misconfigures the
/// watchdog (the very first tick can fire after the timeout has already
/// elapsed). Returns `false` when the pair is misconfigured.
///
/// Extracted as a free function so it can be unit-tested in isolation.
fn validate_heartbeat_pair(interval: Option<Duration>, timeout: Option<Duration>) -> bool {
    match (interval, timeout) {
        (Some(i), Some(t)) if t < i => {
            tracing::warn!(
                target: "strike48_connector::heartbeat",
                interval_ms = i.as_millis() as u64,
                timeout_ms = t.as_millis() as u64,
                "heartbeat_timeout < heartbeat_interval; the watchdog can fire before the first heartbeat reply has a chance to arrive"
            );
            false
        }
        _ => true,
    }
}

/// Fluent builder for [`MultiTransportOptions`].
#[derive(Debug, Clone, Default)]
pub struct MultiTransportOptionsBuilder {
    inner: Option<MultiTransportOptions>,
}

impl MultiTransportOptionsBuilder {
    fn opts(&mut self) -> &mut MultiTransportOptions {
        self.inner
            .get_or_insert_with(MultiTransportOptions::default)
    }

    /// Set the server host:port.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.opts().host = host.into();
        self
    }

    /// Set whether to use TLS.
    pub fn use_tls(mut self, use_tls: bool) -> Self {
        self.opts().use_tls = use_tls;
        self
    }

    /// Set the transport scheme.
    pub fn transport_type(mut self, t: TransportType) -> Self {
        self.opts().transport_type = t;
        self
    }

    /// Override the soft cap on concurrent gRPC streams per channel (gRPC only).
    pub fn max_streams_per_channel(mut self, n: usize) -> Self {
        self.opts().max_streams_per_channel = n;
        self
    }

    /// Override the initial connect timeout (ms).
    pub fn connect_timeout_ms(mut self, ms: u64) -> Self {
        self.opts().connect_timeout_ms = ms;
        self
    }

    /// Override the per-registration `max_concurrent_requests` cap.
    pub fn max_concurrent_requests(mut self, n: usize) -> Self {
        self.opts().max_concurrent_requests = n.max(1);
        self
    }

    /// Enable or disable automatic reconnection on stream loss.
    pub fn reconnect_enabled(mut self, enabled: bool) -> Self {
        self.opts().reconnect_enabled = enabled;
        self
    }

    /// Initial reconnect delay (ms) — the base for exponential backoff.
    pub fn reconnect_delay_ms(mut self, ms: u64) -> Self {
        self.opts().reconnect_delay_ms = ms;
        self
    }

    /// Hard cap on reconnect backoff (ms). Jitter is applied first, then
    /// the result is clamped to this value, so the cap is a strict upper
    /// bound on the wait between attempts.
    pub fn max_backoff_delay_ms(mut self, ms: u64) -> Self {
        self.opts().max_backoff_delay_ms = ms;
        self
    }

    /// Per-attempt jitter range (ms). A uniformly-random value in
    /// `0..=ms` is added to the scaled backoff before capping.
    pub fn reconnect_jitter_ms(mut self, ms: u64) -> Self {
        self.opts().reconnect_jitter_ms = ms;
        self
    }

    /// Override the per-registration heartbeat interval.
    ///
    /// Defaults to **30s** (the Matrix server's session-reaper expectation).
    /// Only tune this when running against a Matrix deployment with a
    /// non-default heartbeat configuration, or for flaky-network testing.
    /// If the resulting `heartbeat_timeout` is shorter than the interval,
    /// a `tracing::warn!` is emitted at builder time but the value is
    /// still applied (the runner uses whatever is configured).
    pub fn heartbeat_interval(mut self, d: Duration) -> Self {
        self.opts().heartbeat_interval = Some(d);
        let _ = validate_heartbeat_pair(
            self.opts().heartbeat_interval,
            self.opts().heartbeat_timeout,
        );
        self
    }

    /// Override the per-registration heartbeat watchdog timeout.
    ///
    /// Defaults to **45s** (Matrix server default + slack for one missed
    /// reply). Only tune this when running against a Matrix deployment
    /// with a non-default heartbeat configuration, or for flaky-network
    /// testing. Misconfigured pairs (`timeout < interval`) emit a
    /// `tracing::warn!` at builder time but are still applied.
    pub fn heartbeat_timeout(mut self, d: Duration) -> Self {
        self.opts().heartbeat_timeout = Some(d);
        let _ = validate_heartbeat_pair(
            self.opts().heartbeat_interval,
            self.opts().heartbeat_timeout,
        );
        self
    }

    /// Trust an additional PEM-encoded CA certificate for the outbound TLS
    /// connection (on top of the system roots). Use to reach an endpoint
    /// fronted by a private or self-signed CA. Ignored when TLS is off.
    pub fn tls_ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.opts().tls_ca_pem = Some(pem.into());
        self
    }

    /// Skip TLS certificate verification for the outbound connection. Dev/test
    /// only — never enable in production. Ignored when TLS is off.
    pub fn tls_insecure(mut self, insecure: bool) -> Self {
        self.opts().tls_insecure = insecure;
        self
    }

    /// Override the per-tenant WebSocket-multiplex handler cap. Defaults to
    /// **512**. Values smaller than 1 are clamped to 1. Ignored for gRPC.
    pub fn max_handlers_per_socket(mut self, n: usize) -> Self {
        self.opts().max_handlers_per_socket = n.max(1);
        self
    }

    /// Build the options.
    pub fn build(mut self) -> MultiTransportOptions {
        self.inner.take().unwrap_or_default()
    }
}

/// One logical connector to run inside a [`MultiConnectorRunner`].
///
/// `config.host`, `config.use_tls`, and `config.transport_type` are ignored —
/// the transport is governed by [`MultiTransportOptions`]. All other fields
/// (`tenant_id`, `connector_type`, `instance_id`, `auth_token`,
/// `display_name`, `tags`, `metadata`, `max_concurrent_requests`,
/// `metrics_*`) apply to this registration only.
///
/// Marked `#[non_exhaustive]` so future fields (e.g. per-registration
/// behaviour overrides) can be added without breaking downstream
/// struct-literal construction. Prefer [`ConnectorRegistration::new`].
#[non_exhaustive]
pub struct ConnectorRegistration {
    pub config: ConnectorConfig,
    pub connector: Arc<dyn BaseConnector>,
}

impl ConnectorRegistration {
    /// Build a registration from a `ConnectorConfig` and any
    /// [`BaseConnector`] implementor — the conversion to
    /// `Arc<dyn BaseConnector>` happens internally so callers don't have
    /// to write `Arc::new(...) as Arc<dyn BaseConnector>` themselves.
    ///
    /// ```
    /// use std::sync::Arc;
    /// use strike48_connector::{
    ///     BaseConnector, ConnectorConfig, ConnectorRegistration, Result,
    /// };
    ///
    /// struct Echo;
    /// impl BaseConnector for Echo {
    ///     fn connector_type(&self) -> &str { "echo" }
    ///     fn version(&self) -> &str { "1.0.0" }
    ///     fn execute(
    ///         &self,
    ///         req: serde_json::Value,
    ///         _: Option<&str>,
    ///     ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>> {
    ///         Box::pin(async move { Ok(req) })
    ///     }
    /// }
    ///
    /// let cfg = ConnectorConfig {
    ///     tenant_id: "demo".into(),
    ///     connector_type: "echo".into(),
    ///     instance_id: "echo-1".into(),
    ///     ..ConnectorConfig::default()
    /// };
    /// let reg = ConnectorRegistration::new(cfg, Echo);
    /// assert_eq!(reg.config.connector_type, "echo");
    /// # let _ = reg;
    /// ```
    pub fn new<T>(config: ConnectorConfig, connector: T) -> Self
    where
        T: BaseConnector + 'static,
    {
        Self {
            config,
            connector: Arc::new(connector) as Arc<dyn BaseConnector>,
        }
    }

    /// Build a registration from a config and an already-erased
    /// `Arc<dyn BaseConnector>`. Useful when callers have a heterogeneous
    /// list of differently-typed connectors that they have already boxed.
    pub fn from_arc(config: ConnectorConfig, connector: Arc<dyn BaseConnector>) -> Self {
        Self { config, connector }
    }
}

impl std::fmt::Debug for ConnectorRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectorRegistration")
            .field("config", &self.config)
            .field(
                "connector",
                &format_args!(
                    "Arc<dyn BaseConnector>(\"{}\")",
                    self.connector.connector_type()
                ),
            )
            .finish()
    }
}

/// Stable identity for a registration. Matches the `tenant.type.instance`
/// triple the Matrix server uses to key a `ConnectorSession`.
///
/// Marked `#[non_exhaustive]` so additional identity dimensions (e.g. an
/// optional region tag) can be added without breaking downstream
/// pattern-match exhaustiveness.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub struct RegistrationKey {
    pub tenant_id: String,
    pub connector_type: String,
    pub instance_id: String,
}

impl RegistrationKey {
    pub fn from_config(config: &ConnectorConfig) -> Self {
        Self {
            tenant_id: config.tenant_id.clone(),
            connector_type: config.connector_type.clone(),
            instance_id: config.instance_id.clone(),
        }
    }
}

impl std::fmt::Display for RegistrationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}",
            self.tenant_id, self.connector_type, self.instance_id
        )
    }
}

// =============================================================================
// MultiConnectorRunner
// =============================================================================

struct RegistrationEntry {
    key: RegistrationKey,
    config: ConnectorConfig,
    connector: Arc<dyn BaseConnector>,
    metrics: Arc<Mutex<ConnectorMetrics>>,
}

/// Runs `N` independently-approvable connectors over a shared transport.
///
/// See module-level docs for transport semantics. From the Matrix server's
/// point of view, each registration is a normal `Connect` RPC.
pub struct MultiConnectorRunner {
    opts: MultiTransportOptions,
    registrations: RwLock<Vec<RegistrationEntry>>,
    shutdown_requested: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
}

impl MultiConnectorRunner {
    /// Create a new runner. Construction does not open any connections —
    /// transport is established lazily by [`MultiConnectorRunner::run`].
    ///
    /// Duplicate registrations (same `tenant.type.instance`) are rejected by
    /// [`MultiConnectorRunner::add`]; duplicates passed in here are reduced
    /// to the first occurrence and logged.
    pub fn new(opts: MultiTransportOptions, registrations: Vec<ConnectorRegistration>) -> Self {
        let mut entries: Vec<RegistrationEntry> = Vec::with_capacity(registrations.len());
        for ConnectorRegistration { config, connector } in registrations {
            let key = RegistrationKey::from_config(&config);
            if entries.iter().any(|e| e.key == key) {
                tracing::warn!(
                    target: "strike48_connector::multi",
                    registration = %key,
                    "duplicate registration ignored"
                );
                continue;
            }
            entries.push(RegistrationEntry {
                key,
                config,
                connector,
                metrics: Arc::new(Mutex::new(ConnectorMetrics::default())),
            });
        }

        Self {
            opts,
            registrations: RwLock::new(entries),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Append a registration. Only valid before [`MultiConnectorRunner::run`]
    /// is called; returns an error if `run()` has already started or if the
    /// registration's `tenant.type.instance` collides with an existing one.
    ///
    /// `running` is checked **inside** the same write-lock critical section
    /// that `run()` uses to snapshot the registration list, so a concurrent
    /// `add` either lands before the snapshot (and is driven) or returns
    /// [`ConnectorError::AlreadyRunning`]. There is no window where the
    /// registration is silently dropped.
    pub async fn add(&self, registration: ConnectorRegistration) -> Result<()> {
        let key = RegistrationKey::from_config(&registration.config);
        let mut regs = self.registrations.write().await;
        if self.running.load(Ordering::SeqCst) {
            return Err(ConnectorError::AlreadyRunning);
        }
        if regs.iter().any(|e| e.key == key) {
            return Err(ConnectorError::InvalidConfig(format!(
                "duplicate registration: {key}"
            )));
        }
        regs.push(RegistrationEntry {
            key,
            config: registration.config,
            connector: registration.connector,
            metrics: Arc::new(Mutex::new(ConnectorMetrics::default())),
        });
        Ok(())
    }

    /// Get a [`ShutdownHandle`] that signals every registration to exit.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle::from_flag(self.shutdown_requested.clone())
    }

    /// Snapshot of the registered keys (in insertion order).
    pub async fn registrations(&self) -> Vec<RegistrationKey> {
        self.registrations
            .read()
            .await
            .iter()
            .map(|e| e.key.clone())
            .collect()
    }

    /// Per-registration metrics snapshot.
    ///
    /// Each registration owns its own [`ConnectorMetrics`] (no global
    /// singleton), so values are independent across registrations sharing the
    /// same transport.
    pub async fn metrics_snapshot(&self) -> HashMap<RegistrationKey, ConnectorMetrics> {
        let regs = self.registrations.read().await;
        let mut out = HashMap::with_capacity(regs.len());
        for entry in regs.iter() {
            let snapshot = entry.metrics.lock().await.clone();
            out.insert(entry.key.clone(), snapshot);
        }
        out
    }

    /// Run all registrations to completion or until shutdown.
    ///
    /// Returns once every registration has exited. Individual registration
    /// failures are logged but do not abort the runner unless
    /// [`MultiTransportOptions::reconnect_enabled`] is `false`.
    pub async fn run(&self) -> Result<()> {
        let logger = Logger::new("multi");

        // Take the write lock so concurrent `add()` calls observe `running`
        // atomically with the snapshot — see `add` for the partner half of
        // this protocol. We hold the lock only long enough to flip `running`
        // and clone the entries.
        let entries: Vec<RegistrationEntry> = {
            let regs = self.registrations.write().await;
            if self
                .running
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return Err(ConnectorError::AlreadyRunning);
            }
            regs.iter()
                .map(|e| RegistrationEntry {
                    key: e.key.clone(),
                    config: e.config.clone(),
                    connector: e.connector.clone(),
                    metrics: e.metrics.clone(),
                })
                .collect()
        };

        // Pre-signalled shutdown is a clean no-op exit.
        if self.shutdown_requested.load(Ordering::SeqCst) {
            logger.debug("shutdown signalled before run; exiting");
            self.running.store(false, Ordering::SeqCst);
            return Ok(());
        }

        if entries.is_empty() {
            logger.warn("no registrations configured; run() exiting immediately");
            self.running.store(false, Ordering::SeqCst);
            return Ok(());
        }

        let result = match self.opts.transport_type {
            TransportType::Grpc => self.run_grpc(entries, logger).await,
            TransportType::WebSocket => self.run_websocket(entries, logger).await,
        };
        self.running.store(false, Ordering::SeqCst);
        result
    }

    async fn run_grpc(&self, entries: Vec<RegistrationEntry>, logger: Logger) -> Result<()> {
        let shared = Arc::new(SharedChannel::new(self.opts.clone()));
        let mut tasks = Vec::with_capacity(entries.len());

        for entry in entries {
            let runner = RegistrationRunner {
                key: entry.key.clone(),
                config: Arc::new(RwLock::new(entry.config)),
                connector: entry.connector,
                shared_channel: shared.clone(),
                shutdown: self.shutdown_requested.clone(),
                metrics: entry.metrics,
                opts: self.opts.clone(),
                request_semaphore: Arc::new(Semaphore::new(
                    self.opts.max_concurrent_requests.max(1),
                )),
                session_token: Arc::new(RwLock::new(None)),
                consecutive_rejections: Arc::new(AtomicU32::new(0)),
            };
            tasks.push(tokio::spawn(async move { runner.run().await }));
        }

        for task in tasks {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    logger.warn(&format!("registration runner exited with error: {e}"));
                }
                Err(join_err) => {
                    logger.error("registration task panicked", &join_err.to_string());
                }
            }
        }

        Ok(())
    }

    /// WebSocket multiplex: every registration that shares a `tenant_id`
    /// is folded onto a single shared Phoenix socket; cross-tenant entries
    /// always get separate sockets (security isolation). Inbound frames are
    /// demuxed by `context["connector_arn"]`; outbound `execute_request` /
    /// `invoke_request` carries a unique `request_id` so responses route
    /// back to the correct handle. Single-connector users see no behavioural
    /// change — the sole-handle fallback path keeps legacy unmarked frames
    /// flowing.
    async fn run_websocket(&self, entries: Vec<RegistrationEntry>, logger: Logger) -> Result<()> {
        let _ = logger;

        let driver_entries: Vec<WsMultiplexEntry> = entries
            .into_iter()
            .map(|e| {
                let mut config = e.config;
                // Pin transport-level fields so each handle's view matches
                // the socket it ends up on.
                config.transport_type = TransportType::WebSocket;
                config.host = self.opts.host.clone();
                config.use_tls = self.opts.use_tls;
                config.reconnect_enabled = self.opts.reconnect_enabled;
                config.reconnect_delay_ms = self.opts.reconnect_delay_ms;
                config.max_backoff_delay_ms = self.opts.max_backoff_delay_ms;
                config.reconnect_jitter_ms = self.opts.reconnect_jitter_ms;
                WsMultiplexEntry {
                    key: e.key,
                    config,
                    connector: e.connector,
                    metrics: e.metrics,
                }
            })
            .collect();

        let driver = WsMultiplexDriver {
            opts: self.opts.clone(),
            shutdown: self.shutdown_requested.clone(),
        };
        driver.run(driver_entries).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ConnectorBehavior;

    struct DummyConnector;
    impl BaseConnector for DummyConnector {
        fn connector_type(&self) -> &str {
            "dummy"
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
        fn behavior(&self) -> ConnectorBehavior {
            ConnectorBehavior::Tool
        }
    }

    fn reg(tenant: &str, ty: &str, inst: &str) -> ConnectorRegistration {
        ConnectorRegistration::new(
            ConnectorConfig {
                tenant_id: tenant.into(),
                connector_type: ty.into(),
                instance_id: inst.into(),
                ..ConnectorConfig::default()
            },
            DummyConnector,
        )
    }

    #[test]
    fn options_builder_defaults_match_default_impl() {
        let built = MultiTransportOptions::builder().build();
        let defaulted = MultiTransportOptions::default();
        assert_eq!(built.host, defaulted.host);
        assert_eq!(built.use_tls, defaulted.use_tls);
        assert_eq!(
            built.max_streams_per_channel,
            defaulted.max_streams_per_channel
        );
        assert_eq!(built.transport_type, defaulted.transport_type);
    }

    #[test]
    fn options_builder_heartbeat_roundtrip() {
        let opts = MultiTransportOptions::builder()
            .heartbeat_interval(Duration::from_secs(5))
            .heartbeat_timeout(Duration::from_secs(15))
            .build();
        assert_eq!(opts.heartbeat_interval, Some(Duration::from_secs(5)));
        assert_eq!(opts.heartbeat_timeout, Some(Duration::from_secs(15)));
    }

    #[test]
    fn options_builder_heartbeat_defaults_are_none() {
        let opts = MultiTransportOptions::builder().build();
        assert!(opts.heartbeat_interval.is_none());
        assert!(opts.heartbeat_timeout.is_none());
    }

    #[test]
    fn validate_heartbeat_pair_flags_misordered_pair() {
        // timeout < interval → invalid (warning emitted; we just check return)
        assert!(!validate_heartbeat_pair(
            Some(Duration::from_secs(30)),
            Some(Duration::from_secs(10))
        ));
        // Properly ordered pair → ok.
        assert!(validate_heartbeat_pair(
            Some(Duration::from_secs(30)),
            Some(Duration::from_secs(45))
        ));
        // Either side missing → ok (caller intends SDK default for the other).
        assert!(validate_heartbeat_pair(None, Some(Duration::from_secs(5))));
        assert!(validate_heartbeat_pair(Some(Duration::from_secs(5)), None));
    }

    #[test]
    fn options_builder_overrides_apply() {
        let opts = MultiTransportOptions::builder()
            .host("h:1")
            .use_tls(true)
            .max_streams_per_channel(42)
            .transport_type(TransportType::WebSocket)
            .build();
        assert_eq!(opts.host, "h:1");
        assert!(opts.use_tls);
        assert_eq!(opts.max_streams_per_channel, 42);
        assert_eq!(opts.transport_type, TransportType::WebSocket);
    }

    #[test]
    fn options_tls_defaults_are_off() {
        let opts = MultiTransportOptions::builder().build();
        assert!(opts.tls_ca_pem.is_none());
        assert!(!opts.tls_insecure);
    }

    #[test]
    fn options_builder_tls_ca_pem_applies() {
        let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        let opts = MultiTransportOptions::builder()
            .use_tls(true)
            .tls_ca_pem(pem.to_vec())
            .build();
        assert_eq!(opts.tls_ca_pem.as_deref(), Some(&pem[..]));
        // CA pinning does not imply skipping verification.
        assert!(!opts.tls_insecure);
    }

    #[test]
    fn options_builder_tls_insecure_applies() {
        let opts = MultiTransportOptions::builder()
            .use_tls(true)
            .tls_insecure(true)
            .build();
        assert!(opts.tls_insecure);
        assert!(opts.tls_ca_pem.is_none());
    }

    #[test]
    fn options_builder_allows_both_tls_ca_pem_and_insecure() {
        // Both may be set; connect_channel documents that insecure takes
        // precedence. The builder records both without complaint.
        let opts = MultiTransportOptions::builder()
            .use_tls(true)
            .tls_ca_pem(b"pem".to_vec())
            .tls_insecure(true)
            .build();
        assert!(opts.tls_insecure);
        assert!(opts.tls_ca_pem.is_some());
    }

    #[tokio::test]
    async fn registration_key_from_config_matches_display_form() {
        let r = reg("t", "c", "i");
        let k = RegistrationKey::from_config(&r.config);
        assert_eq!(k.to_string(), "t.c.i");
    }

    #[tokio::test]
    async fn duplicate_registrations_in_new_are_collapsed() {
        let runner = MultiConnectorRunner::new(
            MultiTransportOptions::default(),
            vec![reg("t", "c", "i"), reg("t", "c", "i"), reg("t", "c", "j")],
        );
        let keys = runner.registrations().await;
        assert_eq!(keys.len(), 2, "second duplicate should be dropped");
        assert_eq!(keys[0].instance_id, "i");
        assert_eq!(keys[1].instance_id, "j");
    }

    #[tokio::test]
    async fn add_rejects_duplicates() {
        let runner =
            MultiConnectorRunner::new(MultiTransportOptions::default(), vec![reg("t", "c", "i")]);
        let err = runner.add(reg("t", "c", "i")).await.unwrap_err();
        assert!(matches!(err, ConnectorError::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn add_after_run_starts_is_rejected() {
        let runner =
            MultiConnectorRunner::new(MultiTransportOptions::default(), vec![reg("t", "c", "i")]);
        runner.running.store(true, Ordering::SeqCst);
        let err = runner.add(reg("t", "c", "j")).await.unwrap_err();
        assert!(matches!(&err, ConnectorError::AlreadyRunning));
    }

    #[tokio::test]
    async fn add_rejects_duplicate_with_invalid_config() {
        let runner =
            MultiConnectorRunner::new(MultiTransportOptions::default(), vec![reg("t", "c", "i")]);
        let err = runner.add(reg("t", "c", "i")).await.unwrap_err();
        assert!(matches!(&err, ConnectorError::InvalidConfig(m) if m.contains("duplicate")));
    }

    #[tokio::test]
    async fn shutdown_handle_signals_internal_flag() {
        let runner =
            MultiConnectorRunner::new(MultiTransportOptions::default(), vec![reg("t", "c", "i")]);
        let h = runner.shutdown_handle();
        assert!(!runner.shutdown_requested.load(Ordering::SeqCst));
        h.shutdown();
        assert!(runner.shutdown_requested.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn run_with_empty_registrations_is_ok() {
        let runner = MultiConnectorRunner::new(MultiTransportOptions::default(), vec![]);
        runner.run().await.expect("empty run should succeed");
    }

    #[tokio::test]
    async fn run_with_pre_signalled_shutdown_is_ok() {
        let runner =
            MultiConnectorRunner::new(MultiTransportOptions::default(), vec![reg("t", "c", "i")]);
        runner.shutdown_handle().shutdown();
        runner
            .run()
            .await
            .expect("pre-signalled shutdown should be a clean Ok exit");
    }

    #[tokio::test]
    async fn run_websocket_accepts_config_and_shuts_down_cleanly() {
        // WS path fans out to N independent ConnectorRunners under the hood.
        // We can't run a real WS server here, so we verify the multi-runner
        // accepts WS config and exits cleanly when shutdown is signalled
        // before run starts.
        let opts = MultiTransportOptions::builder()
            .transport_type(TransportType::WebSocket)
            .host("localhost:65535") // unreachable; reconnect would loop forever
            .build();
        let runner = MultiConnectorRunner::new(opts, vec![reg("t", "c", "i")]);
        runner.shutdown_handle().shutdown();
        runner
            .run()
            .await
            .expect("pre-signalled WS shutdown should be a clean Ok exit");
    }

    #[tokio::test]
    async fn run_websocket_shutdown_does_not_leak_watcher_tasks() {
        // Regression test for the per-registration watcher-task leak. With
        // reconnect disabled the child ConnectorRunner exits on its own
        // (unreachable host, fail-fast). After it returns, the multi
        // run_websocket must tear its bridge task down so we can shut down
        // promptly and not leave a spinning watcher behind.
        let opts = MultiTransportOptions::builder()
            .transport_type(TransportType::WebSocket)
            // Localhost:1 is RFC-reserved and reliably refuses connections.
            .host("127.0.0.1:1")
            .build();
        let mut opts = opts;
        opts.reconnect_enabled = false;

        let runner = MultiConnectorRunner::new(opts, vec![reg("t", "c", "i")]);
        let shutdown = runner.shutdown_handle();

        // Trigger shutdown shortly after starting; the runner must observe
        // it via the watch channel and exit promptly even if the child
        // ConnectorRunner is still mid-handshake.
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            shutdown.shutdown();
        });

        let res = tokio::time::timeout(std::time::Duration::from_secs(5), runner.run()).await;
        assert!(
            res.is_ok(),
            "run_websocket must exit within 5s of shutdown signal"
        );
        res.unwrap()
            .expect("run_websocket should return Ok after clean shutdown");
    }

    #[tokio::test]
    async fn add_races_with_run_either_lands_or_rejects_never_silently_dropped() {
        // Regression test for the TOCTOU between `add()`'s `running.load()`
        // and `run()`'s snapshot. Either the registration must be visible
        // to the runner (driven), or `add()` must return AlreadyRunning —
        // we must never observe "added but not driven".
        //
        // We can't drive a real run() without a server, so we exploit the
        // public surface: spawn run() against an empty pre-shutdown runner
        // (which exits cleanly without touching any registrations) and
        // race add() against it. The invariant is that `add()`'s outcome
        // must be consistent with `registrations()` *as seen after `run()`
        // returns*.
        for _ in 0..200 {
            let opts = MultiTransportOptions::default();
            let runner = std::sync::Arc::new(MultiConnectorRunner::new(opts, vec![]));
            // Pre-signal shutdown so run() exits without needing a server.
            runner.shutdown_handle().shutdown();

            let r1 = runner.clone();
            let run_task = tokio::spawn(async move { r1.run().await });

            // Yield once to let run() take the write lock first sometimes.
            tokio::task::yield_now().await;

            let add_res = runner.add(reg("t", "c", "i")).await;
            run_task.await.expect("run join").expect("run ok");

            match add_res {
                Ok(()) => {
                    // Must be visible in the registration list.
                    let keys = runner.registrations().await;
                    assert!(
                        keys.iter().any(|k| k.instance_id == "i"),
                        "add() succeeded but registration is not visible"
                    );
                }
                Err(ConnectorError::AlreadyRunning) => {
                    // Must NOT be in the list — rejection means not added.
                    let keys = runner.registrations().await;
                    assert!(
                        !keys.iter().any(|k| k.instance_id == "i"),
                        "add() returned AlreadyRunning but registration was still inserted"
                    );
                }
                Err(other) => panic!("unexpected add() error: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn run_called_twice_returns_already_running() {
        let runner = MultiConnectorRunner::new(MultiTransportOptions::default(), vec![]);
        // Manually flip running so the second call hits the AlreadyRunning path
        // without us needing to race with a real run(). We can't naturally
        // observe two concurrent run()s without a running server — this test
        // covers only the precondition.
        runner.running.store(true, Ordering::SeqCst);
        let err = runner.run().await.unwrap_err();
        assert!(matches!(err, ConnectorError::AlreadyRunning));
    }
}

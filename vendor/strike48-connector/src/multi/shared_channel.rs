//! Shared HTTP/2 channel for `MultiConnectorRunner` (gRPC mode).
//!
//! Wraps one or more `tonic::Channel`s and hands out new bidi `Connect`
//! streams. The headline guarantee: until the soft cap
//! [`crate::MultiTransportOptions::max_streams_per_channel`] is reached, every
//! new stream is multiplexed onto the same TCP+HTTP/2 connection. Once the
//! cap is hit a new channel is opened lazily and subsequent streams use it
//! (overflow path, lands in a later phase).
//!
//! WebSocket transport is handled separately — `SharedChannel` is gRPC-only.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{Mutex, mpsc};
use tonic::Streaming;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

use crate::error::{ConnectorError, Result};
use crate::multi::MultiTransportOptions;
use strike48_proto::proto::{StreamMessage, connector_service_client::ConnectorServiceClient};

/// One underlying `tonic::Channel` and the count of streams currently using it.
struct ChannelEntry {
    channel: Channel,
    active_streams: Arc<AtomicUsize>,
}

/// Pool of `tonic::Channel`s. A fresh `MultiConnectorRunner` starts with no
/// channels at all; the first `open_stream` call lazily connects one. When
/// the per-channel stream count reaches `opts.max_streams_per_channel` a new
/// channel is opened and used for subsequent streams.
pub(crate) struct SharedChannel {
    opts: MultiTransportOptions,
    channels: Mutex<Vec<ChannelEntry>>,
    /// Serializes "open a brand-new channel" so a burst of concurrent
    /// callers that each see an empty (or fully-saturated) pool dedupe to
    /// a single dial. The pool lock is NOT held across the dial; only this
    /// dial mutex is, which means callers that find an under-cap channel
    /// in the fast path are never blocked on a slow handshake.
    dial_lock: Mutex<()>,
}

impl SharedChannel {
    pub(crate) fn new(opts: MultiTransportOptions) -> Self {
        Self {
            opts,
            channels: Mutex::new(Vec::new()),
            dial_lock: Mutex::new(()),
        }
    }

    /// Number of underlying TCP connections currently held.
    /// Useful for tests; not part of the public API.
    #[cfg(test)]
    pub(crate) async fn channel_count(&self) -> usize {
        self.channels.lock().await.len()
    }

    /// Open a new bidi `Connect` stream multiplexed on the next available
    /// channel (creating one if needed).
    ///
    /// The `initial_message` is folded into the outbound stream BEFORE
    /// `tonic::client.connect` awaits the response headers. This matches
    /// `transport::grpc::start_stream` and is required because matrix's
    /// elixir-grpc handler does not emit response headers until it receives
    /// at least one message — so calling `connect(empty_stream).await` would
    /// deadlock with the SDK's "send register on the channel after connect
    /// returns" pattern.
    pub(crate) async fn open_stream(
        &self,
        initial_message: StreamMessage,
        outbound_capacity: usize,
    ) -> Result<SharedStream> {
        let entry = self.acquire_channel().await?;
        let channel = entry.channel.clone();
        let counter = entry.active_streams.clone();

        let mut client = ConnectorServiceClient::new(channel);

        let (tx, mut rx) = mpsc::channel::<StreamMessage>(outbound_capacity);

        let outbound = async_stream::stream! {
            yield initial_message;
            while let Some(msg) = rx.recv().await {
                yield msg;
            }
        };

        let response = client.connect(outbound).await.map_err(|status| {
            ConnectorError::ConnectionError(format!(
                "failed to open shared-channel stream: {status}"
            ))
        })?;

        counter.fetch_add(1, Ordering::SeqCst);

        Ok(SharedStream {
            tx,
            inbound: response.into_inner(),
            _release: ChannelStreamGuard { counter },
        })
    }

    async fn acquire_channel(&self) -> Result<ChannelEntry> {
        // Fast path: a channel is already below the soft cap. The pool
        // lock is held only for the (sync) scan and immediately released.
        {
            let channels = self.channels.lock().await;
            if let Some(hit) = pick_under_cap(&channels, self.opts.max_streams_per_channel) {
                return Ok(hit);
            }
        }

        // Slow path: serialize concurrent dials so a burst of N callers
        // creates one channel, not N. The pool lock is NOT held across
        // `endpoint.connect().await` — only the dial lock is — so callers
        // with an under-cap channel still see them in the fast path even
        // while a handshake is in flight.
        let _dial_guard = self.dial_lock.lock().await;

        // Re-check after acquiring the dial lock: another caller may have
        // dialled while we waited.
        {
            let channels = self.channels.lock().await;
            if let Some(hit) = pick_under_cap(&channels, self.opts.max_streams_per_channel) {
                return Ok(hit);
            }
        }

        let channel = connect_channel(&self.opts).await?;

        // Final re-check: between releasing the pool lock above and
        // finishing the dial, yet another caller may have produced an
        // under-cap channel. Prefer reuse to keep TCP usage minimal.
        let mut channels = self.channels.lock().await;
        if let Some(hit) = pick_under_cap(&channels, self.opts.max_streams_per_channel) {
            return Ok(hit);
        }

        let entry = ChannelEntry {
            channel,
            active_streams: Arc::new(AtomicUsize::new(0)),
        };
        let cloned = ChannelEntry {
            channel: entry.channel.clone(),
            active_streams: entry.active_streams.clone(),
        };
        channels.push(entry);
        Ok(cloned)
    }
}

/// Pick the first channel whose active stream count is strictly below
/// `cap`, returning a clone of the entry. Pure helper, no awaits.
fn pick_under_cap(channels: &[ChannelEntry], cap: usize) -> Option<ChannelEntry> {
    channels.iter().find_map(|entry| {
        if entry.active_streams.load(Ordering::SeqCst) < cap {
            Some(ChannelEntry {
                channel: entry.channel.clone(),
                active_streams: entry.active_streams.clone(),
            })
        } else {
            None
        }
    })
}

/// A single bidi stream borrowed from a [`SharedChannel`].
///
/// The initial register message is folded into the outbound stream by
/// [`SharedChannel::open_stream`]; subsequent outbound traffic flows through
/// `tx`. Inbound messages arrive via `inbound`. The `_release` field
/// decrements the per-channel stream count when the stream is dropped.
pub(crate) struct SharedStream {
    /// Sender for follow-up messages (heartbeats, execute responses, ...).
    /// Marked `allow(dead_code)` until the dispatch loop wires execute /
    /// heartbeat handling on top of `RegistrationRunner`.
    #[allow(dead_code)]
    pub tx: mpsc::Sender<StreamMessage>,
    pub inbound: Streaming<StreamMessage>,
    _release: ChannelStreamGuard,
}

struct ChannelStreamGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ChannelStreamGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Build the base `Endpoint` (scheme, keepalive, timeouts) without TLS config.
///
/// `https_scheme` picks the URL scheme: verified-TLS uses `https` (tonic's
/// built-in TLS is layered on via `tls_config`), while the insecure path uses
/// `http` and supplies TLS itself through a custom connector — tonic rejects an
/// `https` URI that has no `tls_config`.
fn build_endpoint(opts: &MultiTransportOptions, https_scheme: bool) -> Result<Endpoint> {
    let scheme = if https_scheme { "https" } else { "http" };
    let url = format!("{scheme}://{}", opts.host);
    let endpoint = Endpoint::from_shared(url.clone())
        .map_err(|e| ConnectorError::InvalidConfig(format!("invalid endpoint url '{url}': {e}")))?
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_millis(opts.connect_timeout_ms));

    Ok(endpoint)
}

/// Extract the hostname (no port) from a `host:port` string, for TLS SNI.
/// Expects a DNS hostname; IPv6 literals (`[::1]:443`) are not supported.
fn host_without_port(host_port: &str) -> &str {
    host_port.split(':').next().unwrap_or(host_port)
}

/// Connect a tonic `Channel` for the given options, applying TLS when enabled.
///
/// TLS modes when `use_tls` is set:
///   - `tls_insecure`: skip certificate verification (dev/test only). Takes
///     precedence over `tls_ca_pem`.
///   - `tls_ca_pem` set: validate against the system roots plus that CA.
///   - otherwise: standard TLS against the system trust store.
///
/// A plain (non-TLS) endpoint is used when `use_tls` is false.
async fn connect_channel(opts: &MultiTransportOptions) -> Result<Channel> {
    if !opts.use_tls {
        return build_endpoint(opts, false)?
            .connect()
            .await
            .map_err(connect_err(opts));
    }

    let host = host_without_port(&opts.host);

    if opts.tls_insecure {
        // Supply TLS ourselves via a custom rustls connector that accepts any
        // certificate and negotiates h2 ALPN. The endpoint uses an `http`
        // scheme because the connector — not tonic — terminates TLS; an `https`
        // URI without a `tls_config` is rejected by tonic.
        let mut rustls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| ConnectorError::ConnectionError(format!("TLS config error: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            crate::transport::grpc::InsecureServerCertVerifier,
        ))
        .with_no_client_auth();
        rustls_config.alpn_protocols = vec![b"h2".to_vec()];

        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(rustls_config));
        let connector =
            crate::transport::grpc::InsecureGrpcConnector::new(tls_connector, host.to_string());
        return build_endpoint(opts, false)?
            .connect_with_connector(connector)
            .await
            .map_err(connect_err(opts));
    }

    // tonic's `tls_config` builds its rustls `ClientConfig` from the process
    // default CryptoProvider. With both aws-lc-rs and ring present in the
    // dependency tree the default is ambiguous and rustls panics, so install
    // aws-lc-rs explicitly first (idempotent — ignores an already-set default).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    build_endpoint(opts, true)?
        .tls_config(verified_tls_config(host, opts.tls_ca_pem.as_deref()))
        .map_err(|e| ConnectorError::ConnectionError(format!("TLS config error: {e}")))?
        .connect()
        .await
        .map_err(connect_err(opts))
}

/// Build a verified-TLS `ClientTlsConfig` for `domain`, trusting the system
/// roots plus an optional pinned CA (`ca_pem`).
///
/// `with_enabled_roots` returns a fresh config, so it must be called before
/// `domain_name` — otherwise the SNI domain is silently discarded.
fn verified_tls_config(domain: &str, ca_pem: Option<&[u8]>) -> ClientTlsConfig {
    let mut tls = ClientTlsConfig::new()
        .with_enabled_roots()
        .domain_name(domain);
    if let Some(ca_pem) = ca_pem {
        tls = tls.ca_certificate(Certificate::from_pem(ca_pem));
    }
    tls
}

/// Shared error mapper for channel connect failures.
fn connect_err(opts: &MultiTransportOptions) -> impl Fn(tonic::transport::Error) -> ConnectorError {
    let host = opts.host.clone();
    move |e| {
        ConnectorError::ConnectionError(format!("failed to connect tonic channel to {host}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportType;

    #[tokio::test]
    async fn shared_channel_starts_with_no_channels() {
        let opts = MultiTransportOptions {
            host: "localhost:50061".into(),
            transport_type: TransportType::Grpc,
            ..Default::default()
        };
        let sc = SharedChannel::new(opts);
        assert_eq!(sc.channel_count().await, 0);
    }

    #[test]
    fn host_without_port_strips_port() {
        assert_eq!(
            host_without_port("connectors.example.com:443"),
            "connectors.example.com"
        );
    }

    #[test]
    fn host_without_port_passes_through_bare_host() {
        assert_eq!(host_without_port("localhost"), "localhost");
    }

    #[test]
    fn build_endpoint_https_scheme_true_yields_https() {
        let opts = MultiTransportOptions {
            host: "example.com:443".into(),
            ..Default::default()
        };
        let ep = build_endpoint(&opts, true).expect("endpoint builds");
        assert_eq!(ep.uri().scheme_str(), Some("https"));
    }

    #[test]
    fn build_endpoint_https_scheme_false_yields_http() {
        // The insecure path forces http even though use_tls is true, because it
        // supplies TLS via a custom connector rather than tonic's tls_config.
        let opts = MultiTransportOptions {
            host: "example.com:443".into(),
            use_tls: true,
            ..Default::default()
        };
        let ep = build_endpoint(&opts, false).expect("endpoint builds");
        assert_eq!(ep.uri().scheme_str(), Some("http"));
    }

    #[test]
    fn verified_tls_config_preserves_domain() {
        // Regression guard: with_enabled_roots returns a fresh config, so the
        // domain must survive the builder chain (Debug exposes the domain).
        let tls = verified_tls_config("connectors.example.com", None);
        assert!(
            format!("{tls:?}").contains("connectors.example.com"),
            "SNI domain must be retained: {tls:?}"
        );
    }

    #[test]
    fn verified_tls_config_pins_ca_when_provided() {
        let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        // Should not panic and should retain the domain alongside the pinned CA.
        let tls = verified_tls_config("example.com", Some(pem));
        assert!(format!("{tls:?}").contains("example.com"));
    }

    #[tokio::test]
    async fn verified_tls_connect_errors_without_panicking() {
        // Regression guard: the verified-TLS path builds a rustls ClientConfig
        // from the process default CryptoProvider, which is ambiguous (aws-lc-rs
        // + ring both present) and would panic unless a default is installed.
        // Connecting to an unroutable address must surface a ConnectionError,
        // not panic.
        let opts = MultiTransportOptions {
            host: "127.0.0.1:1".into(),
            use_tls: true,
            connect_timeout_ms: 200,
            ..Default::default()
        };
        let result = connect_channel(&opts).await;
        assert!(
            matches!(result, Err(ConnectorError::ConnectionError(_))),
            "expected ConnectionError, got {result:?}"
        );
    }
}

//! gRPC Transport for Strike48 Connector SDK.
//!
//! Native gRPC over HTTP/2 - best performance, requires HTTP/2 support.

use async_trait::async_trait;
use futures::StreamExt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tonic::transport::Channel;
use tower_service::Service;
use tracing::{debug, error, trace, warn};

use super::proxy::{ProxyConfig, ProxyStream, connect_through_proxy};
use super::{Transport, TransportOptions, TransportType, create_unbounded_wrapper};
use crate::error::{ConnectorError, Result};
use strike48_proto::proto::StreamMessage;
use strike48_proto::proto::connector_service_client::ConnectorServiceClient;

/// Default channel capacity for bounded message channels.
const DEFAULT_CHANNEL_CAPACITY: usize = 1024;

/// gRPC Transport implementation.
///
/// Uses native gRPC with bidirectional streaming for high-performance
/// connector communication. Requires HTTP/2 support.
pub struct GrpcTransport {
    options: TransportOptions,
    connected: Arc<AtomicBool>,
    channel: Option<Channel>,
    client: Option<ConnectorServiceClient<Channel>>,
    /// Channel capacity for backpressure (default: 1024)
    channel_capacity: usize,
    /// Handle for the spawned response-reader task so we can abort it on disconnect.
    task_handle: Option<tokio::task::JoinHandle<()>>,
    /// Handles for the unbounded-wrapper forwarder tasks.
    wrapper_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl GrpcTransport {
    /// Create a new gRPC transport.
    pub fn new(options: TransportOptions) -> Self {
        debug!(
            "GrpcTransport created: {} (TLS: {})",
            options.host, options.use_tls
        );

        Self {
            channel_capacity: options.channel_capacity.unwrap_or(DEFAULT_CHANNEL_CAPACITY),
            options,
            connected: Arc::new(AtomicBool::new(false)),
            channel: None,
            client: None,
            task_handle: None,
            wrapper_handles: Vec::new(),
        }
    }

    /// Extract hostname without port from a host:port string.
    fn extract_host(host_port: &str) -> String {
        host_port.split(':').next().unwrap_or(host_port).to_string()
    }

    /// Check if MATRIX_TLS_INSECURE environment variable is enabled.
    fn tls_insecure() -> bool {
        std::env::var("MATRIX_TLS_INSECURE")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false)
    }

    /// Build a tonic Channel with insecure TLS (skips certificate verification).
    ///
    /// If `MATRIX_TLS_CA_CERT` is set, loads the CA certificate from that path
    /// and uses tonic's built-in TLS with proper cert validation against that CA.
    /// Otherwise, uses a custom rustls config that accepts any certificate.
    async fn connect_insecure_tls(endpoint_url: &str, connect_timeout_ms: u64) -> Result<Channel> {
        use tonic::transport::ClientTlsConfig;

        // Install the default rustls CryptoProvider (idempotent — ignores if already set).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let host = endpoint_url
            .trim_start_matches("https://")
            .split(':')
            .next()
            .unwrap_or("localhost");

        let tls_config = if let Ok(ca_path) = std::env::var("MATRIX_TLS_CA_CERT") {
            debug!("Loading CA certificate from: {}", ca_path);
            let ca_pem = std::fs::read(&ca_path).map_err(|e| {
                ConnectorError::ConnectionError(format!("Failed to read CA cert {ca_path}: {e}"))
            })?;
            let ca_cert = tonic::transport::Certificate::from_pem(ca_pem);
            ClientTlsConfig::new()
                .domain_name(host)
                .ca_certificate(ca_cert)
        } else {
            debug!("No CA cert specified, using rustls with insecure verifier");
            let mut rustls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| ConnectorError::ConnectionError(format!("TLS config error: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureServerCertVerifier))
            .with_no_client_auth();
            rustls_config.alpn_protocols = vec![b"h2".to_vec()];

            let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(rustls_config));
            let connector = InsecureGrpcConnector {
                tls: tls_connector,
                host: host.to_string(),
            };

            let plain_url = endpoint_url.replace("https://", "http://");
            let channel_builder = Channel::from_shared(plain_url)
                .map_err(|e| ConnectorError::ConnectionError(format!("Invalid endpoint: {e}")))?
                .keep_alive_while_idle(true)
                .http2_keep_alive_interval(Duration::from_secs(30))
                .keep_alive_timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_millis(connect_timeout_ms));

            return timeout(
                Duration::from_millis(connect_timeout_ms),
                channel_builder.connect_with_connector(connector),
            )
            .await
            .map_err(|_| ConnectorError::Timeout("gRPC TLS connection timeout".to_string()))?
            .map_err(|e| {
                use std::error::Error;
                let mut chain = format!("TLS connection failed: {e}");
                let mut src = e.source();
                while let Some(s) = src {
                    chain.push_str(&format!(" -> {s}"));
                    src = s.source();
                }
                ConnectorError::ConnectionError(chain)
            });
        };

        let channel_builder = Channel::from_shared(endpoint_url.to_string())
            .map_err(|e| ConnectorError::ConnectionError(format!("Invalid endpoint: {e}")))?
            .tls_config(tls_config)
            .map_err(|e| ConnectorError::ConnectionError(format!("TLS config error: {e}")))?
            .keep_alive_while_idle(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_millis(connect_timeout_ms));

        timeout(
            Duration::from_millis(connect_timeout_ms),
            channel_builder.connect(),
        )
        .await
        .map_err(|_| ConnectorError::Timeout("gRPC TLS connection timeout".to_string()))?
        .map_err(|e| ConnectorError::ConnectionError(format!("TLS connection failed: {e}")))
    }

    /// Build a tonic Channel with standard TLS (validates certificates against system roots).
    async fn connect_standard_tls(
        endpoint_url: &str,
        host: &str,
        connect_timeout_ms: u64,
    ) -> Result<Channel> {
        use tonic::transport::ClientTlsConfig;

        // Install the default rustls CryptoProvider (idempotent — ignores if already set).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let tls = ClientTlsConfig::new().domain_name(host);

        let channel_builder = Channel::from_shared(endpoint_url.to_string())
            .map_err(|e| ConnectorError::ConnectionError(format!("Invalid endpoint: {e}")))?
            .tls_config(tls)
            .map_err(|e| ConnectorError::ConnectionError(format!("TLS config error: {e}")))?
            .keep_alive_while_idle(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_millis(connect_timeout_ms));

        timeout(
            Duration::from_millis(connect_timeout_ms),
            channel_builder.connect(),
        )
        .await
        .map_err(|_| ConnectorError::Timeout("gRPC TLS connection timeout".to_string()))?
        .map_err(|e| ConnectorError::ConnectionError(format!("TLS connection failed: {e}")))
    }

    /// Build a tonic Channel without TLS (plain HTTP/2).
    async fn connect_plain(endpoint_url: &str, connect_timeout_ms: u64) -> Result<Channel> {
        let channel_builder = Channel::from_shared(endpoint_url.to_string())
            .map_err(|e| ConnectorError::ConnectionError(format!("Invalid endpoint: {e}")))?
            .keep_alive_while_idle(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_millis(connect_timeout_ms));

        timeout(
            Duration::from_millis(connect_timeout_ms),
            channel_builder.connect(),
        )
        .await
        .map_err(|_| ConnectorError::Timeout("gRPC connection timeout".to_string()))?
        .map_err(|e| ConnectorError::ConnectionError(format!("Connection failed: {e}")))
    }

    /// Extract `(host, port)` from a `host:port` string, defaulting the port.
    /// IPv6-aware via the shared proxy authority parser.
    fn target_host_port(host_port: &str, use_tls: bool) -> (String, u16) {
        let default_port = if use_tls { 443 } else { 80 };
        let (host, port) = super::proxy::split_host_port(host_port);
        (host, port.unwrap_or(default_port))
    }

    /// Build a Channel that tunnels through the configured HTTP CONNECT proxy.
    ///
    /// For TLS targets, builds the rustls config honoring the same env knobs as
    /// the direct paths (`MATRIX_TLS_INSECURE`, `MATRIX_TLS_CA_CERT`) and sets
    /// ALPN `h2`, then layers TLS onto the tunneled stream so the TARGET cert is
    /// validated. For plain targets, speaks h2c directly over the tunnel.
    async fn connect_via_proxy(
        proxy: &ProxyConfig,
        host_port: &str,
        use_tls: bool,
        connect_timeout_ms: u64,
    ) -> Result<Channel> {
        let (host, port) = Self::target_host_port(host_port, use_tls);
        // tonic requires a syntactically valid URI for the (ignored) authority;
        // the connector dials the proxy, so this is a placeholder.
        let dummy_url = format!("http://{host}:{port}");
        let channel_builder = Channel::from_shared(dummy_url)
            .map_err(|e| ConnectorError::ConnectionError(format!("Invalid endpoint: {e}")))?
            .keep_alive_while_idle(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_millis(connect_timeout_ms));

        // Build the TLS connector (if needed) before entering the future so its
        // ConnectorError doesn't collide with tonic's transport error type.
        let tls = if use_tls {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            Some(Self::build_proxy_rustls(&host)?)
        } else {
            None
        };

        let connect_fut = async {
            match tls {
                None => {
                    let connector = PlainProxyConnector {
                        proxy: proxy.clone(),
                        host: host.clone(),
                        port,
                        connect_timeout_ms,
                    };
                    channel_builder.connect_with_connector(connector).await
                }
                Some(tls) => {
                    let connector = TlsProxyConnector {
                        proxy: proxy.clone(),
                        tls,
                        host: host.clone(),
                        port,
                        connect_timeout_ms,
                    };
                    channel_builder.connect_with_connector(connector).await
                }
            }
        };

        timeout(Duration::from_millis(connect_timeout_ms), connect_fut)
            .await
            .map_err(|_| ConnectorError::Timeout("gRPC proxy connection timeout".to_string()))?
            .map_err(|e| {
                ConnectorError::ConnectionError(format!("gRPC connect via proxy failed: {e}"))
            })
    }

    /// Build a rustls `TlsConnector` for the proxy-tunneled TLS path, honoring
    /// `MATRIX_TLS_INSECURE` and `MATRIX_TLS_CA_CERT`, with ALPN `h2`.
    fn build_proxy_rustls(host: &str) -> Result<tokio_rustls::TlsConnector> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| ConnectorError::ConnectionError(format!("TLS config error: {e}")))?;

        let mut config = if Self::tls_insecure() {
            warn!(
                "gRPC TLS certificate verification DISABLED (MATRIX_TLS_INSECURE=true). \
                 Do NOT use in production!"
            );
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureServerCertVerifier))
                .with_no_client_auth()
        } else {
            // Always trust the bundled WebPKI roots, and ADD the custom CA on
            // top when MATRIX_TLS_CA_CERT is set. Adding (rather than replacing)
            // keeps this consistent with the WSS (native-tls) and reqwest paths,
            // so the same MATRIX_TLS_CA_CERT works for a TLS-inspecting proxy
            // whether or not studio itself uses a public CA.
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Ok(ca_path) = std::env::var("MATRIX_TLS_CA_CERT") {
                debug!("Loading CA certificate from: {}", ca_path);
                let ca_pem = std::fs::read(&ca_path).map_err(|e| {
                    ConnectorError::ConnectionError(format!(
                        "Failed to read CA cert {ca_path}: {e}"
                    ))
                })?;
                let mut reader = std::io::BufReader::new(&ca_pem[..]);
                for cert in rustls_pemfile::certs(&mut reader) {
                    let cert = cert.map_err(|e| {
                        ConnectorError::ConnectionError(format!("Invalid CA cert: {e}"))
                    })?;
                    roots.add(cert).map_err(|e| {
                        ConnectorError::ConnectionError(format!("Add CA cert: {e}"))
                    })?;
                }
            }
            let _ = host;
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
    }
}

#[async_trait]
impl Transport for GrpcTransport {
    #[allow(dead_code)]
    fn transport_type(&self) -> TransportType {
        TransportType::Grpc
    }

    async fn connect(&mut self) -> Result<()> {
        debug!(
            "Connecting with native gRPC transport (HTTP/2) to {}",
            self.options.host
        );

        let endpoint_url = if self.options.use_tls {
            format!("https://{}", self.options.host)
        } else {
            format!("http://{}", self.options.host)
        };

        debug!("gRPC endpoint: {}", endpoint_url);

        let connect_timeout_ms = self.options.connect_timeout_ms.unwrap_or(10000);

        let channel = if let Some(proxy) = &self.options.proxy {
            debug!(proxy = %proxy, "gRPC tunneling through HTTP CONNECT proxy");
            Self::connect_via_proxy(
                proxy,
                &self.options.host,
                self.options.use_tls,
                connect_timeout_ms,
            )
            .await?
        } else if self.options.use_tls {
            if Self::tls_insecure() {
                warn!(
                    "gRPC TLS certificate verification DISABLED (MATRIX_TLS_INSECURE=true). \
                     Do NOT use in production!"
                );
                Self::connect_insecure_tls(&endpoint_url, connect_timeout_ms).await?
            } else {
                let host = Self::extract_host(&self.options.host);
                Self::connect_standard_tls(&endpoint_url, &host, connect_timeout_ms).await?
            }
        } else {
            Self::connect_plain(&endpoint_url, connect_timeout_ms).await?
        };

        let client = ConnectorServiceClient::new(channel.clone());

        self.connected.store(true, Ordering::SeqCst);
        self.channel = Some(channel);
        self.client = Some(client);

        debug!("gRPC transport connected");
        Ok(())
    }

    async fn start_stream(
        &mut self,
        initial_message: Option<StreamMessage>,
    ) -> Result<(
        mpsc::UnboundedSender<StreamMessage>,
        mpsc::UnboundedReceiver<StreamMessage>,
    )> {
        // Abort any lingering tasks from a previous stream
        if let Some(h) = self.task_handle.take() {
            h.abort();
        }
        for h in self.wrapper_handles.drain(..) {
            h.abort();
        }

        let client = self.client.as_mut().ok_or(ConnectorError::NotConnected)?;

        // Create BOUNDED channels for backpressure
        let (request_tx, mut request_rx) = mpsc::channel::<StreamMessage>(self.channel_capacity);
        let (response_tx, response_rx) = mpsc::channel::<StreamMessage>(self.channel_capacity);

        // Create request stream that yields initial message first, then reads from channel
        let request_stream = async_stream::stream! {
            // CRITICAL: Send initial message immediately to prevent deadlock
            // The gRPC server waits for a message before sending responses
            if let Some(msg) = initial_message {
                debug!("gRPC TX: Sending initial message");
                yield msg;
            }

            // Then read subsequent messages from channel
            while let Some(msg) = request_rx.recv().await {
                trace!("gRPC TX: {:?}", msg.message.as_ref().map(std::mem::discriminant));
                yield msg;
            }
            debug!("gRPC request stream ended");
        };

        // Start bidirectional stream
        let response_stream = client
            .connect(request_stream)
            .await
            .map_err(|e| {
                error!("gRPC stream error: {}", e);
                ConnectorError::ConnectionError(format!("Stream failed: {e}"))
            })?
            .into_inner();

        // Abort any lingering task from a previous stream.
        if let Some(h) = self.task_handle.take() {
            h.abort();
        }

        // Spawn task to forward responses to channel
        let connected = self.connected.clone();
        let reader_handle = tokio::spawn(async move {
            let mut stream = response_stream;
            while let Some(result) = stream.next().await {
                match result {
                    Ok(msg) => {
                        trace!(
                            "gRPC RX: {:?}",
                            msg.message.as_ref().map(std::mem::discriminant)
                        );
                        // Use blocking send for backpressure
                        if response_tx.send(msg).await.is_err() {
                            warn!("Response channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("gRPC receive error: {}", e);
                        break;
                    }
                }
            }
            connected.store(false, Ordering::SeqCst);
            debug!("gRPC stream closed");
        });

        self.task_handle = Some(reader_handle);

        debug!("gRPC bidirectional stream started");

        let (unbounded_tx, unbounded_rx, wrapper_handles) =
            create_unbounded_wrapper(request_tx, response_rx);
        self.wrapper_handles = wrapper_handles;

        Ok((unbounded_tx, unbounded_rx))
    }

    #[allow(dead_code)]
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    async fn disconnect(&mut self) -> Result<()> {
        debug!("Disconnecting gRPC transport");

        self.connected.store(false, Ordering::SeqCst);
        if let Some(h) = self.task_handle.take() {
            h.abort();
        }
        for h in self.wrapper_handles.drain(..) {
            h.abort();
        }
        self.client = None;
        self.channel = None;

        Ok(())
    }
}

impl Drop for GrpcTransport {
    fn drop(&mut self) {
        if let Some(h) = self.task_handle.take() {
            h.abort();
        }
        for h in self.wrapper_handles.drain(..) {
            h.abort();
        }
    }
}

/// Custom gRPC connector that uses tokio-rustls directly for TLS.
/// Bypasses hyper-rustls to handle insecure certs with h2 ALPN.
#[derive(Clone)]
pub(crate) struct InsecureGrpcConnector {
    tls: tokio_rustls::TlsConnector,
    host: String,
}

impl InsecureGrpcConnector {
    /// Construct a connector that dials `host` and layers the given
    /// tokio-rustls TLS connector on the raw TCP stream.
    pub(crate) fn new(tls: tokio_rustls::TlsConnector, host: String) -> Self {
        Self { tls, host }
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Connector that tunnels plain h2c through an HTTP CONNECT proxy (no TLS).
#[derive(Clone)]
struct PlainProxyConnector {
    proxy: ProxyConfig,
    host: String,
    port: u16,
    connect_timeout_ms: u64,
}

impl Service<tonic::transport::Uri> for PlainProxyConnector {
    type Response = hyper_util::rt::TokioIo<ProxyStream>;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: tonic::transport::Uri) -> Self::Future {
        let proxy = self.proxy.clone();
        let host = self.host.clone();
        let port = self.port;
        let t = self.connect_timeout_ms;
        Box::pin(async move {
            let stream = connect_through_proxy(&proxy, &host, port, t).await?;
            Ok(hyper_util::rt::TokioIo::new(stream))
        })
    }
}

/// Connector that tunnels through an HTTP CONNECT proxy then layers rustls
/// (ALPN h2) onto the tunneled stream. The TARGET cert is validated, not the
/// proxy.
#[derive(Clone)]
struct TlsProxyConnector {
    proxy: ProxyConfig,
    tls: tokio_rustls::TlsConnector,
    host: String,
    port: u16,
    connect_timeout_ms: u64,
}

impl Service<tonic::transport::Uri> for TlsProxyConnector {
    type Response = hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<ProxyStream>>;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: tonic::transport::Uri) -> Self::Future {
        let proxy = self.proxy.clone();
        let tls = self.tls.clone();
        let host = self.host.clone();
        let port = self.port;
        let t = self.connect_timeout_ms;
        Box::pin(async move {
            let stream = connect_through_proxy(&proxy, &host, port, t).await?;
            let server_name = rustls::pki_types::ServerName::try_from(host.as_str())
                .map_err(|e| format!("Invalid DNS name: {e}"))?
                .to_owned();
            // Layer the TARGET TLS on top of the tunnel (which may itself be a
            // TLS-to-proxy stream). The target cert is validated against `host`.
            let tls_stream = tls.connect(server_name, stream).await?;
            Ok(hyper_util::rt::TokioIo::new(tls_stream))
        })
    }
}

impl Service<tonic::transport::Uri> for InsecureGrpcConnector {
    type Response = hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: tonic::transport::Uri) -> Self::Future {
        let tls = self.tls.clone();
        let host = self.host.clone();
        Box::pin(async move {
            let port = uri.port_u16().unwrap_or(443);
            let addr = format!("{host}:{port}");

            let tcp = TcpStream::connect(&addr).await?;
            let server_name = rustls::pki_types::ServerName::try_from(host.as_str())
                .map_err(|e| format!("Invalid DNS name: {e}"))?
                .to_owned();
            let tls_stream = tls.connect(server_name, tcp).await?;
            Ok(hyper_util::rt::TokioIo::new(tls_stream))
        })
    }
}

/// Certificate verifier that accepts any server certificate.
/// INSECURE: Only for local development with self-signed certificates.
#[derive(Debug)]
pub(crate) struct InsecureServerCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn target_host_port_defaults_and_parses() {
        assert_eq!(
            GrpcTransport::target_host_port("studio.example", true),
            ("studio.example".to_string(), 443)
        );
        assert_eq!(
            GrpcTransport::target_host_port("studio.example:50061", false),
            ("studio.example".to_string(), 50061)
        );
    }

    /// `connect()` with a proxy configured must issue a CONNECT for the target
    /// to the proxy (not dial the target directly).
    #[tokio::test]
    async fn grpc_connect_routes_through_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            // Reply 200 then drop — the h2 handshake will fail, which is fine;
            // we only assert the CONNECT request was correct.
            let _ = s
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await;
            let _ = tx.send(req);
        });

        let proxy = crate::transport::proxy::ProxyConfig {
            scheme: crate::transport::proxy::ProxyScheme::Http,
            host: "127.0.0.1".into(),
            port: proxy_addr.port(),
            auth: None,
        };
        let mut transport = GrpcTransport::new(TransportOptions {
            host: "studio.example:50061".into(),
            use_tls: false,
            connect_timeout_ms: Some(2000),
            default_timeout_ms: None,
            channel_capacity: Some(16),
            proxy: Some(proxy),
        });
        // Connection may ultimately fail (no real h2 server), but the proxy must
        // have received a well-formed CONNECT for the target.
        let _ = transport.connect().await;
        let req = rx.await.unwrap();
        assert!(
            req.starts_with("CONNECT studio.example:50061 HTTP/1.1\r\n"),
            "got: {req}"
        );
        assert!(req.contains("Host: studio.example:50061\r\n"));
    }

    // =========================================================================
    // extract_host
    // =========================================================================

    #[test]
    fn test_extract_host_with_port() {
        assert_eq!(
            GrpcTransport::extract_host("example.com:443"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_host_without_port() {
        assert_eq!(GrpcTransport::extract_host("example.com"), "example.com");
    }

    #[test]
    fn test_extract_host_localhost() {
        assert_eq!(GrpcTransport::extract_host("localhost:50061"), "localhost");
    }

    #[test]
    fn test_extract_host_ip_address() {
        assert_eq!(
            GrpcTransport::extract_host("192.168.1.1:443"),
            "192.168.1.1"
        );
    }

    #[test]
    fn test_extract_host_empty_string() {
        assert_eq!(GrpcTransport::extract_host(""), "");
    }

    #[test]
    fn test_extract_host_multiple_colons() {
        // Edge case: should return everything before the first colon
        assert_eq!(GrpcTransport::extract_host("host:443:extra"), "host");
    }

    // =========================================================================
    // tls_insecure
    // =========================================================================
    //
    // These tests mutate the process-wide `MATRIX_TLS_INSECURE` env var.
    // Cargo runs tests in parallel by default, so we serialise them with a
    // shared mutex to avoid races (one test removing the var while another
    // is mid-assert with it set).

    fn tls_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        // Tests that fail mid-run can poison the mutex; recover the guard
        // either way since there is no shared invariant to protect.
        match LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    #[test]
    fn test_tls_insecure_not_set() {
        let _guard = tls_env_lock();
        // SAFETY: test-only env manipulation, serialised by `tls_env_lock`.
        unsafe { std::env::remove_var("MATRIX_TLS_INSECURE") };
        assert!(!GrpcTransport::tls_insecure());
    }

    #[test]
    fn test_tls_insecure_true() {
        let _guard = tls_env_lock();
        // SAFETY: test-only env manipulation, serialised by `tls_env_lock`.
        unsafe { std::env::set_var("MATRIX_TLS_INSECURE", "true") };
        assert!(GrpcTransport::tls_insecure());
        unsafe { std::env::remove_var("MATRIX_TLS_INSECURE") };
    }

    #[test]
    fn test_tls_insecure_one() {
        let _guard = tls_env_lock();
        // SAFETY: test-only env manipulation, serialised by `tls_env_lock`.
        unsafe { std::env::set_var("MATRIX_TLS_INSECURE", "1") };
        assert!(GrpcTransport::tls_insecure());
        unsafe { std::env::remove_var("MATRIX_TLS_INSECURE") };
    }

    #[test]
    fn test_tls_insecure_false() {
        let _guard = tls_env_lock();
        // SAFETY: test-only env manipulation, serialised by `tls_env_lock`.
        unsafe { std::env::set_var("MATRIX_TLS_INSECURE", "false") };
        assert!(!GrpcTransport::tls_insecure());
        unsafe { std::env::remove_var("MATRIX_TLS_INSECURE") };
    }

    #[test]
    fn test_tls_insecure_random_value() {
        let _guard = tls_env_lock();
        // SAFETY: test-only env manipulation, serialised by `tls_env_lock`.
        unsafe { std::env::set_var("MATRIX_TLS_INSECURE", "yes") };
        assert!(!GrpcTransport::tls_insecure());
        unsafe { std::env::remove_var("MATRIX_TLS_INSECURE") };
    }

    // =========================================================================
    // InsecureServerCertVerifier
    // =========================================================================

    #[test]
    fn test_insecure_verifier_accepts_any_cert() {
        let verifier = InsecureServerCertVerifier;
        let end_entity = rustls::pki_types::CertificateDer::from(vec![0u8; 32]);
        let intermediates: Vec<rustls::pki_types::CertificateDer<'_>> = vec![];
        let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
        let now = rustls::pki_types::UnixTime::now();

        let result =
            verifier.verify_server_cert(&end_entity, &intermediates, &server_name, &[], now);
        assert!(
            result.is_ok(),
            "InsecureServerCertVerifier should accept any certificate"
        );
    }

    #[test]
    fn test_insecure_verifier_accepts_empty_cert() {
        let verifier = InsecureServerCertVerifier;
        let end_entity = rustls::pki_types::CertificateDer::from(vec![]);
        let intermediates: Vec<rustls::pki_types::CertificateDer<'_>> = vec![];
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

        let result = verifier.verify_server_cert(
            &end_entity,
            &intermediates,
            &server_name,
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_insecure_verifier_accepts_with_intermediates() {
        let verifier = InsecureServerCertVerifier;
        let end_entity = rustls::pki_types::CertificateDer::from(vec![1, 2, 3]);
        let intermediates = vec![
            rustls::pki_types::CertificateDer::from(vec![4, 5, 6]),
            rustls::pki_types::CertificateDer::from(vec![7, 8, 9]),
        ];
        let server_name = rustls::pki_types::ServerName::try_from("test.example.com").unwrap();

        let result = verifier.verify_server_cert(
            &end_entity,
            &intermediates,
            &server_name,
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(result.is_ok());
    }

    // =========================================================================
    // InsecureGrpcConnector (rustls ServerName construction)
    // =========================================================================

    #[test]
    fn test_server_name_from_valid_hostname() {
        let result = rustls::pki_types::ServerName::try_from("example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_server_name_from_localhost() {
        let result = rustls::pki_types::ServerName::try_from("localhost");
        assert!(result.is_ok());
    }

    #[test]
    fn test_server_name_from_subdomain() {
        let result = rustls::pki_types::ServerName::try_from("connectors.strike48.com");
        assert!(result.is_ok());
    }

    // =========================================================================
    // Rustls ClientConfig builder (the API that changes in 0.23)
    // =========================================================================

    #[test]
    fn test_rustls_config_builder_with_insecure_verifier() {
        // This tests the exact code path in connect_insecure_tls that changes with rustls 0.23
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureServerCertVerifier))
        .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];

        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn test_rustls_tls_connector_from_config() {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureServerCertVerifier))
        .with_no_client_auth();

        // This is the exact construction used in connect_insecure_tls
        let _connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        // If we get here without panic, the config is valid for TlsConnector
    }

    // =========================================================================
    // GrpcTransport construction and state
    // =========================================================================

    #[test]
    fn test_grpc_transport_new_defaults() {
        let transport = GrpcTransport::new(TransportOptions {
            host: "localhost:50061".to_string(),
            use_tls: false,
            connect_timeout_ms: None,
            default_timeout_ms: None,
            channel_capacity: None,
            proxy: None,
        });

        assert_eq!(transport.channel_capacity, DEFAULT_CHANNEL_CAPACITY);
        assert!(!transport.is_connected());
        assert!(transport.channel.is_none());
        assert!(transport.client.is_none());
    }

    #[test]
    fn test_grpc_transport_custom_channel_capacity() {
        let transport = GrpcTransport::new(TransportOptions {
            host: "localhost:50061".to_string(),
            use_tls: false,
            connect_timeout_ms: Some(5000),
            default_timeout_ms: Some(30000),
            channel_capacity: Some(2048),
            proxy: None,
        });

        assert_eq!(transport.channel_capacity, 2048);
    }

    #[test]
    fn test_grpc_transport_type() {
        let transport = GrpcTransport::new(TransportOptions {
            host: "localhost:50061".to_string(),
            use_tls: false,
            connect_timeout_ms: None,
            default_timeout_ms: None,
            channel_capacity: None,
            proxy: None,
        });

        assert_eq!(transport.transport_type(), TransportType::Grpc);
    }

    // =========================================================================
    // Connection path selection (plain vs TLS vs insecure TLS)
    // =========================================================================

    #[tokio::test]
    async fn test_connect_plain_invalid_host_returns_error() {
        // Connecting to an invalid host should return a connection error, not panic
        let result =
            GrpcTransport::connect_plain("http://invalid-host-that-does-not-exist:99999", 500)
                .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_plain_timeout() {
        // Use a non-routable address to trigger timeout
        let result = GrpcTransport::connect_plain("http://192.0.2.1:50061", 200).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("timeout")
                || err_str.contains("Timeout")
                || err_str.contains("Connection"),
            "Expected timeout or connection error, got: {err_str}"
        );
    }

    #[tokio::test]
    async fn test_connect_standard_tls_invalid_host_returns_error() {
        let result = GrpcTransport::connect_standard_tls(
            "https://invalid-host-that-does-not-exist:443",
            "invalid-host-that-does-not-exist",
            500,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_insecure_tls_invalid_host_returns_error() {
        // SAFETY: test-only env manipulation
        unsafe { std::env::remove_var("MATRIX_TLS_CA_CERT") };
        let result = GrpcTransport::connect_insecure_tls(
            "https://invalid-host-that-does-not-exist:443",
            500,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_transport_connect_selects_plain_for_no_tls() {
        // Use a non-routable address to ensure connection fails
        let mut transport = GrpcTransport::new(TransportOptions {
            host: "192.0.2.1:50061".to_string(),
            use_tls: false,
            connect_timeout_ms: Some(200),
            default_timeout_ms: None,
            channel_capacity: None,
            proxy: None,
        });

        let result = transport.connect().await;
        // Should fail (no server) but should not panic — confirms plain path was taken
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_transport_connect_selects_tls_for_use_tls() {
        let mut transport = GrpcTransport::new(TransportOptions {
            host: "localhost:99999".to_string(),
            use_tls: true,
            connect_timeout_ms: Some(200),
            default_timeout_ms: None,
            channel_capacity: None,
            proxy: None,
        });

        // Make sure MATRIX_TLS_INSECURE is not set so we go through standard TLS path
        // SAFETY: test-only env manipulation
        unsafe { std::env::remove_var("MATRIX_TLS_INSECURE") };

        let result = transport.connect().await;
        assert!(result.is_err());
    }

    // =========================================================================
    // Disconnect and state transitions
    // =========================================================================

    #[tokio::test]
    async fn test_disconnect_clears_state() {
        let mut transport = GrpcTransport::new(TransportOptions {
            host: "localhost:50061".to_string(),
            use_tls: false,
            connect_timeout_ms: None,
            default_timeout_ms: None,
            channel_capacity: None,
            proxy: None,
        });

        // Disconnect without connecting should be fine (no panic)
        let result = transport.disconnect().await;
        assert!(result.is_ok());
        assert!(!transport.is_connected());
        assert!(transport.channel.is_none());
        assert!(transport.client.is_none());
    }

    #[tokio::test]
    async fn test_disconnect_is_idempotent() {
        let mut transport = GrpcTransport::new(TransportOptions {
            host: "localhost:50061".to_string(),
            use_tls: false,
            connect_timeout_ms: None,
            default_timeout_ms: None,
            channel_capacity: None,
            proxy: None,
        });

        // Multiple disconnects should be fine
        assert!(transport.disconnect().await.is_ok());
        assert!(transport.disconnect().await.is_ok());
        assert!(transport.disconnect().await.is_ok());
    }
}

//! HTTP CONNECT forward-proxy support for studio connections.
//!
//! Target-TLS-agnostic: produces a tunneled byte stream and the transports
//! layer the *target* TLS on top, so the studio cert is always validated end to
//! end (never the proxy). The connector→proxy hop is plaintext for an `http://`
//! proxy, or TLS-wrapped for an `https://` proxy (proxy-over-TLS), which
//! protects the `CONNECT` request — notably any `Proxy-Authorization` header —
//! on the network between the connector and the proxy.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::fmt;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{ConnectorError, Result};

/// A tunnel stream returned by [`connect_through_proxy`]. It is a plain
/// `TcpStream` for an `http://` proxy, or a rustls `TlsStream` for an
/// `https://` proxy. The transports only need `AsyncRead + AsyncWrite` to layer
/// the target TLS / WebSocket upgrade on top, so it is boxed behind a trait
/// object rather than leaking the concrete type.
pub(crate) type ProxyStream = Box<dyn ProxyIo + Unpin + Send>;

/// Marker trait for the byte streams a proxy tunnel can produce.
pub(crate) trait ProxyIo: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> ProxyIo for T {}

/// How to reach the proxy itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyScheme {
    /// Plaintext connection to the proxy (`http://`).
    Http,
    /// TLS-wrapped connection to the proxy (`https://`), a.k.a. proxy-over-TLS /
    /// "secure web proxy". Encrypts the connector→proxy hop.
    Https,
}

/// Maximum size of a CONNECT response header block before we give up (guards
/// against an unbounded/hostile proxy response).
const MAX_CONNECT_HEADER: usize = 8 * 1024;

/// While the same proxy failure persists, log a reminder every N attempts so an
/// unattended connector retrying forever stays visible without flooding logs.
const PROXY_FAIL_LOG_EVERY: u64 = 20;

/// Process-global proxy health for throttled logging. There is one logical
/// proxy per process, so module-level state is sufficient (no per-connector
/// plumbing). `PROXY_FAIL_STREAK` counts consecutive failures; reset to 0 on
/// success. `PROXY_LAST_REASON` holds the last failure's `reason_code` so a
/// change of failure kind re-triggers a loud log.
///
/// The two atomics are updated independently (not as one transaction), so under
/// concurrent dials through the same proxy (e.g. gRPC + WSS, or many tenants)
/// the streak/reason view can momentarily tear. This only affects log verbosity
/// (a duplicated or skipped reminder line) — never correctness — so the
/// throttle is intentionally best-effort rather than mutex-guarded.
static PROXY_FAIL_STREAK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PROXY_LAST_REASON: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// One-time guard for the cleartext-proxy-auth warning.
static PROXY_CLEARTEXT_AUTH_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Proxy Basic-auth credentials. Redacts the password on `Debug`/`Display`.
#[derive(Clone)]
pub struct ProxyAuth {
    username: String,
    password: String,
}

impl ProxyAuth {
    /// `"Basic <base64(user:pass)>"` for the `Proxy-Authorization` header.
    pub fn basic_header_value(&self) -> String {
        let raw = format!("{}:{}", self.username, self.password);
        format!("Basic {}", BASE64.encode(raw.as_bytes()))
    }
}

impl fmt::Debug for ProxyAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:***", self.username)
    }
}

impl fmt::Display for ProxyAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:***", self.username)
    }
}

/// Resolved CONNECT proxy settings.
#[derive(Clone)]
pub struct ProxyConfig {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
    pub auth: Option<ProxyAuth>,
}

impl ProxyConfig {
    /// Parse `http://[user:pass@]host[:port]` or `https://[...]`. Defaults port
    /// to 3128 if absent. `https://` selects proxy-over-TLS (the connector→proxy
    /// hop is TLS-encrypted). Other schemes (socks5…) are rejected here; the
    /// env-resolution path turns that into a direct connection rather than a
    /// hard failure.
    pub fn parse_url(raw: &str) -> Result<ProxyConfig> {
        let (scheme, rest) = if let Some(rest) = raw.strip_prefix("https://") {
            (ProxyScheme::Https, rest)
        } else if let Some(rest) = raw.strip_prefix("http://") {
            (ProxyScheme::Http, rest)
        } else {
            // Don't echo `raw` — it may carry credentials. Report only the scheme.
            let scheme = raw.split("://").next().unwrap_or("(none)");
            return Err(ConnectorError::InvalidConfig(format!(
                "unsupported proxy URL scheme '{scheme}' (expected http:// or https://)"
            )));
        };

        // Split optional `user:pass@` userinfo.
        let (auth, hostport) = match rest.rsplit_once('@') {
            Some((userinfo, hp)) => {
                let (u, p) = userinfo.split_once(':').unwrap_or((userinfo, ""));
                (
                    Some(ProxyAuth {
                        username: u.to_string(),
                        password: p.to_string(),
                    }),
                    hp,
                )
            }
            None => (None, rest),
        };

        // Strip any trailing path.
        let hostport = hostport.split('/').next().unwrap_or(hostport);
        // Reject a malformed `host:` with a non-numeric port (but allow bare
        // IPv6 literals, which split_host_port treats as host-only).
        if hostport.matches(':').count() == 1
            && let Some((_, p)) = hostport.rsplit_once(':')
            && !p.is_empty()
            && !p.chars().all(|c| c.is_ascii_digit())
        {
            return Err(ConnectorError::InvalidConfig(format!(
                "invalid proxy port: {p}"
            )));
        }
        let (host, port) = split_host_port(hostport);
        let port = port.unwrap_or(3128);

        if host.is_empty() {
            return Err(ConnectorError::InvalidConfig(
                "proxy URL missing host".to_string(),
            ));
        }

        Ok(ProxyConfig {
            scheme,
            host,
            port,
            auth,
        })
    }
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProxyConfig {{ {}:{} }}", self.host, self.port)
    }
}

impl fmt::Display for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Split a `host[:port]` authority into `(host, Option<port>)`, IPv6-aware.
///
/// Bracketed IPv6 literals (`[::1]:443`) have the brackets stripped from the
/// host and the trailing `:port` parsed. Bare IPv6 literals (`2001:db8::1`,
/// multiple colons, no brackets) are treated as host-only — we never split at
/// an address colon. A single trailing `:digits` on a non-IPv6 host is a port.
pub(crate) fn split_host_port(authority: &str) -> (String, Option<u16>) {
    if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6: `[addr]` or `[addr]:port`.
        if let Some((addr, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (addr.to_string(), port);
        }
        return (authority.to_string(), None);
    }
    // Bare IPv6 (more than one colon, no brackets) → host-only.
    if authority.matches(':').count() > 1 {
        return (authority.to_string(), None);
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse::<u16>().ok())
        }
        _ => (authority.to_string(), None),
    }
}

/// Strip a trailing `:port` from a host string (IPv6-aware).
fn strip_port(host: &str) -> String {
    split_host_port(host).0
}

/// Whether `target_host` is exempt from proxying per a NO_PROXY value.
pub(crate) fn host_matches_no_proxy(target_host: &str, no_proxy: &str) -> bool {
    let target = strip_port(target_host).to_ascii_lowercase();
    for raw in no_proxy.split(',') {
        let entry = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if entry.is_empty() {
            continue;
        }
        if entry == "*" {
            return true;
        }
        // Normalize a leading `*.` (Java/.NET/`http.nonProxyHosts` style) to a
        // plain dotted suffix, then strip the leading dot.
        let entry = entry.strip_prefix("*.").unwrap_or(&entry);
        let entry = entry.trim_start_matches('.');
        if target == entry || target.ends_with(&format!(".{entry}")) {
            return true;
        }
    }
    false
}

/// Resolve the effective proxy for a target. `env` is injected for testing;
/// production passes a closure over `std::env::var`.
///
/// Precedence: `explicit` → `HTTPS_PROXY`/`https_proxy` (if `use_tls`) →
/// `HTTP_PROXY`/`http_proxy` → `ALL_PROXY`/`all_proxy` → `None`. Returns
/// `Ok(None)` when `NO_PROXY` matches the target.
pub(crate) fn resolve_proxy(
    target_host: &str,
    use_tls: bool,
    explicit: Option<&str>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<ProxyConfig>> {
    // Treat blank/whitespace as unset everywhere: orchestrators commonly
    // template `STUDIO_PROXY=${PROXY:-}` to an empty string, and `HTTPS_PROXY=""`
    // is a conventional way to disable a higher-scope proxy.
    let nonblank = |s: String| -> Option<String> {
        let t = s.trim();
        (!t.is_empty()).then(|| t.to_string())
    };

    // NO_PROXY check first (honor both cases).
    let no_proxy = env("NO_PROXY")
        .and_then(&nonblank)
        .or_else(|| env("no_proxy").and_then(&nonblank));
    if let Some(np) = no_proxy.as_deref()
        && host_matches_no_proxy(target_host, np)
    {
        return Ok(None);
    }

    let pick =
        |keys: &[&str]| -> Option<String> { keys.iter().find_map(|k| env(k).and_then(&nonblank)) };

    // An explicit STUDIO_PROXY is an operator override: a bad value is a hard
    // error so the misconfiguration is surfaced, not silently ignored.
    if let Some(e) = explicit.and_then(|s| nonblank(s.to_string())) {
        return Ok(Some(ProxyConfig::parse_url(&e)?));
    }

    let raw = if use_tls {
        pick(&["HTTPS_PROXY", "https_proxy"])
            .or_else(|| pick(&["HTTP_PROXY", "http_proxy"]))
            .or_else(|| pick(&["ALL_PROXY", "all_proxy"]))
    } else {
        pick(&["HTTP_PROXY", "http_proxy"]).or_else(|| pick(&["ALL_PROXY", "all_proxy"]))
    };

    match raw {
        // Env-sourced proxy: an unsupported scheme (e.g. ALL_PROXY=socks5://…,
        // very common) must NOT hard-fail the connection — skip it and connect
        // directly, logging once so the operator can see why.
        Some(url) => match ProxyConfig::parse_url(&url) {
            Ok(cfg) => Ok(Some(cfg)),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "ignoring unusable proxy from environment; connecting directly"
                );
                Ok(None)
            }
        },
        None => Ok(None),
    }
}

/// Build a `reqwest::Client` that transparently routes through the resolved
/// proxy (if any) and applies the SDK's standard TLS configuration
/// (`MATRIX_TLS_INSECURE` / `MATRIX_TLS_CA_CERT`) — the same knobs the gRPC
/// transport honors. Every outbound HTTP call in the SDK (OTT registration,
/// Keycloak JWT exchange, OAuth) builds its client here so proxy + TLS behavior
/// is defined in exactly one place.
///
/// `target_url` is the eventual request target; its host drives `NO_PROXY`
/// matching. Build the client ONCE and reuse it (it owns a connection pool).
pub(crate) fn build_http_client(target_url: &str) -> reqwest::Client {
    // rustls 0.23 needs a process-level CryptoProvider before any TLS op.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let host = split_host_port(host_authority(target_url)).0;
    let proxy = resolve_proxy(
        &host,
        true,
        std::env::var("STUDIO_PROXY").ok().as_deref(),
        &|k| std::env::var(k).ok(),
    )
    .ok()
    .flatten();

    let mut builder = reqwest::Client::builder();

    if let Some(cfg) = &proxy {
        // reqwest speaks HTTP CONNECT natively; reuse the SAME resolved config.
        // Preserve the scheme so an https:// proxy uses proxy-over-TLS here too
        // (reqwest does the TLS-to-proxy handshake, honoring the rustls-tls roots
        // + any custom CA configured below) — matching the gRPC/WSS tunnel.
        let scheme = match cfg.scheme {
            ProxyScheme::Http => "http",
            ProxyScheme::Https => "https",
        };
        let url = format!("{scheme}://{}:{}", cfg.host, cfg.port);
        match reqwest::Proxy::all(&url) {
            Ok(mut p) => {
                if let Some(auth) = &cfg.auth {
                    p = p.basic_auth(&auth.username, &auth.password);
                }
                // The client may target multiple hosts (studio + Keycloak); let
                // reqwest apply NO_PROXY per request host so an exempted host
                // still connects directly even on this shared client.
                p = p.no_proxy(reqwest::NoProxy::from_env());
                builder = builder.proxy(p);
                tracing::debug!(proxy = %cfg, target = %host, "HTTP client routing through proxy");
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not build reqwest proxy; connecting directly")
            }
        }
    }

    // Same TLS knobs as the transport paths.
    if tls_insecure() {
        builder = builder.danger_accept_invalid_certs(true);
    } else if let Ok(ca_path) = std::env::var("MATRIX_TLS_CA_CERT") {
        match load_ca_certs(&ca_path) {
            Ok(certs) => {
                for cert in certs {
                    builder = builder.add_root_certificate(cert);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not load MATRIX_TLS_CA_CERT for HTTP client")
            }
        }
    }

    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

/// `true` when `MATRIX_TLS_INSECURE` requests skipping TLS verification.
fn tls_insecure() -> bool {
    std::env::var("MATRIX_TLS_INSECURE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

/// Load a PEM CA file into `reqwest::Certificate`s. The file may contain MULTIPLE
/// certificates (a CA plus intermediates, or several roots); `from_pem` parses
/// only the first, so use `from_pem_bundle` to trust the whole set — matching
/// the WSS (native-tls) and gRPC (rustls) paths.
fn load_ca_certs(path: &str) -> Result<Vec<reqwest::Certificate>> {
    let pem = std::fs::read(path).map_err(|e| {
        ConnectorError::ConnectionError(format!("failed to read CA cert {path}: {e}"))
    })?;
    reqwest::Certificate::from_pem_bundle(&pem)
        .map_err(|e| ConnectorError::ConnectionError(format!("invalid CA cert {path}: {e}")))
}

/// Extract the `host[:port]` authority from a URL (strips scheme, path, userinfo).
fn host_authority(url: &str) -> &str {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let after_userinfo = after_scheme
        .rsplit_once('@')
        .map_or(after_scheme, |(_, h)| h);
    after_userinfo
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_userinfo)
}

#[derive(Debug)]
enum ConnectStatus {
    Established,
    AuthRequired,
    Failed(String),
    Incomplete,
}

/// Index just past the `\r\n\r\n` terminator, if present.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_connect_status(buf: &[u8]) -> ConnectStatus {
    if find_header_end(buf).is_none() {
        return ConnectStatus::Incomplete;
    }
    let line_end = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(buf.len());
    let line = String::from_utf8_lossy(&buf[..line_end]);
    // "HTTP/1.x CODE reason"
    let mut parts = line.split_whitespace();
    let _http = parts.next();
    let code = parts.next().unwrap_or("");
    match code {
        c if c.starts_with('2') => ConnectStatus::Established,
        "407" => ConnectStatus::AuthRequired,
        other => ConnectStatus::Failed(format!("proxy returned status {other}")),
    }
}

/// Open a tunneled TCP stream to `target_host:target_port` via the proxy.
///
/// Reads the CONNECT reply byte-by-byte up to and including the `\r\n\r\n`
/// terminator so no bytes belonging to the tunnel (e.g. the first TLS
/// ServerHello bytes) are consumed. The returned stream is ready for the
/// caller to layer TLS on top.
pub(crate) async fn connect_through_proxy(
    cfg: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    connect_timeout_ms: u64,
) -> Result<ProxyStream> {
    metrics::counter!("sdk.proxy.connect_attempts_total").increment(1);
    let started = std::time::Instant::now();

    // Bound the WHOLE handshake (TCP connect to proxy + write CONNECT +
    // byte-by-byte reply read) so a proxy that accepts TCP then goes silent
    // can't wedge the caller's reconnect loop. This makes the function
    // self-protecting regardless of caller-side timeout wrapping.
    let result = match tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        connect_through_proxy_inner(cfg, target_host, target_port),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(ConnectorError::ProxyConnectFailed(format!(
            "proxy {cfg} CONNECT handshake timed out after {connect_timeout_ms}ms"
        ))),
    };

    match &result {
        Ok(_) => {
            let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            metrics::counter!("sdk.proxy.connect_success_total").increment(1);
            metrics::histogram!("sdk.proxy.connect_latency_ms").record(elapsed_ms);
            record_proxy_recovery(cfg, target_host, target_port, elapsed_ms);
        }
        Err(e) => {
            let reason = proxy_failure_reason(e);
            metrics::counter!("sdk.proxy.connect_failures_total", "reason" => reason).increment(1);
            record_proxy_failure(cfg, reason, e);
        }
    }

    result
}

/// Map a proxy error to a stable, low-cardinality metric/label reason.
fn proxy_failure_reason(err: &ConnectorError) -> &'static str {
    match err {
        ConnectorError::ProxyUnreachable(_) => "unreachable",
        ConnectorError::ProxyAuthFailed(_) => "auth",
        ConnectorError::ProxyConnectFailed(_) => "connect_failed",
        _ => "other",
    }
}

/// Log a proxy connect failure "loud, not spammy": the first failure (and any
/// change of failure reason) logs at warn/error with remediation context;
/// while the same failure persists, only every Nth attempt logs (at debug) so
/// an unattended connector retrying forever doesn't flood the log.
fn record_proxy_failure(cfg: &ProxyConfig, reason: &'static str, err: &ConnectorError) {
    use std::sync::atomic::Ordering;

    let prev = PROXY_LAST_REASON.swap(reason_code(reason), Ordering::Relaxed);
    let streak = PROXY_FAIL_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
    let reason_changed = prev != reason_code(reason);

    // First failure of a run, or a new failure kind → loud.
    if streak == 1 || reason_changed {
        match reason {
            "auth" => tracing::error!(
                proxy = %cfg, %reason, code = err.code(),
                "studio proxy authentication failed — check proxy credentials; \
                 retrying indefinitely with backoff"
            ),
            _ => tracing::warn!(
                proxy = %cfg, %reason, code = err.code(), error = %err,
                "studio proxy connect failed — retrying indefinitely with backoff"
            ),
        }
    } else if streak.is_multiple_of(PROXY_FAIL_LOG_EVERY) {
        // Persistent same failure → periodic reminder at debug level.
        tracing::debug!(
            proxy = %cfg, %reason, consecutive_failures = streak,
            "studio proxy still failing"
        );
    }
}

/// On a successful connect after one or more failures, emit a single info-level
/// recovery line and reset the failure streak.
fn record_proxy_recovery(cfg: &ProxyConfig, target: &str, port: u16, elapsed_ms: f64) {
    use std::sync::atomic::Ordering;
    let prior_failures = PROXY_FAIL_STREAK.swap(0, Ordering::Relaxed);
    PROXY_LAST_REASON.store(0, Ordering::Relaxed);
    if prior_failures > 0 {
        tracing::info!(
            proxy = %cfg, target = %format!("{target}:{port}"),
            latency_ms = elapsed_ms, recovered_after = prior_failures,
            "studio proxy tunnel recovered"
        );
    } else {
        tracing::debug!(
            proxy = %cfg, target = %format!("{target}:{port}"),
            latency_ms = elapsed_ms, "studio proxy tunnel established"
        );
    }
}

/// Stable numeric code per failure reason for cheap atomic comparison.
fn reason_code(reason: &str) -> u64 {
    match reason {
        "unreachable" => 1,
        "auth" => 2,
        "connect_failed" => 3,
        _ => 4,
    }
}

async fn connect_through_proxy_inner(
    cfg: &ProxyConfig,
    target_host: &str,
    target_port: u16,
) -> Result<ProxyStream> {
    let proxy_addr = format!("{}:{}", cfg.host, cfg.port);
    let tcp = TcpStream::connect(&proxy_addr)
        .await
        .map_err(|e| ConnectorError::ProxyUnreachable(format!("connect to proxy {cfg}: {e}")))?;

    // For an https:// proxy, wrap the connector→proxy hop in TLS BEFORE the
    // CONNECT exchange so the request (including Proxy-Authorization) is
    // encrypted. The TLS here terminates at the PROXY (SNI = proxy host); the
    // target studio TLS is layered later by the transport, end to end through
    // the tunnel.
    let mut stream: ProxyStream = match cfg.scheme {
        ProxyScheme::Http => Box::new(tcp),
        ProxyScheme::Https => Box::new(tls_wrap_proxy_hop(tcp, &cfg.host).await?),
    };

    // Build CONNECT request (authority-form, include port).
    let mut req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    if let Some(auth) = &cfg.auth {
        // Only warn when the hop is plaintext: for http:// the Basic credentials
        // travel in (reversible) base64 on the Construct↔proxy segment. An
        // https:// proxy encrypts this hop, so no warning.
        if cfg.scheme == ProxyScheme::Http
            && !PROXY_CLEARTEXT_AUTH_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::warn!(
                proxy = %cfg,
                "sending proxy Basic credentials over a plaintext (http) proxy hop; \
                 they are recoverable on the Construct-to-proxy network segment. \
                 Use an https:// proxy URL to encrypt this hop."
            );
        }
        req.push_str(&format!(
            "Proxy-Authorization: {}\r\n",
            auth.basic_header_value()
        ));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| ConnectorError::ProxyConnectFailed(format!("write CONNECT: {e}")))?;

    let mut buf = Vec::with_capacity(256);
    let mut one = [0u8; 1];
    loop {
        let n = stream
            .read(&mut one)
            .await
            .map_err(|e| ConnectorError::ProxyConnectFailed(format!("read CONNECT reply: {e}")))?;
        if n == 0 {
            return Err(ConnectorError::ProxyConnectFailed(
                "proxy closed connection during CONNECT".to_string(),
            ));
        }
        buf.push(one[0]);
        if find_header_end(&buf).is_some() {
            break;
        }
        if buf.len() > MAX_CONNECT_HEADER {
            return Err(ConnectorError::ProxyConnectFailed(
                "CONNECT response header exceeded 8 KiB".to_string(),
            ));
        }
    }

    match parse_connect_status(&buf) {
        ConnectStatus::Established => Ok(stream),
        ConnectStatus::AuthRequired => Err(ConnectorError::ProxyAuthFailed(format!(
            "proxy {cfg} returned 407 (check proxy credentials)"
        ))),
        ConnectStatus::Failed(msg) => Err(ConnectorError::ProxyConnectFailed(msg)),
        ConnectStatus::Incomplete => Err(ConnectorError::ProxyConnectFailed(
            "incomplete CONNECT response".to_string(),
        )),
    }
}

/// Wrap the connector→proxy TCP hop in rustls (server-auth) for an `https://`
/// proxy. SNI / cert validation target the **proxy** host. Honors the same
/// TLS env knobs as the target: `MATRIX_TLS_INSECURE` skips verification,
/// `MATRIX_TLS_CA_CERT` adds a custom CA (a corporate proxy commonly uses a
/// private CA).
async fn tls_wrap_proxy_hop(
    tcp: TcpStream,
    proxy_host: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = build_proxy_hop_rustls()?;
    let server_name = rustls::pki_types::ServerName::try_from(proxy_host.to_string())
        .map_err(|e| ConnectorError::ProxyConnectFailed(format!("invalid proxy DNS name: {e}")))?;
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .map_err(|e| ConnectorError::ProxyConnectFailed(format!("proxy TLS handshake failed: {e}")))
}

/// rustls client config for the proxy-over-TLS hop. Mirrors the gRPC target
/// path: insecure verifier, or system+custom-CA roots.
fn build_proxy_hop_rustls() -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ConnectorError::ProxyConnectFailed(format!("TLS config error: {e}")))?;

    let insecure = std::env::var("MATRIX_TLS_INSECURE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    if insecure {
        tracing::warn!(
            "proxy TLS verification DISABLED (MATRIX_TLS_INSECURE=true). Do NOT use in production!"
        );
        return Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(super::grpc::InsecureServerCertVerifier))
            .with_no_client_auth());
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Ok(ca_path) = std::env::var("MATRIX_TLS_CA_CERT") {
        let ca_pem = std::fs::read(&ca_path).map_err(|e| {
            ConnectorError::ProxyConnectFailed(format!("read proxy CA cert {ca_path}: {e}"))
        })?;
        let mut reader = std::io::BufReader::new(&ca_pem[..]);
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert
                .map_err(|e| ConnectorError::ProxyConnectFailed(format!("invalid CA cert: {e}")))?;
            roots
                .add(cert)
                .map_err(|e| ConnectorError::ProxyConnectFailed(format!("add CA cert: {e}")))?;
        }
    }
    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}

/// Tests that follow `docs/proxy-support.md` claim-by-claim, to catch the docs
/// drifting from the implementation. Each test name maps to a documented claim.
#[cfg(test)]
mod doc_verification {
    use super::*;

    // Tier-2-style check against a REAL external CONNECT proxy, gated on env so
    // it only runs when a live proxy is provided. Set:
    //   REAL_PROXY_PORT, REAL_BACKEND_PORT (proxy requires alice:secret).
    #[tokio::test]
    async fn real_proxy_tunnel_with_basic_auth() {
        let (Ok(pport), Ok(bport)) = (
            std::env::var("REAL_PROXY_PORT"),
            std::env::var("REAL_BACKEND_PORT"),
        ) else {
            eprintln!("skipping real_proxy_tunnel: REAL_PROXY_PORT/REAL_BACKEND_PORT unset");
            return;
        };
        let pport: u16 = pport.parse().unwrap();
        let bport: u16 = bport.parse().unwrap();

        // Good creds → tunnel established, bytes flow end-to-end.
        let cfg =
            ProxyConfig::parse_url(&format!("http://alice:secret@127.0.0.1:{pport}")).unwrap();
        let mut s = connect_through_proxy(&cfg, "127.0.0.1", bport, 5000)
            .await
            .expect("tunnel with good creds");
        s.write_all(b"hi").await.unwrap();
        let mut buf = vec![0u8; 16];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ECHO:hi", "tunnel did not bridge to backend");

        // Bad creds → 407 → PROXY_AUTH_FAILED (docs §Behavior under failure).
        let bad = ProxyConfig::parse_url(&format!("http://alice:wrong@127.0.0.1:{pport}")).unwrap();
        let err = connect_through_proxy(&bad, "127.0.0.1", bport, 5000)
            .await
            .err()
            .expect("expected proxy connect to fail");
        assert_eq!(err.code(), "PROXY_AUTH_FAILED");
    }

    // Docs §Configuration #1: STUDIO_PROXY is the highest-precedence override.
    #[test]
    fn studio_proxy_is_highest_precedence() {
        let env = |k: &str| match k {
            "HTTPS_PROXY" => Some("http://env-proxy:8080".to_string()),
            _ => None,
        };
        // The caller passes STUDIO_PROXY as the `explicit` arg (see client.rs /
        // ws_multiplex.rs). Explicit must win over HTTPS_PROXY.
        let p = resolve_proxy(
            "studio.corp.com",
            true,
            Some("http://studio-proxy:3128"),
            &env,
        )
        .unwrap()
        .unwrap();
        assert_eq!(p.host, "studio-proxy");
        assert_eq!(p.port, 3128);
    }

    // Docs §Configuration #2: HTTPS_PROXY preferred for TLS targets; lowercase honored.
    #[test]
    fn https_proxy_preferred_for_tls_and_lowercase_honored() {
        let env = |k: &str| match k {
            "https_proxy" => Some("http://lower-secure:8080".to_string()),
            "HTTP_PROXY" => Some("http://plain:3128".to_string()),
            _ => None,
        };
        let p = resolve_proxy("studio.corp.com", true, None, &env)
            .unwrap()
            .unwrap();
        assert_eq!(p.host, "lower-secure");
    }

    // Docs §Configuration #3: NO_PROXY exact / suffix (.corp.com and corp.com) / `*`,
    // matched against target with port stripped.
    #[test]
    fn no_proxy_forms_from_docs() {
        assert!(host_matches_no_proxy("studio.corp.com", "studio.corp.com")); // exact
        assert!(host_matches_no_proxy("studio.corp.com", ".corp.com")); // dotted suffix
        assert!(host_matches_no_proxy("studio.corp.com", "corp.com")); // bare suffix
        assert!(host_matches_no_proxy("anything.example", "*")); // wildcard
        assert!(host_matches_no_proxy("studio.corp.com:443", ".corp.com")); // port stripped
    }

    // Docs §Configuration: "If ... NO_PROXY matches, the connection is made directly."
    #[test]
    fn no_proxy_match_yields_direct_connection() {
        let env = |k: &str| match k {
            "HTTPS_PROXY" => Some("http://env-proxy:8080".to_string()),
            "NO_PROXY" => Some(".corp.com".to_string()),
            _ => None,
        };
        // Even with an explicit STUDIO_PROXY, NO_PROXY exempts the target.
        let r = resolve_proxy(
            "studio.corp.com",
            true,
            Some("http://studio-proxy:3128"),
            &env,
        )
        .unwrap();
        assert!(r.is_none(), "NO_PROXY should force a direct connection");
    }

    // Docs §Configuration: "Port defaults to 3128 when the proxy URL omits it."
    #[test]
    fn port_defaults_to_3128() {
        let p = ProxyConfig::parse_url("http://proxy.corp").unwrap();
        assert_eq!(p.port, 3128);
    }

    // Docs §Configuration: a proxy URL without credentials works (no auth).
    // The CONNECT request must carry NO Proxy-Authorization header so an
    // unauthenticated forward proxy accepts it.
    #[tokio::test]
    async fn no_auth_proxy_tunnel_sends_no_auth_header() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Read the full CONNECT request header block.
            let mut buf = Vec::new();
            let mut one = [0u8; 1];
            loop {
                let n = s.read(&mut one).await.unwrap();
                if n == 0 {
                    return;
                }
                buf.push(one[0]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf).to_ascii_lowercase();
            // A no-auth proxy must receive no Proxy-Authorization header.
            assert!(
                !req.contains("proxy-authorization"),
                "unexpected auth header sent to no-auth proxy: {req}"
            );
            s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nOK")
                .await
                .unwrap();
        });

        // URL without credentials → auth is None.
        let cfg = ProxyConfig::parse_url(&format!("http://127.0.0.1:{}", addr.port())).unwrap();
        assert!(
            cfg.auth.is_none(),
            "no-credential URL must parse to auth=None"
        );

        let mut s = connect_through_proxy(&cfg, "studio.corp.com", 443, 5000)
            .await
            .expect("tunnel through no-auth proxy");
        let mut buf = [0u8; 8];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"OK");
    }

    // Docs §Authentication: credentials from URL; base64 Basic header.
    #[test]
    fn basic_auth_from_url() {
        let p = ProxyConfig::parse_url("http://user:pass@proxy.corp:3128").unwrap();
        let auth = p.auth.expect("auth parsed from URL");
        // base64("user:pass") = "dXNlcjpwYXNz"
        assert_eq!(auth.basic_header_value(), "Basic dXNlcjpwYXNz");
    }

    // Docs §Authentication: "Credentials are never logged — redacts to host:port
    // in all Debug/Display/error output."
    #[test]
    fn credentials_never_appear_in_any_output() {
        let p = ProxyConfig::parse_url("http://user:hunter2@proxy.corp:3128").unwrap();
        for s in [format!("{p}"), format!("{p:?}")] {
            assert!(!s.contains("hunter2"), "leaked password: {s}");
            assert!(!s.contains("user:hunter2"), "leaked userinfo: {s}");
        }
        // And in an error string built from the config (as the runtime does).
        let err = ConnectorError::ProxyAuthFailed(format!("proxy {p} returned 407"));
        assert!(!err.to_string().contains("hunter2"));
    }

    // Docs §Behavior under failure: the three documented error codes exist and
    // are all recoverable (so the reconnect loop retries indefinitely).
    #[test]
    fn documented_error_codes_exist_and_are_recoverable() {
        let cases = [
            (
                ConnectorError::ProxyUnreachable("x".into()),
                "PROXY_UNREACHABLE",
            ),
            (
                ConnectorError::ProxyConnectFailed("x".into()),
                "PROXY_CONNECT_FAILED",
            ),
            (
                ConnectorError::ProxyAuthFailed("x".into()),
                "PROXY_AUTH_FAILED",
            ),
        ];
        for (err, code) in cases {
            assert_eq!(err.code(), code);
            assert!(err.is_recoverable(), "{code} must be recoverable (retried)");
        }
    }

    // Edge: empty/blank STUDIO_PROXY (orchestrator `${PROXY:-}`) means "no proxy",
    // not a hard error.
    #[test]
    fn blank_explicit_proxy_is_treated_as_unset() {
        let env = |_k: &str| None;
        assert!(
            resolve_proxy("studio", true, Some(""), &env)
                .unwrap()
                .is_none()
        );
        assert!(
            resolve_proxy("studio", true, Some("   "), &env)
                .unwrap()
                .is_none()
        );
    }

    // Edge: blank env proxy var is ignored (curl-style "disable higher scope").
    #[test]
    fn blank_env_proxy_is_ignored() {
        let env = |k: &str| match k {
            "HTTPS_PROXY" => Some("".to_string()),
            _ => None,
        };
        assert!(resolve_proxy("studio", true, None, &env).unwrap().is_none());
    }

    // Edge: ALL_PROXY=socks5://… (unsupported scheme from env) → direct, not a
    // hard failure. Very common on hosts with a general SOCKS proxy set.
    #[test]
    fn unsupported_env_scheme_falls_through_to_direct() {
        let env = |k: &str| match k {
            "ALL_PROXY" => Some("socks5://socks.corp:1080".to_string()),
            _ => None,
        };
        assert!(resolve_proxy("studio", true, None, &env).unwrap().is_none());
    }

    // Edge: explicit STUDIO_PROXY with a bad scheme IS a hard error (operator
    // override should surface misconfig, not be silently dropped).
    #[test]
    fn explicit_bad_scheme_is_hard_error() {
        let env = |_k: &str| None;
        assert!(resolve_proxy("studio", true, Some("socks5://x:1080"), &env).is_err());
    }

    // Docs: https:// proxy URL selects proxy-over-TLS (TLS to the proxy hop).
    #[test]
    fn https_proxy_url_selects_tls() {
        let p = ProxyConfig::parse_url("https://proxy.corp:3128").unwrap();
        assert_eq!(p.scheme, ProxyScheme::Https);
        assert_eq!(p.host, "proxy.corp");
        assert_eq!(p.port, 3128);
        // http:// stays plaintext
        let h = ProxyConfig::parse_url("http://proxy.corp:3128").unwrap();
        assert_eq!(h.scheme, ProxyScheme::Http);
    }

    // Docs §NO_PROXY: Java/.NET `*.corp.com` wildcard form is honored.
    #[test]
    fn no_proxy_star_dot_form() {
        assert!(host_matches_no_proxy("studio.corp.com", "*.corp.com"));
        assert!(!host_matches_no_proxy("studio.other.com", "*.corp.com"));
    }

    // Edge: a stalled proxy (accepts TCP, never replies) must hit the deadline,
    // not hang forever.
    #[tokio::test]
    async fn stalled_proxy_times_out() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            // Never reply; hold the connection.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });
        let cfg = ProxyConfig {
            scheme: ProxyScheme::Http,
            host: "127.0.0.1".into(),
            port: addr.port(),
            auth: None,
        };
        let err = connect_through_proxy(&cfg, "studio.corp.com", 443, 300)
            .await
            .err()
            .expect("expected proxy connect to fail");
        assert_eq!(err.code(), "PROXY_CONNECT_FAILED");
        assert!(err.to_string().contains("timed out"));
    }

    // Docs §Observability: failure reasons map to stable low-cardinality labels.
    #[test]
    fn failure_reasons_are_stable_labels() {
        assert_eq!(
            proxy_failure_reason(&ConnectorError::ProxyUnreachable("x".into())),
            "unreachable"
        );
        assert_eq!(
            proxy_failure_reason(&ConnectorError::ProxyAuthFailed("x".into())),
            "auth"
        );
        assert_eq!(
            proxy_failure_reason(&ConnectorError::ProxyConnectFailed("x".into())),
            "connect_failed"
        );
        // Distinct reasons must have distinct codes (drives "log again on change").
        assert_ne!(reason_code("unreachable"), reason_code("auth"));
        assert_ne!(reason_code("auth"), reason_code("connect_failed"));
    }

    // Docs §Behavior under failure: a 502 from the proxy is classified as
    // connect_failed — the reason string that becomes the metric label and
    // drives the throttled-logging decision. (This asserts the classification,
    // not the counter value; the metrics facade has no test recorder wired up.)
    #[tokio::test]
    async fn proxy_502_classified_as_connect_failed() {
        use tokio::net::TcpListener;
        // A 502 from the proxy → ProxyConnectFailed, counted under reason=connect_failed.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await
                .unwrap();
        });
        let cfg = ProxyConfig {
            scheme: ProxyScheme::Http,
            host: "127.0.0.1".into(),
            port: addr.port(),
            auth: None,
        };
        let err = connect_through_proxy(&cfg, "studio.corp.com", 443, 5000)
            .await
            .err()
            .expect("expected proxy connect to fail");
        // Reason classification (the value behind the metric label) is correct.
        assert_eq!(proxy_failure_reason(&err), "connect_failed");
    }

    // Docs §Behavior under failure: a 407 maps to PROXY_AUTH_FAILED (end-to-end
    // through connect_through_proxy against a mock proxy).
    #[tokio::test]
    async fn proxy_407_surfaces_auth_failed_code() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let cfg = ProxyConfig {
            scheme: ProxyScheme::Http,
            host: "127.0.0.1".into(),
            port: addr.port(),
            auth: None,
        };
        let err = connect_through_proxy(&cfg, "studio.corp.com", 443, 5000)
            .await
            .err()
            .expect("expected proxy connect to fail");
        assert_eq!(err.code(), "PROXY_AUTH_FAILED");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_url_with_auth() {
        let p = ProxyConfig::parse_url("http://alice:secret@proxy.corp:3128").unwrap();
        assert_eq!(p.host, "proxy.corp");
        assert_eq!(p.port, 3128);
        let auth = p.auth.unwrap();
        // base64("alice:secret") = "YWxpY2U6c2VjcmV0"
        assert_eq!(auth.basic_header_value(), "Basic YWxpY2U6c2VjcmV0");
    }

    #[test]
    fn parses_url_without_auth_defaults_port() {
        let p = ProxyConfig::parse_url("http://proxy.corp").unwrap();
        assert_eq!(p.host, "proxy.corp");
        assert_eq!(p.port, 3128);
        assert!(p.auth.is_none());
    }

    #[test]
    fn rejects_bad_scheme() {
        assert!(ProxyConfig::parse_url("ftp://proxy.corp:3128").is_err());
    }

    #[test]
    fn redacts_credentials_in_debug_and_display() {
        let p = ProxyConfig::parse_url("http://alice:secret@proxy.corp:3128").unwrap();
        let dbg = format!("{p:?}");
        let disp = format!("{p}");
        assert!(!dbg.contains("secret"), "debug leaked password: {dbg}");
        assert!(!disp.contains("secret"), "display leaked password: {disp}");
        assert!(!dbg.contains("alice:secret"));
    }

    #[test]
    fn no_proxy_exact_and_suffix_and_wildcard() {
        assert!(host_matches_no_proxy("studio.corp.com", "studio.corp.com"));
        assert!(host_matches_no_proxy("studio.corp.com", ".corp.com"));
        assert!(host_matches_no_proxy("studio.corp.com", "corp.com"));
        assert!(host_matches_no_proxy("anything", "*"));
        assert!(host_matches_no_proxy("localhost", "localhost"));
        assert!(!host_matches_no_proxy("studio.corp.com", "other.com"));
        assert!(host_matches_no_proxy("studio.corp.com:443", ".corp.com"));
        assert!(host_matches_no_proxy(
            "studio.corp.com",
            "a.com, .corp.com ,b.com"
        ));
    }

    #[test]
    fn resolve_prefers_explicit_then_env() {
        let env = |_k: &str| None;
        let p = resolve_proxy("studio.corp.com", true, Some("http://p1:3128"), &env)
            .unwrap()
            .unwrap();
        assert_eq!(p.host, "p1");
    }

    #[test]
    fn resolve_uses_https_proxy_for_tls_target() {
        let env = |k: &str| match k {
            "HTTPS_PROXY" => Some("http://secure:8080".to_string()),
            "HTTP_PROXY" => Some("http://plain:3128".to_string()),
            _ => None,
        };
        let p = resolve_proxy("studio.corp.com", true, None, &env)
            .unwrap()
            .unwrap();
        assert_eq!(p.host, "secure");
    }

    #[test]
    fn resolve_returns_none_when_no_proxy_matches() {
        let env = |k: &str| match k {
            "HTTPS_PROXY" => Some("http://secure:8080".to_string()),
            "NO_PROXY" => Some(".corp.com".to_string()),
            _ => None,
        };
        let r = resolve_proxy("studio.corp.com", true, None, &env).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn resolve_returns_none_when_unset() {
        let env = |_k: &str| None;
        assert!(
            resolve_proxy("studio.corp.com", true, None, &env)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn split_host_port_variants() {
        assert_eq!(split_host_port("studio:443"), ("studio".into(), Some(443)));
        assert_eq!(split_host_port("studio"), ("studio".into(), None));
        // Bracketed IPv6 with and without port.
        assert_eq!(split_host_port("[::1]:443"), ("::1".into(), Some(443)));
        assert_eq!(
            split_host_port("[2001:db8::1]"),
            ("2001:db8::1".into(), None)
        );
        // Bare IPv6 literal → host-only, never split at an address colon.
        assert_eq!(split_host_port("2001:db8::1"), ("2001:db8::1".into(), None));
    }

    #[test]
    fn parses_bracketed_ipv6_proxy_url() {
        let p = ProxyConfig::parse_url("http://[::1]:3128").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 3128);
    }

    #[test]
    fn rejects_non_numeric_port() {
        assert!(ProxyConfig::parse_url("http://proxy:abc").is_err());
    }

    #[test]
    fn parses_200_established() {
        let resp = b"HTTP/1.1 200 Connection Established\r\nVia: x\r\n\r\n";
        assert!(matches!(
            parse_connect_status(resp),
            ConnectStatus::Established
        ));
    }

    #[test]
    fn parses_http10_200() {
        let resp = b"HTTP/1.0 200 OK\r\n\r\n";
        assert!(matches!(
            parse_connect_status(resp),
            ConnectStatus::Established
        ));
    }

    #[test]
    fn parses_407() {
        let resp = b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
        assert!(matches!(
            parse_connect_status(resp),
            ConnectStatus::AuthRequired
        ));
    }

    #[test]
    fn parses_502_failed() {
        let resp = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";
        assert!(matches!(
            parse_connect_status(resp),
            ConnectStatus::Failed(_)
        ));
    }

    #[test]
    fn incomplete_without_terminator() {
        let resp = b"HTTP/1.1 200 Connection Esta";
        assert!(matches!(
            parse_connect_status(resp),
            ConnectStatus::Incomplete
        ));
    }

    #[tokio::test]
    async fn tunnel_succeeds_and_preserves_leftover_bytes() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(
                req.starts_with("CONNECT studio.example:443 HTTP/1.1\r\n"),
                "got: {req}"
            );
            assert!(req.contains("Host: studio.example:443\r\n"));
            s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nLEFTOVER")
                .await
                .unwrap();
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
        });

        let cfg = ProxyConfig {
            scheme: ProxyScheme::Http,
            host: "127.0.0.1".into(),
            port: addr.port(),
            auth: None,
        };
        let mut stream = connect_through_proxy(&cfg, "studio.example", 443, 5000)
            .await
            .unwrap();
        let mut got = [0u8; 8];
        let n = stream.read(&mut got).await.unwrap();
        assert_eq!(&got[..n], b"LEFTOVER");
    }

    #[tokio::test]
    async fn tunnel_407_maps_to_auth_failed() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let cfg = ProxyConfig {
            scheme: ProxyScheme::Http,
            host: "127.0.0.1".into(),
            port: addr.port(),
            auth: None,
        };
        let err = connect_through_proxy(&cfg, "studio.example", 443, 5000)
            .await
            .err()
            .expect("expected proxy connect to fail");
        assert_eq!(err.code(), "PROXY_AUTH_FAILED");
    }
}

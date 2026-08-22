//! One-Time Token (OTT) authentication provider for secure connector authentication.
//!
//! This module supports 4 deployment options:
//!
//! 1. PRE-APPROVAL (OTT): Admin creates OTT → Connector uses it to register
//!    - Set STRIKE48_REGISTRATION_TOKEN or STRIKE48_REGISTRATION_TOKEN_FILE
//!    - Connector generates keypair and registers with public key
//!
//! 2. POST-APPROVAL: Connector connects → Admin approves → OTT via gRPC stream
//!    - No env vars needed, credentials issued after approval
//!
//! 3. K8S CERT-MANAGER: cert-manager creates keypair → All pods share it
//!    - Set STRIKE48_PRIVATE_KEY_PATH to the mounted secret path
//!    - Set STRIKE48_CLIENT_ID to the pre-configured client ID
//!    - Set STRIKE48_AUTH_URL to the auth realm URL
//!
//! 4. DIRECT AUTH: Operator creates auth client directly
//!    - Set STRIKE48_PRIVATE_KEY_PATH to the private key file
//!    - Set STRIKE48_CLIENT_ID to the auth client ID
//!    - Set STRIKE48_AUTH_URL to the auth realm URL

use crate::error::{ConnectorError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

/// Default retry configuration for HTTP requests
const MAX_RETRIES: u32 = 3;
const INITIAL_RETRY_DELAY_MS: u64 = 500;
const MAX_RETRY_DELAY_MS: u64 = 5000;

const DEFAULT_OTT_PATHS: &[&str] = &[
    "/var/run/secrets/matrix/registration-token",
    ".matrix/registration-token",
];

const DEFAULT_PRIVATE_KEY_PATHS: &[&str] = &[
    "/var/run/secrets/matrix/connector-key.pem",
    "/var/run/secrets/matrix/tls.key",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OttData {
    token: String,
    #[serde(rename = "matrix_url")]
    api_url: Option<String>,
    #[serde(rename = "keycloak_url")]
    auth_url: Option<String>,
    #[serde(rename = "expires_at")]
    expires_at: Option<String>,
    #[serde(rename = "connector_type")]
    connector_type: Option<String>,
    #[serde(rename = "tenant_id")]
    tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    #[serde(rename = "client_id")]
    pub client_id: String,
    #[serde(rename = "keycloak_url")]
    pub auth_url: String,
    #[serde(rename = "tenant_id")]
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

#[derive(Debug, Clone)]
struct DirectConfig {
    private_key_path: String,
    client_id: String,
    auth_url: String,
}

/// Level at which a caller should emit a note from
/// [`OttProvider::resolve_register_base_verbose`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallbackNote {
    Info,
    Warn,
}

/// Resolved OTT callback base plus pre-formatted diagnostics for the caller to
/// emit through its own logger. `None` when no source yielded a base.
pub(crate) type ResolvedCallbackBase = Option<(String, Vec<(CallbackNote, String)>)>;

pub struct OttProvider {
    api_url: Option<String>,
    keys_dir: PathBuf,
    credentials_dir: PathBuf,
    /// Private key PEM string (RSA PKCS#1, RSA PKCS#8, or EC PKCS#8)
    private_key_pem: Option<String>,
    credentials: Option<Credentials>,
    access_token: Option<String>,
    token_expires_at: Option<u64>,
    connector_type: Option<String>,
    instance_id: Option<String>,
    direct_config: Option<DirectConfig>,
    http_client: Client,
}

impl OttProvider {
    pub fn new(connector_type: Option<String>, instance_id: Option<String>) -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let keys_dir =
            std::env::var("STRIKE48_KEYS_DIR").unwrap_or_else(|_| format!("{home}/.strike48/keys"));
        let credentials_dir = format!("{home}/.strike48/credentials");

        let api_url = std::env::var("STRIKE48_API_URL").ok();

        // Check for direct configuration
        let direct_config = Self::load_direct_config();

        // Build the HTTP client used for the OTT registration POST and the
        // Keycloak JWT exchange. `build_http_client` routes through the
        // configured proxy (if any) and applies the SDK's standard TLS config
        // (MATRIX_TLS_INSECURE / MATRIX_TLS_CA_CERT) — so these calls go through
        // the same proxy and trust the same CA as the studio transport.
        // Built once and reused (owns a connection pool). The target host for
        // NO_PROXY matching is the studio API URL when known, else Keycloak is
        // resolved per-request via reqwest's NoProxy.
        let http_target = api_url
            .clone()
            .unwrap_or_else(|| "https://studio".to_string());
        let http_client = crate::transport::proxy::build_http_client(&http_target);

        Self {
            api_url,
            keys_dir: PathBuf::from(keys_dir),
            credentials_dir: PathBuf::from(credentials_dir),
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type,
            instance_id,
            direct_config,
            http_client,
        }
    }

    fn load_direct_config() -> Option<DirectConfig> {
        let private_key_path = std::env::var("STRIKE48_PRIVATE_KEY_PATH")
            .ok()
            .or_else(Self::find_default_private_key)?;

        let client_id = std::env::var("STRIKE48_CLIENT_ID").ok()?;
        let auth_url = std::env::var("STRIKE48_AUTH_URL").ok()?;

        if Path::new(&private_key_path).exists() {
            Some(DirectConfig {
                private_key_path,
                client_id,
                auth_url,
            })
        } else {
            None
        }
    }

    fn find_default_private_key() -> Option<String> {
        for path in DEFAULT_PRIVATE_KEY_PATHS {
            if Path::new(path).exists() {
                return Some(path.to_string());
            }
        }
        None
    }

    pub fn has_direct_config(&self) -> bool {
        self.direct_config.is_some()
    }

    pub fn initialize_from_direct_config(&mut self) -> Result<Credentials> {
        let config = self.direct_config.as_ref().ok_or_else(|| {
            ConnectorError::InvalidConfig("Direct config not available".to_string())
        })?;

        self.private_key_pem = Some(Self::load_private_key_from_path(&config.private_key_path)?);

        let tenant_id = std::env::var("TENANT_ID").map_err(|_| {
            ConnectorError::InvalidConfig(
                "TENANT_ID is required for direct-config auth".to_string(),
            )
        })?;
        let credentials = Credentials {
            client_id: config.client_id.clone(),
            auth_url: config.auth_url.clone(),
            tenant_id,
            kid: None,
        };

        self.credentials = Some(credentials.clone());
        Ok(credentials)
    }

    pub fn has_ott(&self) -> bool {
        self.load_ott().is_some()
    }

    /// Resolve the base URL this connector POSTs its OTT registration to.
    ///
    /// The connector — never the server — decides where its own credentials
    /// go. Precedence:
    ///
    /// 1. `configured` (`STRIKE48_API_URL`): the explicit operator override.
    /// 2. `dialed_host`: the host this connector actually connected to. This is
    ///    per-connector by construction, so N connectors pointed at N tenants
    ///    each call back to their own tenant host.
    /// 3. `server_supplied` (`CredentialsIssued.matrix_api_url`): last resort.
    ///
    /// Why the server value cannot lead: in a multi-tenant studio it is a
    /// single global fallback that cannot name each tenant's host, and it
    /// degrades to a `http://localhost:4001` placeholder when the deployment
    /// has not configured one. Following it either strands the connector or,
    /// worse, points a credential exchange at an unrelated local listener.
    ///
    /// Returns `None` only when every source is empty.
    ///
    /// # Errors
    ///
    /// Returns an error when `configured` is non-empty but is not a valid
    /// HTTP(S) URL. The override is *authoritative* — it decides where
    /// credentials go — so a typo must fail loudly here rather than surface
    /// later as an opaque "relative URL without a base" from the HTTP client.
    pub(crate) fn resolve_register_base(
        configured: Option<&str>,
        dialed_host: Option<&str>,
        use_tls: bool,
        server_supplied: &str,
    ) -> Result<Option<String>> {
        let clean = |s: &str| {
            let t = s.trim().trim_end_matches('/');
            (!t.is_empty()).then(|| t.to_string())
        };

        if let Some(base) = configured.and_then(clean) {
            // Validate before trusting it: `parse_origin` accepts only
            // http/https with a host, which is exactly what the caller needs to
            // build `{base}{path}`.
            if parse_origin(&base).is_none() {
                return Err(ConnectorError::InvalidConfig(format!(
                    "STRIKE48_API_URL is not a valid HTTP(S) URL: {base:?} \
                     (expected e.g. \"https://studio.example.com\")"
                )));
            }
            return Ok(Some(base));
        }
        if let Some(base) = dialed_host.and_then(|h| Self::derive_api_base(h, use_tls)) {
            return Ok(Some(base));
        }
        // Last resort: the server-advertised value. Validate it through
        // `parse_origin` exactly like the operator override above — otherwise a
        // malformed or non-HTTP(S) `matrix_api_url` would flow into
        // `enforce_same_origin` where, with no `STRIKE48_API_URL` set, it is
        // only ever compared against itself (a trivial pass). Refusing here
        // means an unusable server value fails loud instead of being POSTed to.
        match clean(server_supplied) {
            Some(base) => {
                if parse_origin(&base).is_none() {
                    return Err(ConnectorError::InvalidConfig(format!(
                        "server-advertised matrix_api_url is not a valid HTTP(S) URL: {base:?}"
                    )));
                }
                Ok(Some(base))
            }
            None => Ok(None),
        }
    }

    /// [`Self::resolve_register_base`] plus the diagnostics every call site
    /// wants to log, so the three OTT paths (single runner, gRPC multi-runner,
    /// WS multiplex) cannot drift in what they resolve *or* what they report.
    ///
    /// Returns `Ok(None)` when no source yields a base. Notes are pre-formatted
    /// messages the caller emits through its own logger (each has a different
    /// prefix), paired with the level to emit them at.
    pub(crate) fn resolve_register_base_verbose(
        configured: Option<&str>,
        dialed_host: Option<&str>,
        use_tls: bool,
        server_supplied: &str,
    ) -> Result<ResolvedCallbackBase> {
        let Some(base) =
            Self::resolve_register_base(configured, dialed_host, use_tls, server_supplied)?
        else {
            return Ok(None);
        };

        let mut notes = Vec::new();

        // Diverging from what the server asked for is worth surfacing at info,
        // not debug: it is the whole behaviour change, and when the server
        // advertised a localhost placeholder it is also a security-relevant
        // redirect an operator should be able to see in normal logs.
        let advertised = server_supplied.trim().trim_end_matches('/');
        if !advertised.is_empty() && advertised != base {
            notes.push((
                CallbackNote::Info,
                format!(
                    "OTT callback base overridden: server advertised {advertised:?}, using {base:?}"
                ),
            ));
        }

        // The derivation assumes the HTTP API is co-located with the transport.
        // A retained non-default port is where that is most likely wrong (gRPC
        // on :50051, HTTP API on :443), and the operator cannot be rescued by
        // the server value since the dialed host outranks it.
        if configured.is_none_or(|c| c.trim().is_empty())
            && let Some(host) = dialed_host
            && let Some((_, kept_port)) = Self::derive_api_base_checked(host, use_tls)
            && kept_port
        {
            notes.push((
                CallbackNote::Warn,
                format!(
                    "OTT callback base {base:?} was derived from the dialed transport endpoint \
                     and kept its non-default port. If this deployment serves the HTTP API on a \
                     different port than the transport, set STRIKE48_API_URL explicitly."
                ),
            ));
        }

        // Provenance of the resolved base decides how loudly to flag it. The
        // dialed-host path is the intended default and needs no warning; the
        // two risky provenances do:
        //   * base came straight from the server-advertised value (no override,
        //     no derivable dialed host) — it is NOT pinned by STRIKE48_API_URL,
        //     so the same-origin check downstream degrades to a self-compare.
        //   * base resolves to a loopback origin — the server almost certainly
        //     advertised a placeholder (matrix#3695 `localhost:4001`); POSTing
        //     credentials there hits the connector's own host.
        // These are emitted at Warn so they survive the SDK's default
        // (warn-level) EnvFilter, unlike the Info override note above.
        let from_override = configured.is_some_and(|c| !c.trim().is_empty());
        let from_dialed = !from_override
            && dialed_host.is_some_and(|h| Self::derive_api_base(h, use_tls).is_some());
        let from_server = !from_override && !from_dialed;

        if from_server {
            notes.push((
                CallbackNote::Warn,
                format!(
                    "OTT callback base {base:?} came from the server-advertised value and is                      NOT pinned by STRIKE48_API_URL; the destination is only self-validated.                      Set STRIKE48_API_URL to enforce an independent origin allowlist."
                ),
            ));
        }

        if parse_origin(&base).is_some_and(|(_, host, _)| Self::is_loopback_host(&host)) {
            notes.push((
                CallbackNote::Warn,
                format!(
                    "OTT callback base {base:?} is a loopback origin — the server likely                      advertised a placeholder. Credentials would be POSTed to this host;                      set STRIKE48_API_URL or fix the tenant's callback host."
                ),
            ));
        }

        Ok(Some((base, notes)))
    }

    /// True when `host` is a loopback name/address (registration to it means the
    /// server advertised a placeholder rather than a reachable tenant host).
    fn is_loopback_host(host: &str) -> bool {
        let h = host.trim().trim_start_matches('[').trim_end_matches(']');
        h.eq_ignore_ascii_case("localhost") || h == "::1" || h.starts_with("127.")
    }

    /// Turn a connector host into its HTTP(S) API base.
    ///
    /// Accepts either a full connector URL (`wss://connectors-studio.example.com:443`)
    /// or the bare `host:port` the client stores after [`crate::parse_url`]
    /// (which always carries an explicit port — see `ParsedEndpoint::host_port`).
    /// Strips the transport scheme, drops a leading `connectors-` label, and
    /// removes the scheme's default port so the `Host` header stays clean for
    /// hostname-based gateway routing.
    ///
    /// An explicitly secure input (`wss://`/`https://`/`grpcs://`) is never
    /// downgraded by `use_tls: false`.
    ///
    /// # Assumption: the HTTP API is co-located with the transport
    ///
    /// A non-default port is **carried through**, because the common deployment
    /// puts transport and HTTP API behind one ingress (`wss://host:443` →
    /// `https://host`). Deployments that split them — gRPC on `:50051`, the HTTP
    /// API on `:443` — derive an unreachable base; those must set
    /// `STRIKE48_API_URL`. [`Self::derive_api_base_checked`] surfaces that case
    /// so the caller can warn instead of failing silently.
    ///
    /// The `connectors-` strip encodes a **deployment naming convention** (a
    /// `connectors-` ingress label fronting the same studio), not a general
    /// rule. It mirrors pick's `derive_api_url` so both ends agree. A host whose
    /// real name legitimately begins with `connectors-` is rewritten by it and
    /// needs `STRIKE48_API_URL`.
    pub(crate) fn derive_api_base(host: &str, use_tls: bool) -> Option<String> {
        Self::derive_api_base_checked(host, use_tls).map(|(base, _)| base)
    }

    /// [`Self::derive_api_base`], additionally reporting whether the derived
    /// base kept a non-default port — the case where the co-location
    /// assumption above is most likely to be wrong.
    pub(crate) fn derive_api_base_checked(host: &str, use_tls: bool) -> Option<(String, bool)> {
        const SCHEMES: [&str; 6] = [
            "grpcs://", "grpc://", "https://", "http://", "wss://", "ws://",
        ];
        const SECURE: [&str; 3] = ["wss://", "https://", "grpcs://"];

        let trimmed = host.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.is_empty() {
            return None;
        }

        let secure = SECURE.iter().any(|p| lower.starts_with(p));
        let mut bare = trimmed;
        for p in SCHEMES {
            if lower.starts_with(p) {
                bare = &trimmed[p.len()..];
                break;
            }
        }

        let authority = bare.split('/').next().unwrap_or(bare);
        let scheme = if use_tls || secure { "https" } else { "http" };
        let default_port: u16 = if scheme == "https" { 443 } else { 80 };

        // Split IPv6-aware: a naive `strip_suffix(":443")` turns the bare
        // literal `2001:db8::443` into `2001:db8:`.
        let (host_only, port) = crate::transport::proxy::split_host_port(authority);
        let host_only = host_only
            .strip_prefix("connectors-")
            .unwrap_or(&host_only)
            .to_string();
        if host_only.is_empty() {
            return None;
        }

        // Re-bracket an IPv6 literal so the result is a parseable URL.
        let host_part = if host_only.contains(':') && !host_only.starts_with('[') {
            format!("[{host_only}]")
        } else {
            host_only
        };

        match port {
            Some(p) if p != default_port => Some((format!("{scheme}://{host_part}:{p}"), true)),
            _ => Some((format!("{scheme}://{host_part}"), false)),
        }
    }

    /// Validate that a server-supplied registration URL points at the
    /// configured Matrix API origin (scheme + host + port).
    ///
    /// - When `configured` is `Some` (i.e. `STRIKE48_API_URL` is set),
    ///   the call only succeeds if `target` shares the configured origin.
    /// - When `configured` is `None` (dev / local CLI usage), a `warn!`
    ///   is emitted and validation is skipped. Production deployments
    ///   should always set `STRIKE48_API_URL`.
    pub(crate) fn validate_register_origin(target: &str, configured: Option<&str>) -> Result<()> {
        let configured = match configured {
            Some(c) if !c.trim().is_empty() => c,
            _ => {
                tracing::warn!(
                    "STRIKE48_API_URL is not configured; skipping the OTT register-URL \
                     allowlist check against it. The resolved callback base is still \
                     enforced (see `enforce_same_origin`); set STRIKE48_API_URL to pin \
                     the origin explicitly."
                );
                return Ok(());
            }
        };
        Self::enforce_same_origin(target, configured, "STRIKE48_API_URL")
    }

    /// Refuse to POST credentials anywhere but `allowed`'s origin.
    ///
    /// `source` names where `allowed` came from, so the error tells an operator
    /// which knob to turn (`STRIKE48_API_URL` vs. the resolved callback base).
    pub(crate) fn enforce_same_origin(target: &str, allowed: &str, source: &str) -> Result<()> {
        let target_origin = parse_origin(target).ok_or_else(|| {
            ConnectorError::InvalidConfig(format!(
                "OTT register URL is not a valid HTTP(S) URL: {target}"
            ))
        })?;
        let allowed_origin = parse_origin(allowed).ok_or_else(|| {
            ConnectorError::InvalidConfig(format!("{source} is not a valid HTTP(S) URL: {allowed}"))
        })?;

        if target_origin == allowed_origin {
            Ok(())
        } else {
            Err(ConnectorError::InvalidConfig(format!(
                "OTT register URL origin {target_origin:?} does not match \
                 {source} origin {allowed_origin:?}; refusing to send \
                 credentials to an unapproved host"
            )))
        }
    }

    fn load_ott(&self) -> Option<OttData> {
        // Priority 1: Inline environment variable
        if let Ok(ott_value) = std::env::var("STRIKE48_REGISTRATION_TOKEN") {
            return Self::parse_ott(&ott_value);
        }

        // Priority 2: File path from environment
        if let Ok(ott_file) = std::env::var("STRIKE48_REGISTRATION_TOKEN_FILE")
            && Path::new(&ott_file).exists()
        {
            return Self::load_ott_from_file(&ott_file);
        }

        // Priority 3: Default paths
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        for ott_path in DEFAULT_OTT_PATHS {
            let full_path = if ott_path.starts_with('/') {
                ott_path.to_string()
            } else {
                format!("{home}/{ott_path}")
            };
            if Path::new(&full_path).exists() {
                return Self::load_ott_from_file(&full_path);
            }
        }

        None
    }

    fn load_ott_from_file(file_path: &str) -> Option<OttData> {
        fs::read_to_string(file_path)
            .ok()
            .map(|content| content.trim().to_string())
            .and_then(|content| Self::parse_ott(&content))
    }

    fn parse_ott(value: &str) -> Option<OttData> {
        // Try direct JSON parse first
        if value.starts_with('{') {
            return serde_json::from_str(value).ok();
        }

        // Try base64 decode
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        if let Ok(decoded) = STANDARD.decode(value)
            && let Ok(utf8) = String::from_utf8(decoded)
            && let Ok(ott_data) = serde_json::from_str::<OttData>(&utf8)
        {
            return Some(ott_data);
        }

        // Assume it's just the token string
        Some(OttData {
            token: value.to_string(),
            api_url: None,
            auth_url: None,
            expires_at: None,
            connector_type: None,
            tenant_id: None,
        })
    }

    fn get_private_key_path(&self, connector_type: &str, instance_id: Option<&str>) -> PathBuf {
        let filename = format!(
            "{}_{}.pem",
            connector_type,
            instance_id.unwrap_or("default")
        );
        self.keys_dir.join(filename)
    }

    pub async fn register_with_ott(
        &mut self,
        connector_type: &str,
        instance_id: Option<&str>,
    ) -> Result<Credentials> {
        let ott_data = self
            .load_ott()
            .ok_or_else(|| ConnectorError::InvalidConfig("No OTT found".to_string()))?;

        // Get or generate keypair for private_key_jwt authentication
        let public_key_pem = self
            .get_or_create_keypair_for_connector(connector_type, instance_id)
            .await?;

        // Register with Strike48 API
        let api_url = ott_data
            .api_url
            .as_ref()
            .or(self.api_url.as_ref())
            .ok_or_else(|| ConnectorError::InvalidConfig("API URL not configured".to_string()))?;

        let register_url = format!("{api_url}/api/connectors/register-with-ott");

        // Pre-approval parity with the post-approval path: `api_url` here comes
        // from the staged OTT blob (`ott_data.api_url`) or `self.api_url`, so a
        // tampered blob could redirect this token + public-key POST anywhere.
        // Enforce the operator's `STRIKE48_API_URL` origin allowlist when set
        // (a no-op warn when unset, since the OTT blob is operator-staged in the
        // normal case — the env var is the defence-in-depth pin).
        let configured_api_url = std::env::var("STRIKE48_API_URL").ok();
        Self::validate_register_origin(&register_url, configured_api_url.as_deref())?;

        // Build payload with public key for private_key_jwt authentication
        let payload = serde_json::json!({
            "token": ott_data.token,
            "public_key": public_key_pem,
            "connector_type": connector_type,
            "instance_id": instance_id,
        });

        let response = self
            .http_client
            .post(&register_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| ConnectorError::ConnectionError(format!("HTTP request failed: {e}")))?;

        if response.status().is_success() {
            let credentials: Credentials = response.json().await.map_err(|e| {
                ConnectorError::SerializationError(format!("Failed to parse response: {e}"))
            })?;

            self.save_credentials(connector_type, instance_id, &credentials)?;
            self.credentials = Some(credentials.clone());
            Ok(credentials)
        } else if response.status() == 401 {
            Err(ConnectorError::InvalidConfig(
                "Invalid or expired OTT".to_string(),
            ))
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(ConnectorError::RegistrationError(format!(
                "OTT registration failed: {error_text}"
            )))
        }
    }

    async fn get_or_create_keypair_for_connector(
        &mut self,
        connector_type: &str,
        instance_id: Option<&str>,
    ) -> Result<String> {
        let key_path = self.get_private_key_path(connector_type, instance_id);

        if key_path.exists() {
            let pem = fs::read_to_string(&key_path)
                .map_err(|e| std::io::Error::other(format!("Failed to read private key: {e}")))?;

            // Try to extract EC public key from existing key
            if let Ok(public_key_pem) = Self::extract_ec_public_key_pem(&pem) {
                self.private_key_pem = Some(pem);
                self.connector_type = Some(connector_type.to_string());
                self.instance_id = instance_id.map(|s| s.to_string());
                return Ok(public_key_pem);
            }

            // Legacy RSA key — generate new EC key for re-registration
            tracing::info!(
                "Upgrading legacy RSA key to EC P-256 for connector {}",
                connector_type
            );
        }

        // Generate new EC P-256 keypair
        let (private_pem, public_pem) = Self::generate_ec_keypair()?;

        // Save private key
        if !self.keys_dir.exists() {
            fs::create_dir_all(&self.keys_dir).map_err(|e| {
                std::io::Error::other(format!("Failed to create keys directory: {e}"))
            })?;
        }

        fs::write(&key_path, private_pem.as_bytes())
            .map_err(|e| std::io::Error::other(format!("Failed to write private key: {e}")))?;

        // Set permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_path, perms)?;
        }

        self.private_key_pem = Some(private_pem);
        self.connector_type = Some(connector_type.to_string());
        self.instance_id = instance_id.map(|s| s.to_string());

        Ok(public_pem)
    }

    fn load_private_key_from_path(key_path: &str) -> Result<String> {
        let pem = fs::read_to_string(key_path)
            .map_err(|e| std::io::Error::other(format!("Failed to read private key: {e}")))?;

        // Validate it looks like a PEM key
        if !pem.contains("BEGIN") || !pem.contains("PRIVATE KEY") {
            return Err(ConnectorError::InvalidConfig(
                "File does not contain a PEM private key".to_string(),
            ));
        }

        Ok(pem)
    }

    /// Generate a new EC P-256 keypair, returning (private_pem, public_pem).
    fn generate_ec_keypair() -> Result<(String, String)> {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};

        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| ConnectorError::Other(format!("Failed to generate EC keypair: {e}")))?;

        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_doc.as_ref()).map_err(
                |e| ConnectorError::Other(format!("Failed to parse generated keypair: {e}")),
            )?;

        let private_pem = Self::der_to_pem(pkcs8_doc.as_ref(), "PRIVATE KEY");
        let public_key_bytes = key_pair.public_key().as_ref();
        let spki_der = Self::ec_p256_public_key_to_spki(public_key_bytes);
        let public_pem = Self::der_to_pem(&spki_der, "PUBLIC KEY");

        Ok((private_pem, public_pem))
    }

    /// Try to extract an EC public key PEM from a PKCS#8 private key PEM.
    /// Returns Err if the key is not a valid EC P-256 PKCS#8 key.
    fn extract_ec_public_key_pem(private_key_pem: &str) -> Result<String> {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};

        let der = Self::pem_to_der(private_key_pem)?;
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &der)
            .map_err(|e| ConnectorError::Other(format!("Not a valid EC P-256 key: {e}")))?;

        let public_key_bytes = key_pair.public_key().as_ref();
        let spki_der = Self::ec_p256_public_key_to_spki(public_key_bytes);
        Ok(Self::der_to_pem(&spki_der, "PUBLIC KEY"))
    }

    /// Build the SPKI (SubjectPublicKeyInfo) DER encoding for a P-256 public key.
    fn ec_p256_public_key_to_spki(public_key_bytes: &[u8]) -> Vec<u8> {
        // Fixed ASN.1 prefix for P-256 SPKI:
        //   SEQUENCE { SEQUENCE { OID ecPublicKey, OID P-256 }, BIT STRING { ... } }
        let prefix: &[u8] = &[
            0x30, 0x59, // SEQUENCE (89 bytes)
            0x30, 0x13, // SEQUENCE (19 bytes) — AlgorithmIdentifier
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
            0x07, // OID 1.2.840.10045.3.1.7
            0x03, 0x42, 0x00, // BIT STRING (66 bytes, 0 unused bits)
        ];
        let mut spki = Vec::with_capacity(prefix.len() + public_key_bytes.len());
        spki.extend_from_slice(prefix);
        spki.extend_from_slice(public_key_bytes);
        spki
    }

    /// Convert DER bytes to PEM format with the given label.
    fn der_to_pem(der: &[u8], label: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let b64 = STANDARD.encode(der);
        let mut pem = format!("-----BEGIN {label}-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str(&format!("-----END {label}-----\n"));
        pem
    }

    /// Decode a PEM string to DER bytes (strips headers, base64-decodes).
    fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let b64: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        STANDARD
            .decode(&b64)
            .map_err(|e| ConnectorError::Other(format!("Failed to decode PEM: {e}")))
    }

    pub fn load_saved_credentials(
        &mut self,
        connector_type: &str,
        instance_id: Option<&str>,
    ) -> Option<Credentials> {
        let filename = format!(
            "{}_{}.json",
            connector_type,
            instance_id.unwrap_or("default")
        );
        let filepath = self.credentials_dir.join(&filename);

        tracing::debug!("Looking for saved credentials at: {}", filepath.display());

        if filepath.exists() {
            tracing::debug!("Credentials file found, loading...");
            if let Ok(data) = fs::read_to_string(&filepath) {
                if let Ok(creds) = serde_json::from_str::<Credentials>(&data) {
                    tracing::debug!(
                        "Loaded credentials from {}: client_id={}",
                        filepath.display(),
                        creds.client_id
                    );
                    self.credentials = Some(creds.clone());
                    return Some(creds);
                } else {
                    tracing::warn!(
                        "Failed to parse credentials JSON from {}",
                        filepath.display()
                    );
                }
            } else {
                tracing::warn!("Failed to read credentials file: {}", filepath.display());
            }
        } else {
            tracing::debug!("Credentials file not found: {}", filepath.display());
        }

        None
    }

    fn save_credentials(
        &self,
        connector_type: &str,
        instance_id: Option<&str>,
        credentials: &Credentials,
    ) -> Result<()> {
        if !self.credentials_dir.exists() {
            fs::create_dir_all(&self.credentials_dir).map_err(|e| {
                std::io::Error::other(format!("Failed to create credentials directory: {e}"))
            })?;
        }

        let filename = format!(
            "{}_{}.json",
            connector_type,
            instance_id.unwrap_or("default")
        );
        let filepath = self.credentials_dir.join(filename);

        let json = serde_json::to_string_pretty(credentials).map_err(|e| {
            ConnectorError::SerializationError(format!("Failed to serialize credentials: {e}"))
        })?;

        fs::write(&filepath, json)
            .map_err(|e| std::io::Error::other(format!("Failed to write credentials: {e}")))?;

        // Credential JSON files contain the Keycloak `client_id` and the
        // tenant the connector authenticates as. They live alongside the
        // private key under `~/.strike48/credentials`; tighten the mode so
        // only the owning user can read them, matching the private key.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&filepath)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&filepath, perms)?;
        }

        Ok(())
    }

    pub async fn register_public_key_with_ott_data(
        &mut self,
        ott: &str,
        api_url: &str,
        register_url: &str,
        connector_type: &str,
        instance_id: Option<&str>,
    ) -> Result<Credentials> {
        // Ensure we have a keypair
        let public_key_pem = self
            .get_or_create_keypair_for_connector(connector_type, instance_id)
            .await?;

        // Build full URL. `register_url` is documented as a *path*
        // (connector_service.proto: "URL path for OTT registration"), but the
        // server can send an absolute URL, in which case it names the host
        // itself and `api_url` is bypassed entirely.
        let full_url = if register_url.starts_with("http") {
            register_url.to_string()
        } else {
            format!("{}{}", api_url.trim_end_matches('/'), register_url)
        };

        // Defence-in-depth: `register_url` comes from a `CredentialsIssued`
        // server message. A compromised or misconfigured server could name an
        // attacker-controlled host and receive this connector's OTT and public
        // key.
        //
        // The allowlist origin is `api_url` — the base the *caller* resolved
        // (operator override → dialed host → server value; see
        // `resolve_register_base`) — NOT `STRIKE48_API_URL` directly. That
        // matters: the override is frequently unset now that the dialed host
        // serves as the default, and gating on the env var alone would leave an
        // absolute server-supplied `register_url` completely unchecked in the
        // common configuration. Validating against the resolved base means the
        // connector, not the server, decides the destination in every config.
        //
        // `STRIKE48_API_URL` is still consulted as a second, independent
        // constraint when set, so an explicit operator allowlist keeps its
        // meaning even if the resolved base came from elsewhere.
        Self::enforce_same_origin(&full_url, api_url, "the resolved OTT callback base")?;
        let configured_api_url = std::env::var("STRIKE48_API_URL").ok();
        Self::validate_register_origin(&full_url, configured_api_url.as_deref())?;

        tracing::debug!(
            "OTT registration: api_url={}, register_url={}, full_url={}",
            api_url,
            register_url,
            full_url
        );
        tracing::debug!(
            "OTT registration: sending token for connector_type={}",
            connector_type
        );

        let payload = serde_json::json!({
            "token": ott,
            "public_key": public_key_pem,
            "connector_type": connector_type,
            "instance_id": instance_id,
        });

        tracing::debug!(
            "OTT registration payload: connector_type={}, instance_id={:?}",
            connector_type,
            instance_id
        );

        // Retry logic for OTT registration
        // In multi-pod deployments, the OTT is stored in Horde.Registry (CRDT)
        // which may take a few seconds to sync across pods. Retry handles this race.
        const MAX_RETRIES: u32 = 4;
        const INITIAL_DELAY_MS: u64 = 500;
        const MAX_DELAY_MS: u64 = 3000;

        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                let delay = std::cmp::min(INITIAL_DELAY_MS * 2_u64.pow(attempt - 1), MAX_DELAY_MS);
                tracing::warn!(
                    "OTT registration retry {}/{} after {}ms (waiting for cluster sync)",
                    attempt + 1,
                    MAX_RETRIES,
                    delay
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
            }

            let response = match self.http_client.post(&full_url).json(&payload).send().await {
                Ok(resp) => resp,
                Err(e) => {
                    last_error = Some(format!("HTTP request failed: {e}"));
                    continue;
                }
            };

            tracing::debug!(
                "OTT registration response status: {} (attempt {})",
                response.status(),
                attempt + 1
            );

            if response.status().is_success() {
                let credentials: Credentials = response.json().await.map_err(|e| {
                    ConnectorError::SerializationError(format!("Failed to parse response: {e}"))
                })?;

                // Save credentials to disk for persistence across restarts
                self.save_credentials(connector_type, instance_id, &credentials)?;
                self.credentials = Some(credentials.clone());
                return Ok(credentials);
            }

            // Check if it's a retryable error (401 = OTT not found, might be sync delay)
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            if status.as_u16() == 401 && error_text.contains("Invalid or expired") {
                // This could be Horde sync delay - retry
                last_error = Some(error_text);
                continue;
            }

            // Non-retryable error
            return Err(ConnectorError::RegistrationError(format!(
                "Post-approval OTT registration failed: {error_text}"
            )));
        }

        // All retries exhausted
        Err(ConnectorError::RegistrationError(format!(
            "Post-approval OTT registration failed after {} retries: {}",
            MAX_RETRIES,
            last_error.unwrap_or_else(|| "Unknown error".to_string())
        )))
    }

    pub async fn get_token(&mut self) -> Result<String> {
        // Check if we have a valid cached token
        if let (Some(token), Some(expires_at)) = (&self.access_token, self.token_expires_at) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now < expires_at - 30 {
                return Ok(token.clone());
            }
        }

        let credentials = self
            .credentials
            .as_ref()
            .ok_or_else(|| ConnectorError::InvalidConfig("No credentials available".to_string()))?
            .clone();

        // Use private_key_jwt authentication
        self.get_token_via_private_key_jwt(&credentials).await
    }

    /// Clear the cached access token.
    ///
    /// This should be called when the token is rejected (e.g., 401 from server)
    /// to force a fresh token request on the next get_token() call.
    pub fn clear_token_cache(&mut self) {
        self.access_token = None;
        self.token_expires_at = None;
        tracing::debug!("Token cache cleared");
    }

    /// Delete the saved credentials file from disk for this connector instance.
    ///
    /// Call this when credentials are known to be invalid (e.g. repeated JWT decode
    /// failures) so that the next startup doesn't re-load broken credentials and
    /// enter an infinite auth-failure loop. After calling this, the connector will
    /// fall through to the post-approval flow on the next connection attempt.
    pub fn delete_saved_credentials(&self) {
        if let (Some(connector_type), instance_id) =
            (&self.connector_type, self.instance_id.as_deref())
        {
            let filename = format!(
                "{}_{}.json",
                connector_type,
                instance_id.unwrap_or("default")
            );
            let filepath = self.credentials_dir.join(&filename);
            if filepath.exists() {
                match std::fs::remove_file(&filepath) {
                    Ok(()) => {
                        tracing::info!("Deleted stale credentials file: {}", filepath.display())
                    }
                    Err(e) => tracing::warn!(
                        "Failed to delete stale credentials file {}: {}",
                        filepath.display(),
                        e
                    ),
                }
            }
        }
    }

    /// Reset all in-memory credential and token state.
    ///
    /// Clears loaded credentials, cached access token, and token expiry so the
    /// next `get_token()` call starts from a clean slate. Does not touch disk —
    /// call `delete_saved_credentials()` first if you also want to remove the
    /// persisted file.
    pub fn reset(&mut self) {
        self.credentials = None;
        self.private_key_pem = None;
        self.access_token = None;
        self.token_expires_at = None;
        tracing::debug!("OttProvider state reset");
    }

    /// Check if credentials are loaded (useful for connection state checks).
    #[allow(dead_code)]
    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    async fn get_token_via_private_key_jwt(&mut self, credentials: &Credentials) -> Result<String> {
        // Load private key if not already loaded
        if self.private_key_pem.is_none() {
            if let Some(connector_type) = &self.connector_type {
                let key_path =
                    self.get_private_key_path(connector_type, self.instance_id.as_deref());
                if let Some(key_path_str) = key_path.to_str() {
                    self.private_key_pem = Some(Self::load_private_key_from_path(key_path_str)?);
                } else {
                    return Err(ConnectorError::InvalidConfig(
                        "Invalid key path".to_string(),
                    ));
                }
            } else {
                return Err(ConnectorError::InvalidConfig(
                    "Connector identity not set".to_string(),
                ));
            }
        }

        let private_key_pem = self.private_key_pem.as_ref().ok_or_else(|| {
            ConnectorError::InvalidConfig("Private key not available".to_string())
        })?;

        // Create client assertion JWT
        let client_assertion = self.create_client_assertion(private_key_pem, credentials)?;

        // Exchange for access token
        let token_url = format!(
            "{}/protocol/openid-connect/token",
            credentials.auth_url.trim_end_matches('/')
        );

        let mut params = HashMap::new();
        params.insert("grant_type", "client_credentials");
        params.insert("client_id", &credentials.client_id);
        params.insert(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        );
        params.insert("client_assertion", &client_assertion);

        // Retry with exponential backoff for resilience against transient failures
        let mut last_error = None;
        let mut delay_ms = INITIAL_RETRY_DELAY_MS;

        for attempt in 1..=MAX_RETRIES {
            tracing::debug!(
                "Token request attempt {}/{} to {}",
                attempt,
                MAX_RETRIES,
                token_url
            );

            match self.http_client.post(&token_url).form(&params).send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        // Parse and cache the token
                        #[derive(Deserialize)]
                        struct TokenResponse {
                            access_token: String,
                            expires_in: Option<u64>,
                        }

                        match response.json::<TokenResponse>().await {
                            Ok(token_data) => {
                                self.access_token = Some(token_data.access_token.clone());
                                let expires_in = token_data.expires_in.unwrap_or(300);
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                self.token_expires_at = Some(now + expires_in);
                                tracing::debug!(
                                    "Token obtained successfully, expires in {}s",
                                    expires_in
                                );
                                return Ok(token_data.access_token);
                            }
                            Err(e) => {
                                return Err(ConnectorError::SerializationError(format!(
                                    "Failed to parse token response: {e}"
                                )));
                            }
                        }
                    }
                    // Non-retryable HTTP error (4xx)
                    if status.is_client_error() {
                        let error_text = response
                            .text()
                            .await
                            .unwrap_or_else(|_| "Unknown error".to_string());
                        tracing::error!("Token request rejected ({status}): {error_text}");

                        // Clear token cache on 401 - credentials may have been revoked
                        if status.as_u16() == 401 {
                            self.clear_token_cache();
                            tracing::warn!("Cleared token cache due to 401 Unauthorized");
                        }

                        return Err(ConnectorError::InvalidConfig(format!(
                            "Token request failed ({status}): {error_text}"
                        )));
                    }
                    // Server error (5xx) - retry
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    last_error = Some(ConnectorError::ConnectionError(format!(
                        "Token request failed ({status}): {error_text}"
                    )));
                }
                Err(e) => {
                    // Network error - retry. Walk the source chain so the
                    // underlying TLS/TCP/DNS cause isn't hidden by reqwest's
                    // terse Display.
                    use std::error::Error as _;
                    let mut chain = format!("{e}");
                    let mut src: Option<&(dyn std::error::Error + 'static)> = e.source();
                    while let Some(s) = src {
                        chain.push_str(&format!(" -> {s}"));
                        src = s.source();
                    }
                    tracing::debug!("Token request failed (full chain): {chain}");
                    last_error = Some(ConnectorError::ConnectionError(format!(
                        "Token request network error: {chain}"
                    )));
                }
            }

            // Don't sleep after last attempt
            if attempt < MAX_RETRIES {
                tracing::warn!(
                    "Token request failed (attempt {}/{}), retrying in {}ms...",
                    attempt,
                    MAX_RETRIES,
                    delay_ms
                );
                sleep(Duration::from_millis(delay_ms)).await;
                delay_ms = std::cmp::min(delay_ms * 2, MAX_RETRY_DELAY_MS);
            }
        }

        Err(last_error.unwrap_or_else(|| {
            ConnectorError::ConnectionError("Token request failed after all retries".to_string())
        }))
    }

    fn create_client_assertion(
        &self,
        private_key_pem: &str,
        credentials: &Credentials,
    ) -> Result<String> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        use serde_json::json;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = json!({
            "iss": credentials.client_id,
            "sub": credentials.client_id,
            "aud": credentials.auth_url,
            "exp": now + 60,
            "iat": now,
            "jti": uuid::Uuid::new_v4().to_string(),
        });

        // Detect key type from PEM header and choose appropriate algorithm
        let pem_bytes = private_key_pem.as_bytes();
        let (algorithm, encoding_key) = if private_key_pem.contains("BEGIN RSA PRIVATE KEY") {
            // PKCS#1 RSA key (legacy)
            let key = EncodingKey::from_rsa_pem(pem_bytes)
                .map_err(|e| ConnectorError::Other(format!("Failed to create RSA key: {e}")))?;
            (Algorithm::RS256, key)
        } else if private_key_pem.contains("BEGIN EC PRIVATE KEY") {
            // SEC1 EC key
            let key = EncodingKey::from_ec_pem(pem_bytes)
                .map_err(|e| ConnectorError::Other(format!("Failed to create EC key: {e}")))?;
            (Algorithm::ES256, key)
        } else {
            // PKCS#8 (could be RSA or EC) — try EC first (new default), fall back to RSA
            match EncodingKey::from_ec_pem(pem_bytes) {
                Ok(key) => (Algorithm::ES256, key),
                Err(_) => {
                    let key = EncodingKey::from_rsa_pem(pem_bytes).map_err(|e| {
                        ConnectorError::Other(format!("Failed to create encoding key: {e}"))
                    })?;
                    (Algorithm::RS256, key)
                }
            }
        };

        let mut header = Header::new(algorithm);
        if let Some(ref kid) = credentials.kid {
            header.kid = Some(kid.clone());
        }

        encode(&header, &claims, &encoding_key)
            .map_err(|e| ConnectorError::Other(format!("Failed to sign JWT: {e}")))
    }

    #[allow(dead_code)]
    pub async fn get_auth_token(&mut self) -> Option<String> {
        self.get_token().await.ok()
    }
}

/// Parsed origin: `(scheme, host, port)`. Falls back to the URL crate's
/// default port for the scheme when none is specified, so
/// `https://example.com` and `https://example.com:443` compare equal.
fn parse_origin(s: &str) -> Option<(String, String, u16)> {
    let url = reqwest::Url::parse(s).ok()?;
    let scheme = url.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    let port = url.port_or_known_default()?;
    Some((scheme, host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Register-URL allowlist (validate_register_origin)
    // =========================================================================

    #[test]
    fn validate_register_origin_same_host_passes() {
        OttProvider::validate_register_origin(
            "https://api.matrix.example.com/connectors/v1/register",
            Some("https://api.matrix.example.com"),
        )
        .expect("same origin must pass");
    }

    #[test]
    fn validate_register_origin_default_port_normalised() {
        // https implies :443; explicit and implicit forms must be treated equal.
        OttProvider::validate_register_origin(
            "https://api.matrix.example.com:443/x",
            Some("https://api.matrix.example.com/"),
        )
        .expect("443 == default https port");
    }

    #[test]
    fn validate_register_origin_cross_host_rejected() {
        let err = OttProvider::validate_register_origin(
            "https://attacker.example.com/connectors/v1/register",
            Some("https://api.matrix.example.com"),
        )
        .expect_err("cross-host must be rejected");
        assert!(matches!(err, ConnectorError::InvalidConfig(_)));
    }

    #[test]
    fn validate_register_origin_scheme_mismatch_rejected() {
        // http→https is a downgrade attack the connector must refuse even
        // when host matches.
        let err = OttProvider::validate_register_origin(
            "http://api.matrix.example.com/x",
            Some("https://api.matrix.example.com"),
        )
        .expect_err("scheme mismatch must be rejected");
        assert!(matches!(err, ConnectorError::InvalidConfig(_)));
    }

    #[test]
    fn validate_register_origin_port_mismatch_rejected() {
        let err = OttProvider::validate_register_origin(
            "https://api.matrix.example.com:8443/x",
            Some("https://api.matrix.example.com"),
        )
        .expect_err("port mismatch must be rejected");
        assert!(matches!(err, ConnectorError::InvalidConfig(_)));
    }

    #[test]
    fn validate_register_origin_no_allowlist_skips() {
        // STRIKE48_API_URL unset → permissive (with a warn!) for dev
        // ergonomics. Production deployments must set the env var.
        OttProvider::validate_register_origin("https://api.example.com/x", None)
            .expect("no allowlist => allow");
        OttProvider::validate_register_origin("https://api.example.com/x", Some("   "))
            .expect("blank allowlist => allow");
    }

    // =========================================================================
    // Callback-origin resolution (resolve_register_base / derive_api_base)
    // =========================================================================

    #[test]
    fn derive_api_base_strips_scheme_default_port_and_connectors_label() {
        assert_eq!(
            OttProvider::derive_api_base("wss://connectors-studio.example.com:443", true).unwrap(),
            "https://studio.example.com"
        );
        // Bare host:port, the shape the client stores after `parse_url`.
        assert_eq!(
            OttProvider::derive_api_base("studio.example.com:443", true).unwrap(),
            "https://studio.example.com"
        );
        // Non-default port is preserved.
        assert_eq!(
            OttProvider::derive_api_base("studio.example.com:8443", true).unwrap(),
            "https://studio.example.com:8443"
        );
    }

    #[test]
    fn derive_api_base_honours_tls_flag_but_never_downgrades_explicit_tls() {
        assert_eq!(
            OttProvider::derive_api_base("ws://localhost:4000", false).unwrap(),
            "http://localhost:4000"
        );
        // An explicitly secure scheme wins over `use_tls: false`.
        assert_eq!(
            OttProvider::derive_api_base("wss://studio.example.com", false).unwrap(),
            "https://studio.example.com"
        );
    }

    #[test]
    fn derive_api_base_rejects_empty() {
        assert!(OttProvider::derive_api_base("", true).is_none());
        assert!(OttProvider::derive_api_base("   ", true).is_none());
        assert!(OttProvider::derive_api_base("wss://", true).is_none());
    }

    #[test]
    fn resolve_register_base_prefers_configured_override() {
        let got = OttProvider::resolve_register_base(
            Some("https://api.example.com/"),
            Some("studio.other.com:443"),
            true,
            "http://localhost:4001",
        );
        assert_eq!(got.unwrap().unwrap(), "https://api.example.com");
    }

    #[test]
    fn resolve_register_base_uses_dialed_host_over_server_value() {
        // The regression this guards: a multi-tenant studio with no per-tenant
        // callback configured advertises a localhost placeholder. The connector
        // must fall back to the host it actually dialed, not follow the server.
        let got = OttProvider::resolve_register_base(
            None,
            Some("wss://tenant-a.example.com:443"),
            true,
            "http://localhost:4001",
        );
        assert_eq!(got.unwrap().unwrap(), "https://tenant-a.example.com");
    }

    #[test]
    fn resolve_register_base_is_per_connector() {
        // Two connectors against two tenants resolve to their own hosts from
        // the same server-supplied global — the property a single server-side
        // setting cannot provide.
        let a = OttProvider::resolve_register_base(
            None,
            Some("wss://tenant-a.example.com:443"),
            true,
            "https://global.example.com",
        );
        let b = OttProvider::resolve_register_base(
            None,
            Some("wss://tenant-b.example.com:443"),
            true,
            "https://global.example.com",
        );
        assert_eq!(a.unwrap().unwrap(), "https://tenant-a.example.com");
        assert_eq!(b.unwrap().unwrap(), "https://tenant-b.example.com");
    }

    #[test]
    fn resolve_register_base_falls_back_to_server_value() {
        let got =
            OttProvider::resolve_register_base(None, None, true, "https://studio.example.com/");
        assert_eq!(got.unwrap().unwrap(), "https://studio.example.com");
    }

    #[test]
    fn resolve_register_base_rejects_malformed_server_value() {
        // A non-HTTP(S) / unparseable server value must fail loud rather than
        // flow into a downstream self-compare (review finding #1).
        assert!(OttProvider::resolve_register_base(None, None, true, "not a url").is_err());
        assert!(OttProvider::resolve_register_base(None, None, true, "ftp://x").is_err());
    }

    #[test]
    fn verbose_warns_when_base_is_server_value_or_loopback() {
        // Fell back to server value with no STRIKE48_API_URL pin -> Warn.
        let (_base, notes) = OttProvider::resolve_register_base_verbose(
            None,
            None,
            true,
            "https://studio.example.com",
        )
        .unwrap()
        .unwrap();
        assert!(
            notes.iter().any(|(sev, _)| *sev == CallbackNote::Warn),
            "server-value provenance must warn"
        );

        // Loopback base (placeholder) -> Warn.
        let (_b, notes2) =
            OttProvider::resolve_register_base_verbose(None, None, true, "http://localhost:4001")
                .unwrap()
                .unwrap();
        assert!(
            notes2.iter().any(|(sev, _)| *sev == CallbackNote::Warn),
            "loopback base must warn"
        );

        // Explicit override -> no warn (the pinned, intended case).
        let (_c, notes3) = OttProvider::resolve_register_base_verbose(
            Some("https://api.example.com"),
            None,
            true,
            "https://studio.example.com",
        )
        .unwrap()
        .unwrap();
        assert!(
            !notes3.iter().any(|(sev, _)| *sev == CallbackNote::Warn),
            "explicit override must not warn"
        );
    }

    #[test]
    fn is_loopback_host_matches_placeholders() {
        assert!(OttProvider::is_loopback_host("localhost"));
        assert!(OttProvider::is_loopback_host("127.0.0.1"));
        assert!(OttProvider::is_loopback_host("::1"));
        assert!(!OttProvider::is_loopback_host("studio.example.com"));
    }

    #[test]
    fn derive_api_base_handles_ipv6_literals() {
        // A naive `strip_suffix(":443")` eats the last hextet of a bare IPv6
        // literal, producing the unusable "https://2001:db8:".
        assert_eq!(
            OttProvider::derive_api_base("2001:db8::443", true).unwrap(),
            "https://[2001:db8::443]"
        );
        assert_eq!(
            OttProvider::derive_api_base("[2001:db8::1]:443", true).unwrap(),
            "https://[2001:db8::1]"
        );
        assert_eq!(
            OttProvider::derive_api_base("[2001:db8::1]:8443", true).unwrap(),
            "https://[2001:db8::1]:8443"
        );
        // Whatever we produce must be a parseable HTTP(S) origin, since the
        // caller builds `{base}{path}` and validates the result.
        for host in [
            "2001:db8::443",
            "[2001:db8::1]:8443",
            "studio.example.com:443",
        ] {
            let base = OttProvider::derive_api_base(host, true).unwrap();
            assert!(
                parse_origin(&base).is_some(),
                "derived base {base:?} must be a valid HTTP(S) origin"
            );
        }
    }

    #[test]
    fn derive_api_base_checked_flags_retained_non_default_port() {
        // The co-location assumption (HTTP API on the transport's port) is most
        // likely wrong when a non-default port survives — e.g. gRPC on :50051.
        let (base, kept) = OttProvider::derive_api_base_checked("studio.example.com:50051", true)
            .expect("derivation must succeed");
        assert_eq!(base, "https://studio.example.com:50051");
        assert!(kept, "a non-default port must be flagged to the caller");

        let (base, kept) = OttProvider::derive_api_base_checked("studio.example.com:443", true)
            .expect("derivation must succeed");
        assert_eq!(base, "https://studio.example.com");
        assert!(!kept, "the scheme's default port is not a divergence");
    }

    #[test]
    fn resolve_register_base_rejects_malformed_override() {
        // STRIKE48_API_URL is authoritative, so a typo must fail loudly here
        // rather than surface later as a reqwest "relative URL without a base".
        let err = OttProvider::resolve_register_base(
            Some("studio.example.com"), // no scheme
            Some("wss://tenant-a.example.com:443"),
            true,
            "",
        )
        .expect_err("a schemeless override must be rejected");
        assert!(
            err.to_string().contains("STRIKE48_API_URL"),
            "error must name the offending knob, got: {err}"
        );

        OttProvider::resolve_register_base(Some("ftp://studio.example.com"), None, true, "")
            .expect_err("a non-HTTP(S) override must be rejected");
    }

    #[test]
    fn resolve_register_base_verbose_reports_override_and_port_risk() {
        // Diverging from the server's advertised value is an info-level event.
        let (base, notes) = OttProvider::resolve_register_base_verbose(
            None,
            Some("wss://tenant-a.example.com:443"),
            true,
            "http://localhost:4001",
        )
        .unwrap()
        .unwrap();
        assert_eq!(base, "https://tenant-a.example.com");
        assert!(
            notes.iter().any(|(l, m)| *l == CallbackNote::Info
                && m.contains("localhost:4001")
                && m.contains("tenant-a.example.com")),
            "an override of the server value must be reported: {notes:?}"
        );

        // A derived base that kept a non-default port warns, since the server
        // value can no longer rescue it.
        let (_, notes) = OttProvider::resolve_register_base_verbose(
            None,
            Some("grpcs://studio.example.com:50051"),
            true,
            "",
        )
        .unwrap()
        .unwrap();
        assert!(
            notes
                .iter()
                .any(|(l, m)| *l == CallbackNote::Warn && m.contains("STRIKE48_API_URL")),
            "a retained non-default port must warn: {notes:?}"
        );

        // Agreeing with the server, on the default port, is silent.
        let (_, notes) = OttProvider::resolve_register_base_verbose(
            None,
            Some("wss://studio.example.com:443"),
            true,
            "https://studio.example.com",
        )
        .unwrap()
        .unwrap();
        assert!(
            notes.is_empty(),
            "no divergence should be silent: {notes:?}"
        );
    }

    #[test]
    fn enforce_same_origin_blocks_absolute_server_register_url() {
        // The regression that matters: `register_url` is documented as a path,
        // but an absolute one bypasses the resolved base entirely. It must be
        // refused against the RESOLVED base, with no dependence on
        // STRIKE48_API_URL being set.
        let err = OttProvider::enforce_same_origin(
            "http://evil.example.com/api/connectors/register-with-ott",
            "https://tenant-a.example.com",
            "the resolved OTT callback base",
        )
        .expect_err("a foreign absolute register URL must be refused");
        assert!(
            err.to_string().contains("refusing to send credentials"),
            "got: {err}"
        );

        // Same origin still passes.
        OttProvider::enforce_same_origin(
            "https://tenant-a.example.com/api/connectors/register-with-ott",
            "https://tenant-a.example.com",
            "the resolved OTT callback base",
        )
        .expect("same origin must pass");
    }

    #[test]
    fn resolve_register_base_none_when_every_source_empty() {
        assert!(
            OttProvider::resolve_register_base(Some("  "), Some(""), true, "")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn validate_register_origin_invalid_target_rejected() {
        let err =
            OttProvider::validate_register_origin("not a url", Some("https://api.example.com"))
                .expect_err("malformed URL must be rejected");
        assert!(matches!(err, ConnectorError::InvalidConfig(_)));
    }

    // =========================================================================
    // Credential file permissions (save_credentials)
    // =========================================================================

    #[cfg(unix)]
    #[test]
    fn save_credentials_writes_file_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let provider = OttProvider {
            api_url: None,
            keys_dir: tmp.path().join("keys"),
            credentials_dir: tmp.path().join("creds"),
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type: Some("perm_test".into()),
            instance_id: Some("inst_a".into()),
            direct_config: None,
            http_client: Client::new(),
        };
        let credentials = Credentials {
            client_id: "ci-1".into(),
            auth_url: "https://auth.example.com".into(),
            tenant_id: "demo".into(),
            kid: None,
        };
        provider
            .save_credentials("perm_test", Some("inst_a"), &credentials)
            .expect("save_credentials");
        let path = tmp.path().join("creds").join("perm_test_inst_a.json");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        // POSIX permission bits live in the low 9; mask off any sticky/setuid.
        assert_eq!(
            mode & 0o777,
            0o600,
            "credential file must be owner-only readable, got mode={mode:o}"
        );
    }

    // =========================================================================
    // OTT parsing (parse_ott)
    // =========================================================================

    #[test]
    fn test_parse_ott_raw_token_string() {
        let result = OttProvider::parse_ott("ott_hXg1Adwu12345");
        assert!(result.is_some());
        let ott = result.unwrap();
        assert_eq!(ott.token, "ott_hXg1Adwu12345");
        assert!(ott.api_url.is_none());
        assert!(ott.auth_url.is_none());
        assert!(ott.expires_at.is_none());
    }

    #[test]
    fn test_parse_ott_json_inline() {
        let json_str = r#"{"token":"ott_abc123","matrix_url":"https://api.example.com","keycloak_url":"https://auth.example.com/realms/matrix"}"#;
        let result = OttProvider::parse_ott(json_str);
        assert!(result.is_some());
        let ott = result.unwrap();
        assert_eq!(ott.token, "ott_abc123");
        assert_eq!(ott.api_url.as_deref(), Some("https://api.example.com"));
        assert_eq!(
            ott.auth_url.as_deref(),
            Some("https://auth.example.com/realms/matrix")
        );
    }

    #[test]
    fn test_parse_ott_json_with_all_fields() {
        let json_str = r#"{
            "token": "ott_full",
            "matrix_url": "https://api.example.com",
            "keycloak_url": "https://auth.example.com",
            "expires_at": "2026-12-31T23:59:59Z",
            "connector_type": "my-connector",
            "tenant_id": "tenant-1"
        }"#;
        let result = OttProvider::parse_ott(json_str);
        assert!(result.is_some());
        let ott = result.unwrap();
        assert_eq!(ott.token, "ott_full");
        assert_eq!(ott.connector_type.as_deref(), Some("my-connector"));
        assert_eq!(ott.tenant_id.as_deref(), Some("tenant-1"));
        assert_eq!(ott.expires_at.as_deref(), Some("2026-12-31T23:59:59Z"));
    }

    #[test]
    fn test_parse_ott_base64_encoded_json() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let json_str = r#"{"token":"ott_b64","matrix_url":"https://api.test.com"}"#;
        let encoded = STANDARD.encode(json_str.as_bytes());
        let result = OttProvider::parse_ott(&encoded);
        assert!(result.is_some());
        let ott = result.unwrap();
        assert_eq!(ott.token, "ott_b64");
        assert_eq!(ott.api_url.as_deref(), Some("https://api.test.com"));
    }

    #[test]
    fn test_parse_ott_empty_string() {
        let result = OttProvider::parse_ott("");
        assert!(result.is_some());
        let ott = result.unwrap();
        assert_eq!(ott.token, "");
    }

    #[test]
    fn test_parse_ott_json_missing_token_fails() {
        let json_str = r#"{"matrix_url":"https://api.example.com"}"#;
        let result = OttProvider::parse_ott(json_str);
        // serde will fail because "token" is required
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_ott_json_minimal() {
        let json_str = r#"{"token":"ott_min"}"#;
        let result = OttProvider::parse_ott(json_str);
        assert!(result.is_some());
        let ott = result.unwrap();
        assert_eq!(ott.token, "ott_min");
        assert!(ott.api_url.is_none());
    }

    // =========================================================================
    // EC key generation and PEM round-tripping
    // =========================================================================

    #[tokio::test]
    async fn test_keypair_generation_and_pem_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let keys_dir = temp_dir.path().join("keys");

        let mut provider = OttProvider {
            api_url: None,
            keys_dir,
            credentials_dir: temp_dir.path().join("creds"),
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type: Some("test-connector".to_string()),
            instance_id: Some("test-instance".to_string()),
            direct_config: None,
            http_client: Client::new(),
        };

        // Generate keypair
        let public_key_pem = provider
            .get_or_create_keypair_for_connector("test-connector", Some("test-instance"))
            .await
            .unwrap();

        // Verify the public key PEM is valid SPKI format
        assert!(public_key_pem.contains("BEGIN PUBLIC KEY"));
        assert!(public_key_pem.contains("END PUBLIC KEY"));

        // Verify private key was stored in memory
        assert!(provider.private_key_pem.is_some());

        // Verify private key file was written to disk
        let key_path = provider.get_private_key_path("test-connector", Some("test-instance"));
        assert!(key_path.exists());

        // Verify the file contains PKCS#8 EC PEM
        let key_data = std::fs::read_to_string(&key_path).unwrap();
        assert!(key_data.contains("BEGIN PRIVATE KEY"));

        // Verify round-trip: load key from file and extract same public key
        let loaded_pem =
            OttProvider::load_private_key_from_path(key_path.to_str().unwrap()).unwrap();
        let loaded_pub_pem = OttProvider::extract_ec_public_key_pem(&loaded_pem).unwrap();
        assert_eq!(public_key_pem, loaded_pub_pem);
    }

    #[tokio::test]
    async fn test_keypair_reuse_on_second_call() {
        let temp_dir = tempfile::tempdir().unwrap();
        let keys_dir = temp_dir.path().join("keys");

        let mut provider = OttProvider {
            api_url: None,
            keys_dir,
            credentials_dir: temp_dir.path().join("creds"),
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type: Some("test-connector".to_string()),
            instance_id: Some("inst".to_string()),
            direct_config: None,
            http_client: Client::new(),
        };

        // First call generates
        let pub1 = provider
            .get_or_create_keypair_for_connector("test-connector", Some("inst"))
            .await
            .unwrap();

        // Clear in-memory key to force reload from disk
        provider.private_key_pem = None;

        // Second call loads from disk
        let pub2 = provider
            .get_or_create_keypair_for_connector("test-connector", Some("inst"))
            .await
            .unwrap();

        // Should be the same key
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_private_key_path_format() {
        let provider = OttProvider::new(Some("my-type".to_string()), Some("my-inst".to_string()));
        let path = provider.get_private_key_path("my-type", Some("my-inst"));
        let filename = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(filename, "my-type_my-inst.pem");
    }

    #[test]
    fn test_private_key_path_default_instance() {
        let provider = OttProvider::new(Some("my-type".to_string()), None);
        let path = provider.get_private_key_path("my-type", None);
        let filename = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(filename, "my-type_default.pem");
    }

    // =========================================================================
    // Credential save/load persistence
    // =========================================================================

    #[test]
    fn test_save_and_load_credentials() {
        let temp_dir = tempfile::tempdir().unwrap();
        let creds_dir = temp_dir.path().join("credentials");

        let mut provider = OttProvider {
            api_url: None,
            keys_dir: temp_dir.path().join("keys"),
            credentials_dir: creds_dir.clone(),
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type: Some("cred-test".to_string()),
            instance_id: Some("inst-1".to_string()),
            direct_config: None,
            http_client: Client::new(),
        };

        let creds = Credentials {
            client_id: "client-abc".to_string(),
            auth_url: "https://auth.example.com/realms/matrix".to_string(),
            tenant_id: "tenant-1".to_string(),
            kid: None,
        };

        // Save
        provider
            .save_credentials("cred-test", Some("inst-1"), &creds)
            .unwrap();

        // Verify file exists
        let filepath = creds_dir.join("cred-test_inst-1.json");
        assert!(filepath.exists());

        // Verify file contents are valid JSON
        let file_content = std::fs::read_to_string(&filepath).unwrap();
        let parsed: Credentials = serde_json::from_str(&file_content).unwrap();
        assert_eq!(parsed.client_id, "client-abc");
        assert_eq!(parsed.auth_url, "https://auth.example.com/realms/matrix");
        assert_eq!(parsed.tenant_id, "tenant-1");

        // Load back via the provider
        let loaded = provider.load_saved_credentials("cred-test", Some("inst-1"));
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.client_id, "client-abc");
        assert_eq!(loaded.auth_url, "https://auth.example.com/realms/matrix");
        assert_eq!(loaded.tenant_id, "tenant-1");
    }

    #[test]
    fn test_load_credentials_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut provider = OttProvider {
            api_url: None,
            keys_dir: temp_dir.path().join("keys"),
            credentials_dir: temp_dir.path().join("credentials"),
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type: Some("missing".to_string()),
            instance_id: Some("inst".to_string()),
            direct_config: None,
            http_client: Client::new(),
        };

        let loaded = provider.load_saved_credentials("missing", Some("inst"));
        assert!(loaded.is_none());
    }

    #[test]
    fn test_load_credentials_default_instance() {
        let temp_dir = tempfile::tempdir().unwrap();
        let creds_dir = temp_dir.path().join("credentials");

        let mut provider = OttProvider {
            api_url: None,
            keys_dir: temp_dir.path().join("keys"),
            credentials_dir: creds_dir,
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type: Some("test".to_string()),
            instance_id: None,
            direct_config: None,
            http_client: Client::new(),
        };

        let creds = Credentials {
            client_id: "default-client".to_string(),
            auth_url: "https://auth.example.com".to_string(),
            tenant_id: "default".to_string(),
            kid: None,
        };

        provider.save_credentials("test", None, &creds).unwrap();
        let loaded = provider.load_saved_credentials("test", None);
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().client_id, "default-client");
    }

    #[test]
    fn test_delete_saved_credentials() {
        let temp_dir = tempfile::tempdir().unwrap();
        let creds_dir = temp_dir.path().join("credentials");

        let provider = OttProvider {
            api_url: None,
            keys_dir: temp_dir.path().join("keys"),
            credentials_dir: creds_dir.clone(),
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type: Some("del-test".to_string()),
            instance_id: Some("inst".to_string()),
            direct_config: None,
            http_client: Client::new(),
        };

        // Save credentials first
        provider
            .save_credentials(
                "del-test",
                Some("inst"),
                &Credentials {
                    client_id: "to-delete".to_string(),
                    auth_url: "https://auth.example.com".to_string(),
                    tenant_id: "t".to_string(),
                    kid: None,
                },
            )
            .unwrap();

        let filepath = creds_dir.join("del-test_inst.json");
        assert!(filepath.exists());

        // Delete
        provider.delete_saved_credentials();
        assert!(!filepath.exists());
    }

    #[test]
    fn test_delete_saved_credentials_nonexistent_is_noop() {
        let temp_dir = tempfile::tempdir().unwrap();
        let provider = OttProvider {
            api_url: None,
            keys_dir: temp_dir.path().join("keys"),
            credentials_dir: temp_dir.path().join("credentials"),
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type: Some("nope".to_string()),
            instance_id: Some("nope".to_string()),
            direct_config: None,
            http_client: Client::new(),
        };

        // Should not panic
        provider.delete_saved_credentials();
    }

    // =========================================================================
    // Token cache management
    // =========================================================================

    #[test]
    fn test_clear_token_cache() {
        let mut provider = OttProvider::new(Some("test".to_string()), Some("inst".to_string()));
        provider.access_token = Some("cached-token".to_string());
        provider.token_expires_at = Some(9999999999);

        provider.clear_token_cache();

        assert!(provider.access_token.is_none());
        assert!(provider.token_expires_at.is_none());
    }

    #[test]
    fn test_reset_clears_all_state() {
        let mut provider = OttProvider::new(Some("test".to_string()), Some("inst".to_string()));
        provider.access_token = Some("token".to_string());
        provider.token_expires_at = Some(123);
        provider.credentials = Some(Credentials {
            client_id: "c".to_string(),
            auth_url: "a".to_string(),
            tenant_id: "t".to_string(),
            kid: None,
        });

        provider.reset();

        assert!(provider.access_token.is_none());
        assert!(provider.token_expires_at.is_none());
        assert!(provider.credentials.is_none());
        assert!(provider.private_key_pem.is_none());
    }

    // =========================================================================
    // JWT client assertion creation (the jsonwebtoken API surface)
    // =========================================================================

    #[tokio::test]
    async fn test_create_client_assertion_produces_valid_jwt() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut provider = OttProvider {
            api_url: None,
            keys_dir: temp_dir.path().join("keys"),
            credentials_dir: temp_dir.path().join("creds"),
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type: Some("jwt-test".to_string()),
            instance_id: Some("inst".to_string()),
            direct_config: None,
            http_client: Client::new(),
        };

        // Generate a keypair
        provider
            .get_or_create_keypair_for_connector("jwt-test", Some("inst"))
            .await
            .unwrap();

        let private_key_pem = provider.private_key_pem.as_ref().unwrap();
        let credentials = Credentials {
            client_id: "test-client-id".to_string(),
            auth_url: "https://auth.example.com/realms/matrix".to_string(),
            tenant_id: "test-tenant".to_string(),
            kid: None,
        };

        let jwt = provider
            .create_client_assertion(private_key_pem, &credentials)
            .unwrap();

        // JWT should have 3 parts (header.payload.signature)
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 dot-separated parts");

        // Decode header to verify algorithm
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");

        // Decode payload to verify claims
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(claims["iss"], "test-client-id");
        assert_eq!(claims["sub"], "test-client-id");
        assert_eq!(claims["aud"], "https://auth.example.com/realms/matrix");
        assert!(claims["exp"].is_number());
        assert!(claims["iat"].is_number());
        assert!(claims["jti"].is_string());

        // Verify exp is ~60s after iat
        let iat = claims["iat"].as_u64().unwrap();
        let exp = claims["exp"].as_u64().unwrap();
        assert_eq!(exp - iat, 60);

        // Verify jti is a valid UUID
        let jti = claims["jti"].as_str().unwrap();
        assert!(uuid::Uuid::parse_str(jti).is_ok());
    }

    #[tokio::test]
    async fn test_create_client_assertion_signature_is_verifiable() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut provider = OttProvider {
            api_url: None,
            keys_dir: temp_dir.path().join("keys"),
            credentials_dir: temp_dir.path().join("creds"),
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type: Some("verify-test".to_string()),
            instance_id: Some("inst".to_string()),
            direct_config: None,
            http_client: Client::new(),
        };

        let public_key_pem = provider
            .get_or_create_keypair_for_connector("verify-test", Some("inst"))
            .await
            .unwrap();

        let private_key_pem = provider.private_key_pem.as_ref().unwrap();
        let credentials = Credentials {
            client_id: "verify-client".to_string(),
            auth_url: "https://auth.example.com".to_string(),
            tenant_id: "t".to_string(),
            kid: None,
        };

        let jwt = provider
            .create_client_assertion(private_key_pem, &credentials)
            .unwrap();

        // Verify the JWT signature using the EC public key
        use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
        let decoding_key = DecodingKey::from_ec_pem(public_key_pem.as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["https://auth.example.com"]);
        validation.set_issuer(&["verify-client"]);
        validation.sub = Some("verify-client".to_string());

        let decoded = decode::<serde_json::Value>(&jwt, &decoding_key, &validation);
        assert!(
            decoded.is_ok(),
            "JWT signature verification failed: {:?}",
            decoded.err()
        );
    }

    #[tokio::test]
    async fn test_create_two_assertions_have_different_jti() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut provider = OttProvider {
            api_url: None,
            keys_dir: temp_dir.path().join("keys"),
            credentials_dir: temp_dir.path().join("creds"),
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type: Some("jti-test".to_string()),
            instance_id: Some("inst".to_string()),
            direct_config: None,
            http_client: Client::new(),
        };

        provider
            .get_or_create_keypair_for_connector("jti-test", Some("inst"))
            .await
            .unwrap();

        let private_key_pem = provider.private_key_pem.as_ref().unwrap();
        let credentials = Credentials {
            client_id: "c".to_string(),
            auth_url: "a".to_string(),
            tenant_id: "t".to_string(),
            kid: None,
        };

        let jwt1 = provider
            .create_client_assertion(private_key_pem, &credentials)
            .unwrap();
        let jwt2 = provider
            .create_client_assertion(private_key_pem, &credentials)
            .unwrap();

        // Different JTI means different tokens (replay protection)
        assert_ne!(jwt1, jwt2);
    }

    // =========================================================================
    // Legacy RSA key backward compatibility
    // =========================================================================

    #[tokio::test]
    async fn test_legacy_rsa_key_signs_jwt_with_rs256() {
        // Simulate a legacy RSA PKCS#1 key loaded from disk via direct config
        // Generate a temporary RSA key using jsonwebtoken's test infrastructure
        let rsa_pem = include_str!("../../test_fixtures/legacy_rsa_key.pem");

        let provider = OttProvider::new(Some("test".to_string()), None);
        let credentials = Credentials {
            client_id: "legacy-client".to_string(),
            auth_url: "https://auth.example.com".to_string(),
            tenant_id: "t".to_string(),
            kid: None,
        };

        let jwt = provider
            .create_client_assertion(rsa_pem, &credentials)
            .unwrap();

        // Verify it used RS256
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let parts: Vec<&str> = jwt.split('.').collect();
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "RS256");
    }

    #[tokio::test]
    async fn test_legacy_rsa_key_upgraded_on_re_registration() {
        let temp_dir = tempfile::tempdir().unwrap();
        let keys_dir = temp_dir.path().join("keys");
        fs::create_dir_all(&keys_dir).unwrap();

        // Write a legacy RSA key to disk
        let rsa_pem = include_str!("../../test_fixtures/legacy_rsa_key.pem");
        let key_path = keys_dir.join("upgrade-test_inst.pem");
        fs::write(&key_path, rsa_pem).unwrap();

        let mut provider = OttProvider {
            api_url: None,
            keys_dir,
            credentials_dir: temp_dir.path().join("creds"),
            private_key_pem: None,
            credentials: None,
            access_token: None,
            token_expires_at: None,
            connector_type: Some("upgrade-test".to_string()),
            instance_id: Some("inst".to_string()),
            direct_config: None,
            http_client: Client::new(),
        };

        // Re-registration should generate a new EC key
        let public_key_pem = provider
            .get_or_create_keypair_for_connector("upgrade-test", Some("inst"))
            .await
            .unwrap();

        assert!(public_key_pem.contains("BEGIN PUBLIC KEY"));
        // The private key on disk should now be EC PKCS#8
        let new_key_data = fs::read_to_string(&key_path).unwrap();
        assert!(new_key_data.contains("BEGIN PRIVATE KEY"));
        assert!(!new_key_data.contains("RSA"));
    }

    // =========================================================================
    // Token caching behavior
    // =========================================================================

    #[tokio::test]
    async fn test_get_token_returns_cached_when_valid() {
        let mut provider = OttProvider::new(Some("test".to_string()), Some("inst".to_string()));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        provider.access_token = Some("cached-jwt".to_string());
        provider.token_expires_at = Some(now + 120); // expires in 2 minutes
        provider.credentials = Some(Credentials {
            client_id: "c".to_string(),
            auth_url: "a".to_string(),
            tenant_id: "t".to_string(),
            kid: None,
        });

        // Should return cached token without hitting Keycloak
        let token = provider.get_token().await.unwrap();
        assert_eq!(token, "cached-jwt");
    }

    #[tokio::test]
    async fn test_get_token_expired_cache_triggers_refresh() {
        let mut provider = OttProvider::new(Some("test".to_string()), Some("inst".to_string()));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        provider.access_token = Some("expired-jwt".to_string());
        provider.token_expires_at = Some(now + 10); // expires in 10s, but 30s buffer means "expired"
        provider.credentials = Some(Credentials {
            client_id: "c".to_string(),
            auth_url: "https://auth.invalid.test".to_string(),
            tenant_id: "t".to_string(),
            kid: None,
        });

        // Should try to refresh (and fail since no real Keycloak)
        let result = provider.get_token().await;
        assert!(
            result.is_err(),
            "Should fail trying to refresh expired token"
        );
    }

    // =========================================================================
    // Direct config detection
    // =========================================================================

    #[test]
    fn test_has_direct_config_false_by_default() {
        // SAFETY: test-only env cleanup
        unsafe {
            std::env::remove_var("STRIKE48_PRIVATE_KEY_PATH");
            std::env::remove_var("STRIKE48_CLIENT_ID");
            std::env::remove_var("STRIKE48_AUTH_URL");
        }
        let provider = OttProvider::new(Some("test".to_string()), None);
        assert!(!provider.has_direct_config());
    }

    // =========================================================================
    // Credentials serialization format
    // =========================================================================

    #[test]
    fn test_credentials_json_field_names() {
        let creds = Credentials {
            client_id: "cid".to_string(),
            auth_url: "https://auth.example.com".to_string(),
            tenant_id: "tid".to_string(),
            kid: None,
        };
        let json = serde_json::to_value(&creds).unwrap();

        // Verify field names match what Matrix server expects
        assert!(json.get("client_id").is_some());
        assert!(json.get("keycloak_url").is_some()); // Note: serialized as keycloak_url
        assert!(json.get("tenant_id").is_some());
        assert_eq!(json["client_id"], "cid");
        assert_eq!(json["keycloak_url"], "https://auth.example.com");
        assert_eq!(json["tenant_id"], "tid");
    }

    #[test]
    fn test_credentials_deserialization_from_server_format() {
        // Simulate what the /api/connectors/register-with-ott endpoint returns
        let server_json = r#"{
            "client_id": "connector-client-abc",
            "keycloak_url": "https://keycloak.example.com/realms/matrix",
            "tenant_id": "production"
        }"#;
        let creds: Credentials = serde_json::from_str(server_json).unwrap();
        assert_eq!(creds.client_id, "connector-client-abc");
        assert_eq!(creds.auth_url, "https://keycloak.example.com/realms/matrix");
        assert_eq!(creds.tenant_id, "production");
    }

    // =========================================================================
    // OTT data serialization
    // =========================================================================

    #[test]
    fn test_ott_data_json_field_names() {
        let ott = OttData {
            token: "ott_test".to_string(),
            api_url: Some("https://api.example.com".to_string()),
            auth_url: Some("https://auth.example.com".to_string()),
            expires_at: Some("2026-12-31".to_string()),
            connector_type: Some("my-conn".to_string()),
            tenant_id: Some("t1".to_string()),
        };
        let json = serde_json::to_value(&ott).unwrap();

        // Verify field names match what the pre-approve endpoint produces
        assert_eq!(json["token"], "ott_test");
        assert_eq!(json["matrix_url"], "https://api.example.com");
        assert_eq!(json["keycloak_url"], "https://auth.example.com");
        assert_eq!(json["expires_at"], "2026-12-31");
        assert_eq!(json["connector_type"], "my-conn");
        assert_eq!(json["tenant_id"], "t1");
    }

    #[test]
    fn test_ott_data_deserialization_from_server_format() {
        let server_json = r#"{
            "token": "ott_from_server",
            "matrix_url": "https://matrix.prod.example.com",
            "keycloak_url": "https://auth.prod.example.com/realms/matrix"
        }"#;
        let ott: OttData = serde_json::from_str(server_json).unwrap();
        assert_eq!(ott.token, "ott_from_server");
        assert_eq!(
            ott.api_url.as_deref(),
            Some("https://matrix.prod.example.com")
        );
        assert_eq!(
            ott.auth_url.as_deref(),
            Some("https://auth.prod.example.com/realms/matrix")
        );
    }
}

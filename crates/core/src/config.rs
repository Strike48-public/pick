//! Configuration types for the connector

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::aggression::AggressionLevel;

/// Shell execution mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ShellMode {
    /// Run commands directly on the host machine (native shell)
    Native,
    /// Run commands inside the sandboxed BlackArch environment (bwrap/proot).
    /// Default: the connector sandboxes tool execution out of the box.
    #[default]
    Proot,
}

/// UI theme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Theme {
    Strike48,
    Dark,
    Light,
    Dracula,
    Gruvbox,
    TokyoNight,
    Matrix,
    Cyberpunk,
    Nord,
    #[default]
    Sage,
    SageLight,
}

/// Border radius style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BorderRadius {
    Sharp,   // 0px
    Minimal, // 4px
    #[default]
    Rounded, // 8px
    Soft,    // 16px
    Pill,    // 999px
}

/// UI density / spacing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Density {
    Compact,
    #[default]
    Normal,
    Comfortable,
}

/// Configuration for connecting to the Strike48 backend
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectorConfig {
    /// Strike48 server URL (e.g., "grpc://localhost:50061" or "wss://strike48.example.com")
    pub host: String,

    /// Tenant identifier
    pub tenant_id: String,

    /// Authentication token (JWT or OTT)
    pub auth_token: String,

    /// Instance ID for this connector (auto-generated if not provided)
    pub instance_id: String,

    /// Connector name used as the gateway identity in Matrix.
    /// Instances sharing the same connector_name are round-robin'd;
    /// set a unique name (e.g. via CONNECTOR_NAME env var) to get a
    /// dedicated agent view. Defaults to "pentest-connector".
    #[serde(default = "default_connector_name")]
    pub connector_name: String,

    /// Display name shown in the Strike48 UI
    pub display_name: Option<String>,

    /// Tags for categorizing this connector
    pub tags: Vec<String>,

    /// Whether to use TLS
    pub use_tls: bool,

    /// Reconnection settings
    pub reconnect_enabled: bool,
    pub reconnect_delay_ms: u64,
    pub max_backoff_delay_ms: u64,

    /// Aggression level for penetration testing scans
    #[serde(default)]
    pub aggression_level: AggressionLevel,
}

fn default_connector_name() -> String {
    "pentest-connector".to_string()
}

/// Whether the PLG easy-mode connect should sign in first or connect silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlgConnectStep {
    /// Connect straight away (expert mode, or easy mode with saved creds).
    Silent,
    /// Run OAuth-first, then exchange for an OTT before connecting.
    SignIn,
}

/// Decide the easy-mode connect path. Only easy mode with no saved connector
/// credentials needs the OAuth-first flow; every other case connects silently
/// (expert mode's own path is unaffected).
pub fn plg_connect_decision(easy_mode: bool, creds_present: bool) -> PlgConnectStep {
    if easy_mode && !creds_present {
        PlgConnectStep::SignIn
    } else {
        PlgConnectStep::Silent
    }
}

impl Default for ConnectorConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            tenant_id: "default".to_string(),
            auth_token: String::new(),
            instance_id: Uuid::new_v4().to_string(),
            connector_name: default_connector_name(),
            display_name: None,
            tags: vec![],
            use_tls: true,
            reconnect_enabled: true,
            reconnect_delay_ms: 5000,
            max_backoff_delay_ms: 60000,
            aggression_level: AggressionLevel::default(),
        }
    }
}

/// Outcome of [`ConnectorConfig::normalize_host`].
///
/// Carries the canonical URL plus a record of which parts (scheme, port) were
/// supplied by inference rather than typed by the user. Callers display the
/// inference via [`Self::hint`] so users can verify the resolved transport
/// before connecting — see the doc on `normalize_host` for the rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHost {
    /// Canonical URL with scheme and explicit port.
    pub value: String,
    /// `Some(scheme)` if `normalize_host` supplied a scheme the user did not type.
    pub inferred_scheme: Option<&'static str>,
    /// `Some(port)` if `normalize_host` supplied a port the user did not type.
    pub inferred_port: Option<u16>,
}

impl NormalizedHost {
    /// `true` if any defaulting occurred (scheme or port was supplied).
    pub fn was_inferred(&self) -> bool {
        self.inferred_scheme.is_some() || self.inferred_port.is_some()
    }

    /// User-facing line describing what we resolved, e.g.
    /// `Will connect as wss://discoball.strike48.engineering:443`.
    /// Returns `None` when the user typed everything explicitly.
    pub fn hint(&self) -> Option<String> {
        if self.was_inferred() {
            Some(format!("Will connect as {}", self.value))
        } else {
            None
        }
    }
}

/// Returns `true` if `bare` contains a `:port` suffix.
///
/// Detects the *last* colon to avoid being fooled by any future IPv6 literal
/// support; until then this is conservative and correct for `host:port` and
/// `host` (no port).
fn bare_has_port(bare: &str) -> bool {
    bare.rsplit_once(':')
        .is_some_and(|(_, port)| !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()))
}

impl ConnectorConfig {
    /// Create a new configuration with the given URL
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            ..Default::default()
        }
    }

    /// Set the tenant ID
    pub fn tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = tenant_id.into();
        self
    }

    /// Set the auth token
    pub fn auth_token(mut self, auth_token: impl Into<String>) -> Self {
        self.auth_token = auth_token.into();
        self
    }

    /// Validate the configuration including SSRF protection
    pub fn validate(&self) -> Result<(), String> {
        if self.host.is_empty() {
            return Err("Strike48 host is required".to_string());
        }
        if self.tenant_id.is_empty() {
            return Err("Tenant ID is required".to_string());
        }

        // Validate host URL for SSRF protection.
        use crate::url_validation::validate_url;

        let validation_mode = Self::resolve_validation_mode(
            std::env::var("PENTEST_ALLOW_PRIVATE_IPS").ok().as_deref(),
        );
        validate_url(&self.host, validation_mode, None)
            .map_err(|e| format!("Invalid host URL: {}", e))?;

        Ok(())
    }

    /// Select the SSRF [`ValidationMode`] for the connector host from the
    /// `PENTEST_ALLOW_PRIVATE_IPS` opt-in.
    ///
    /// In-cluster/local dev connects to the platform over a private ClusterIP
    /// (e.g. `connectors-studio-grpc.default.svc:50061` -> `10.x`), which the
    /// default Production guard blocks as SSRF. Setting
    /// `PENTEST_ALLOW_PRIVATE_IPS=true|1` selects [`ValidationMode::PrivateNetwork`],
    /// which permits RFC-1918 / loopback targets but STILL blocks the
    /// cloud-metadata / link-local range (169.254.0.0/16) — a deliberately
    /// narrower relaxation than full Development mode.
    ///
    /// Secure by default: any other value (including unset) falls back to
    /// [`ValidationMode::default()`], which is Production in release builds.
    /// Pure (no I/O) so it can be unit-tested independent of the build profile.
    ///
    /// Delegates to [`crate::url_validation::resolve_validation_mode`], the
    /// single source of truth now shared with per-tool target validation
    /// (`nikto`/`ffuf`/`dirb`/`gobuster`). Kept as an associated function so the
    /// connector-host call site and its tests read naturally.
    fn resolve_validation_mode(env_val: Option<&str>) -> crate::url_validation::ValidationMode {
        crate::url_validation::resolve_validation_mode(env_val)
    }

    /// Check if this config has authentication
    pub fn has_auth(&self) -> bool {
        !self.auth_token.is_empty()
    }

    /// Validate `host` and return a [`NormalizedHost`] with the final URL
    /// plus a record of any defaults that were applied.
    ///
    /// # Inference policy (option C: visible inference)
    ///
    /// We *infer* sensible defaults rather than rejecting incomplete input,
    /// AND we *report* what was inferred via [`NormalizedHost::hint`] rather
    /// than hiding it. The reasons, kept here so future-us can revisit:
    ///
    /// 1. The dominant Strike48 case is Cloudflare-fronted WebSocket on :443.
    ///    Forcing users to type `wss://host:443` is friction without payoff.
    /// 2. Once gRPC ships, the same bare host could legitimately mean either
    ///    transport. Showing the resolved URL lets users verify intent up-front
    ///    instead of debugging mysterious routing later.
    /// 3. Trustworthy tooling (cargo, gh, kubectl) reports what it resolved;
    ///    pentest users distrust magic, so we match that contract.
    ///
    /// To revert: drop [`NormalizedHost::hint`] to make inference silent, or
    /// change the no-scheme/no-port branch below to return `Err` for strict
    /// rejection.
    ///
    /// # Defaults applied
    ///
    /// | Input                       | Output                          | Inferred           |
    /// |-----------------------------|---------------------------------|--------------------|
    /// | `wss://host:443`            | `wss://host:443`                | none               |
    /// | `wss://host`                | `wss://host:443`                | port               |
    /// | `host:443`                  | `wss://host:443`                | scheme             |
    /// | `host`                      | `wss://host:443`                | scheme + port      |
    /// | `grpc://host`               | `grpc://host:50051`             | port               |
    /// | `grpcs://host`              | `grpcs://host:443`              | port               |
    /// | `ws://localhost`            | `ws://localhost:80`             | port               |
    /// | `localhost:50061`           | `localhost:50061`               | none (SDK→gRPC)    |
    ///
    /// IPv6 literals (`[::1]:443`) are not supported by the port detector
    /// here; revisit when needed.
    ///
    /// Returns `Err` on truly malformed input (empty, scheme with no host).
    pub fn normalize_host(host: &str) -> Result<NormalizedHost, String> {
        // Scheme → default port. Order matters only for matching; every entry
        // is checked against the lowercased input.
        const SCHEMES: &[(&str, u16)] = &[
            ("grpc://", 50051),
            ("grpcs://", 443),
            ("http://", 80),
            ("https://", 443),
            ("ws://", 80),
            ("wss://", 443),
        ];

        let trimmed = host.trim();
        if trimmed.is_empty() {
            return Err(
                "Strike48 host is required (e.g., wss://strike48.example.com or strike48.example.com:443)"
                    .to_string(),
            );
        }

        let lower = trimmed.to_lowercase();
        let scheme_match = SCHEMES.iter().find_map(|(s, p)| {
            lower
                .strip_prefix(s)
                .map(|_| (&trimmed[..s.len()], *p, &trimmed[s.len()..]))
        });

        // Resolve scheme + bare host portion. Track whether the scheme was
        // inferred so the UI can disclose it.
        let (scheme, bare_str, default_port, scheme_inferred): (String, String, u16, bool) =
            match scheme_match {
                Some((original_scheme, port, bare)) => {
                    (original_scheme.to_string(), bare.to_string(), port, false)
                }
                None => {
                    // No scheme. Decide based on what port (if any) is present.
                    let has_port = bare_has_port(trimmed);
                    if !has_port {
                        // No scheme, no port — Strike48-on-Cloudflare default.
                        ("wss://".to_string(), trimmed.to_string(), 443, true)
                    } else if trimmed.ends_with(":443") {
                        // :443 implies HTTPS/WebSocket through Cloudflare.
                        ("wss://".to_string(), trimmed.to_string(), 443, true)
                    } else {
                        // Non-443 port without a scheme: leave bare and let the
                        // SDK pick its default transport (currently gRPC).
                        ("".to_string(), trimmed.to_string(), 0, false)
                    }
                }
            };

        // Trim any path/query suffix and trailing slash so a pasted browser
        // URL (`https://strike48.example.com/`) doesn't leave the bare form
        // ending in `/`, which would produce `strike48.example.com/:443` when
        // we append the inferred port (pick#223).
        let bare_str = bare_str
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(&bare_str)
            .to_string();

        if bare_str.is_empty() {
            return Err(format!(
                "Invalid host: missing hostname after scheme. Try {}strike48.example.com",
                scheme
            ));
        }

        let port_inferred = !bare_has_port(&bare_str);
        let final_bare = if port_inferred {
            format!("{}:{}", bare_str, default_port)
        } else {
            bare_str
        };

        let value = format!("{}{}", scheme, final_bare);

        Ok(NormalizedHost {
            value,
            inferred_scheme: if scheme_inferred {
                Some("wss://")
            } else {
                None
            },
            inferred_port: if port_inferred {
                Some(default_port)
            } else {
                None
            },
        })
    }

    /// Derive a stable, env-scoped instance id from the persistent `device_id`
    /// and the target `host`.
    ///
    /// Saved credentials and connector approval are keyed by instance id. With a
    /// single global instance id, one credential is reused for every env, so a
    /// token minted for env A is rejected by env B's gateway. Folding a host slug
    /// into the instance id gives each Strike48 instance its own credential +
    /// approval. The mapping is deterministic — the same host always yields the
    /// same id — so approval persists across restarts and env switches "just work".
    pub fn env_scoped_instance_id(device_id: &str, host: &str) -> String {
        let slug = Self::host_slug(host);
        if slug.is_empty() {
            device_id.to_string()
        } else {
            format!("{device_id}-{slug}")
        }
    }

    /// The env vars operators use to pin a tenant identity, in preference
    /// order. `MATRIX_TENANT_ID` comes first because operators typically
    /// use it to carry an explicit UUID (aligning with StrikeHub's own
    /// convention). `STRIKE48_TENANT` and its `TENANT_ID` alias are legacy
    /// slug carriers; they still work but Studio's app-viewer routes by
    /// UUID, so we prefer any UUID-shaped value we can find (pick#223).
    pub const TENANT_ENV_VARS: &'static [&'static str] =
        &["MATRIX_TENANT_ID", "STRIKE48_TENANT", "TENANT_ID"];

    /// Does `s` parse as a canonical UUID?
    ///
    /// Used to distinguish tenant UUIDs from slugs when picking between
    /// multiple env-var carriers or between a form value and an env
    /// override. Trims whitespace so pasted values with newlines still
    /// match.
    pub fn is_uuid_like(s: &str) -> bool {
        Uuid::parse_str(s.trim()).is_ok()
    }

    /// Return a tenant UUID from the first `TENANT_ENV_VARS` entry that
    /// carries one, if any.
    ///
    /// Callers use this to promote a UUID over a slug the operator typed
    /// in the ConfigForm — the slug is a valid registration identity but
    /// Studio addresses the App-behavior connector by UUID, so an
    /// explicit env-var UUID wins (see [`is_uuid_like`]).
    pub fn tenant_uuid_from_env() -> Option<String> {
        for var in Self::TENANT_ENV_VARS {
            if let Ok(v) = std::env::var(var) {
                let trimmed = v.trim();
                if !trimmed.is_empty() && Self::is_uuid_like(trimmed) {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }

    /// Build an easy-mode default config from the PLG target supplied at BUILD
    /// time via `option_env!("STRIKE48_HOST")` (+ optional `STRIKE48_TENANT`),
    /// falling back to the RUNTIME [`from_env`] for desktop/dev where the process
    /// environment is real. This is the correct path for the mobile apps, which
    /// have no runtime environment — a runtime `std::env::var` is always empty
    /// on-device, so the host must be baked in at build time (same mechanism as
    /// the Sentry DSN). Nothing is hardcoded in the repo: absent a build-time
    /// host, this returns `None` and the connect form shows as the escape hatch.
    pub fn from_baked_or_env() -> Option<Self> {
        // Build-time host (baked into the binary). Empty/unset -> fall through.
        let baked_host = option_env!("STRIKE48_HOST")
            .or(option_env!("STRIKE48_URL"))
            .or(option_env!("STRIKE48_API_URL"))
            .map(str::trim)
            .filter(|h| !h.is_empty());

        let Some(host) = baked_host else {
            // No build-time host: use the runtime env (desktop/dev/headless).
            return Self::from_env();
        };

        let mut config = ConnectorConfig {
            host: host.to_string(),
            ..Default::default()
        };
        // Build-time tenant (UUID preferred, else slug). Optional.
        if let Some(tenant) = option_env!("STRIKE48_TENANT")
            .or(option_env!("MATRIX_TENANT_ID"))
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            config.tenant_id = tenant.to_string();
        }
        if let Some(tls) = option_env!("STRIKE48_TLS") {
            config.use_tls = tls != "false" && tls != "0";
        }
        Some(config)
    }

    /// Build a config from environment variables alone (host + tenant + tls),
    /// with an empty auth token (post-approval flow). Returns `None` if no host
    /// env var is set, so callers can distinguish "env configured a PLG target"
    /// from "nothing configured". Used by easy mode (#283) to default-connect to
    /// a PLG tenant supplied at build/deploy time without a baked-in host.
    ///
    /// Host carriers: `STRIKE48_HOST` / `STRIKE48_URL` / `STRIKE48_API_URL`.
    /// Tenant resolution mirrors [`load_connector_config`]: prefer a UUID-shaped
    /// value across [`TENANT_ENV_VARS`], else the first non-empty slug.
    pub fn from_env() -> Option<Self> {
        let host = std::env::var("STRIKE48_HOST")
            .or_else(|_| std::env::var("STRIKE48_URL"))
            .or_else(|_| std::env::var("STRIKE48_API_URL"))
            .ok()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())?;

        let mut config = ConnectorConfig {
            host,
            ..Default::default()
        };

        // Tenant: UUID wins over slug across the supported carriers.
        let mut slug_fallback: Option<String> = None;
        for var in Self::TENANT_ENV_VARS {
            let Ok(v) = std::env::var(var) else { continue };
            let trimmed = v.trim();
            if trimmed.is_empty() {
                continue;
            }
            if Self::is_uuid_like(trimmed) {
                config.tenant_id = trimmed.to_string();
                slug_fallback = None;
                break;
            }
            if slug_fallback.is_none() {
                slug_fallback = Some(trimmed.to_string());
            }
        }
        if let Some(slug) = slug_fallback {
            config.tenant_id = slug;
        }

        if let Ok(tls) = std::env::var("STRIKE48_TLS") {
            config.use_tls = tls != "false" && tls != "0";
        }

        Some(config)
    }

    /// Read the tenant UUID the SDK stored during OTT approval, if any.
    ///
    /// Studio addresses App-behavior connectors by tenant UUID
    /// (`/#/apps/matrix%3A<uuid>%3A<connector>%3A...`). The connector's
    /// initial pending-approval registration can carry either a tenant
    /// slug or a UUID — the server accepts both — but Studio only routes
    /// app-viewer traffic to the identity that matches its URL. When the
    /// operator types the slug, the server-issued JWT is minted against
    /// the canonical UUID and the SDK writes it to
    /// `~/.strike48/credentials/<connector>_<instance_id>.json`. Reading
    /// that file at connect time lets us reuse the UUID for subsequent
    /// registrations so the slug→UUID gap is invisible to the operator
    /// (pick#223).
    ///
    /// StrikeHub does the equivalent server-side: it pre-resolves the
    /// user's tenant via a `userDetails { domain.id }` GraphQL query
    /// (`strikehub/crates/sh-core/src/auth.rs::fetch_tenant_id`) and
    /// injects the UUID into every spawned connector's env. Standalone
    /// Pick has no authenticated context up front, so we rely on the
    /// post-OTT credentials file instead.
    ///
    /// Returns `None` when the file is missing, unreadable, or the
    /// `tenant_id` field is absent — callers should fall back to the
    /// user-supplied tenant string.
    pub fn read_credentials_tenant_id(connector_name: &str, instance_id: &str) -> Option<String> {
        let home = std::env::var("HOME").ok()?;
        let path = std::path::PathBuf::from(home)
            .join(".strike48")
            .join("credentials")
            .join(format!("{connector_name}_{instance_id}.json"));
        let content = std::fs::read_to_string(&path).ok()?;
        let value: serde_json::Value = serde_json::from_str(&content).ok()?;
        value
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// True when the SDK has already persisted connector credentials for this
    /// identity (i.e. a prior OTT registration succeeded), so we can connect
    /// without signing in again.
    pub fn credentials_present(connector_name: &str, instance_id: &str) -> bool {
        let home = match std::env::var("HOME") {
            Ok(h) => h,
            Err(_) => return false,
        };
        std::path::PathBuf::from(home)
            .join(".strike48")
            .join("credentials")
            .join(format!("{connector_name}_{instance_id}.json"))
            .exists()
    }

    /// Delete the SDK's persisted connector credentials for this identity, if
    /// present. Used by "Log out" so the next launch does a fully fresh OTT
    /// registration rather than silently reconnecting the old connector.
    /// Best-effort: a missing file or unset HOME is a no-op.
    pub fn clear_credentials(connector_name: &str, instance_id: &str) {
        let Ok(home) = std::env::var("HOME") else {
            return;
        };
        let path = std::path::PathBuf::from(home)
            .join(".strike48")
            .join("credentials")
            .join(format!("{connector_name}_{instance_id}.json"));
        let _ = std::fs::remove_file(path);
    }

    /// Split a Strike48-style URL (accepts anything [`normalize_host`] produces
    /// plus bare hosts) into `(hostname, port)`.
    ///
    /// Callers that only need to open a TCP/TLS socket — e.g. the pre-connect
    /// probe in `pentest-ui` — should use this rather than re-parsing by hand,
    /// so the two ends of the connect pipeline agree on port defaulting, IPv6
    /// bracket handling, and trailing-slash trimming. Returns `Err` on empty
    /// input or a non-numeric port.
    ///
    /// When no port is present the default is `443`, matching
    /// [`normalize_host`]'s Cloudflare-fronted-WebSocket default.
    pub fn split_authority(url: &str) -> Result<(String, u16), String> {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            return Err("Strike48 host is empty".to_string());
        }

        let after_scheme = trimmed
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(trimmed);

        let authority = after_scheme
            .split('/')
            .next()
            .unwrap_or(after_scheme)
            .trim_end_matches('/');

        // IPv6 literal `[::1]:443`
        if let Some((host, tail)) = authority
            .strip_prefix('[')
            .and_then(|rest| rest.find(']').map(|end| (&rest[..end], &rest[end + 1..])))
        {
            let port = tail
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(443);
            return Ok((host.to_string(), port));
        }

        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() => {
                let port = p
                    .parse::<u16>()
                    .map_err(|_| format!("Invalid port in URL: {}", url))?;
                (h.to_string(), port)
            }
            _ => (authority.to_string(), 443),
        };

        if host.is_empty() {
            return Err(format!("Missing hostname in URL: {}", url));
        }

        Ok((host, port))
    }

    /// Reduce a host URL to a short, stable identifier slug: scheme and port are
    /// stripped and any run of non-alphanumeric characters collapses to a single
    /// `-` (e.g. `wss://studio.example.com:443` -> `studio-example-com`).
    fn host_slug(host: &str) -> String {
        let after_scheme = host.rsplit("://").next().unwrap_or(host);
        let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
        // Drop a trailing :port (last colon only, so IPv6 forms degrade gracefully).
        let hostname = authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority);

        let mut slug = String::with_capacity(hostname.len());
        let mut prev_dash = false;
        for c in hostname.chars() {
            if c.is_ascii_alphanumeric() {
                slug.push(c.to_ascii_lowercase());
                prev_dash = false;
            } else if !prev_dash {
                slug.push('-');
                prev_dash = true;
            }
        }
        slug.trim_matches('-').to_string()
    }

    /// Convert to the SDK's ConnectorConfig
    pub fn to_sdk_config(&self) -> strike48_connector::ConnectorConfig {
        let mut sdk_config = strike48_connector::ConnectorConfig {
            host: self.host.clone(),
            tenant_id: self.tenant_id.clone(),
            instance_id: self.instance_id.clone(),
            connector_type: self.connector_name.clone(),
            use_tls: self.use_tls,
            reconnect_enabled: self.reconnect_enabled,
            reconnect_delay_ms: self.reconnect_delay_ms,
            max_backoff_delay_ms: self.max_backoff_delay_ms,
            ..strike48_connector::ConnectorConfig::default()
        };

        sdk_config.auth_token = self.auth_token.clone();

        if let Some(ref name) = self.display_name {
            sdk_config.display_name = Some(name.clone());
        }

        sdk_config.tags = self.tags.clone();

        // Auto-detect transport type from URL scheme
        if let Ok(parsed) = strike48_connector::parse_url(&self.host) {
            sdk_config.transport_type = parsed.transport;
            sdk_config.use_tls = parsed.use_tls;
            sdk_config.host = parsed.host_port();
        }

        sdk_config
    }
}

/// Download state for BlackArch ISO
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DownloadState {
    /// Whether the BlackArch ISO has been downloaded
    pub blackarch_downloaded: bool,

    /// Path to the downloaded BlackArch ISO
    pub blackarch_download_path: Option<String>,

    /// Runtime-only download progress (0.0–1.0), not persisted
    #[serde(skip)]
    pub download_progress: Option<f64>,
}

/// Application settings (persisted locally)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    /// Persistent device/instance ID - generated once per install
    pub device_id: String,

    /// Last used connector configuration
    pub last_config: Option<ConnectorConfig>,

    /// Auto-connect on startup
    pub auto_connect: bool,

    /// Terminal settings
    pub terminal_font_size: u32,
    pub terminal_max_lines: usize,

    /// Theme preference
    pub theme: Theme,
    pub border_radius: BorderRadius,
    pub density: Density,

    /// Shell execution mode (native or proot)
    pub shell_mode: ShellMode,

    /// Download state for BlackArch ISO
    pub download_state: DownloadState,

    /// Selected WiFi adapter for scanning (interface name, e.g., "wlan1")
    /// If None, will use first available adapter
    pub wifi_adapter: Option<String>,

    /// Whether anonymous usage telemetry (Sentry) is enabled. On by default;
    /// users can opt out. No PII or target/scan data is ever sent.
    #[serde(default = "default_telemetry_enabled")]
    pub telemetry_enabled: bool,

    /// The Matrix API URL the cached chat token was minted for, so on startup we
    /// only restore the token (from the secure store — see `secure_store`) when
    /// still pointing at the same host. The token itself is NEVER stored here;
    /// it lives in the OS secure store (iOS Keychain / Android Keystore).
    #[serde(default)]
    pub matrix_api_url: String,

    /// User's Easy Mode preference. `None` means "never chosen" — fall through to
    /// the build-time / per-app default (see [`resolve_easy_mode`]). `Some(b)` is
    /// an explicit in-app Settings choice that overrides the default.
    #[serde(default)]
    pub easy_mode: Option<bool>,

    /// Whether the user dismissed the Windows "install WSL for better scanning"
    /// banner. The show logic still hides the banner once a sandbox backend is
    /// available, so this only suppresses the nag while none is.
    #[serde(default)]
    pub wsl_banner_dismissed: bool,
}

/// Cross-target result of the guided WSL install, surfaced to the UI banner.
///
/// This is the platform-agnostic mirror of
/// `pentest_platform::desktop::sandbox::wsl_install::InstallOutcome`. It lives
/// in `pentest-core` so `pentest-ui` (which is cross-target and must not depend
/// on the desktop-only `wsl_install` module) can name the states in its
/// `ConnectorAppConfig` hook signature. The desktop wrapper maps `InstallOutcome`
/// onto this enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WslInstallStatus {
    /// Features + kernel installed successfully; the machine must reboot before
    /// WSL is usable.
    RebootRequired,
    /// The install completed and WSL is ready (no reboot needed).
    Completed,
    /// A UAC-elevating relaunch was launched; the elevated helper continues the
    /// install out-of-process. Nothing more for this process to do.
    ElevationLaunched,
    /// The install failed; the string carries a human-readable reason.
    Failed(String),
}

/// Resolve the effective Easy Mode flag from all sources, most-specific first:
///  1. the user's persisted Settings choice (`settings_easy_mode`), if set;
///  2. the BUILD-TIME `PICK_EASY_MODE` env (baked via `option_env!`, the only
///     source that reaches mobile) — `true`/`1` or `false`/`0`;
///  3. the per-app compile-time default (`app_default`, from `ConnectorAppConfig`).
///
/// This lets a build ship easy-mode-first (`PICK_EASY_MODE=true`) without code
/// edits, while the in-app toggle still wins.
pub fn resolve_easy_mode(settings_easy_mode: Option<bool>, app_default: bool) -> bool {
    if let Some(choice) = settings_easy_mode {
        return choice;
    }
    if let Some(v) = option_env!("PICK_EASY_MODE") {
        match v.trim() {
            "true" | "1" => return true,
            "false" | "0" => return false,
            _ => {}
        }
    }
    app_default
}

/// Telemetry is opt-out: enabled by default so PLG usage analytics work, with a
/// settings toggle to disable it.
fn default_telemetry_enabled() -> bool {
    true
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            device_id: Uuid::new_v4().to_string(),
            last_config: None,
            auto_connect: false,
            terminal_font_size: 14,
            terminal_max_lines: 10000,
            theme: Theme::default(),
            border_radius: BorderRadius::default(),
            density: Density::default(),
            shell_mode: ShellMode::default(),
            download_state: DownloadState::default(),
            wifi_adapter: None,
            telemetry_enabled: default_telemetry_enabled(),
            matrix_api_url: String::new(),
            easy_mode: None,
            wsl_banner_dismissed: false,
        }
    }
}

/// Result of attempting to load connector config from CLI args, env vars, and saved settings.
#[derive(Debug)]
pub enum ConfigLoadResult {
    /// Successfully loaded a config.
    Ok(ConnectorConfig),
    /// The user passed `--help` / `-h`.
    Help,
    /// An error occurred (unknown flag, bad host format, etc.).
    Error(String),
    /// Config validation failed (SSRF protection, invalid URL, etc.).
    ValidationFailed(String),
}

/// Build a [`ConnectorConfig`] by layering saved settings, environment variables,
/// and command-line arguments (highest priority wins).
///
/// `args` should be the full argv slice (including the program name at index 0).
/// The caller is responsible for collecting `std::env::args()` and passing them in
/// so that this function remains independent of process-global state.
///
/// Precedence (highest to lowest):
/// 1. CLI arguments
/// 2. Environment variables (`STRIKE48_HOST`, `STRIKE48_TOKEN`, etc.)
/// 3. Saved settings on disk (via [`crate::settings::load_settings`])
/// 4. Defaults
pub fn load_connector_config(args: &[String]) -> ConfigLoadResult {
    use crate::settings::load_settings;

    // Try saved settings first (auto-connect)
    let saved = load_settings();
    let mut config = saved.last_config.unwrap_or_default();

    // Ensure we have a device ID
    let device_id = if saved.device_id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        saved.device_id
    };
    config.instance_id = device_id;

    // Env vars override saved settings.
    // Accept both pentest-agent names (STRIKE48_HOST) and StrikeHub names
    // (STRIKE48_URL, TENANT_ID) so the binary works standalone and under StrikeHub.
    if let Ok(host) = std::env::var("STRIKE48_HOST")
        .or_else(|_| std::env::var("STRIKE48_URL"))
        .or_else(|_| std::env::var("STRIKE48_API_URL"))
    {
        config.host = host;
    }
    if let Ok(token) = std::env::var("STRIKE48_TOKEN") {
        config.auth_token = token;
    }
    // Tenant resolution: prefer any UUID-shaped value over a slug across
    // the supported carriers (MATRIX_TENANT_ID, STRIKE48_TENANT, TENANT_ID),
    // then fall back to the first non-empty slug. Studio addresses
    // App-behavior connectors by tenant UUID, so a UUID env var wins even
    // if a slug is present (pick#223).
    let mut env_slug_fallback: Option<String> = None;
    for var in ConnectorConfig::TENANT_ENV_VARS {
        let Ok(v) = std::env::var(var) else { continue };
        let trimmed = v.trim();
        if trimmed.is_empty() {
            continue;
        }
        if ConnectorConfig::is_uuid_like(trimmed) {
            config.tenant_id = trimmed.to_string();
            env_slug_fallback = None;
            break;
        }
        if env_slug_fallback.is_none() {
            env_slug_fallback = Some(trimmed.to_string());
        }
    }
    if let Some(slug) = env_slug_fallback {
        config.tenant_id = slug;
    }
    if let Ok(id) = std::env::var("STRIKE48_INSTANCE_ID").or_else(|_| std::env::var("INSTANCE_ID"))
    {
        config.instance_id = id;
    }
    if let Ok(tls) = std::env::var("STRIKE48_TLS") {
        config.use_tls = tls != "false" && tls != "0";
    }
    if let Ok(name) = std::env::var("CONNECTOR_NAME") {
        config.connector_name = name;
    }
    if let Ok(aggression) = std::env::var("AGGRESSION_LEVEL") {
        if let Ok(level) = aggression.parse::<crate::aggression::AggressionLevel>() {
            config.aggression_level = level;
        }
    }

    // CLI args override everything
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--token" | "-t" => {
                i += 1;
                if i < args.len() {
                    config.auth_token = args[i].clone();
                }
            }
            "--tenant" => {
                i += 1;
                if i < args.len() {
                    config.tenant_id = args[i].clone();
                }
            }
            "--instance-id" => {
                i += 1;
                if i < args.len() {
                    config.instance_id = args[i].clone();
                }
            }
            "--connector-name" => {
                i += 1;
                if i < args.len() {
                    config.connector_name = args[i].clone();
                }
            }
            "--no-tls" => {
                config.use_tls = false;
            }
            "--aggression" | "-a" => {
                i += 1;
                if i < args.len() {
                    match args[i].parse::<crate::aggression::AggressionLevel>() {
                        Ok(level) => {
                            // Display cost warning if expensive mode selected
                            if let Some(warning) = level.cost_warning() {
                                use crate::aggression::WarnLevel;
                                let prefix = match warning.level {
                                    WarnLevel::Info => "ℹ️ ",
                                    WarnLevel::Warning => "⚠️  ",
                                };
                                eprintln!("{}{}", prefix, warning.message);
                                eprintln!();
                            }
                            config.aggression_level = level;
                        }
                        Err(e) => {
                            return ConfigLoadResult::Error(e);
                        }
                    }
                }
            }
            "--help" | "-h" => {
                return ConfigLoadResult::Help;
            }
            arg if !arg.starts_with('-') && config.host.is_empty() => {
                config.host = arg.to_string();
            }
            arg if !arg.starts_with('-') => {
                // Positional after host — treat as host override
                config.host = arg.to_string();
            }
            _ => {
                return ConfigLoadResult::Error(format!("Unknown option: {}", args[i]));
            }
        }
        i += 1;
    }

    // Preserve the original URL (including scheme) so that to_sdk_config()
    // can auto-detect transport type (WebSocket vs gRPC) and TLS from the scheme.

    // Validate config before returning (SSRF protection, required fields, etc.).
    // Under StrikeHub the host is chosen by the trusted local launcher and may
    // legitimately be a private-IP / self-hosted studio, so skip the SSRF host
    // check in that mode — main() already intends to skip validation when launched
    // by StrikeHub, but this earlier check would otherwise reject it first.
    // Standalone mode keeps full validation.
    let is_strikehub = std::env::var("STRIKEHUB_SOCKET").is_ok();
    if !is_strikehub {
        if let Err(e) = config.validate() {
            tracing::warn!("Config validation failed: {}", e);
            return ConfigLoadResult::ValidationFailed(e);
        }
    }

    ConfigLoadResult::Ok(config)
}

impl AppSettings {
    /// Ensure the device_id is set (generates one if empty, for upgrades from old settings)
    pub fn ensure_device_id(&mut self) {
        if self.device_id.is_empty() {
            self.device_id = Uuid::new_v4().to_string();
        }
    }

    /// Returns the shell modes available based on download state.
    /// Proot is only available when BlackArch ISO has been downloaded.
    pub fn available_shell_modes(&self) -> Vec<ShellMode> {
        let mut modes = vec![ShellMode::Native];
        if self.download_state.blackarch_downloaded {
            modes.push(ShellMode::Proot);
        }
        modes
    }

    /// Get a ConnectorConfig using the persistent device_id as instance_id
    pub fn get_config_with_device_id(&self, base_config: ConnectorConfig) -> ConnectorConfig {
        ConnectorConfig {
            instance_id: self.device_id.clone(),
            ..base_config
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_settings_defaults_wsl_banner_not_dismissed() {
        let s = AppSettings::default();
        assert!(!s.wsl_banner_dismissed);
    }

    #[test]
    fn app_settings_deserializes_without_wsl_banner_field() {
        // Older settings.json lacks the field; must default, not fail.
        let s: AppSettings = serde_json::from_str("{}").unwrap();
        assert!(!s.wsl_banner_dismissed);
    }

    /// Serialises every test that mutates a process-global env var — the
    /// tenant vars (`TENANT_ENV_VARS`) AND `HOME` (the credential-file tests set
    /// it to a tempdir). All must share ONE lock: env vars are process-global,
    /// so a `HOME`-mutating test racing a tenant test (or the two `HOME` tests
    /// racing each other) lets one test's `set_var`/`remove_var` leak into
    /// another's view. Per-test locks provide no mutual exclusion. Symptoms seen
    /// on CI: `..._prefers_matrix_tenant_id` flipping `..._returns_none...`'s
    /// assertion, and `read_credentials_tenant_id_extracts_uuid`'s `HOME` being
    /// cleared mid-read by a sibling's restore (its `assert_eq!` on the UUID).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn preserves_explicit_wss_with_port() {
        let n = ConnectorConfig::normalize_host("wss://studio.example.com:443").unwrap();
        assert_eq!(n.value, "wss://studio.example.com:443");
        assert!(!n.was_inferred());
        assert!(n.hint().is_none());
    }

    #[test]
    fn preserves_explicit_grpc_with_port() {
        let n = ConnectorConfig::normalize_host("grpc://localhost:50061").unwrap();
        assert_eq!(n.value, "grpc://localhost:50061");
        assert!(!n.was_inferred());
    }

    #[test]
    fn infers_wss_scheme_when_only_443_typed() {
        let n = ConnectorConfig::normalize_host("studio.example.com:443").unwrap();
        assert_eq!(n.value, "wss://studio.example.com:443");
        assert_eq!(n.inferred_scheme, Some("wss://"));
        assert_eq!(n.inferred_port, None);
    }

    #[test]
    fn infers_wss_and_443_for_bare_host() {
        let n = ConnectorConfig::normalize_host("discoball.strike48.engineering").unwrap();
        assert_eq!(n.value, "wss://discoball.strike48.engineering:443");
        assert_eq!(n.inferred_scheme, Some("wss://"));
        assert_eq!(n.inferred_port, Some(443));
        assert_eq!(
            n.hint().as_deref(),
            Some("Will connect as wss://discoball.strike48.engineering:443"),
        );
    }

    #[test]
    fn infers_443_for_wss_without_port() {
        let n = ConnectorConfig::normalize_host("wss://strike48.example.com").unwrap();
        assert_eq!(n.value, "wss://strike48.example.com:443");
        assert_eq!(n.inferred_scheme, None);
        assert_eq!(n.inferred_port, Some(443));
    }

    #[test]
    fn infers_443_for_https_without_port() {
        let n = ConnectorConfig::normalize_host("https://strike48.example.com").unwrap();
        assert_eq!(n.value, "https://strike48.example.com:443");
        assert_eq!(n.inferred_port, Some(443));
    }

    #[test]
    fn infers_80_for_ws_without_port() {
        let n = ConnectorConfig::normalize_host("ws://localhost").unwrap();
        assert_eq!(n.value, "ws://localhost:80");
        assert_eq!(n.inferred_port, Some(80));
    }

    #[test]
    fn infers_50051_for_grpc_without_port() {
        let n = ConnectorConfig::normalize_host("grpc://localhost").unwrap();
        assert_eq!(n.value, "grpc://localhost:50051");
        assert_eq!(n.inferred_port, Some(50051));
    }

    #[test]
    fn infers_443_for_grpcs_without_port() {
        // grpcs:// is the Cloudflare-fronted gRPC case — same TLS port as wss.
        let n = ConnectorConfig::normalize_host("grpcs://strike48.example.com").unwrap();
        assert_eq!(n.value, "grpcs://strike48.example.com:443");
        assert_eq!(n.inferred_port, Some(443));
    }

    #[test]
    fn leaves_bare_host_with_non_443_port_alone() {
        // Non-443 bare port: SDK picks gRPC (its default) — preserve user intent.
        let n = ConnectorConfig::normalize_host("localhost:50061").unwrap();
        assert_eq!(n.value, "localhost:50061");
        assert!(!n.was_inferred());
    }

    #[test]
    fn strips_trailing_slash_before_inferring_port() {
        // Pasting a browser URL with a trailing `/` used to produce
        // `wss://host/:443` because the slash was baked into the bare form
        // before we appended the default port (pick#223).
        let n = ConnectorConfig::normalize_host("https://non-prod.strike48.test/").unwrap();
        assert_eq!(n.value, "https://non-prod.strike48.test:443");
        assert_eq!(n.inferred_port, Some(443));
    }

    #[test]
    fn strips_path_after_authority() {
        let n = ConnectorConfig::normalize_host("wss://strike48.example.com/socket/foo").unwrap();
        assert_eq!(n.value, "wss://strike48.example.com:443");
    }

    #[test]
    fn strips_query_and_fragment() {
        let n = ConnectorConfig::normalize_host("https://strike48.example.com/?x=1#frag").unwrap();
        assert_eq!(n.value, "https://strike48.example.com:443");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let n = ConnectorConfig::normalize_host("  wss://x.example.com:443  ").unwrap();
        assert_eq!(n.value, "wss://x.example.com:443");
        assert!(!n.was_inferred());
    }

    #[test]
    fn scheme_matching_is_case_insensitive() {
        let n = ConnectorConfig::normalize_host("WSS://Studio.Example.com:443").unwrap();
        assert_eq!(n.value, "WSS://Studio.Example.com:443");
        assert!(!n.was_inferred());
    }

    #[test]
    fn rejects_empty_input() {
        assert!(ConnectorConfig::normalize_host("").is_err());
        assert!(ConnectorConfig::normalize_host("   ").is_err());
    }

    #[test]
    fn idempotent_when_reapplied() {
        let first = ConnectorConfig::normalize_host("discoball.strike48.engineering").unwrap();
        let second = ConnectorConfig::normalize_host(&first.value).unwrap();
        assert_eq!(first.value, second.value);
        assert!(!second.was_inferred(), "second pass should not re-infer");
    }

    #[test]
    fn is_uuid_like_accepts_canonical_and_rejects_slug() {
        assert!(ConnectorConfig::is_uuid_like(
            "019f4d37-0212-72cb-945a-f8d01726ebf5"
        ));
        assert!(ConnectorConfig::is_uuid_like(
            "  019f4d37-0212-72cb-945a-f8d01726ebf5\n"
        ));
        assert!(!ConnectorConfig::is_uuid_like("non-prod"));
        assert!(!ConnectorConfig::is_uuid_like(""));
        assert!(!ConnectorConfig::is_uuid_like("019f4d37-0212"));
    }

    #[test]
    fn tenant_uuid_from_env_prefers_matrix_tenant_id() {
        // Serialise all tenant-env manipulation on the shared lock so parallel
        // tests can't leak into each other's env-var view.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let previous: Vec<(&str, Option<String>)> = ConnectorConfig::TENANT_ENV_VARS
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
        // SAFETY: `LOCK` above serialises access to these env vars across
        // config tests; other threads in this binary do not read them.
        unsafe {
            for k in ConnectorConfig::TENANT_ENV_VARS {
                std::env::remove_var(k);
            }
            std::env::set_var("STRIKE48_TENANT", "non-prod");
            std::env::set_var("MATRIX_TENANT_ID", "019f4d37-0212-72cb-945a-f8d01726ebf5");
        }

        let got = ConnectorConfig::tenant_uuid_from_env();

        // Restore before asserting so failure doesn't leak state.
        unsafe {
            for (k, v) in previous {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
        assert_eq!(got.as_deref(), Some("019f4d37-0212-72cb-945a-f8d01726ebf5"));
    }

    #[test]
    fn tenant_uuid_from_env_returns_none_when_only_slugs_present() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let previous: Vec<(&str, Option<String>)> = ConnectorConfig::TENANT_ENV_VARS
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
        unsafe {
            for k in ConnectorConfig::TENANT_ENV_VARS {
                std::env::remove_var(k);
            }
            std::env::set_var("STRIKE48_TENANT", "non-prod");
        }

        let got = ConnectorConfig::tenant_uuid_from_env();

        unsafe {
            for (k, v) in previous {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
        assert!(got.is_none());
    }

    #[test]
    fn read_credentials_tenant_id_extracts_uuid() {
        // Serialise with every other env-mutating config test: this test sets
        // HOME (process-global), and a concurrent test's set/remove of HOME (or
        // the tenant tests) would otherwise flip the read below. See ENV_LOCK.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Isolate HOME so the test doesn't touch the real credentials dir.
        let tmp = tempfile::tempdir().expect("tempdir");
        let creds_dir = tmp.path().join(".strike48").join("credentials");
        std::fs::create_dir_all(&creds_dir).expect("mkdir creds");
        let file = creds_dir.join("pentest-connector_dev-abc.json");
        std::fs::write(
            &file,
            r#"{"client_id":"matrix:connector:local:019f4d37-0212-72cb-945a-f8d01726ebf5:pentest-connector:dev-abc","keycloak_url":"https://auth.example","tenant_id":"019f4d37-0212-72cb-945a-f8d01726ebf5"}"#,
        )
        .expect("write creds");

        // SAFETY: single-threaded config tests, no other thread reads HOME here.
        let prev = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", tmp.path()) };
        let got = ConnectorConfig::read_credentials_tenant_id("pentest-connector", "dev-abc");
        // Restore before assertions so a failing test doesn't leak env state.
        match prev {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert_eq!(got.as_deref(), Some("019f4d37-0212-72cb-945a-f8d01726ebf5"));
    }

    #[test]
    fn read_credentials_tenant_id_returns_none_when_missing() {
        // Serialise with every other env-mutating config test (sets HOME). See ENV_LOCK.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let prev = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", tmp.path()) };
        let got = ConnectorConfig::read_credentials_tenant_id("pentest-connector", "never-ott");
        match prev {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert!(got.is_none());
    }

    #[test]
    fn split_authority_parses_wss_with_port() {
        assert_eq!(
            ConnectorConfig::split_authority("wss://studio.example.com:443").unwrap(),
            ("studio.example.com".to_string(), 443)
        );
    }

    #[test]
    fn split_authority_defaults_bare_host_to_443() {
        assert_eq!(
            ConnectorConfig::split_authority("studio.example.com").unwrap(),
            ("studio.example.com".to_string(), 443)
        );
    }

    #[test]
    fn split_authority_parses_ipv6_bracketed() {
        assert_eq!(
            ConnectorConfig::split_authority("wss://[::1]:8443").unwrap(),
            ("::1".to_string(), 8443)
        );
    }

    #[test]
    fn split_authority_preserves_custom_port() {
        assert_eq!(
            ConnectorConfig::split_authority("grpc://localhost:50061").unwrap(),
            ("localhost".to_string(), 50061)
        );
    }

    #[test]
    fn split_authority_rejects_empty() {
        assert!(ConnectorConfig::split_authority("").is_err());
        assert!(ConnectorConfig::split_authority("   ").is_err());
    }

    #[test]
    fn split_authority_rejects_invalid_port() {
        assert!(ConnectorConfig::split_authority("wss://x.example.com:notaport").is_err());
    }

    #[test]
    fn host_slug_strips_scheme_and_port() {
        assert_eq!(
            ConnectorConfig::host_slug("wss://studio.example.com:443"),
            "studio-example-com"
        );
        assert_eq!(
            ConnectorConfig::host_slug("connectors.example.org:443"),
            "connectors-example-org"
        );
        assert_eq!(
            ConnectorConfig::host_slug("grpc://localhost:50061"),
            "localhost"
        );
    }

    #[test]
    fn host_slug_is_empty_for_empty_host() {
        assert_eq!(ConnectorConfig::host_slug(""), "");
    }

    #[test]
    fn env_scoped_instance_id_differs_per_host() {
        let device = "device-0001";
        let a = ConnectorConfig::env_scoped_instance_id(device, "wss://studio.example.com:443");
        let b = ConnectorConfig::env_scoped_instance_id(device, "wss://studio.example.org:443");
        assert_eq!(a, format!("{device}-studio-example-com"));
        assert_ne!(a, b);
    }

    #[test]
    fn env_scoped_instance_id_is_stable_for_same_host() {
        let device = "device-0001";
        let a = ConnectorConfig::env_scoped_instance_id(device, "wss://studio.example.com:443");
        let b = ConnectorConfig::env_scoped_instance_id(device, "wss://studio.example.com:443");
        assert_eq!(a, b);
    }

    #[test]
    fn env_scoped_instance_id_falls_back_to_device_id_when_host_empty() {
        assert_eq!(
            ConnectorConfig::env_scoped_instance_id("dev-1", ""),
            "dev-1"
        );
    }

    #[test]
    fn plg_connect_decision_matrix() {
        use crate::config::{plg_connect_decision, PlgConnectStep};
        assert_eq!(plg_connect_decision(true, true), PlgConnectStep::Silent);
        assert_eq!(plg_connect_decision(true, false), PlgConnectStep::SignIn);
        // Expert mode is handled by the existing path; decision is Silent.
        assert_eq!(plg_connect_decision(false, false), PlgConnectStep::Silent);
        assert_eq!(plg_connect_decision(false, true), PlgConnectStep::Silent);
    }

    // The SSRF-mode selection is a pure function of the env-var value, so it is
    // tested directly — no env manipulation, and (crucially) the assertions run
    // in CI's debug build, unlike anything gated on `debug_assertions`.
    use crate::url_validation::ValidationMode;

    #[test]
    fn resolve_validation_mode_opts_in_on_truthy_values() {
        // "true"/"1", case-insensitive, whitespace-tolerant → PrivateNetwork.
        for v in ["true", "1", "TRUE", "True", "  true  ", "\t1\n"] {
            assert_eq!(
                ConnectorConfig::resolve_validation_mode(Some(v)),
                ValidationMode::PrivateNetwork,
                "{v:?} should opt in to PrivateNetwork"
            );
        }
    }

    #[test]
    fn resolve_validation_mode_secure_default_otherwise() {
        // Anything non-truthy, and unset, falls back to the default (Production
        // in release builds). Asserting equality with default() makes the test
        // build-profile-independent and meaningful in CI's debug run.
        for v in [
            Some("false"),
            Some("0"),
            Some("yes"),
            Some(""),
            Some("nope"),
            Some("ture"),
            None,
        ] {
            assert_eq!(
                ConnectorConfig::resolve_validation_mode(v),
                ValidationMode::default(),
                "{v:?} must NOT opt in (secure default)"
            );
        }
    }

    #[test]
    fn resolve_validation_mode_never_returns_development() {
        // The opt-in must select the NARROW PrivateNetwork mode, never full
        // Development (which would also unblock link-local / cloud-metadata).
        assert_ne!(
            ConnectorConfig::resolve_validation_mode(Some("true")),
            ValidationMode::Development
        );
    }

    #[test]
    fn validate_allows_private_cluster_ip_via_private_network_mode() {
        // End-to-end: PrivateNetwork mode accepts an in-cluster ClusterIP but
        // still rejects the cloud-metadata endpoint. Uses validate_url directly
        // with the mode resolve_validation_mode would pick, so it is stable in
        // both debug and release.
        use crate::url_validation::validate_url;
        assert!(
            validate_url(
                "grpc://10.109.18.109:50061",
                ValidationMode::PrivateNetwork,
                None
            )
            .is_ok(),
            "ClusterIP must be allowed in PrivateNetwork mode"
        );
        assert!(
            validate_url(
                "http://169.254.169.254:80",
                ValidationMode::PrivateNetwork,
                None
            )
            .is_err(),
            "cloud-metadata endpoint must stay blocked in PrivateNetwork mode"
        );
    }

    #[test]
    fn sage_is_default_theme() {
        assert_eq!(Theme::default(), Theme::Sage);
    }

    #[test]
    fn sage_themes_roundtrip_serde() {
        for t in [Theme::Sage, Theme::SageLight] {
            let json = serde_json::to_string(&t).unwrap();
            let back: Theme = serde_json::from_str(&json).unwrap();
            assert_eq!(t, back);
        }
    }

    #[test]
    fn app_settings_roundtrips_last_config_host() {
        let s = AppSettings {
            last_config: Some(ConnectorConfig {
                host: "wss://user-chosen.example".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: AppSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.last_config.unwrap().host,
            "wss://user-chosen.example",
            "a persisted endpoint must survive restart"
        );
    }
}

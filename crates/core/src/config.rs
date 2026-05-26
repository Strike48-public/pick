//! Configuration types for the connector

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::aggression::AggressionLevel;

/// Shell execution mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ShellMode {
    /// Run commands directly on the host machine (native shell)
    #[default]
    Native,
    /// Run commands inside the proot BlackArch environment
    Proot,
}

/// UI theme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Theme {
    #[default]
    Strike48,
    Dark,
    Light,
    Dracula,
    Gruvbox,
    TokyoNight,
    Matrix,
    Cyberpunk,
    Nord,
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

        // Validate host URL for SSRF protection
        use crate::url_validation::{validate_url, ValidationMode};

        let validation_mode = ValidationMode::default();
        validate_url(&self.host, validation_mode, None)
            .map_err(|e| format!("Invalid host URL: {}", e))?;

        Ok(())
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
    if let Ok(tenant) = std::env::var("STRIKE48_TENANT").or_else(|_| std::env::var("TENANT_ID")) {
        config.tenant_id = tenant;
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
}

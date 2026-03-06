//! Configuration types for the connector

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Shell execution mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ShellMode {
    /// Run commands directly on the host machine (native shell)
    #[default]
    Native,
    /// Run commands inside the proot BlackArch environment
    Proot,
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
}

impl Default for ConnectorConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            tenant_id: "default".to_string(),
            auth_token: String::new(),
            instance_id: Uuid::new_v4().to_string(),
            display_name: None,
            tags: vec![],
            use_tls: true,
            reconnect_enabled: true,
            reconnect_delay_ms: 5000,
            max_backoff_delay_ms: 60000,
        }
    }
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

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.host.is_empty() {
            return Err("Strike48 host is required".to_string());
        }
        if self.tenant_id.is_empty() {
            return Err("Tenant ID is required".to_string());
        }
        Ok(())
    }

    /// Check if this config has authentication
    pub fn has_auth(&self) -> bool {
        !self.auth_token.is_empty()
    }

    /// Strip any URL scheme prefix from the host and return the bare `host:port`.
    ///
    /// Handles `grpc://`, `grpcs://`, `http://`, `https://`, `ws://`, `wss://`.
    /// Returns `Err` if the result is empty or missing a port (no `:`).
    pub fn normalize_host(host: &str) -> Result<String, String> {
        let schemes = [
            "grpc://", "grpcs://", "http://", "https://", "ws://", "wss://",
        ];
        let mut h = host.trim();
        for scheme in &schemes {
            if let Some(stripped) = h.strip_prefix(scheme) {
                h = stripped;
                break;
            }
        }

        if h.is_empty() || !h.contains(':') {
            return Err("Invalid host format. Use host:port (e.g., localhost:50061)".to_string());
        }
        Ok(h.to_string())
    }

    /// Convert to the SDK's ConnectorConfig
    pub fn to_sdk_config(&self) -> strike48_connector::ConnectorConfig {
        let mut sdk_config = strike48_connector::ConnectorConfig {
            host: self.host.clone(),
            tenant_id: self.tenant_id.clone(),
            instance_id: self.instance_id.clone(),
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
    pub dark_mode: bool,

    /// Shell execution mode (native or proot)
    pub shell_mode: ShellMode,

    /// Download state for BlackArch ISO
    pub download_state: DownloadState,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            device_id: Uuid::new_v4().to_string(),
            last_config: None,
            auto_connect: false,
            terminal_font_size: 14,
            terminal_max_lines: 10000,
            dark_mode: true,
            shell_mode: ShellMode::default(),
            download_state: DownloadState::default(),
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
    if let Ok(host) = std::env::var("STRIKE48_HOST").or_else(|_| std::env::var("STRIKE48_URL")) {
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
            "--no-tls" => {
                config.use_tls = false;
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
    // normalize_host used to strip the scheme here, which broke WSS detection.

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

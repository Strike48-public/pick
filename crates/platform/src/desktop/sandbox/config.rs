//! Sandbox configuration and error types

use std::path::PathBuf;
use thiserror::Error;

/// Sandbox execution errors
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Neither bwrap nor proot available
    #[error(
        "No sandbox backend available: bwrap requires Linux with user namespaces, proot not found"
    )]
    NoBackendAvailable,

    /// Rootfs download/setup failed
    #[error("Rootfs setup failed: {0}")]
    RootfsSetupFailed(String),

    /// IO error during sandbox operations
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Network/download error
    #[error("Download error: {0}")]
    Download(String),

    /// Timeout during execution
    #[error("Command timed out after {0} seconds")]
    Timeout(u64),

    /// WSL2 not available
    #[error("WSL2 not available: {0}")]
    WslNotAvailable(String),

    /// WSL distro operation failed
    #[error("WSL distro error: {0}")]
    WslDistroError(String),
}

/// Result type for sandbox operations
pub type SandboxResult<T> = std::result::Result<T, SandboxError>;

/// Sandbox backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxBackend {
    /// Bubblewrap (Linux namespaces) - preferred on Linux
    Bwrap,
    /// Proot - universal fallback
    Proot,
    /// WSL2 - preferred on Windows
    Wsl,
    /// Docker - cross-platform, preferred on macOS
    Docker,
}

impl std::fmt::Display for SandboxBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxBackend::Bwrap => write!(f, "bwrap"),
            SandboxBackend::Proot => write!(f, "proot"),
            SandboxBackend::Wsl => write!(f, "wsl"),
            SandboxBackend::Docker => write!(f, "docker"),
        }
    }
}

/// Configuration for the sandbox environment
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Directory to store the rootfs and related files
    pub data_dir: PathBuf,

    /// Workspace directory to mount inside the sandbox
    pub workspace_dir: Option<PathBuf>,

    /// Preferred backend (None = auto-detect)
    pub preferred_backend: Option<SandboxBackend>,

    /// Whether to enable network access (default: true for pentest tools)
    pub network_access: bool,

    /// Environment variables to pass into the sandbox
    pub env_vars: Vec<(String, String)>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            workspace_dir: None,
            preferred_backend: None,
            network_access: true,
            env_vars: vec![
                ("TERM".to_string(), "xterm-256color".to_string()),
                ("HOME".to_string(), "/root".to_string()),
                (
                    "PATH".to_string(),
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                ),
            ],
        }
    }
}

impl SandboxConfig {
    /// Create a new config with the given data directory
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            ..Default::default()
        }
    }

    /// Set the workspace directory
    pub fn with_workspace(mut self, workspace: PathBuf) -> Self {
        self.workspace_dir = Some(workspace);
        self
    }

    /// Set the preferred backend
    pub fn with_backend(mut self, backend: SandboxBackend) -> Self {
        self.preferred_backend = Some(backend);
        self
    }

    /// Disable network access
    pub fn without_network(mut self) -> Self {
        self.network_access = false;
        self
    }

    /// Add an environment variable
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }

    /// Get the rootfs directory path
    pub fn rootfs_dir(&self) -> PathBuf {
        self.data_dir.join("blackarch-rootfs")
    }

    /// Get the proot binary path (for downloaded proot)
    pub fn proot_binary_path(&self) -> PathBuf {
        self.data_dir.join("bin").join("proot")
    }

    /// Get the WSL distro name
    pub fn wsl_distro_name(&self) -> &str {
        "pentest-blackarch"
    }

    /// Get the WSL distro install directory
    pub fn wsl_install_dir(&self) -> PathBuf {
        self.data_dir.join("wsl-distro")
    }
}

/// Get the default data directory for sandbox files
fn default_data_dir() -> PathBuf {
    // On Windows, use %LOCALAPPDATA%
    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join("pentest-sandbox");
        }
    }

    // Try XDG_DATA_HOME first, fall back to ~/.local/share
    if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg_data).join("pentest-sandbox")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("pentest-sandbox")
    } else {
        // Last resort
        PathBuf::from("/tmp/pentest-sandbox")
    }
}

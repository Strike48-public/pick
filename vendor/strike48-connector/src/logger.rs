use tracing::{debug, error, info, trace, warn};

/// Initialize the logger with configurable log levels.
///
/// # Default Level
///
/// The default log level is `warn`. This means only warnings and errors are shown.
///
/// # Environment Variable Override
///
/// Set the `RUST_LOG` environment variable to override the log level:
///
/// ```bash
/// # Show info-level logs (connection status, registration)
/// RUST_LOG=info cargo run
///
/// # Show debug-level logs (transport details, token operations)
/// RUST_LOG=debug cargo run
///
/// # Show trace-level logs (per-message, heartbeats)
/// RUST_LOG=trace cargo run
///
/// # Module-specific filtering
/// RUST_LOG=strike48_connector=debug,warn cargo run
/// ```
///
/// # Log Level Guidelines
///
/// - **error**: Failures that prevent operation (connection failed, registration rejected)
/// - **warn**: Issues that may need attention (reconnecting, token expired)
/// - **info**: Significant lifecycle events (connected, registered, shutting down)
/// - **debug**: Operational details (token refresh, stream operations, config)
/// - **trace**: Per-message/heartbeat details (individual messages, pings)
pub fn init_logger() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();
}

/// Create a logger for a specific module
pub struct Logger {
    module: String,
}

impl Logger {
    pub fn new(module: &str) -> Self {
        Self {
            module: module.to_string(),
        }
    }

    pub fn info(&self, message: &str) {
        info!(module = %self.module, "{}", message);
    }

    pub fn debug(&self, message: &str) {
        debug!(module = %self.module, "{}", message);
    }

    #[allow(dead_code)]
    pub fn trace(&self, message: &str) {
        trace!(module = %self.module, "{}", message);
    }

    pub fn warn(&self, message: &str) {
        warn!(module = %self.module, "{}", message);
    }

    pub fn error(&self, message: &str, error_msg: &str) {
        error!(module = %self.module, "{}: {}", message, error_msg);
    }
}

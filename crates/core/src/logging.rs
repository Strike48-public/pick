//! Shared logging initialization for all Pentest Connector applications.
//!
//! Centralises `tracing_subscriber` setup so every binary gets consistent
//! formatting, env-filter behaviour and the `pentest=<level>` directive.

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialise a console-only tracing subscriber.
///
/// `default_level` is the tracing level applied to the `pentest` target
/// (e.g. `"info"`, `"debug"`).  The `RUST_LOG` env var can still override
/// at runtime.
///
/// # Panics
/// Panics if the level string cannot be parsed as a valid tracing directive.
pub fn init_logging(default_level: &str) {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env()
                .add_directive(format!("pentest={default_level}").parse().unwrap()),
        )
        .init();
}

/// Initialise a tracing subscriber that writes to **both** the console and a
/// log file.
///
/// The console layer uses ANSI colours; the file layer does not.
///
/// `default_level` is the tracing level applied to the `pentest` target
/// (e.g. `"info"`, `"debug"`).
///
/// Returns the path to the created log file so callers can log it.
///
/// # Panics
/// Panics if the log directory cannot be created or the log file cannot be
/// opened.
pub fn init_logging_with_file(default_level: &str) -> std::path::PathBuf {
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("pentest-connector")
        .join("logs");
    std::fs::create_dir_all(&log_dir).expect("failed to create log directory");

    let log_path = log_dir.join("connector.log");
    let log_file = std::fs::File::create(&log_path).expect("failed to create log file");

    tracing_subscriber::registry()
        .with(fmt::layer().with_ansi(true))
        .with(
            fmt::layer()
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(log_file)),
        )
        .with(
            EnvFilter::from_default_env()
                .add_directive(format!("pentest={default_level}").parse().unwrap()),
        )
        .init();

    log_path
}

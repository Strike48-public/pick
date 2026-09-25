//! Shared logging initialization for all Pentest Connector applications.
//!
//! Centralises `tracing_subscriber` setup so every binary gets consistent
//! formatting, env-filter behaviour and the `pentest=<level>` directive.
//!
//! The file sink is the artifact a customer hands to support after a failure,
//! so it is built to survive the things that happen around a failure: it
//! appends instead of truncating (a relaunch must not erase the evidence),
//! rotates daily and keeps [`LOG_FILES_KEPT`] files, and writes JSON lines so
//! a log can be filtered by `tool_call_id` with one command and parsed by the
//! diagnostics export (pick#476).

use std::path::{Path, PathBuf};
use tracing::Subscriber;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Layer};

/// Daily log files kept on disk before the oldest is pruned. A week bounds
/// disk use while still covering a failure the customer only noticed later.
pub const LOG_FILES_KEPT: usize = 7;

/// Rotated files are named `connector.<YYYY-MM-DD>.log`.
pub const LOG_FILE_PREFIX: &str = "connector";
const LOG_FILE_SUFFIX: &str = "log";

/// Directory the file sink writes to: the platform's local data dir under
/// `pentest-connector/logs` (macOS `~/Library/Application Support`, Linux
/// `~/.local/share`, Windows `%LOCALAPPDATA%`), with `/tmp` as the fallback
/// on targets that report no data dir.
pub fn log_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("pentest-connector")
        .join("logs")
}

/// Open the rolling file appender in `log_dir`, creating the directory.
///
/// The appender always opens its file in append mode, rotates at midnight
/// UTC, and prunes to [`LOG_FILES_KEPT`] files. Errors are returned, not
/// panicked on, so a host where the directory cannot be created (a read-only
/// container filesystem, a locked-down profile) can still start with console
/// logging only.
pub fn open_log_appender(log_dir: &Path) -> std::io::Result<RollingFileAppender> {
    std::fs::create_dir_all(log_dir)?;
    restrict_to_owner(log_dir)?;
    RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(LOG_FILE_PREFIX)
        .filename_suffix(LOG_FILE_SUFFIX)
        .max_log_files(LOG_FILES_KEPT)
        .build(log_dir)
        .map_err(std::io::Error::other)
}

/// Make the log directory owner-only (`0700`).
///
/// The appender creates files with the process umask, which is usually
/// world-readable, and Pick logs carry tool output from an engagement. Locking
/// the directory covers every file in it, including ones already written.
#[cfg(unix)]
fn restrict_to_owner(log_dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(log_dir, std::fs::Permissions::from_mode(0o700))
}

/// Windows has no mode bits; `%LOCALAPPDATA%` is already per-user.
#[cfg(not(unix))]
fn restrict_to_owner(_log_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// The JSON-lines file layer.
///
/// One object per event with `timestamp`, `level`, `target`, `fields`, the
/// current `span` and the enclosing `spans`, so the correlation ids carried by
/// the tool-execution span land on every line as queryable keys rather than
/// as text to be parsed out of a prefix.
pub fn json_file_layer<S>(appender: RollingFileAppender) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fmt::layer()
        .json()
        .with_ansi(false)
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(appender)
}

/// `RUST_LOG` if set, plus the `pentest=<default_level>` directive for Pick's
/// own crates.
///
/// # Panics
/// Panics if the level string cannot be parsed as a valid tracing directive.
fn env_filter(default_level: &str) -> EnvFilter {
    EnvFilter::from_default_env().add_directive(
        format!("pentest={default_level}")
            .parse()
            .expect("default level is a valid tracing directive"),
    )
}

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
        .with(env_filter(default_level))
        .init();
}

/// Initialise a tracing subscriber that writes to **both** the console and
/// the rolling JSON log file under [`log_dir`].
///
/// The console layer keeps the human-readable format; the file layer is
/// JSON lines (see [`json_file_layer`]).
///
/// `default_level` is the tracing level applied to the `pentest` target
/// (e.g. `"info"`, `"debug"`).
///
/// Returns the log directory when the file sink is active. When the
/// directory cannot be created or the file cannot be opened, a console-only
/// subscriber is installed instead, a warning names the failure, and `None`
/// is returned: a missing log file must not stop the connector from starting.
///
/// # Panics
/// Panics if the level string cannot be parsed as a valid tracing directive.
pub fn init_logging_with_file(default_level: &str) -> Option<PathBuf> {
    let log_dir = log_dir();
    match open_log_appender(&log_dir) {
        Ok(appender) => {
            tracing_subscriber::registry()
                .with(fmt::layer())
                .with(json_file_layer(appender))
                .with(env_filter(default_level))
                .init();
            Some(log_dir)
        }
        Err(err) => {
            init_logging(default_level);
            tracing::warn!(
                error = %err,
                dir = %log_dir.display(),
                "log file sink unavailable; logging to console only"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_files(dir: &Path) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .expect("log dir readable")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        files.sort();
        files
    }

    fn emit_one_round(dir: &Path, f: impl FnOnce()) {
        let appender = open_log_appender(dir).expect("appender opens");
        let subscriber = tracing_subscriber::registry().with(json_file_layer(appender));
        tracing::subscriber::with_default(subscriber, f);
    }

    fn json_lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .expect("log file readable")
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}")))
            .collect()
    }

    #[test]
    fn file_sink_appends_across_restarts_instead_of_truncating() {
        let tmp = tempfile::tempdir().expect("tempdir");

        emit_one_round(tmp.path(), || tracing::info!(round = 1, "restart marker"));
        emit_one_round(tmp.path(), || tracing::info!(round = 2, "restart marker"));

        let files = log_files(tmp.path());
        assert_eq!(files.len(), 1, "one daily file expected: {files:?}");
        let name = files[0].file_name().unwrap().to_string_lossy();
        assert!(
            name.starts_with("connector.") && name.ends_with(".log"),
            "unexpected file name {name}"
        );

        let lines = json_lines(&files[0]);
        let rounds: Vec<u64> = lines
            .iter()
            .map(|v| v["fields"]["round"].as_u64().expect("round field"))
            .collect();
        assert_eq!(
            rounds,
            vec![1, 2],
            "second start must append after the first, not replace it"
        );
    }

    #[test]
    fn file_sink_lines_carry_span_fields_as_json_keys() {
        let tmp = tempfile::tempdir().expect("tempdir");

        emit_one_round(tmp.path(), || {
            let span = tracing::info_span!("tool_execution", tool = "nmap", request_id = "req-1");
            let _guard = span.enter();
            tracing::warn!(error = "boom", "tool execution failed");
        });

        let lines = json_lines(&log_files(tmp.path())[0]);
        assert_eq!(lines.len(), 1, "{lines:?}");
        let line = &lines[0];
        assert_eq!(line["level"], "WARN");
        assert_eq!(line["fields"]["message"], "tool execution failed");
        assert_eq!(line["fields"]["error"], "boom");
        assert_eq!(line["span"]["name"], "tool_execution");
        assert_eq!(line["span"]["request_id"], "req-1");
        assert_eq!(line["spans"][0]["tool"], "nmap");
    }

    #[test]
    fn open_log_appender_creates_a_missing_nested_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("pentest-connector").join("logs");
        assert!(!nested.exists());

        open_log_appender(&nested).expect("appender opens");

        assert!(nested.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn open_log_appender_makes_the_directory_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("logs");

        open_log_appender(&dir).expect("appender opens");

        let mode = std::fs::metadata(&dir)
            .expect("dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "log dir must not be group/world readable");
    }

    #[test]
    fn open_log_appender_returns_an_error_instead_of_panicking() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let not_a_dir = tmp.path().join("occupied");
        std::fs::write(&not_a_dir, b"x").expect("write marker file");

        let err = open_log_appender(&not_a_dir).expect_err("a file cannot be a log dir");
        assert!(!err.to_string().is_empty());
    }
}

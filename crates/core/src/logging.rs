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

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
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
    precreate_todays_file(log_dir)?;
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

/// Create today's file owner-only (`0600`) before the appender opens it.
///
/// `tracing_appender` opens with the process umask (usually `0644`) and has
/// no mode option; it appends to an existing file without changing its mode,
/// so creating the file first fixes the mode of the file this process starts
/// writing. A file the appender rolls over to mid-run is still created with
/// the umask, inside the `0700` directory.
#[cfg(unix)]
fn precreate_todays_file(log_dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let name = format!(
        "{LOG_FILE_PREFIX}.{}.{LOG_FILE_SUFFIX}",
        chrono::Utc::now().format("%Y-%m-%d")
    );
    let path = log_dir.join(name);
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&path)?;
    // An existing file keeps its old mode through `open`.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn precreate_todays_file(_log_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Wrap a file-sink writer so write failures are visible and never corrupt
/// a neighbouring record. `tracing_subscriber`'s fmt layer swallows writer
/// errors: with a bare `RollingFileAppender`, a disk-full or quota failure
/// stops the file with no signal anywhere, and a write cut short leaves a
/// partial JSON line that the next record is appended onto (review findings
/// on pick#484, probed with RLIMIT_FSIZE).
///
/// Each event is buffered and committed as one line-terminated record. If a
/// commit fails after some of its bytes landed, the next record starts with a
/// newline, so the cut-off fragment stays on a line of its own and every
/// later record parses. The first failure prints one loud console line and
/// is recorded in [`FileSinkHealth`]; later records keep retrying the
/// underlying sink (so a transient ENOSPC self-heals) and never panic or
/// propagate the error into the event stream.
struct FailLoud<W> {
    inner: W,
    health: Arc<FileSinkHealth>,
}

impl<'a, W> fmt::MakeWriter<'a> for FailLoud<W>
where
    W: fmt::MakeWriter<'a>,
{
    type Writer = FailLoudWriter<W::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        FailLoudWriter {
            inner: self.inner.make_writer(),
            record: Vec::new(),
            health: self.health.clone(),
        }
    }
}

/// One event's writer: collects the formatted record and commits it whole
/// on flush or drop.
struct FailLoudWriter<W: Write> {
    inner: W,
    record: Vec<u8>,
    health: Arc<FileSinkHealth>,
}

impl<W: Write> FailLoudWriter<W> {
    fn commit(&mut self) {
        if self.record.is_empty() {
            return;
        }
        let mut record = std::mem::take(&mut self.record);
        // Held across the write so in-process records cannot interleave with
        // the fragment bookkeeping.
        let mut fragment_open = self
            .health
            .fragment_open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prefixed = *fragment_open;
        if prefixed {
            record.insert(0, b'\n');
        }
        match write_counted(&mut self.inner, &record) {
            Ok(()) => *fragment_open = false,
            Err((written, err)) => {
                // The line is left open unless exactly the separator newline
                // landed: nothing at all written with no prefix, or only the
                // prefix written.
                *fragment_open = written != usize::from(prefixed);
                drop(fragment_open);
                self.health.record_failure(&err);
            }
        }
    }
}

impl<W: Write> Write for FailLoudWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.record.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.commit();
        if let Err(err) = self.inner.flush() {
            self.health.record_failure(&err);
        }
        // A failed log write must never take down the event stream.
        Ok(())
    }
}

impl<W: Write> Drop for FailLoudWriter<W> {
    fn drop(&mut self) {
        self.commit();
    }
}

/// `write_all` that reports how many bytes landed before an error.
fn write_counted(w: &mut impl Write, buf: &[u8]) -> Result<(), (usize, std::io::Error)> {
    let mut written = 0;
    while written < buf.len() {
        match w.write(&buf[written..]) {
            Ok(0) => return Err((written, std::io::ErrorKind::WriteZero.into())),
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err((written, e)),
        }
    }
    Ok(())
}

/// Whether the file sink has dropped events to a write failure.
///
/// The installed sink's handle is kept for the life of the process and read
/// through [`file_sink_failed`], which the settings Logs card shows.
#[derive(Default)]
pub struct FileSinkHealth {
    failed: AtomicBool,
    reported: AtomicBool,
    /// A failed write left a partial line at the end of the file.
    fragment_open: Mutex<bool>,
}

impl FileSinkHealth {
    /// True once a write to the file sink has failed this process.
    pub fn has_failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    fn record_failure(&self, err: &std::io::Error) {
        self.failed.store(true, Ordering::Relaxed);
        if !self.reported.swap(true, Ordering::Relaxed) {
            eprintln!(
                "pick log file sink is failing (IO error: {err}); events are NOT reaching the log file until this resolves"
            );
        }
    }
}

/// Health of the file sink installed by [`init_logging_with_file`].
static FILE_SINK_HEALTH: OnceLock<Arc<FileSinkHealth>> = OnceLock::new();

/// True when the installed file sink has failed a write this process. False
/// when it is healthy or when no file sink is installed.
pub fn file_sink_failed() -> bool {
    FILE_SINK_HEALTH.get().is_some_and(|h| h.has_failed())
}

/// The JSON-lines file layer, plus the health handle of its sink.
///
/// One object per event with `timestamp`, `level`, `target`, `fields`, the
/// current `span` and the enclosing `spans`, so the correlation ids carried by
/// the tool-execution span land on every line as queryable keys rather than
/// as text to be parsed out of a prefix. The writer is wrapped in
/// [`FailLoud`], so a write failure is reported and never corrupts a record.
pub fn json_file_layer<S, W>(writer: W) -> (impl Layer<S>, Arc<FileSinkHealth>)
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'a> fmt::MakeWriter<'a> + 'static,
{
    let health = Arc::new(FileSinkHealth::default());
    let layer = json_layer(FailLoud {
        inner: writer,
        health: health.clone(),
    });
    (layer, health)
}

fn json_layer<S, W>(writer: W) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'a> fmt::MakeWriter<'a> + 'static,
{
    fmt::layer()
        .json()
        .with_ansi(false)
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(writer)
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
            let (file_layer, health) = json_file_layer(appender);
            // Retained so the settings Logs card can say the file stopped.
            let _ = FILE_SINK_HEALTH.set(health);
            tracing_subscriber::registry()
                .with(fmt::layer())
                .with(file_layer)
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
        let (layer, _health) = json_file_layer(appender);
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, f);
    }

    /// A disk with an optional size limit, the shape the review probed with
    /// RLIMIT_FSIZE: a write that crosses the limit lands only the bytes that
    /// fit, and every later write fails until the limit is lifted. The room
    /// left is computed with `saturating_sub`, so a full disk stays full.
    /// Local newtype so the orphan rules allow the MakeWriter impl.
    #[derive(Clone, Default)]
    struct FakeDisk(Arc<Mutex<DiskState>>);

    #[derive(Default)]
    struct DiskState {
        bytes: Vec<u8>,
        limit: Option<usize>,
        failed_writes: usize,
    }

    impl FakeDisk {
        fn state(&self) -> std::sync::MutexGuard<'_, DiskState> {
            self.0.lock().expect("fake disk poisoned")
        }

        /// Fill up: allow `extra` more bytes, then fail every write.
        fn fill_after(&self, extra: usize) {
            let mut st = self.state();
            st.limit = Some(st.bytes.len() + extra);
        }

        fn free_space(&self) {
            self.state().limit = None;
        }

        fn contents(&self) -> String {
            String::from_utf8(self.state().bytes.clone()).expect("utf8 log")
        }
    }

    impl fmt::MakeWriter<'_> for FakeDisk {
        type Writer = FakeDisk;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    impl Write for FakeDisk {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut st = self.state();
            let room = st
                .limit
                .map_or(usize::MAX, |limit| limit.saturating_sub(st.bytes.len()));
            if room == 0 {
                st.failed_writes += 1;
                return Err(std::io::Error::other("disk full (simulated)"));
            }
            let n = buf.len().min(room);
            st.bytes.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Run `f` against the production file layer writing to `disk`.
    fn with_file_layer(disk: &FakeDisk, f: impl FnOnce()) -> Arc<FileSinkHealth> {
        let (layer, health) = json_file_layer(disk.clone());
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, f);
        health
    }

    /// The review's defect shape: the disk fills mid-record and stays full.
    /// The subscriber must not panic, must keep retrying every later record
    /// (each one fails), and the failure must be observable.
    #[test]
    fn write_failures_are_loud_and_never_panic() {
        let disk = FakeDisk::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_file_layer(&disk, || {
                tracing::info!(event = 0, "before the disk fills");
                disk.fill_after(10);
                for i in 1..50 {
                    tracing::info!(event = i, "survives sink failure");
                }
            })
        }));
        let health = result.expect("a failing file sink must never panic the process");
        assert!(
            health.has_failed(),
            "the write failure must be observable, not silent"
        );
        assert_eq!(
            disk.state().failed_writes,
            49,
            "every record after the disk filled must be retried and fail"
        );
    }

    /// No corruption: a record cut short by a failed write must not swallow
    /// the next one. After space frees up, every later record is whole JSON
    /// on its own line; the only unparseable line is the cut-off fragment.
    #[test]
    fn a_failed_partial_write_never_corrupts_the_next_record() {
        let disk = FakeDisk::default();
        with_file_layer(&disk, || {
            tracing::info!(event = 0, "written whole");
            disk.fill_after(10);
            for i in 1..5 {
                tracing::info!(event = i, "dropped while the disk is full");
            }
            disk.free_space();
            for i in 5..10 {
                tracing::info!(event = i, "written after recovery");
            }
        });

        let contents = disk.contents();
        let (parsed, fragments): (Vec<_>, Vec<_>) = contents
            .lines()
            .map(|l| (l, serde_json::from_str::<serde_json::Value>(l)))
            .partition(|(_, r)| r.is_ok());
        let events: Vec<u64> = parsed
            .into_iter()
            .map(|(_, r)| r.unwrap()["fields"]["event"].as_u64().expect("event"))
            .collect();
        assert_eq!(events, vec![0, 5, 6, 7, 8, 9], "file was:\n{contents}");
        assert_eq!(fragments.len(), 1, "one cut-off fragment: {contents}");
        assert_eq!(
            fragments[0].0.len(),
            10,
            "fragment is the 10 bytes that fit"
        );
        assert!(contents.ends_with('\n'), "file ends on a whole line");
    }

    #[cfg(unix)]
    #[test]
    fn log_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");

        emit_one_round(tmp.path(), || tracing::info!("mode probe"));

        let files = log_files(tmp.path());
        assert_eq!(files.len(), 1, "{files:?}");
        let mode = std::fs::metadata(&files[0])
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "log file must not be group/world readable");
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

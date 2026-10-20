//! The one in-memory buffer behind every Logs page (pick#476).
//!
//! Before this module the native page (`connector_app`) and the LiveView page
//! (`WorkspaceApp`) each kept their own list, fed by different paths, so a
//! line could reach one page and not the other, and the LiveView copy stopped
//! updating at its cap. Now there is one bounded ring buffer:
//!
//! * [`emit`] is how UI code writes a line. The full line, details included,
//!   goes to the buffer; a tracing event marked `ui = true` carries only the
//!   level and the redacted message to the console and the log file. Tool
//!   arguments and results stay in memory and never reach the log file.
//! * [`UiLogLayer`] adds every other `WARN`/`ERROR` tracing event to the
//!   buffer, so a failure logged anywhere in Pick shows on the Logs page
//!   without a second call at the call site. It skips `ui = true` events,
//!   which are already in the buffer.
//! * [`seed_from_log_file`] restores the previous session's UI lines and
//!   warnings from the newest log file at start-up (pick#399).
//!
//! Every line gets a sequence number. A page keeps the last number it has
//! shown and appends only newer lines, so its own Clear sticks and a full
//! buffer keeps flowing (the old page compared line counts, which stop
//! changing at the cap).

use crate::provenance::redact;
use crate::terminal::{LogLevel, TerminalLine};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{LazyLock, Mutex, PoisonError};
use tokio::sync::watch;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Most lines held. The oldest line is dropped when a new one would exceed it.
pub const UI_LOG_CAPACITY: usize = 5000;

/// Most previous-session lines restored at start-up.
pub const SEED_MAX_LINES: usize = 500;

/// Field that marks a tracing event as a UI line already in the buffer.
const UI_FIELD: &str = "ui";
/// Field that carries [`LogLevel::Success`], which tracing has no level for.
const OUTCOME_FIELD: &str = "outcome";
const OUTCOME_SUCCESS: &str = "success";
/// Field that carries [`TerminalLine::source`].
const SOURCE_FIELD: &str = "source";

/// A bounded, sequence-numbered list of [`TerminalLine`]s with a change
/// notifier.
pub struct UiLog {
    capacity: usize,
    inner: Mutex<Inner>,
    /// Carries the newest sequence number; a page awaits `changed()`.
    notify: watch::Sender<u64>,
}

#[derive(Default)]
struct Inner {
    lines: VecDeque<(u64, TerminalLine)>,
    last_seq: u64,
}

impl UiLog {
    /// An empty buffer holding at most `capacity` lines.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new(Inner::default()),
            notify: watch::channel(0).0,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A push cannot leave the deque half-updated, so a poisoned lock is
        // still consistent. Recovering silently matters here: logging the
        // poison would re-enter this buffer through the layer.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Add `line` to the buffer and wake the pages. Emits no tracing event,
    /// so it is safe to call from inside a tracing layer. Returns the line's
    /// sequence number (the first line is 1).
    pub fn push(&self, line: TerminalLine) -> u64 {
        let seq = {
            let mut inner = self.lock();
            inner.last_seq += 1;
            let seq = inner.last_seq;
            inner.lines.push_back((seq, line));
            while inner.lines.len() > self.capacity {
                inner.lines.pop_front();
            }
            seq
        };
        self.notify.send_replace(seq);
        seq
    }

    /// The lines numbered after `seq`, oldest first, and the newest number.
    /// Lines already dropped from the buffer are not returned.
    pub fn since(&self, seq: u64) -> (Vec<TerminalLine>, u64) {
        let inner = self.lock();
        let lines = inner
            .lines
            .iter()
            .filter(|(s, _)| *s > seq)
            .map(|(_, line)| line.clone())
            .collect();
        (lines, inner.last_seq)
    }

    /// A receiver whose `changed()` resolves after each [`push`](Self::push).
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.notify.subscribe()
    }

    /// Add `line` to the buffer and send its level and redacted message to
    /// the tracing subscriber. The details stay in the buffer only.
    pub fn emit(&self, line: TerminalLine) {
        trace_ui_line(&line);
        self.push(line);
    }
}

/// The process-wide buffer every Logs page reads.
pub fn global() -> &'static UiLog {
    static GLOBAL: LazyLock<UiLog> = LazyLock::new(|| UiLog::new(UI_LOG_CAPACITY));
    &GLOBAL
}

/// Write a line to the Logs pages (see [`UiLog::emit`]).
pub fn emit(line: TerminalLine) {
    global().emit(line);
}

/// The `ui = true` tracing event for a line: level, redacted message and
/// source, never the details.
fn trace_ui_line(line: &TerminalLine) {
    let message = redact(&line.message);
    let source = line.source.as_deref();
    match line.level {
        LogLevel::Debug => tracing::debug!(ui = true, source, "{message}"),
        LogLevel::Info => tracing::info!(ui = true, source, "{message}"),
        LogLevel::Success => {
            tracing::info!(ui = true, outcome = OUTCOME_SUCCESS, source, "{message}")
        }
        LogLevel::Warning => tracing::warn!(ui = true, source, "{message}"),
        LogLevel::Error => tracing::error!(ui = true, source, "{message}"),
    }
}

/// A tracing layer that adds `WARN` and `ERROR` events to a [`UiLog`].
///
/// Events marked `ui = true` are skipped: [`UiLog::emit`] already put them in
/// the buffer. The layer never emits tracing itself, so it cannot recurse.
pub struct UiLogLayer {
    log: &'static UiLog,
}

/// The layer feeding the [`global`] buffer.
pub fn layer() -> UiLogLayer {
    UiLogLayer { log: global() }
}

impl UiLogLayer {
    /// A layer feeding `log` instead of the global buffer.
    pub fn new(log: &'static UiLog) -> Self {
        Self { log }
    }
}

impl<S: Subscriber> Layer<S> for UiLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // Tracing orders levels by verbosity: everything above WARN is
        // INFO, DEBUG or TRACE.
        let level = *event.metadata().level();
        if level > Level::WARN {
            return;
        }
        let mut fields = EventFields::default();
        event.record(&mut fields);
        if fields.ui {
            return;
        }
        let level = if level == Level::ERROR {
            LogLevel::Error
        } else {
            LogLevel::Warning
        };
        self.log
            .push(TerminalLine::new(level, redact(&fields.text())));
    }
}

/// The message and remaining fields of one event.
#[derive(Default)]
struct EventFields {
    ui: bool,
    message: String,
    rest: Vec<String>,
}

impl EventFields {
    /// `message k=v k=v`, the shape the console formatter prints.
    fn text(&self) -> String {
        std::iter::once(self.message.as_str())
            .chain(self.rest.iter().map(String::as_str))
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl Visit for EventFields {
    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == UI_FIELD {
            self.ui = value;
        } else {
            self.rest.push(format!("{}={value}", field.name()));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.rest.push(format!("{}={value}", field.name()));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.rest.push(format!("{}={value:?}", field.name()));
        }
    }
}

/// Restore the previous session from the JSON log file at `path` into `log`:
/// the last [`SEED_MAX_LINES`] records that were UI lines (`fields.ui`) or
/// `WARN`/`ERROR` events, with their original timestamps, after one marker
/// line. Pushed straight to the buffer, not through tracing, so they are not
/// written to the log file a second time. Returns how many records were
/// restored; nothing (not even the marker) is pushed when there are none.
///
/// Call it before this process writes to the file, so its own records are
/// not mistaken for the previous session's.
pub fn seed_from_log_file(log: &UiLog, path: &Path) -> usize {
    let Ok(records) = crate::diagnostics::read_tail_lines(path, usize::MAX) else {
        return 0;
    };
    let lines: Vec<TerminalLine> = records
        .iter()
        .filter_map(|record| seed_line(record))
        .collect();
    let skip = lines.len().saturating_sub(SEED_MAX_LINES);
    let restored = &lines[skip..];
    if restored.is_empty() {
        return 0;
    }
    let file = path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    log.push(TerminalLine::with_source(
        LogLevel::Info,
        format!(
            "Restored {} lines from the previous session ({file})",
            restored.len()
        ),
        "previous session",
    ));
    for line in restored {
        log.push(line.clone());
    }
    restored.len()
}

/// One JSON log record as a Logs line, or `None` when it is not a UI line or
/// a warning/error, or does not parse.
fn seed_line(record: &str) -> Option<TerminalLine> {
    let value: serde_json::Value = serde_json::from_str(record).ok()?;
    let fields = value.get("fields")?.as_object()?;
    let is_ui = fields.get(UI_FIELD).and_then(|v| v.as_bool()) == Some(true);
    let level = match value.get("level")?.as_str()? {
        "ERROR" => LogLevel::Error,
        "WARN" => LogLevel::Warning,
        _ if !is_ui => return None,
        "DEBUG" | "TRACE" => LogLevel::Debug,
        _ if fields.get(OUTCOME_FIELD).and_then(|v| v.as_str()) == Some(OUTCOME_SUCCESS) => {
            LogLevel::Success
        }
        _ => LogLevel::Info,
    };
    let timestamp = value
        .get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())?
        .with_timezone(&chrono::Utc);
    let message = fields.get("message").map(json_text).unwrap_or_default();
    // A warning's other fields are part of what it says; a UI line's extra
    // fields are this module's own markers.
    let rest = fields
        .iter()
        .filter(|(k, _)| !is_ui && k.as_str() != "message")
        .map(|(k, v)| format!("{k}={}", json_text(v)));
    let text = std::iter::once(message)
        .chain(rest)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Some(TerminalLine {
        timestamp,
        level,
        message: redact(&text),
        source: fields
            .get(SOURCE_FIELD)
            .filter(|_| is_ui)
            .and_then(|v| v.as_str())
            .map(str::to_string),
        details: None,
    })
}

fn json_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::test_support::Capture;
    use tracing_subscriber::prelude::*;

    fn leaked(capacity: usize) -> &'static UiLog {
        Box::leak(Box::new(UiLog::new(capacity)))
    }

    fn messages(lines: &[TerminalLine]) -> Vec<&str> {
        lines.iter().map(|l| l.message.as_str()).collect()
    }

    #[test]
    fn push_numbers_lines_and_drops_the_oldest_past_capacity() {
        let log = UiLog::new(3);
        for i in 1..=5 {
            assert_eq!(log.push(TerminalLine::info(format!("l{i}"))), i);
        }
        let (lines, last) = log.since(0);
        assert_eq!(messages(&lines), vec!["l3", "l4", "l5"]);
        assert_eq!(last, 5);
    }

    /// The old page compared line counts, which stop changing at the cap.
    /// Reading by sequence keeps delivering new lines once the buffer is full.
    #[test]
    fn since_keeps_delivering_new_lines_once_the_buffer_is_full() {
        let log = UiLog::new(2);
        log.push(TerminalLine::info("a"));
        log.push(TerminalLine::info("b"));
        let (_, seen) = log.since(0);
        log.push(TerminalLine::info("c"));
        let (lines, last) = log.since(seen);
        assert_eq!(messages(&lines), vec!["c"]);
        assert_eq!(last, 3);
        assert!(log.since(last).0.is_empty());
    }

    #[test]
    fn push_wakes_subscribers() {
        let log = UiLog::new(10);
        let mut rx = log.subscribe();
        log.push(TerminalLine::info("x"));
        assert!(rx.has_changed().expect("sender alive"));
        assert_eq!(*rx.borrow_and_update(), 1);
    }

    fn with_layer(log: &'static UiLog, f: impl FnOnce()) {
        let subscriber = tracing_subscriber::registry().with(UiLogLayer::new(log));
        tracing::subscriber::with_default(subscriber, f);
    }

    #[test]
    fn layer_adds_warnings_and_errors_with_their_fields() {
        let log = leaked(10);
        with_layer(log, || {
            tracing::info!("not shown");
            tracing::debug!("not shown");
            tracing::warn!(dir = "/x", "sink unavailable");
            tracing::error!("boom {}", 7);
        });
        let (lines, _) = log.since(0);
        assert_eq!(messages(&lines), vec!["sink unavailable dir=/x", "boom 7"]);
        assert_eq!(lines[0].level, LogLevel::Warning);
        assert_eq!(lines[1].level, LogLevel::Error);
    }

    #[test]
    fn layer_redacts_what_it_adds() {
        let log = leaked(10);
        with_layer(log, || {
            tracing::error!("request failed: Authorization: Bearer abcdefghijklmnop");
        });
        let (lines, _) = log.since(0);
        assert!(
            !lines[0].message.contains("abcdefghijklmnop"),
            "{:?}",
            lines[0].message
        );
    }

    /// An emitted error is in the buffer once: the layer skips its tracing
    /// event. Without the `ui` skip the line would appear twice.
    #[test]
    fn emit_reaches_the_buffer_once_through_the_layer() {
        let log = leaked(10);
        with_layer(log, || {
            log.emit(TerminalLine::error("connect failed"));
            log.emit(TerminalLine::info("connected"));
        });
        let (lines, _) = log.since(0);
        assert_eq!(messages(&lines), vec!["connect failed", "connected"]);
    }

    /// The tracing event carries the redacted message, the level and the
    /// success marker, never the details (tool args and results).
    #[test]
    fn emit_sends_the_redacted_message_and_never_the_details() {
        let log = leaked(10);
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(capture.clone()),
        );
        tracing::subscriber::with_default(subscriber, || {
            log.emit(
                TerminalLine::success("[tool] nmap completed token=supersecretvalue1")
                    .with_details("SECRET-TOOL-OUTPUT"),
            );
        });
        let out = capture.contents();
        let record: serde_json::Value = serde_json::from_str(out.trim()).expect("one JSON record");
        assert_eq!(record["level"], "INFO");
        assert_eq!(record["fields"]["ui"], true);
        assert_eq!(record["fields"]["outcome"], "success");
        assert!(!out.contains("SECRET-TOOL-OUTPUT"), "{out}");
        assert!(!out.contains("supersecretvalue1"), "{out}");
        let (lines, _) = log.since(0);
        assert_eq!(lines[0].details.as_deref(), Some("SECRET-TOOL-OUTPUT"));
    }

    fn write_log(records: &[serde_json::Value]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("connector.2026-10-19.log");
        let text: String = records.iter().map(|r| format!("{r}\n")).collect();
        std::fs::write(&path, format!("{text}not json\n")).expect("write log");
        (dir, path)
    }

    #[test]
    fn seed_restores_ui_lines_and_warnings_with_their_timestamps() {
        let (_dir, path) = write_log(&[
            serde_json::json!({"timestamp": "2026-10-19T08:00:00.5Z", "level": "INFO",
                "fields": {"message": "plain info"}}),
            serde_json::json!({"timestamp": "2026-10-19T08:00:01Z", "level": "INFO",
                "fields": {"message": "[tool] nmap completed", "ui": true, "outcome": "success"}}),
            serde_json::json!({"timestamp": "2026-10-19T08:00:02Z", "level": "WARN",
                "fields": {"message": "sink unavailable", "dir": "/x"}}),
            serde_json::json!({"timestamp": "2026-10-19T08:00:03Z", "level": "ERROR",
                "fields": {"message": "Connection error", "ui": true, "source": "connector"}}),
            serde_json::json!({"timestamp": "2026-10-19T08:00:04Z", "level": "DEBUG",
                "fields": {"message": "debug ui", "ui": true}}),
        ]);
        let log = UiLog::new(100);
        assert_eq!(seed_from_log_file(&log, &path), 4);
        let (lines, _) = log.since(0);
        assert!(
            lines[0].message.starts_with("Restored 4 lines"),
            "{lines:?}"
        );
        assert!(lines[0].message.contains("connector.2026-10-19.log"));
        let restored = &lines[1..];
        assert_eq!(
            messages(restored),
            vec![
                "[tool] nmap completed",
                "sink unavailable dir=/x",
                "Connection error",
                "debug ui"
            ]
        );
        let levels: Vec<LogLevel> = restored.iter().map(|l| l.level).collect();
        assert_eq!(
            levels,
            vec![
                LogLevel::Success,
                LogLevel::Warning,
                LogLevel::Error,
                LogLevel::Debug
            ]
        );
        assert_eq!(
            restored[0].timestamp.to_rfc3339(),
            "2026-10-19T08:00:01+00:00"
        );
        assert_eq!(restored[2].source.as_deref(), Some("connector"));
    }

    #[test]
    fn seed_keeps_only_the_newest_lines() {
        let records: Vec<_> = (0..SEED_MAX_LINES + 5)
            .map(|i| {
                serde_json::json!({"timestamp": "2026-10-19T08:00:00Z", "level": "WARN",
                    "fields": {"message": format!("w{i}")}})
            })
            .collect();
        let (_dir, path) = write_log(&records);
        let log = UiLog::new(UI_LOG_CAPACITY);
        assert_eq!(seed_from_log_file(&log, &path), SEED_MAX_LINES);
        let (lines, _) = log.since(0);
        assert_eq!(lines[1].message, "w5");
        assert_eq!(
            lines.last().unwrap().message,
            format!("w{}", SEED_MAX_LINES + 4)
        );
    }

    #[test]
    fn seed_redacts_restored_warnings() {
        let (_dir, path) = write_log(&[serde_json::json!({
            "timestamp": "2026-10-19T08:00:00Z", "level": "ERROR",
            "fields": {"message": "failed: Authorization: Bearer abcdefghijklmnop"}})]);
        let log = UiLog::new(10);
        seed_from_log_file(&log, &path);
        let (lines, _) = log.since(0);
        assert!(!lines[1].message.contains("abcdefghijklmnop"), "{lines:?}");
    }

    #[test]
    fn seed_pushes_nothing_without_a_restorable_record() {
        let (_dir, path) = write_log(&[serde_json::json!({
            "timestamp": "2026-10-19T08:00:00Z", "level": "INFO",
            "fields": {"message": "plain"}})]);
        let log = UiLog::new(10);
        assert_eq!(seed_from_log_file(&log, &path), 0);
        assert_eq!(seed_from_log_file(&log, Path::new("/nonexistent/x.log")), 0);
        assert!(log.since(0).0.is_empty());
    }
}

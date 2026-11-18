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
//!
//! Every line gets a sequence number. A page keeps the last number it has
//! shown and appends only newer lines, so its own Clear sticks and a full
//! buffer keeps flowing (the old page compared line counts, which stop
//! changing at the cap).

use crate::diagnostics::cap_bytes;
use crate::provenance::redact;
use crate::terminal::{LogLevel, TerminalLine};
use std::collections::VecDeque;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use tokio::sync::watch;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Most lines held. The oldest line is dropped when a new one would exceed it.
pub const UI_LOG_CAPACITY: usize = 5000;

/// Most bytes of [`TerminalLine::details`] kept per line. Details carry full
/// tool results, so the line cap alone does not bound the buffer's memory.
pub const UI_LOG_DETAILS_MAX_BYTES: usize = 64 * 1024;

/// Field that marks a tracing event as a UI line already in the buffer.
const UI_FIELD: &str = "ui";
/// Value of the `outcome` field that carries [`LogLevel::Success`], which
/// tracing has no level for.
const OUTCOME_SUCCESS: &str = "success";

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
    /// `Arc` so [`UiLog::since`] copies refcounts, not details, under the lock.
    lines: VecDeque<(u64, Arc<TerminalLine>)>,
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
    pub fn push(&self, mut line: TerminalLine) -> u64 {
        line.details = line.details.map(|d| cap_bytes(d, UI_LOG_DETAILS_MAX_BYTES));
        let line = Arc::new(line);
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
        let (shared, last_seq) = {
            let inner = self.lock();
            // Numbers are contiguous, so the first wanted line is found by
            // arithmetic instead of a scan held under the lock.
            let first = inner.lines.front().map_or(0, |(s, _)| *s);
            let start = usize::try_from(seq.saturating_add(1).saturating_sub(first))
                .unwrap_or(usize::MAX)
                .min(inner.lines.len());
            let shared: Vec<Arc<TerminalLine>> = inner
                .lines
                .range(start..)
                .map(|(_, line)| Arc::clone(line))
                .collect();
            (shared, inner.last_seq)
        };
        // The deep copies happen after the lock is released, so a page
        // reading the whole buffer never stalls a tracing call site.
        let lines = shared
            .iter()
            .map(|line| TerminalLine::clone(line))
            .collect();
        (lines, last_seq)
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
    let source = line.source.as_deref().map(redact);
    let source = source.as_deref();
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
    fn since_handles_a_reader_behind_the_buffer_or_past_its_end() {
        let log = UiLog::new(3);
        for i in 1..=6 {
            log.push(TerminalLine::info(format!("l{i}")));
        }
        // Lines 1-3 were dropped: a reader that last saw 2 gets what is left.
        assert_eq!(messages(&log.since(2).0), vec!["l4", "l5", "l6"]);
        assert_eq!(messages(&log.since(4).0), vec!["l5", "l6"]);
        assert!(log.since(6).0.is_empty());
        assert!(log.since(99).0.is_empty());
        assert!(UiLog::new(3).since(0).0.is_empty());
    }

    #[test]
    fn push_wakes_subscribers() {
        let log = UiLog::new(10);
        let mut rx = log.subscribe();
        log.push(TerminalLine::info("x"));
        assert!(rx.has_changed().expect("sender alive"));
        assert_eq!(*rx.borrow_and_update(), 1);
    }

    /// Details carry full tool results; the line cap alone would let the
    /// buffer hold 5000 of them at any size.
    #[test]
    fn push_caps_details_by_bytes() {
        let log = UiLog::new(10);
        log.push(TerminalLine::info("big").with_details("x".repeat(UI_LOG_DETAILS_MAX_BYTES * 4)));
        log.push(TerminalLine::info("small").with_details("kept whole"));
        let (lines, _) = log.since(0);
        let big = lines[0].details.as_deref().expect("details");
        assert!(big.len() <= UI_LOG_DETAILS_MAX_BYTES + 20, "{}", big.len());
        assert!(big.ends_with("...<truncated>"));
        assert_eq!(lines[1].details.as_deref(), Some("kept whole"));
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
            log.emit(TerminalLine::with_source(
                LogLevel::Warning,
                "retrying",
                "connector token=supersecretvalue2",
            ));
        });
        let out = capture.contents();
        let records: Vec<serde_json::Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).expect("JSON record"))
            .collect();
        assert_eq!(records.len(), 2, "{out}");
        let record = &records[0];
        assert_eq!(record["level"], "INFO");
        assert_eq!(record["fields"]["ui"], true);
        assert_eq!(record["fields"]["outcome"], "success");
        assert!(records[1]["fields"]["source"]
            .as_str()
            .is_some_and(|s| s.starts_with("connector")));
        assert!(!out.contains("SECRET-TOOL-OUTPUT"), "{out}");
        assert!(!out.contains("supersecretvalue1"), "{out}");
        assert!(!out.contains("supersecretvalue2"), "{out}");
        let (lines, _) = log.since(0);
        assert_eq!(lines[0].details.as_deref(), Some("SECRET-TOOL-OUTPUT"));
    }
}

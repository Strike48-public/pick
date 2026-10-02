//! Shared logging initialization for all Pentest Connector applications.
//!
//! Centralises `tracing_subscriber` setup so every binary gets consistent
//! formatting, env-filter behaviour and the `pentest=<level>` directive.

use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Apply the fleet-wide span policy to a formatting layer.
///
/// Every layer Pick installs emits a `close` event when a span ends, carrying
/// the span's fields and its `time.busy` / `time.idle` durations. Combined with
/// the `tool_execution` span opened at each connector hop
/// ([`crate::spans::tool_execution_span`]), this gives one line per tool
/// invocation that says which tool, which `request_id` / `tool_call_id`, and
/// how long it took, without touching the individual log calls underneath.
pub fn apply_span_policy<S, N, E, W>(mut layer: fmt::Layer<S, N, E, W>) -> fmt::Layer<S, N, E, W> {
    layer.set_span_events(FmtSpan::CLOSE);
    layer
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
        .with(apply_span_policy(fmt::layer()))
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
        .with(apply_span_policy(fmt::layer().with_ansi(true)))
        .with(apply_span_policy(
            fmt::layer()
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(log_file)),
        ))
        .with(
            EnvFilter::from_default_env()
                .add_directive(format!("pentest={default_level}").parse().unwrap()),
        )
        .init();

    log_path
}

/// Test-only in-memory writer so tests can assert on formatted output.
#[cfg(test)]
pub(crate) mod test_support {
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    pub(crate) struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Capture {
        pub(crate) fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("capture poisoned")).into_owned()
        }
    }

    pub(crate) struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("capture poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = CaptureWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CaptureWriter(self.0.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::Capture;
    use super::*;

    #[test]
    fn span_policy_emits_close_event_with_fields_and_duration() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(apply_span_policy(
            fmt::layer().with_ansi(false).with_writer(capture.clone()),
        ));

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("tool_execution", tool = "nmap");
            let _guard = span.enter();
        });

        let output = capture.contents();
        let close_line = output
            .lines()
            .find(|l| l.contains("close"))
            .unwrap_or_else(|| panic!("no close event in {output:?}"));
        assert!(
            close_line.contains("tool_execution{tool=\"nmap\"}"),
            "{close_line}"
        );
        assert!(close_line.contains("time.busy="), "{close_line}");
    }
}

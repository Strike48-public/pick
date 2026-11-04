//! Structured failure fields for the tool-execution hops.
//!
//! A tool that fails as a probe usually still returns `Ok(ToolResult)`: the
//! process ran, exited nonzero or timed out, and its exit code and stderr sit
//! inside `data`. Logging only `success=false` at the hop leaves a support
//! engineer with no cause. [`log_tool_result`] puts `exit_code`, `timed_out`,
//! `duration_ms` and a redacted stderr tail on the failure line itself as
//! structured fields, so the JSON log file carries them as fields and the line
//! inherits the `tool_execution` span's correlation ids (pick#476).

use serde_json::Value;

use crate::provenance::redact;
use crate::tools::{ToolOutcome, ToolResult};

/// Upper bound on the stderr tail put on a failure line, in bytes. The end of
/// stderr is where a failing tool usually says why; the full stream stays in
/// the result `data`.
pub const STDERR_TAIL_MAX_BYTES: usize = 512;

/// How much of the end of stderr is redacted before the tail is cut. Bounds
/// the regex work on a tool that dumps megabytes of stderr; the window edge is
/// far enough from the tail that a secret split there cannot reach it.
const REDACT_WINDOW_BYTES: usize = 64 * 1024;

/// Failure details read from a tool result's `data`. Each field is `None` when
/// the tool did not report it, so the log line omits it rather than printing a
/// guess.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FailureFields {
    pub exit_code: Option<i64>,
    pub timed_out: Option<bool>,
    pub stderr_tail: Option<String>,
}

impl FailureFields {
    /// Read the process-level failure details tools report in `data`
    /// (`exit_code`, `timed_out`, `stderr`, as `execute_command` and the
    /// external runners write them).
    pub fn from_data(data: &Value) -> Self {
        Self {
            exit_code: data.get("exit_code").and_then(Value::as_i64),
            timed_out: data.get("timed_out").and_then(Value::as_bool),
            stderr_tail: data
                .get("stderr")
                .and_then(Value::as_str)
                .and_then(redacted_tail),
        }
    }
}

/// Redact the end of `stderr`, then keep at most [`STDERR_TAIL_MAX_BYTES`].
///
/// Redaction runs before the tail is cut: cutting first can split a secret
/// from the prefix that identifies it (`Bearer <token>`), and the remainder no
/// longer matches any pattern.
fn redacted_tail(stderr: &str) -> Option<String> {
    let redacted = redact(tail(stderr.trim(), REDACT_WINDOW_BYTES));
    if redacted.is_empty() {
        return None;
    }
    Some(tail(&redacted, STDERR_TAIL_MAX_BYTES).to_string())
}

/// The last `max` bytes of `s`, moved forward to a char boundary.
fn tail(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

/// Log the outcome of one tool invocation at a hop.
///
/// A completed run logs `tool execution completed` at info. A failed run logs
/// `tool execution failed` at warn with the [`FailureFields`] and the redacted
/// error message. A skipped run (precondition not met, nothing went wrong)
/// logs `tool execution skipped` at info with its reason.
pub fn log_tool_result(tool: &str, duration_ms: u64, result: &ToolResult) {
    let error = result.error.as_deref().map(redact);
    match result.outcome {
        ToolOutcome::Ran if result.success => {
            tracing::info!(
                tool,
                duration_ms,
                success = true,
                "tool execution completed"
            );
        }
        ToolOutcome::Skipped => {
            tracing::info!(
                tool,
                duration_ms,
                reason = error.as_deref(),
                "tool execution skipped"
            );
        }
        // `Ran` without success is a failure the tool did not reclassify.
        ToolOutcome::Ran | ToolOutcome::Failed => {
            let fields = FailureFields::from_data(&result.data);
            tracing::warn!(
                tool,
                duration_ms,
                outcome = ?result.outcome,
                exit_code = fields.exit_code,
                timed_out = fields.timed_out,
                stderr_tail = fields.stderr_tail.as_deref(),
                error = error.as_deref(),
                "tool execution failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::test_support::Capture;
    use serde_json::json;
    use tracing_subscriber::{fmt, prelude::*};

    fn capture_with<F: FnOnce()>(f: F) -> String {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry()
            .with(fmt::layer().with_ansi(false).with_writer(capture.clone()));
        tracing::subscriber::with_default(subscriber, || {
            // The hop tests in tool_connector drive these callsites with no
            // subscriber; if one registered first it cached Interest::NEVER.
            // Re-evaluate against this thread's subscriber before emitting.
            tracing::callsite::rebuild_interest_cache();
            f()
        });
        capture.contents()
    }

    #[test]
    fn from_data_reads_exit_code_timeout_and_stderr() {
        let fields = FailureFields::from_data(&json!({
            "stdout": "",
            "stderr": "  nmap: connection refused\n",
            "exit_code": 2,
            "timed_out": false,
        }));
        assert_eq!(
            fields,
            FailureFields {
                exit_code: Some(2),
                timed_out: Some(false),
                stderr_tail: Some("nmap: connection refused".to_string()),
            }
        );
    }

    #[test]
    fn from_data_leaves_unreported_fields_absent() {
        assert_eq!(
            FailureFields::from_data(&Value::Null),
            FailureFields::default()
        );
        let blank = FailureFields::from_data(&json!({"stderr": "   \n"}));
        assert_eq!(blank.stderr_tail, None);
    }

    #[test]
    fn stderr_tail_keeps_the_end_and_is_bounded() {
        // Spaced filler: a solid alphanumeric run would match redact's
        // long-base64 pattern and be collapsed before the cut.
        let stderr = format!("{}final cause", "x ".repeat(1000));
        let tail = FailureFields::from_data(&json!({ "stderr": stderr }))
            .stderr_tail
            .expect("tail present");
        assert_eq!(tail.len(), STDERR_TAIL_MAX_BYTES);
        assert!(tail.ends_with("final cause"), "{tail}");
    }

    #[test]
    fn huge_stderr_is_windowed_and_still_redacted_near_the_end() {
        let stderr = format!(
            "{}Authorization: Bearer s3cr.e7-tok.en-\nfatal: auth failed",
            "x ".repeat(REDACT_WINDOW_BYTES)
        );
        let tail = FailureFields::from_data(&json!({ "stderr": stderr }))
            .stderr_tail
            .expect("tail present");
        assert!(!tail.contains("s3cr.e7"), "secret leaked into tail: {tail}");
        assert!(tail.ends_with("fatal: auth failed"), "{tail}");
    }

    #[test]
    fn stderr_tail_cut_lands_on_a_char_boundary() {
        // 3-byte chars put the raw cut point mid-character.
        let stderr = "\u{2603}".repeat(STDERR_TAIL_MAX_BYTES);
        let tail = FailureFields::from_data(&json!({ "stderr": stderr }))
            .stderr_tail
            .expect("tail present");
        assert!(tail.len() <= STDERR_TAIL_MAX_BYTES);
        assert!(tail.chars().all(|c| c == '\u{2603}'), "{tail}");
    }

    #[test]
    fn stderr_is_redacted_before_it_is_cut() {
        // The token outruns the tail, so cutting first would drop the
        // `Bearer` prefix and leave bare token segments no pattern matches.
        // The `.`/`-` separators keep the long-hex/base64 patterns from
        // catching it on their own.
        let token = "s3cr.e7-".repeat(80);
        let stderr = format!("Authorization: Bearer {token}\ncurl: (7) connection refused");
        let tail = FailureFields::from_data(&json!({ "stderr": stderr }))
            .stderr_tail
            .expect("tail present");
        assert!(!tail.contains("s3cr.e7"), "secret leaked into tail: {tail}");
        assert!(tail.contains("connection refused"), "{tail}");
    }

    #[test]
    fn failed_run_logs_failure_fields_on_the_failure_line() {
        let result = ToolResult::success(json!({
            "stderr": "nmap: connection refused",
            "exit_code": 2,
            "timed_out": true,
        }))
        .with_outcome(ToolOutcome::Failed);

        let output = capture_with(|| log_tool_result("nmap", 1234, &result));
        let line = output
            .lines()
            .find(|l| l.contains("tool execution failed"))
            .unwrap_or_else(|| panic!("no failure line in {output:?}"));
        for expected in [
            "WARN",
            "tool=\"nmap\"",
            "duration_ms=1234",
            "outcome=Failed",
            "exit_code=2",
            "timed_out=true",
            "stderr_tail=\"nmap: connection refused\"",
        ] {
            assert!(line.contains(expected), "missing {expected} in {line}");
        }
    }

    #[test]
    fn failure_line_redacts_the_error_message() {
        // Fake credential; phrased as an error line, not a command, so it reads
        // as the test fixture it is.
        let result = ToolResult::error("request rejected (Authorization: Bearer abc.def-ghi)");
        let output = capture_with(|| log_tool_result("http_request", 5, &result));
        let line = output
            .lines()
            .find(|l| l.contains("tool execution failed"))
            .unwrap_or_else(|| panic!("no failure line in {output:?}"));
        assert!(line.contains("duration_ms=5"), "{line}");
        assert!(line.contains("error="), "{line}");
        assert!(
            !line.contains("abc.def-ghi"),
            "secret in failure line: {line}"
        );
    }

    #[test]
    fn completed_run_logs_at_info_without_failure_fields() {
        let result = ToolResult::success(json!({"exit_code": 0, "stderr": "noise"}));
        let output = capture_with(|| log_tool_result("nmap", 7, &result));
        assert!(output.contains("tool execution completed"), "{output}");
        assert!(!output.contains("tool execution failed"), "{output}");
        assert!(!output.contains("stderr_tail"), "{output}");
    }

    #[test]
    fn skipped_run_is_not_logged_as_a_failure() {
        let result = ToolResult::skipped("nmap is not installed");
        let output = capture_with(|| log_tool_result("nmap", 1, &result));
        assert!(output.contains("tool execution skipped"), "{output}");
        assert!(output.contains("nmap is not installed"), "{output}");
        assert!(!output.contains("tool execution failed"), "{output}");
    }
}

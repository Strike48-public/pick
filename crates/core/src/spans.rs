//! Correlation spans for the tool-execution path.
//!
//! Every hop that runs a tool on behalf of Strike48 opens a `tool_execution`
//! span carrying the identifiers an operator needs to filter a log down to a
//! single invocation: the tool name, the connector instance, and the
//! platform's `request_id` / `tool_call_id`. Events emitted inside the span,
//! including the failure line, inherit those fields, and
//! [`crate::logging::apply_span_policy`] emits a close event with the span's
//! duration.
//!
//! Only correlation identifiers are recorded. The execute context also carries
//! `session_token`; that must never reach a span or a log line.

use std::collections::HashMap;
use tracing::field::Empty;
use tracing::Span;

/// Context key the platform uses for the request identifier.
pub const REQUEST_ID_KEY: &str = "request_id";
/// Context key the platform uses for the agent's tool-call identifier.
pub const TOOL_CALL_ID_KEY: &str = "tool_call_id";

/// Open the `tool_execution` span for one tool invocation.
///
/// `context` is the execute-request context the SDK hands to
/// `execute_with_context`. Identifiers that are absent or empty are left off
/// the span rather than printed as blanks.
pub fn tool_execution_span(
    tool: &str,
    instance_id: &str,
    context: &HashMap<String, String>,
) -> Span {
    let span = tracing::info_span!(
        "tool_execution",
        tool = %tool,
        instance_id = Empty,
        request_id = Empty,
        tool_call_id = Empty,
    );
    record_if_present(&span, "instance_id", Some(instance_id));
    record_if_present(
        &span,
        "request_id",
        context.get(REQUEST_ID_KEY).map(String::as_str),
    );
    record_if_present(
        &span,
        "tool_call_id",
        context.get(TOOL_CALL_ID_KEY).map(String::as_str),
    );
    span
}

fn record_if_present(span: &Span, field: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        // `display` so ids print as `request_id=req-1`, matching the `%`
        // formatted `tool` field, rather than as a quoted `Debug` string.
        span.record(field, tracing::field::display(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::apply_span_policy;
    use crate::logging::test_support::Capture;
    use tracing_subscriber::{fmt, prelude::*};

    fn capture_with<F: FnOnce()>(f: F) -> String {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(apply_span_policy(
            fmt::layer().with_ansi(false).with_writer(capture.clone()),
        ));
        tracing::subscriber::with_default(subscriber, f);
        capture.contents()
    }

    fn context(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn events_inside_span_inherit_correlation_ids() {
        let output = capture_with(|| {
            let ctx = context(&[("request_id", "req-1"), ("tool_call_id", "call-1")]);
            let span = tool_execution_span("nmap", "inst-1", &ctx);
            let _guard = span.enter();
            tracing::info!("boom");
        });

        let event_line = output
            .lines()
            .find(|l| l.contains("boom"))
            .expect("event line present");
        for expected in [
            "tool_execution{",
            "tool=nmap",
            "instance_id=inst-1",
            "request_id=req-1",
            "tool_call_id=call-1",
        ] {
            assert!(
                event_line.contains(expected),
                "missing {expected} in {event_line}"
            );
        }
    }

    #[test]
    fn absent_or_empty_ids_are_omitted_not_blank() {
        let output = capture_with(|| {
            let ctx = context(&[("tool_call_id", "")]);
            let span = tool_execution_span("nmap", "", &ctx);
            let _guard = span.enter();
            tracing::info!("boom");
        });

        assert!(output.contains("tool=nmap"));
        assert!(!output.contains("request_id="), "{output}");
        assert!(!output.contains("tool_call_id="), "{output}");
        assert!(!output.contains("instance_id="), "{output}");
    }

    #[test]
    fn session_token_never_reaches_the_span() {
        let output = capture_with(|| {
            let ctx = context(&[
                ("request_id", "req-1"),
                ("session_token", "secret-token-value"),
            ]);
            let span = tool_execution_span("nmap", "inst-1", &ctx);
            let _guard = span.enter();
            tracing::info!("boom");
        });

        assert!(output.contains("request_id=req-1"));
        assert!(!output.contains("secret-token-value"), "{output}");
        assert!(!output.contains("session_token"), "{output}");
    }
}

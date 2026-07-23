//! Usage telemetry + release health via Sentry.
//!
//! Mirrors StrikeHub's `sentry_init.rs`: release-health sessions (DAU/WAU +
//! crash-free rate), platform tags, and per-activity business events. Ties into
//! the PLG "who is using Pick and how" goal (Strike48-public/pick#278).
//!
//! Privacy model: only anonymous/pseudonymous data leaves the device — the
//! per-install `device_id`, platform/mode tags, and coarse event names. **No
//! PII, no target hosts, no scan results, no command arguments.** Event
//! properties are restricted to safe enums/counts. Telemetry is opt-out
//! (enabled by default) and honors the `telemetry_enabled` setting.
//!
//! The Sentry DSN is baked at build time via `option_env!("SENTRY_DSN")`; when
//! it's absent (local dev, forks) telemetry is a no-op — nothing is sent.
//!
//! NOTE: the event names below (`scan.start`, `tool.run`, `network.check`) are
//! PROVISIONAL, pending the shared taxonomy spec (project-management#101). They
//! route through the helpers here so renaming is a one-file change.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// True while a live Sentry client is installed, so event helpers can cheaply
/// no-op when telemetry is disabled or the DSN is absent.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Holds the Sentry client guard. A `Mutex<Option<..>>` (not a `OnceLock`) so
/// telemetry can be turned OFF at runtime: dropping the guard closes the client
/// and stops release-health sessions, and turning it back ON re-inits. The
/// guard isn't `Clone` and its only job is to live until torn down (drop
/// flushes pending events).
static GUARD: Mutex<Option<sentry::ClientInitGuard>> = Mutex::new(None);

/// The last `(device_id, easy_mode)` seen by `init`, retained so `set_enabled`
/// can re-init with the same identity/tags after the user toggles telemetry
/// back on within a session.
static IDENTITY: Mutex<Option<(String, bool)>> = Mutex::new(None);


/// Metadata keys under which the backend forwards distributed-trace headers in
/// the tool-request frame, so a connector-side tool span can join the backend's
/// conversation trace. The connector copies these from the inbound request's
/// `metadata` into `ToolContext::metadata`; `start_tool_span` reads them. Named
/// after the W3C/Sentry headers so the platform contract is obvious.
pub const SENTRY_TRACE_HEADER: &str = "sentry_trace";
pub const BAGGAGE_HEADER: &str = "baggage";

/// Compile-time DSN. `None` (the default in local/dev builds) disables Sentry
/// entirely — release CI injects `SENTRY_DSN` so shipped builds report.
const DSN: Option<&str> = option_env!("SENTRY_DSN");

/// The build environment reported to Sentry. Resolved in priority order:
///   1. `STRIKE48_SENTRY_ENV` baked at BUILD time (`option_env!`) — the source
///      that works for the mobile FFI libs, which have no runtime environment.
///   2. `STRIKE48_SENTRY_ENV` at RUNTIME (`std::env::var`) — for the desktop /
///      headless path where the process env is set.
///   3. The build profile: `development` under debug, else `production`.
///
/// The mobile `release-ffi` libs build with debug_assertions OFF, so without an
/// explicit override they'd tag as `production`; a local dev build sets
/// `STRIKE48_SENTRY_ENV=development` at build time to keep test traffic out of
/// the production environment.
fn environment() -> String {
    if let Some(env) = option_env!("STRIKE48_SENTRY_ENV") {
        if !env.is_empty() {
            return env.to_string();
        }
    }
    if let Ok(env) = std::env::var("STRIKE48_SENTRY_ENV") {
        if !env.is_empty() {
            return env;
        }
    }
    if cfg!(debug_assertions) {
        "development".to_string()
    } else {
        "production".to_string()
    }
}

/// The app channel tag: easy mode vs the full advanced UI.
fn channel(easy_mode: bool) -> &'static str {
    if easy_mode {
        "easy"
    } else {
        "advanced"
    }
}

/// The app form-factor tag (`app.mode`): mobile vs desktop, from the build target.
fn form_factor() -> &'static str {
    if cfg!(any(target_os = "android", target_os = "ios")) {
        "mobile"
    } else {
        "desktop"
    }
}

/// Initialize telemetry at startup with the user's opt-out setting. Remembers
/// the identity so a later runtime toggle (see [`set_enabled`]) can re-install
/// with the same tags. Does nothing when the DSN is absent or the user has
/// opted out (the env override or `enabled=false`).
///
/// - `enabled`: the user's `telemetry_enabled` setting (opt-out).
/// - `device_id`: the persistent anonymous install id.
/// - `easy_mode`: whether this build runs the easy-mode UI (channel tag).
pub fn init(enabled: bool, device_id: &str, easy_mode: bool) {
    if let Ok(mut id) = IDENTITY.lock() {
        *id = Some((device_id.to_string(), easy_mode));
    }
    if enabled {
        install(device_id, easy_mode);
    } else {
        tracing::debug!("telemetry disabled at startup (opt-out)");
    }
}

/// Turn telemetry on or off at runtime (from the Settings toggle). Turning it
/// OFF fully closes the Sentry client — no events AND no release-health sessions
/// leave the device. Turning it ON re-installs with the identity captured at
/// [`init`]. No-op if the requested state already matches, or if `init` was
/// never called (no identity to install with).
pub fn set_enabled(enabled: bool) {
    let currently = ENABLED.load(Ordering::Relaxed);
    if enabled == currently {
        return;
    }
    if enabled {
        let identity = IDENTITY.lock().ok().and_then(|g| g.clone());
        match identity {
            Some((device_id, easy_mode)) => install(&device_id, easy_mode),
            None => tracing::warn!("telemetry set_enabled(true) before init; ignoring"),
        }
    } else {
        // Drop the guard -> flush pending events, end the release-health
        // session, close the client. Nothing further sent until re-enabled.
        ENABLED.store(false, Ordering::Relaxed);
        if let Ok(mut g) = GUARD.lock() {
            *g = None;
        }
        tracing::info!("telemetry disabled at runtime");
    }
}

/// Build and install a live Sentry client, storing the guard. Private: callers
/// go through [`init`] or [`set_enabled`]. No-op when the DSN is absent or the
/// `STRIKE48_TELEMETRY` env kill-switch is set, or a client is already live.
fn install(device_id: &str, easy_mode: bool) {
    if ENABLED.load(Ordering::Relaxed) {
        return; // already installed
    }
    // An env override lets any target opt out without touching settings/UI
    // (e.g. `STRIKE48_TELEMETRY=0`). Truthy setting AND not env-disabled.
    let env_opt_out = std::env::var("STRIKE48_TELEMETRY")
        .map(|v| matches!(v.as_str(), "0" | "false" | "off" | "no"))
        .unwrap_or(false);
    let dsn = match (!env_opt_out, DSN) {
        (true, Some(dsn)) if !dsn.is_empty() => dsn,
        _ => {
            tracing::debug!("telemetry not installed (env kill-switch or no DSN)");
            return;
        }
    };

    // The SDK's internal transport logging, on only when STRIKE48_SENTRY_DEBUG
    // is set — surfaces "sending envelope"/transport errors so a dev build can
    // see WHY delivery fails (TLS, DNS, timeout) instead of guessing.
    let debug = option_env!("STRIKE48_SENTRY_DEBUG").is_some()
        || std::env::var("STRIKE48_SENTRY_DEBUG").is_ok();

    let guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: Some(env!("CARGO_PKG_VERSION").into()),
            environment: Some(environment().into()),
            debug,
            // Release-health sessions power DAU/WAU + crash-free rate.
            auto_session_tracking: true,
            session_mode: sentry::SessionMode::Application,
            // Send all activity transactions (see `record`). These are the
            // who/how usage signal and are low-volume, so full sampling is fine;
            // revisit if volume grows. Without this, start_transaction is
            // sampled out and nothing reaches Traces.
            traces_sample_rate: 1.0,
            // Never attach the connecting server URL or request bodies.
            send_default_pii: false,
            ..Default::default()
        },
    ));

    // Static platform/identity tags on every event and session.
    sentry::configure_scope(|scope| {
        // Pseudonymous install identity (no PII).
        scope.set_user(Some(sentry::User {
            id: Some(device_id.to_string()),
            ..Default::default()
        }));
        scope.set_tag("app.platform", std::env::consts::OS);
        scope.set_tag("app.arch", std::env::consts::ARCH);
        scope.set_tag("app.mode", form_factor());
        scope.set_tag("app.channel", channel(easy_mode));
    });

    if let Ok(mut g) = GUARD.lock() {
        *g = Some(guard);
    }
    ENABLED.store(true, Ordering::Relaxed);
    tracing::info!(
        "telemetry initialized (env={}, channel={})",
        environment(),
        channel(easy_mode)
    );
}

/// Flush any queued telemetry to Sentry, blocking up to `timeout`. The shell
/// should call this when it backgrounds so batched events survive a subsequent
/// process termination (our client guard lives in a `static` and never Drops).
/// No-op when telemetry is disabled.
pub fn flush() {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    if let Some(client) = sentry::Hub::current().client() {
        let flushed = client.flush(Some(std::time::Duration::from_secs(3)));
        tracing::debug!("telemetry flush requested (drained={flushed})");
    }
}

/// Attach the authenticated PLG identity once the user connects. Still
/// pseudonymous — an opaque tenant/user id, never an email or target data.
pub fn set_plg_identity(tenant_id: &str) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    sentry::configure_scope(|scope| {
        scope.set_tag("plg.tenant", tenant_id);
    });
}

/// Capture an agent backend error as a Sentry **issue** (a captured event, not a
/// span). Usage activity is emitted only as traces and the tracing layer ignores
/// events, so real failures like an agent-turn error would otherwise never reach
/// Sentry. `kind` is a coarse classifier (e.g. "token_limit" / "upstream" /
/// "stream_error"); `detail` MUST be non-PII (a short reason string, never a
/// host, argument, or scan output). No-op when telemetry is disabled.
pub fn capture_agent_error(kind: &str, detail: &str) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    sentry::with_scope(
        |scope| {
            scope.set_tag("error.source", "agent_backend");
            scope.set_tag("error.kind", kind);
        },
        || {
            sentry::capture_message(
                &format!("agent error: {kind}"),
                sentry::Level::Error,
            );
        },
    );
    tracing::warn!("captured agent error to sentry: kind={kind} detail={detail}");
}

/// A telemetry-safe activity event. Names are provisional (see module docs) and
/// deliberately coarse; properties must be non-PII (enums, counts, booleans) —
/// never hostnames, tool arguments, or scan output.
///
/// Provisional taxonomy (pending project-management#101):
/// - `scan.start`   — the easy-mode "Scan My Network" action fired
/// - `tool.run`     — a connector tool executed (property: tool name only)
/// - `network.check`— a network discovery/check completed
#[derive(Debug, Clone, Copy)]
pub enum Activity {
    ScanStart,
    ToolRun,
    NetworkCheck,
}

impl Activity {
    fn name(self) -> &'static str {
        match self {
            Activity::ScanStart => "scan.start",
            Activity::ToolRun => "tool.run",
            Activity::NetworkCheck => "network.check",
        }
    }
}

/// Record an INSTANTANEOUS activity (no duration) as a standalone Sentry
/// transaction. Routes to Traces, never Issues. Use [`ToolSpan`] for durationful
/// work (tool runs).
///
/// Property values MUST be non-sensitive: tool names, result enums, counts —
/// never target hosts, arguments, or scan data. Callers are responsible for
/// passing only safe values; this is the single choke point so the rule is easy
/// to audit.
pub fn record(activity: Activity, props: &[(&str, &str)]) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let ctx = sentry::TransactionContext::new(activity.name(), "activity");
    let tx = sentry::start_transaction(ctx);
    for (k, v) in props {
        tx.set_data(k, sentry::protocol::Value::from(*v));
    }
    tx.finish();
}

/// A live, timed span for a user-facing UI action (e.g. "send", "open reports",
/// "create share link"). Opened when the action's async work starts and finished
/// when it returns, so each becomes a small standalone trace with a real
/// duration and outcome — the lightweight "what did the user do and how long did
/// it take" signal. `None` when telemetry is off (cheap no-op).
#[must_use = "a UiSpan must be finished to record its duration"]
pub struct UiSpan(Option<sentry::Transaction>);

/// Start a timed UI-action span named `action` (a short, stable verb like
/// "send", "load_conversation", "create_share_link"). Finish with
/// [`UiSpan::finish`], passing the outcome ("ok"/"error").
pub fn start_ui_span(action: &str) -> UiSpan {
    if !ENABLED.load(Ordering::Relaxed) {
        return UiSpan(None);
    }
    let ctx = sentry::TransactionContext::new(action, "ui.action");
    UiSpan(Some(sentry::start_transaction(ctx)))
}

impl UiSpan {
    /// Finish the span with an outcome tag and send it with its measured
    /// duration. No-op if telemetry was off.
    pub fn finish(self, outcome: &str) {
        if let Some(tx) = self.0 {
            tx.set_data("outcome", sentry::protocol::Value::from(outcome));
            tx.finish();
        }
    }
}

/// A live, timed span for a tool run. Opened before `execute()` and finished
/// after, so it carries the real duration. When the inbound tool request carried
/// distributed-trace headers (`sentry-trace` / `baggage`, forwarded by the
/// backend), the span CONTINUES that trace — so the tool nests under the
/// backend's conversation transaction as part of ONE cross-process trace, with
/// no shared-memory parent. Absent headers it's a standalone transaction.
/// `None` inside when telemetry is off, so it's a cheap no-op handle callers can
/// hold across an await unconditionally.
#[must_use = "a ToolSpan must be finished to record its duration"]
pub struct ToolSpan(Option<sentry::TransactionOrSpan>);

/// Start a timed `tool.run` span, continuing the distributed trace from the
/// (optional) `sentry-trace` / `baggage` headers the backend forwarded in the
/// tool request. Pass safe start props (e.g. tool name); finish with
/// [`ToolSpan::finish`] and the outcome once the tool returns.
pub fn start_tool_span(
    props: &[(&str, &str)],
    sentry_trace: Option<&str>,
    baggage: Option<&str>,
) -> ToolSpan {
    if !ENABLED.load(Ordering::Relaxed) {
        return ToolSpan(None);
    }
    let name = Activity::ToolRun.name();
    // Build trace headers from whatever the backend sent so the span joins the
    // distributed trace. `continue_from_headers` with no headers just starts a
    // fresh root transaction, so this is safe when the backend sends nothing.
    let mut headers: Vec<(&str, &str)> = Vec::new();
    if let Some(t) = sentry_trace.filter(|s| !s.is_empty()) {
        headers.push(("sentry-trace", t));
    }
    if let Some(b) = baggage.filter(|s| !s.is_empty()) {
        headers.push(("baggage", b));
    }
    let ctx = sentry::TransactionContext::continue_from_headers(name, "activity", headers);
    let span: sentry::TransactionOrSpan = sentry::start_transaction(ctx).into();
    for (k, v) in props {
        span.set_data(k, sentry::protocol::Value::from(*v));
    }
    ToolSpan(Some(span))
}

impl ToolSpan {
    /// Finish the span, stamping final props (e.g. outcome) and sending it with
    /// its measured duration. No-op if telemetry was off.
    pub fn finish(self, extra: &[(&str, &str)]) {
        if let Some(span) = self.0 {
            for (k, v) in extra {
                span.set_data(k, sentry::protocol::Value::from(*v));
            }
            span.finish();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_names_are_stable() {
        assert_eq!(Activity::ScanStart.name(), "scan.start");
        assert_eq!(Activity::ToolRun.name(), "tool.run");
        assert_eq!(Activity::NetworkCheck.name(), "network.check");
    }

    #[test]
    fn environment_profile_default_and_override() {
        // One test (not two) so the env var can't race a sibling running in
        // parallel. Default in debug/test builds is "development"; the override
        // wins when set. Restore prior state to avoid leaking into other tests.
        let prior = std::env::var("STRIKE48_SENTRY_ENV").ok();
        std::env::remove_var("STRIKE48_SENTRY_ENV");
        assert_eq!(environment(), "development");

        std::env::set_var("STRIKE48_SENTRY_ENV", "staging");
        assert_eq!(environment(), "staging");

        match prior {
            Some(v) => std::env::set_var("STRIKE48_SENTRY_ENV", v),
            None => std::env::remove_var("STRIKE48_SENTRY_ENV"),
        }
    }

    #[test]
    fn channel_reflects_mode() {
        assert_eq!(channel(true), "easy");
        assert_eq!(channel(false), "advanced");
    }

    #[test]
    fn form_factor_is_desktop_in_host_tests() {
        // The test suite runs on a desktop host target.
        assert_eq!(form_factor(), "desktop");
    }

    #[test]
    fn record_is_noop_when_disabled() {
        // Not initialized in tests -> ENABLED is false -> record must not panic.
        record(Activity::ScanStart, &[("k", "v")]);
        set_plg_identity("tenant-x");
    }

    #[test]
    fn init_without_dsn_is_noop() {
        // No SENTRY_DSN in the test build -> init does nothing and telemetry
        // stays disabled (record/set_plg_identity remain no-ops).
        init(true, "device-1", true);
        assert!(!ENABLED.load(Ordering::Relaxed));
    }

    #[test]
    fn set_enabled_is_noop_without_dsn() {
        // Toggling telemetry with no DSN must never panic and must leave it
        // disabled (install() bails when the DSN is absent).
        init(true, "device-1", true); // records identity, installs nothing
        set_enabled(false);
        assert!(!ENABLED.load(Ordering::Relaxed));
        set_enabled(true);
        assert!(!ENABLED.load(Ordering::Relaxed));
    }
}

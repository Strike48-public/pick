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
        // session, close the client. Nothing further is sent until re-enabled.
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

/// Record an instantaneous activity event with optional safe key/value
/// properties, as a zero-duration `tracing` span. The `sentry-tracing` layer
/// (installed in the shell's tracing subscriber) turns it into a Sentry span —
/// nested under the current span (e.g. the conversation-turn span) when one is
/// active on this task, otherwise a standalone transaction — so activities land
/// in Traces, never Issues. Durationful work (tool runs) is instrumented at the
/// call site with its own `tracing` span instead (see `tools.rs`).
///
/// Property values MUST be non-sensitive: tool names, result enums, counts —
/// never target hosts, arguments, or scan data. Callers are responsible for
/// passing only safe values; this is the single choke point so the rule is easy
/// to audit.
pub fn record(activity: Activity, props: &[(&str, &str)]) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    // Emit a short-lived `tracing` span; the sentry-tracing layer turns spans
    // into Sentry transactions/child-spans (nested under the current span on
    // this task when there is one), so activities land in Traces, never Issues.
    // `props` are attached as span fields via a dynamic valueset is not possible
    // (tracing fields are static), so they ride along as span data through the
    // `sentry_props` field which the layer serialises.
    let props_str = props
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",");
    let span = tracing::info_span!("activity", otel.name = activity.name(), props = %props_str);
    let _guard = span.enter();

    // Also a breadcrumb for error-timeline context if a real error follows.
    let mut data = std::collections::BTreeMap::new();
    for (k, v) in props {
        data.insert((*k).to_string(), sentry::protocol::Value::from(*v));
    }
    sentry::add_breadcrumb(sentry::Breadcrumb {
        category: Some("activity".into()),
        message: Some(activity.name().to_string()),
        level: sentry::Level::Info,
        data,
        ..Default::default()
    });
}

/// The `sentry-tracing` layer, to be added to the shell's `tracing` subscriber.
/// It turns `tracing` spans into Sentry transactions/spans **with real
/// durations** and automatic parent/child nesting (a span entered inside another
/// becomes its child) — the idiomatic Rust+Sentry way, instead of hand-managing
/// transactions. Re-exported here so shells install it without each taking a
/// direct `sentry` dependency. Harmless when no client is initialized.
///
/// Only spans named for our activity taxonomy become transactions; ordinary
/// debug/info tracing stays out of Sentry via the span filter.
pub fn sentry_tracing_layer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use sentry::integrations::tracing::EventFilter;
    sentry::integrations::tracing::layer()
        // Only record our own activity/tool spans as transactions; don't turn
        // every info-level tracing span in the app into a Sentry transaction.
        .span_filter(|md| {
            matches!(md.name(), "activity" | "tool.run")
        })
        // Never auto-capture tracing events as Sentry issues; we only want
        // spans (traces). Errors are surfaced deliberately elsewhere.
        .event_filter(|_md| EventFilter::Ignore)
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

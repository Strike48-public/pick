package com.strike48.pickcrux

import android.app.Application
import io.sentry.android.core.SentryAndroid
import io.sentry.SentryLevel

/**
 * Application subclass whose only job is to initialise the native Sentry SDK
 * (sentry-android) as early as possible, so uncaught Kotlin/JVM exceptions,
 * native (NDK) crashes, and ANRs in the view layer are captured. The Rust core
 * has its own Sentry client for its panics + traces; this covers everything
 * above the FFI boundary that the Rust SDK is blind to.
 *
 * The DSN and environment come from BuildConfig (injected from the build env by
 * gradle). When the DSN is empty (local builds without SENTRY_DSN set), the SDK
 * is not initialised and nothing is sent.
 *
 * Telemetry opt-out: the user's choice is enforced in the Rust core (which fully
 * closes its client). Here we gate the native SDK on the same persisted flag at
 * startup; a mid-session toggle affects the Rust side immediately and the native
 * side on next launch (closing sentry-android at runtime isn't supported cleanly).
 */
class PickApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        val dsn = BuildConfig.SENTRY_DSN
        if (dsn.isEmpty()) return // no DSN baked in -> native telemetry disabled

        // Respect the persisted opt-out (defaults on). The Rust core reads the
        // same store; keeping them consistent avoids native crashes reporting
        // after the user opted out.
        if (!SettingsStore(this).telemetryEnabled) return

        SentryAndroid.init(this) { options ->
            options.dsn = dsn
            options.environment = BuildConfig.SENTRY_ENV
            options.release = "pick-crux@${BuildConfig.VERSION_NAME}"
            // Crash + ANR capture is on by default; be explicit about ANRs.
            options.isAnrEnabled = true
            // Native performance: app-start timing + slow/frozen frames attach to
            // the SDK's auto activity transactions, so they only flow when tracing
            // is sampled. Enable at a modest rate for those mobile vitals. Distinct
            // from the Rust core's UI-action traces (different span names).
            options.isEnableFramesTracking = true
            options.tracesSampleRate = 1.0
            // Auto breadcrumbs (activity lifecycle / UI / network) are on by
            // default and give a crash its leadup; left enabled.
            options.isSendDefaultPii = false
            options.setTag("app.layer", "native_view")
            options.setDiagnosticLevel(SentryLevel.WARNING)
        }
    }
}

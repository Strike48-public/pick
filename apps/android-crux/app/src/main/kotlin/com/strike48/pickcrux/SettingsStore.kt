package com.strike48.pickcrux

import android.content.Context

/**
 * Persists non-secret user settings (feature flags) across launches. Plain
 * SharedPreferences — unlike the auth token these values aren't sensitive, so
 * they don't need Keystore encryption. The core is the source of truth at
 * runtime; this just seeds it at startup and records the user's choices.
 */
class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Telemetry opt-out flag. Defaults to true (on) to match the core default. */
    var telemetryEnabled: Boolean
        get() = prefs.getBoolean(KEY_TELEMETRY, true)
        set(value) {
            prefs.edit().putBoolean(KEY_TELEMETRY, value).apply()
        }

    companion object {
        private const val PREFS_NAME = "pick_settings"
        private const val KEY_TELEMETRY = "telemetry_enabled"
    }
}

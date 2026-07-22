package com.strike48.pickcrux

import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject

/**
 * Persists the workspace-scoped Studio session token in Keystore-backed
 * encrypted storage so a relaunch can skip the browser sign-in, mirroring the
 * Dioxus app's `pentest_core::secure_store` (Keychain on iOS / Keystore on
 * Android).
 *
 * The token is a bearer credential and must not sit in plaintext prefs; the
 * MasterKey is held in the Android Keystore. The underlying Studio session
 * token is short-lived, so restore still falls back to sign-in once it expires
 * (see [isTokenExpired]) — the same limitation the Dioxus app has.
 */
class TokenStore(context: Context) {
    private val prefs by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    /** Save (or overwrite) the token. Failures are logged, never fatal. */
    fun save(token: String) {
        runCatching { prefs.edit().putString(KEY_TOKEN, token).apply() }
            .onFailure { Log.w(TAG, "Failed to persist token: ${it.message}") }
    }

    /** Load the token, or null if none is stored / storage is unavailable. */
    fun load(): String? =
        runCatching { prefs.getString(KEY_TOKEN, null)?.takeIf { it.isNotEmpty() } }
            .getOrElse { Log.w(TAG, "Failed to load token: ${it.message}"); null }

    /** Delete the stored token (sign-out). */
    fun clear() {
        runCatching { prefs.edit().remove(KEY_TOKEN).apply() }
            .onFailure { Log.w(TAG, "Failed to clear token: ${it.message}") }
    }

    companion object {
        private const val TAG = "PickCruxTokenStore"
        private const val PREFS_NAME = "pick_secure_prefs"
        private const val KEY_TOKEN = "matrix_auth_token"

        /**
         * Best-effort JWT-expiry check so we don't seed the core with a dead
         * token on startup (matches the Dioxus `restore_matrix_token` guard).
         * Returns true if the token is a JWT whose `exp` is in the past. Tokens
         * we can't parse are treated as NOT expired — let the backend reject.
         */
        fun isTokenExpired(token: String): Boolean {
            val parts = token.split(".")
            if (parts.size != 3) return false
            return runCatching {
                val payload = String(
                    Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP),
                    Charsets.UTF_8,
                )
                val exp = JSONObject(payload).optDouble("exp", 0.0)
                exp > 0.0 && System.currentTimeMillis() / 1000.0 >= exp
            }.getOrDefault(false)
        }
    }
}

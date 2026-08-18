package com.strike48.pick

import android.app.Activity
import android.os.Bundle
import android.util.Log

/**
 * Transparent Activity that intercepts OAuth redirects via custom URI scheme.
 *
 * When the Matrix server redirects to `com.strike48.pentest://oauth/callback?access_token=xxx`,
 * Android's intent system routes the URI here (via the manifest intent-filter).
 *
 * This Activity:
 * 1. Reads the full callback URI from the intent
 * 2. Hands it to the Rust core via the `deliverOAuthToken` JNI export, which
 *    parses the token and completes the in-flight login
 * 3. Finishes immediately (no UI)
 *
 * Delivery is a direct JNI call into the core (in `libmain.so`, the same native
 * library the Dioxus/wry MainActivity loads), NOT an HTTP POST to a loopback
 * server. Launching the system browser backgrounds the app, and Android
 * suspends the process — so any in-process HTTP listener is dead by the time
 * this callback fires. The JNI hand-off works regardless of app state.
 */
class OAuthCallbackActivity : Activity() {
    companion object {
        private const val TAG = "OAuthCallback"

        init {
            // Ensure the core is loaded even if this Activity is the process's
            // cold entrypoint (app was killed while the browser was open).
            // Loading an already-loaded library is a no-op.
            try {
                System.loadLibrary("main")
            } catch (e: Throwable) {
                Log.e(TAG, "Failed to load native library: ${e.message}")
            }
        }
    }

    /**
     * Deliver the OAuth callback URL to the Rust core. Returns true when a
     * login was in flight and a token was delivered. Implemented in
     * `apps/mobile/src/main.rs` as
     * `Java_com_strike48_pick_OAuthCallbackActivity_deliverOAuthToken`.
     */
    private external fun deliverOAuthToken(url: String): Boolean

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val uri = intent?.data
        Log.i(TAG, "OAuth callback received: ${uri?.toString()?.take(60)}")

        if (uri != null) {
            try {
                val delivered = deliverOAuthToken(uri.toString())
                Log.i(TAG, "Token delivery to core: $delivered")
            } catch (e: Throwable) {
                Log.e(TAG, "Failed to deliver token to core: ${e.message}")
            }
        } else {
            Log.w(TAG, "No data URI in callback intent")
        }

        finish()
    }
}

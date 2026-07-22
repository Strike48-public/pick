package com.strike48.pickcrux

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log

/**
 * Transparent Activity that intercepts the native-OAuth redirect delivered via
 * the custom URI scheme `com.strike48.pentest://oauth/callback`.
 *
 * The Matrix server runs the Keycloak SSO login in the browser / Custom Tab and,
 * on success, redirects to
 * `com.strike48.pentest://oauth/callback?access_token=<TOKEN>` (the token may
 * also arrive as a URL fragment `#access_token=...`). Android routes that URI
 * here via the manifest intent-filter.
 *
 * This Activity extracts `access_token` (query OR fragment), stashes it in
 * [OAuthTokenHolder], then relaunches [MainActivity] (singleTop) so the resumed
 * shell can adopt the token via `pick_set_token` and re-drive the view.
 */
class OAuthCallbackActivity : Activity() {
    companion object {
        private const val TAG = "OAuthCallback"

        /** Extract `access_token` from either the query string or the URL fragment. */
        fun extractToken(uri: Uri?): String? {
            if (uri == null) return null
            uri.getQueryParameter("access_token")?.let { if (it.isNotEmpty()) return it }
            // Fragment form: com.strike48.pentest://oauth/callback#access_token=...&foo=bar
            val fragment = uri.fragment ?: return null
            for (part in fragment.split('&')) {
                val idx = part.indexOf('=')
                if (idx > 0 && part.substring(0, idx) == "access_token") {
                    val value = part.substring(idx + 1)
                    if (value.isNotEmpty()) {
                        return runCatching { Uri.decode(value) }.getOrDefault(value)
                    }
                }
            }
            return null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val uri = intent?.data
        Log.i(TAG, "OAuth callback received: ${uri?.toString()?.take(60)}")

        val token = extractToken(uri)
        if (token != null) {
            Log.i(TAG, "Captured access_token (len=${token.length})")
            OAuthTokenHolder.deliver(token)
        } else {
            Log.w(TAG, "No access_token in callback URI")
        }

        // Bring the shell back to the foreground so it can adopt the token.
        val resume = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        startActivity(resume)
        finish()
    }
}

/**
 * Process-global hand-off from [OAuthCallbackActivity] to the resumed
 * [MainActivity]. The callback Activity runs in the same process, so a simple
 * holder + listener is enough — no loopback server needed.
 */
object OAuthTokenHolder {
    @Volatile
    private var pending: String? = null

    @Volatile
    private var listener: ((String) -> Unit)? = null

    /** Called by the callback Activity. Fans out to a listener if one is set. */
    @Synchronized
    fun deliver(token: String) {
        val l = listener
        if (l != null) {
            l(token)
        } else {
            pending = token
        }
    }

    /**
     * MainActivity registers here on resume. If a token arrived before the
     * listener was set (callback raced ahead of resume), it is replayed once.
     */
    @Synchronized
    fun setListener(l: (String) -> Unit) {
        listener = l
        pending?.let {
            pending = null
            l(it)
        }
    }

    @Synchronized
    fun clearListener() {
        listener = null
    }
}

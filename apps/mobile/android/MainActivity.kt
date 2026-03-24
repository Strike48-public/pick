package dev.dioxus.main

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.webkit.WebView
import android.webkit.WebSettings
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatDelegate
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import com.strike48.pentest_connector.BuildConfig

typealias BuildConfig = BuildConfig

class MainActivity : WryActivity() {

    private val screenCaptureLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK && result.data != null) {
            startScreenCaptureService(result.resultCode, result.data!!)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // Switch to DayNight theme so the Activity (and its WebView) follows
        // the system light/dark preference. The generated Dioxus styles.xml
        // uses Theme.AppCompat.Light — we override that here.
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
        setTheme(androidx.appcompat.R.style.Theme_AppCompat_DayNight_NoActionBar)
        super.onCreate(savedInstanceState)

        // Register this Activity and screen capture callback with ConnectorBridge
        // so that JNI calls can trigger the consent dialog via registerForActivityResult
        // instead of launching a separate Activity (which crashes Dioxus).
        // Uses reflection to avoid compile-time dependency on android-lib.
        registerWithBridge()
    }

    /**
     * Register this Activity and the screen capture callback with ConnectorBridge
     * via reflection to avoid compile-time dependency on android-lib.
     */
    private fun registerWithBridge() {
        try {
            val bridgeClass = Class.forName("com.strike48.pentest_connector.ConnectorBridge")

            // ConnectorBridge.setActivity(this)
            val setActivity = bridgeClass.getMethod("setActivity", android.app.Activity::class.java)
            setActivity.invoke(null, this)

            // ConnectorBridge.setScreenCaptureCallback(Runnable { requestScreenCaptureConsent() })
            val setCallback = bridgeClass.getMethod("setScreenCaptureCallback", Runnable::class.java)
            setCallback.invoke(null, Runnable { requestScreenCaptureConsent() })
        } catch (e: Exception) {
            android.util.Log.w("MainActivity", "Failed to register with ConnectorBridge", e)
        }
    }

    fun requestScreenCaptureConsent() {
        val projectionManager =
            getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        screenCaptureLauncher.launch(projectionManager.createScreenCaptureIntent())
    }

    /**
     * Start ScreenCaptureService via explicit component name to avoid a compile-time
     * dependency on android-lib (which isn't available during the dx build Gradle step).
     */
    private fun startScreenCaptureService(resultCode: Int, data: Intent) {
        val intent = Intent().apply {
            component = ComponentName(
                this@MainActivity,
                "com.strike48.pentest_connector.ScreenCaptureService"
            )
            putExtra("result_code", resultCode)
            putExtra("data", data)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    override fun onWebViewCreate(webView: WebView) {
        super.onWebViewCreate(webView)

        // Allow the WebView to load resources from localhost (127.0.0.1:3030).
        // The Dioxus WebView uses a custom dioxus:// scheme; without these settings,
        // cross-origin requests to the local LiveView TCP server are blocked.
        webView.settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
        @Suppress("DEPRECATION")
        webView.settings.allowUniversalAccessFromFileURLs = true
        webView.settings.allowContentAccess = true
        webView.settings.allowFileAccess = true

        // Enable the WebView to respect prefers-color-scheme based on system dark mode.
        if (Build.VERSION.SDK_INT >= 33) {
            if (WebViewFeature.isFeatureSupported(WebViewFeature.ALGORITHMIC_DARKENING)) {
                WebSettingsCompat.setAlgorithmicDarkeningAllowed(webView.settings, true)
            }
        } else if (Build.VERSION.SDK_INT >= 29) {
            @Suppress("DEPRECATION")
            webView.settings.forceDark = WebSettings.FORCE_DARK_AUTO
        }
    }
}

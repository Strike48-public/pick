package dev.dioxus.main

import android.os.Build
import android.os.Bundle
import android.webkit.WebView
import android.webkit.WebSettings
import androidx.appcompat.app.AppCompatDelegate
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import com.strike48.pentest_connector.BuildConfig

typealias BuildConfig = BuildConfig

class MainActivity : WryActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        // Switch to DayNight theme so the Activity (and its WebView) follows
        // the system light/dark preference. The generated Dioxus styles.xml
        // uses Theme.AppCompat.Light — we override that here.
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
        setTheme(androidx.appcompat.R.style.Theme_AppCompat_DayNight_NoActionBar)
        super.onCreate(savedInstanceState)
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

package com.strike48.pickcrux.ui

import android.annotation.SuppressLint
import android.graphics.Color as AndroidColor
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import org.json.JSONArray

/**
 * Renders a Mermaid diagram in a WebView, mirroring the Dioxus app which loads
 * mermaid.js from a CDN and renders with the dark theme. The diagram source is
 * pre-extracted by the SHARED markdown parser (```mermaid fenced blocks surface
 * as `MarkdownBlock.Mermaid`).
 *
 * The page reports its rendered content height back through a JS bridge so the
 * Compose layout sizes the block to fit instead of guessing a fixed height.
 */
@SuppressLint("SetJavaScriptEnabled")
@Composable
fun MermaidDiagram(code: String) {
    // Height in dp reported by the page once the SVG lays out.
    var heightDp by remember(code) { mutableStateOf(120) }

    AndroidView(
        modifier = Modifier
            .fillMaxWidth()
            .height(heightDp.dp)
            .padding(vertical = 4.dp),
        factory = { ctx ->
            WebView(ctx).apply {
                settings.javaScriptEnabled = true
                setBackgroundColor(AndroidColor.TRANSPARENT)
                addJavascriptInterface(
                    object {
                        @JavascriptInterface
                        fun reportHeight(px: Int) {
                            // px is CSS pixels; WebView density ~ device density,
                            // so treat as dp for layout purposes.
                            if (px > 0) heightDp = px
                        }
                    },
                    "AndroidBridge",
                )
                loadDataWithBaseURL(
                    "https://cdn.jsdelivr.net",
                    htmlFor(code),
                    "text/html",
                    "utf-8",
                    null,
                )
            }
        },
        update = { web ->
            if (web.tag != code) {
                web.tag = code
                web.loadDataWithBaseURL(
                    "https://cdn.jsdelivr.net",
                    htmlFor(code),
                    "text/html",
                    "utf-8",
                    null,
                )
            }
        },
    )
}

/** Minimal HTML page that renders the diagram and posts its height back. */
private fun htmlFor(code: String): String {
    // JSON-encode the source so any characters are safe to embed in JS.
    val json = JSONArray().put(code).toString()
    return """
        <!doctype html>
        <html>
        <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          html, body { margin: 0; padding: 8px; background: transparent; }
          #d { display: flex; justify-content: center; }
          svg { max-width: 100%; height: auto; }
        </style>
        <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
        </head>
        <body>
        <div id="d"></div>
        <script>
          var src = ($json)[0];
          function reportHeight() {
            AndroidBridge.reportHeight(document.body.scrollHeight);
          }
          mermaid.initialize({ startOnLoad: false, theme: 'dark' });
          mermaid.render('m0', src).then(function (r) {
            document.getElementById('d').innerHTML = r.svg;
            setTimeout(reportHeight, 50);
          }).catch(function (e) {
            document.getElementById('d').innerText = String(e);
            setTimeout(reportHeight, 50);
          });
        </script>
        </body>
        </html>
    """.trimIndent()
}

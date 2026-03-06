//! HTML page generation, Phoenix shim JavaScript, CSS injection helpers,
//! and static HTML/JS content.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

/// Embedded restty terminal bundle for Strike48 proxy (inline loading, GPU-accelerated)
static RESTTY_JS: &[u8] = include_bytes!("../assets/restty.js");

/// Embedded JetBrains Mono Regular font for Strike48 proxy
/// (CSP blocks CDN font fetches in sandboxed iframes)
static FONT_REGULAR_TTF: &[u8] = include_bytes!("../assets/jetbrains-mono-regular.ttf");

/// Phoenix WebSocket shim JavaScript (loaded from external file)
static PHOENIX_SHIM_JS: &str = include_str!("../assets/phoenix_shim.js");

/// Inject Phoenix WebSocket shim for Strike48 platform
pub fn inject_websocket_shim(html: &str) -> String {
    if !html.contains("</head>") {
        return html.to_string();
    }

    let phoenix_shim = format!("<script>\n{}\n</script>", PHOENIX_SHIM_JS);

    // Inject restty terminal bundle as inline script for Strike48 context
    let restty_js = String::from_utf8_lossy(RESTTY_JS);

    let restty_shim = format!(
        r#"<script>
// restty terminal bundle inlined (GPU-accelerated, WASM embedded in JS)
{}
</script>"#,
        restty_js
    );

    // Inject JetBrains Mono font as base64 buffer for Strike48 context
    // (CSP blocks CDN font fetches, local-fonts permission denied in iframe)
    let font_b64 = BASE64.encode(FONT_REGULAR_TTF);
    let font_shim = format!(
        r#"<script>
// JetBrains Mono Regular font (base64-decoded ArrayBuffer for restty fontSources)
(function() {{
  var b64 = '{}';
  var raw = atob(b64);
  var buf = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  window.__STRIKE48_FONT_REGULAR__ = buf.buffer;
}})();
</script>"#,
        font_b64
    );

    let combined = format!("{}{}{}", phoenix_shim, restty_shim, font_shim);
    html.replace("</head>", &format!("{}</head>", combined))
}

//! Copy text to the clipboard from any UI surface.
//!
//! Shared by the documents panel's "Copy link" and the Settings "Copy
//! diagnostics" action, so every copy goes through the same native-then-JS
//! path.

use dioxus::document;

/// Build the JS snippet that copies `text` to the clipboard. `serde_json`
/// produces a spec-valid JS string literal (safe for any input), unlike
/// `{:?}` which emits `\u{..}` brace-escapes that are invalid JavaScript.
pub(crate) fn clipboard_js(text: &str) -> String {
    let literal = serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_string());
    format!("navigator.clipboard && navigator.clipboard.writeText({literal})")
}

/// Copy `text` to the clipboard, preferring the native OS clipboard handler
/// (registered by desktop targets) and falling back to the webview's
/// `navigator.clipboard`. The JS path silently no-ops in WebView2 on Windows
/// (no `navigator.clipboard` from the custom-protocol origin), so desktop must
/// go through the native handler; mobile/web have no handler and use the JS
/// path, which works in their (WebKit) renderers.
pub(crate) async fn copy_to_clipboard(text: &str) {
    if pentest_core::clipboard::copy_text(text).is_ok() {
        return;
    }
    let _ = document::eval(&clipboard_js(text)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_js_produces_valid_js_string_literal() {
        assert_eq!(
            clipboard_js("https://studio.example.test/s/abc123"),
            r#"navigator.clipboard && navigator.clipboard.writeText("https://studio.example.test/s/abc123")"#
        );
    }

    #[test]
    fn clipboard_js_escapes_quotes_and_backslashes() {
        // A hostile/odd URL must not break out of the JS string literal.
        let js = clipboard_js(r#"a"b\c"#);
        assert_eq!(
            js,
            r#"navigator.clipboard && navigator.clipboard.writeText("a\"b\\c")"#
        );
    }

    #[test]
    fn clipboard_js_keeps_multiline_text_on_one_js_line() {
        // A diagnostics bundle is many lines; a raw newline would end the JS
        // string literal.
        let js = clipboard_js("== Pick diagnostics ==\nversion: 0.1.0\n");
        assert!(!js.contains('\n'), "{js}");
        assert!(js.contains(r"\nversion: 0.1.0\n"), "{js}");
    }
}

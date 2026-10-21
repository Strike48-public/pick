//! Copy text to the clipboard from any UI surface.
//!
//! Shared by the documents panel's "Copy link" and the Settings "Copy
//! diagnostics" action, so every copy goes through the same native-then-JS
//! path.

use dioxus::document;
use std::time::Duration;

/// How long to wait for the webview to confirm a JS clipboard write.
const JS_COPY_CONFIRM_TIMEOUT: Duration = Duration::from_secs(3);

/// Build the JS snippet that copies `text` to the clipboard and reports
/// whether the write succeeded over `dioxus.send`, then parks so the send
/// binding stays alive (the pattern `workspace_app` uses for credentials; the
/// eval return value is dropped on WebView2). `serde_json` produces a
/// spec-valid JS string literal (safe for any input), unlike `{:?}` which
/// emits `\u{..}` brace-escapes that are invalid JavaScript.
fn confirmed_clipboard_js(text: &str) -> String {
    let literal = serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_string());
    format!(
        "let ok = false;\n\
         try {{ if (navigator.clipboard) {{ await navigator.clipboard.writeText({literal}); ok = true; }} }} catch (e) {{}}\n\
         dioxus.send(ok);\n\
         await new Promise(function() {{}});"
    )
}

/// Copy `text` to the clipboard, preferring the native OS clipboard handler
/// (registered by desktop targets) and falling back to the webview's
/// `navigator.clipboard`. The JS path silently no-ops in WebView2 on Windows
/// (no `navigator.clipboard` from the custom-protocol origin), so desktop must
/// go through the native handler; mobile/web have no handler and use the JS
/// path, which works in their (WebKit) renderers.
///
/// Returns whether the copy is known to have happened. A JS write the
/// webview does not confirm in time counts as not copied, so the caller can
/// offer the text another way instead of claiming success.
pub(crate) async fn copy_to_clipboard(text: &str) -> bool {
    if pentest_core::clipboard::copy_text(text).is_ok() {
        return true;
    }
    let mut eval = document::eval(&confirmed_clipboard_js(text));
    matches!(
        tokio::time::timeout(JS_COPY_CONFIRM_TIMEOUT, eval.recv::<bool>()).await,
        Ok(Ok(true))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_js_writes_a_valid_js_string_literal() {
        let js = confirmed_clipboard_js("https://studio.example.test/s/abc123");
        assert!(
            js.contains(r#"writeText("https://studio.example.test/s/abc123")"#),
            "{js}"
        );
    }

    #[test]
    fn clipboard_js_escapes_quotes_and_backslashes() {
        // A hostile/odd URL must not break out of the JS string literal.
        let js = confirmed_clipboard_js(r#"a"b\c"#);
        assert!(js.contains(r#"writeText("a\"b\\c")"#), "{js}");
    }

    #[test]
    fn clipboard_js_reports_the_outcome() {
        let js = confirmed_clipboard_js("x");
        assert!(js.contains("dioxus.send(ok)"), "{js}");
        // A missing clipboard API leaves `ok` false rather than throwing.
        assert!(js.contains("if (navigator.clipboard)"), "{js}");
    }

    #[test]
    fn clipboard_js_keeps_multiline_text_inside_the_literal() {
        // A diagnostics bundle is many lines; a raw newline inside the JS
        // string literal would end it.
        let js = confirmed_clipboard_js("== Pick diagnostics ==\nversion: 0.1.0\n");
        assert!(
            js.contains(r#"writeText("== Pick diagnostics ==\nversion: 0.1.0\n")"#),
            "{js}"
        );
    }
}

//! Process-global handler for copying text to the OS clipboard.
//!
//! Registered by each desktop target at startup (via `arboard`). Mirrors
//! `matrix::set_browser_opener` and `share::set_share_handler`.
//!
//! Why this exists: the web layer's `navigator.clipboard.writeText()` is
//! unavailable in WebView2 (Windows) when the app is served from Dioxus's
//! custom protocol — it is not treated as a secure context, so
//! `navigator.clipboard` is `undefined` and the copy silently no-ops. macOS
//! and Linux use WebKitGTK, which exposes it, so the JS path works there. A
//! native handler makes "Copy link" work on every desktop; callers fall back
//! to the JS path (mobile / no handler registered).

type CopyHandlerFn = Option<Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>>;

static COPY_HANDLER: std::sync::Mutex<CopyHandlerFn> = std::sync::Mutex::new(None);

/// Register the platform clipboard handler. Call once at startup.
pub fn set_clipboard_handler<F>(handler: F)
where
    F: Fn(&str) -> Result<(), String> + Send + Sync + 'static,
{
    if let Ok(mut lock) = COPY_HANDLER.lock() {
        *lock = Some(Box::new(handler));
    }
}

/// Whether a native clipboard handler is registered.
pub fn is_available() -> bool {
    COPY_HANDLER.lock().map(|l| l.is_some()).unwrap_or(false)
}

/// Copy `text` to the clipboard via the registered handler. Returns `Err` when
/// no handler is registered (mobile / web) so the caller can fall back to the
/// JS `navigator.clipboard` path.
pub fn copy_text(text: &str) -> Result<(), String> {
    match COPY_HANDLER.lock() {
        Ok(lock) => match lock.as_ref() {
            Some(handler) => handler(text),
            None => Err("no clipboard handler registered".to_string()),
        },
        Err(_) => Err("clipboard handler lock poisoned".to_string()),
    }
}

#[doc(hidden)]
pub fn clear_clipboard_handler_for_test() {
    if let Ok(mut lock) = COPY_HANDLER.lock() {
        *lock = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // COPY_HANDLER is a process-global; the two tests below both mutate it.
    // Rust runs tests multi-threaded by default, so without serialization they
    // race — `copy_text_uses_registered_handler` can set the handler between the
    // other test's `clear` and its `is_available()` assert, flaking on some
    // platforms/orderings (observed failing on macOS, passing on Linux). This
    // lock forces the two to run one at a time.
    static TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn copy_text_errors_when_no_handler() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_clipboard_handler_for_test();
        assert!(!is_available());
        assert!(copy_text("hello").is_err());
    }

    #[test]
    fn copy_text_uses_registered_handler() {
        use std::sync::{Arc, Mutex};
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let seen = Arc::new(Mutex::new(String::new()));
        let seen2 = seen.clone();
        set_clipboard_handler(move |t| {
            *seen2.lock().unwrap() = t.to_string();
            Ok(())
        });
        assert!(is_available());
        assert!(copy_text("copied!").is_ok());
        assert_eq!(*seen.lock().unwrap(), "copied!");
        clear_clipboard_handler_for_test();
    }
}

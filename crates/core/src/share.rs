//! Process-global handler for invoking the OS share sheet (share a text/URL).
//!
//! Registered by each app target at startup (iOS: UIActivityViewController;
//! Android: ACTION_SEND). Mirrors `matrix::set_browser_opener`.

type ShareHandlerFn = Option<Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>>;

static SHARE_HANDLER: std::sync::Mutex<ShareHandlerFn> = std::sync::Mutex::new(None);

/// Register the platform share handler.
pub fn set_share_handler<F>(handler: F)
where
    F: Fn(&str) -> Result<(), String> + Send + Sync + 'static,
{
    if let Ok(mut lock) = SHARE_HANDLER.lock() {
        *lock = Some(Box::new(handler));
    }
}

/// Invoke the registered share handler. Returns `Err` if none is registered.
pub fn share_text(text: &str) -> Result<(), String> {
    match SHARE_HANDLER.lock() {
        Ok(lock) => match lock.as_ref() {
            Some(handler) => handler(text),
            None => Err("no share handler registered".to_string()),
        },
        Err(_) => Err("share handler lock poisoned".to_string()),
    }
}

#[doc(hidden)]
pub fn clear_share_handler_for_test() {
    if let Ok(mut lock) = SHARE_HANDLER.lock() {
        *lock = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_text_errors_when_no_handler() {
        // Fresh process default: no handler registered -> Err.
        // (Registering is process-global; keep this test first / independent.)
        clear_share_handler_for_test();
        assert!(share_text("hello").is_err());
    }

    #[test]
    fn share_text_uses_registered_handler() {
        use std::sync::{Arc, Mutex};
        let seen = Arc::new(Mutex::new(String::new()));
        let seen2 = seen.clone();
        set_share_handler(move |t| {
            *seen2.lock().unwrap() = t.to_string();
            Ok(())
        });
        assert!(share_text("shared!").is_ok());
        assert_eq!(*seen.lock().unwrap(), "shared!");
        clear_share_handler_for_test();
    }
}

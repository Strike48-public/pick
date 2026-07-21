//! Secure credential storage abstraction.
//!
//! The Matrix chat access token is a bearer credential — it must not sit in the
//! plaintext settings JSON on mobile. Platforms register a secure backend here
//! (iOS: Keychain; Android: Keystore-backed storage) via [`set_backend`]; the UI
//! calls the platform-agnostic [`store_token`] / [`load_token`] / [`clear_token`].
//!
//! When no backend is registered (e.g. desktop dev, headless), calls report
//! "unavailable" and the caller falls back to the settings file — acceptable on
//! a single-user desktop, never the path taken on iOS/Android where a backend is
//! always registered at startup.

/// A registered secure-storage backend: `(set, get, delete)` by string key.
/// `get` returns `None` when the key is absent.
type SetFn = Box<dyn Fn(&str, &str) -> Result<(), String> + Send + Sync>;
type GetFn = Box<dyn Fn(&str) -> Result<Option<String>, String> + Send + Sync>;
type DeleteFn = Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

struct Backend {
    set: SetFn,
    get: GetFn,
    delete: DeleteFn,
}

static BACKEND: std::sync::Mutex<Option<Backend>> = std::sync::Mutex::new(None);

/// The Keychain/Keystore item key for the Matrix chat token.
const MATRIX_TOKEN_KEY: &str = "matrix_auth_token";

/// Register the platform secure-storage backend. Call once at startup.
pub fn set_backend<S, G, D>(set: S, get: G, delete: D)
where
    S: Fn(&str, &str) -> Result<(), String> + Send + Sync + 'static,
    G: Fn(&str) -> Result<Option<String>, String> + Send + Sync + 'static,
    D: Fn(&str) -> Result<(), String> + Send + Sync + 'static,
{
    if let Ok(mut guard) = BACKEND.lock() {
        *guard = Some(Backend {
            set: Box::new(set),
            get: Box::new(get),
            delete: Box::new(delete),
        });
    }
}

/// Whether a secure backend is registered (i.e. we can store secrets safely).
pub fn is_available() -> bool {
    BACKEND.lock().map(|g| g.is_some()).unwrap_or(false)
}

/// Persist the Matrix chat token to the secure store. Returns `Err` (with the
/// backend's message, or "no secure store") so the caller can fall back.
pub fn store_token(token: &str) -> Result<(), String> {
    match BACKEND.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(b) => (b.set)(MATRIX_TOKEN_KEY, token),
            None => Err("no secure store registered".to_string()),
        },
        Err(_) => Err("secure store lock poisoned".to_string()),
    }
}

/// Load the Matrix chat token from the secure store, if present.
pub fn load_token() -> Result<Option<String>, String> {
    match BACKEND.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(b) => (b.get)(MATRIX_TOKEN_KEY),
            None => Err("no secure store registered".to_string()),
        },
        Err(_) => Err("secure store lock poisoned".to_string()),
    }
}

/// Remove the Matrix chat token from the secure store (e.g. on sign-out).
pub fn clear_token() -> Result<(), String> {
    match BACKEND.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(b) => (b.delete)(MATRIX_TOKEN_KEY),
            None => Err("no secure store registered".to_string()),
        },
        Err(_) => Err("secure store lock poisoned".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn unavailable_without_backend_by_default() {
        // A fresh key that no test registered — behavior depends on global state,
        // so only assert the no-backend error shape via a scoped clear.
        if let Ok(mut g) = BACKEND.lock() {
            *g = None;
        }
        assert!(!is_available());
        assert!(store_token("x").is_err());
        assert!(load_token().is_err());
    }

    #[test]
    fn registered_backend_round_trips() {
        let store: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let s1 = store.clone();
        let s2 = store.clone();
        let s3 = store.clone();
        set_backend(
            move |_k, v| {
                *s1.lock().unwrap() = Some(v.to_string());
                Ok(())
            },
            move |_k| Ok(s2.lock().unwrap().clone()),
            move |_k| {
                *s3.lock().unwrap() = None;
                Ok(())
            },
        );
        assert!(is_available());
        store_token("tok-123").unwrap();
        assert_eq!(load_token().unwrap(), Some("tok-123".to_string()));
        clear_token().unwrap();
        assert_eq!(load_token().unwrap(), None);
        // Reset global for other tests.
        if let Ok(mut g) = BACKEND.lock() {
            *g = None;
        }
    }
}

//! Desktop secure credential storage backed by the OS credential store.
//!
//! Uses the [`keyring`] crate, which wraps the platform-native secret store:
//! Windows Credential Manager, macOS Keychain, and the Linux Secret Service
//! (GNOME Keyring / KWallet via D-Bus). This is the desktop counterpart to the
//! iOS Keychain / Android Keystore backends registered in `apps/mobile`; the UI
//! calls the platform-agnostic `pentest_core::secure_store` API, and this module
//! is what makes the Matrix chat token survive a relaunch on desktop instead of
//! forcing a fresh browser sign-in every launch.
//!
//! When the OS has no usable credential store (common on headless Linux/VMs
//! without a running Secret Service), these functions return `Err`; the caller
//! (`pentest_core::secure_store`) treats that as "unavailable" and the token
//! simply is not persisted — the same fallback behavior as when no backend is
//! registered at all.

/// Service name under which our secrets are grouped in the OS credential store.
/// The item's account/username is the per-secret key handed in by
/// `pentest_core::secure_store` (e.g. `"matrix_auth_token"`).
const SERVICE: &str = "pentest-connector";

/// Build a keyring entry for `key` within our service namespace.
fn entry(key: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, key).map_err(|e| e.to_string())
}

/// Store `value` under `key` in the OS credential store.
pub fn secure_set(key: &str, value: &str) -> Result<(), String> {
    entry(key)?.set_password(value).map_err(|e| e.to_string())
}

/// Load the value stored under `key`, or `None` if no entry exists.
pub fn secure_get(key: &str) -> Result<Option<String>, String> {
    match entry(key)?.get_password() {
        Ok(v) => Ok(Some(v)),
        // A missing entry is not an error — it just means nothing is stored yet.
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Delete the value stored under `key`. A missing entry is treated as success
/// (deleting something that isn't there is a no-op, not a failure).
pub fn secure_delete(key: &str) -> Result<(), String> {
    match entry(key)?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

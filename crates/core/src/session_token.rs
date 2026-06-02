//! Process-global session token for LLM proxy authentication.
//!
//! Set by the tool execution layer when the platform provides a session token
//! in the execute request context. Read by the LLM proxy to authenticate
//! conversation API calls on behalf of the user.

use std::sync::{LazyLock, RwLock};

static TOKEN: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new(String::new()));

/// Set the current session token (called on each execute request from StrikeKit).
pub fn set(token: &str) {
    if let Ok(mut guard) = TOKEN.write() {
        guard.clear();
        guard.push_str(token);
        tracing::info!("[session_token] SET len={}", token.len());
    } else {
        tracing::error!("[session_token] SET FAILED — RwLock poisoned");
    }
}

/// Get the current session token (empty string if not set).
pub fn get() -> String {
    let result = TOKEN.read().map(|g| g.clone()).unwrap_or_default();
    tracing::info!("[session_token] GET len={}", result.len());
    result
}

//! Global session token store.
//!
//! Provides a process-wide auth token that the ChatPanel (and any other
//! component) can read without needing a Dioxus signal prop chain.
//! The connector writes the Matrix access token here after browser OAuth
//! succeeds; the ChatPanel reads it in `make_client`.

use std::sync::{LazyLock, RwLock};

static AUTH_TOKEN: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new(String::new()));
static TENANT_ID: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new(String::new()));

/// Read the current session auth token (Matrix access token for GraphQL).
pub fn get_auth_token() -> String {
    AUTH_TOKEN.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Store a new session auth token.
pub fn set_auth_token(token: &str) {
    let mut guard = AUTH_TOKEN.write().unwrap_or_else(|e| e.into_inner());
    guard.clear();
    guard.push_str(token);
}

/// Read the current tenant/realm name (e.g. "non-prod").
pub fn get_tenant_id() -> String {
    TENANT_ID.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Store the tenant/realm name.
pub fn set_tenant_id(tenant: &str) {
    let mut guard = TENANT_ID.write().unwrap_or_else(|e| e.into_inner());
    guard.clear();
    guard.push_str(tenant);
}

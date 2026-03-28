//! Global session token store.
//!
//! Provides a process-wide auth token that the ChatPanel (and any other
//! component) can read without needing a Dioxus signal prop chain.
//! The connector writes the Matrix access token here after browser OAuth
//! succeeds; the ChatPanel reads it in `make_client`.

use pentest_core::tools::ToolRegistry;
use std::sync::{Arc, LazyLock, RwLock};
use tokio::sync::RwLock as TokioRwLock;

static AUTH_TOKEN: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new(String::new()));
static TENANT_ID: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new(String::new()));
static CONNECTOR_NAME: LazyLock<RwLock<String>> =
    LazyLock::new(|| RwLock::new("pentest-connector".to_string()));
static TOOL_NAMES: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));

type SharedToolRegistry = Arc<RwLock<Option<Arc<TokioRwLock<ToolRegistry>>>>>;
static TOOL_REGISTRY: LazyLock<SharedToolRegistry> = LazyLock::new(|| Arc::new(RwLock::new(None)));

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

/// Read the connector name (gateway identity in Matrix).
pub fn get_connector_name() -> String {
    CONNECTOR_NAME
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Store the connector name.
pub fn set_connector_name(name: &str) {
    let mut guard = CONNECTOR_NAME.write().unwrap_or_else(|e| e.into_inner());
    guard.clear();
    guard.push_str(name);
}

/// Read the registered connector tool names.
pub fn get_tool_names() -> Vec<String> {
    TOOL_NAMES.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Store the registered connector tool names.
pub fn set_tool_names(names: Vec<String>) {
    let mut guard = TOOL_NAMES.write().unwrap_or_else(|e| e.into_inner());
    *guard = names;
}

/// Store the tool registry for global access from UI components.
pub fn set_tool_registry(registry: Arc<TokioRwLock<ToolRegistry>>) {
    let mut guard = TOOL_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    *guard = Some(registry);
}

/// Get a reference to the tool registry for executing tools from UI components.
pub fn get_tool_registry() -> Option<Arc<TokioRwLock<ToolRegistry>>> {
    TOOL_REGISTRY
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .cloned()
}

//! Parameter extraction helpers for tool implementations.
//!
//! Every tool repeats the same `params.get("key").and_then(|v| v.as_str())…`
//! boilerplate.  These tiny helpers eliminate that noise while keeping the
//! call-sites readable.

use serde_json::Value;

/// Extract a string parameter, returning an empty string if missing.
pub fn param_str(params: &Value, key: &str) -> String {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Extract an optional string parameter.
pub fn param_str_opt(params: &Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract a `u64` parameter with a default value.
pub fn param_u64(params: &Value, key: &str, default: u64) -> u64 {
    params.get(key).and_then(|v| v.as_u64()).unwrap_or(default)
}

/// Extract a `bool` parameter with a default value.
pub fn param_bool(params: &Value, key: &str, default: bool) -> bool {
    params.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

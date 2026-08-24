//! Per-request execution context surfaced via [`crate::BaseConnector::execute_with_context`].
//!
//! The Matrix server populates [`crate::types::ExecuteRequest::context`] with caller
//! identity and request-scoped metadata. Connectors that need to read these keys
//! should use the constants in [`keys`] instead of hardcoding strings.
//!
//! ## `params.metadata` ↔ `context` duplication
//!
//! Matrix populates each [`crate::types::ExecuteRequest`] with two parallel
//! views of the caller's metadata:
//!
//! - `context: HashMap<String, String>` — flat string map. Complex values
//!   (like `agent_context`) are JSON-encoded strings and must be
//!   `serde_json::from_str`-decoded before use.
//! - `params["metadata"]: serde_json::Value` — the same data with values
//!   already decoded as JSON.
//!
//! For complex values prefer `params["metadata"][<key>]`; the `context` form
//! is provided so you can fast-path on simple keys (`tenant_id`, `user_id`)
//! without parsing the full payload.
//!
//! Tool arguments themselves are nested under `params["parameters"]`;
//! `params["metadata"]` and `params["tool"]` are siblings of that field.
//!
//! ## Example
//!
//! ```no_run
//! use std::collections::HashMap;
//! use strike48_connector::context::keys;
//!
//! fn handle(context: &HashMap<String, String>) -> &str {
//!     context.get(keys::TENANT_ID).map(String::as_str).unwrap_or("default")
//! }
//! ```

/// Well-known [`crate::types::ExecuteRequest::context`] keys produced by the
/// Matrix server. Connectors that read identity off context should reference
/// these constants so a future server-side rename is a one-line SDK change.
pub mod keys {
    /// Caller tenant identifier in multi-tenant deployments.
    /// Used by downstream consumers to scope storage / KV / spool isolation.
    ///
    /// In modern Matrix deployments this is the canonical tenant UUID. The
    /// human-readable form is in [`TENANT_SLUG`]; consumers that need to
    /// match against operator-configured tenant names should prefer the
    /// slug when present.
    pub const TENANT_ID: &str = "tenant_id";

    /// Caller tenant slug — the human-readable tenant name (e.g. `"acme"`)
    /// that operators configure connectors under. Populated by Matrix
    /// alongside [`TENANT_ID`] (the UUID); older servers may omit it, in
    /// which case [`TENANT_ID`] is the slug itself.
    ///
    /// Connectors that match the caller's tenant against an
    /// operator-supplied identifier should consult this key first and fall
    /// back to [`TENANT_ID`] when absent.
    pub const TENANT_SLUG: &str = "tenant_slug";

    /// Caller subject (e.g. K8s service-account, OIDC sub claim).
    /// Used primarily for audit logging.
    pub const SUBJECT: &str = "user_id";

    /// Whether the request originated from an agent execution flow.
    ///
    /// The value is the string `"true"` or `"false"` — the surrounding map is
    /// `HashMap<String, String>`, so this is *not* a JSON boolean. Callers
    /// that want a typed bool should compare against `"true"` explicitly.
    pub const AGENT_EXECUTION: &str = "agent_execution";

    // Note: a previous `ATTR_PREFIX = "strike48.attrs."` constant was removed
    // in 0.3.8 — Matrix does not emit prefixed attribute keys, so it had no
    // matching server-side contract.

    /// Per-request agent context blob.
    ///
    /// The value in `context: HashMap<String, String>` is a **JSON-encoded
    /// string** — to consume it from `context` you must
    /// `serde_json::from_str(...)` it first. Prefer reading the already
    /// decoded form at `params["metadata"]["agent_context"]`, which Matrix
    /// populates as the same data with values pre-decoded as JSON.
    pub const AGENT_CONTEXT: &str = "agent_context";
}

#[cfg(test)]
mod tests {
    use super::keys;

    #[test]
    fn well_known_key_values_match_matrix_server_contract() {
        // The Matrix server populates these exact keys on every ExecuteRequest.
        // Changing the value side of these constants is a behavioral change for
        // any consumer that hardcoded the old strings, so pin the expected
        // values explicitly rather than asserting prefixes.
        assert_eq!(keys::TENANT_ID, "tenant_id");
        assert_eq!(keys::TENANT_SLUG, "tenant_slug");
        assert_eq!(keys::SUBJECT, "user_id");
        assert_eq!(keys::AGENT_EXECUTION, "agent_execution");
        assert_eq!(keys::AGENT_CONTEXT, "agent_context");
    }

    #[test]
    fn keys_are_distinct() {
        let all = [
            keys::TENANT_ID,
            keys::TENANT_SLUG,
            keys::SUBJECT,
            keys::AGENT_EXECUTION,
            keys::AGENT_CONTEXT,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}

//! Connector-side identity store for differential authorization testing
//! (pick#162).
//!
//! The differential-authz method needs to replay the same request as several
//! operator-provided identities (unauth / user / admin / tenant-A/B) and diff
//! the responses. Those identities are authenticated by **secrets** - cookies,
//! bearer tokens, or raw header bundles the operator supplies at engagement
//! setup.
//!
//! # Why the secret lives here and not in [`crate::specialist_spawner::TestIdentity`]
//!
//! Pick runs standalone *and* through StrikeKit/Matrix. When spawned via Matrix,
//! the specialist's [`SpecialistContext`](crate::specialist_spawner::SpecialistContext)
//! is serialized and sent to the agent (the LLM reasons server-side; only tool
//! *execution* returns to the connector). If the raw session material rode in
//! that context it would transit to and rest on Matrix and sit in the LLM
//! window - a leak surface for the *customer's* credentials.
//!
//! So the context carries only **references** (`TestIdentity { label, role,
//! tenant }`), and the raw material stays connector-side in this
//! [`IdentityStore`], keyed by `label`. The LLM references an identity by label
//! in its tool calls; the connector resolves the label here and injects the
//! auth locally at execution time. The secret never crosses the Matrix/LLM
//! boundary.
//!
//! This handles **Type 1** credentials only: operator-*provided* identities for
//! authorized testing. Type 2 (credentials *discovered* mid-engagement) are
//! findings/evidence - logged and flagged, not redacted - and are out of scope
//! here (see pick#313).
//!
//! Population is two-pathed: standalone (operator config/UI) ships now; the
//! StrikeKit/Matrix provisioning path is pick#312.

use std::collections::HashMap;

/// Opaque session material (cookies, bearer token, or a raw header bundle) that
/// authenticates a test identity when a specialist replays requests.
///
/// This is a secret. Its `Debug` and `Display` impls **redact** the value so it
/// cannot leak into logs, `tracing` fields, or error messages - the
/// secret-hygiene rule shared with pick#179. It is intentionally **not**
/// `Serialize`: unlike the pattern-based [`crate::provenance::redact`] (which
/// scrubs secrets out of tool output), this type keeps the secret off every
/// serialized surface entirely. It is never placed in
/// [`SpecialistContext`](crate::specialist_spawner::SpecialistContext); it lives
/// only in the connector-side [`IdentityStore`]. Reach the raw value only via
/// [`SessionMaterial::expose`], and only on the authentication path.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SessionMaterial(String);

impl SessionMaterial {
    /// Wrap operator-provided session material.
    pub fn new(material: impl Into<String>) -> Self {
        Self(material.into())
    }

    /// Borrow the raw material. This is the authentication path only - callers
    /// that route the result into logs, evidence nodes, or tool output violate
    /// the secret-hygiene contract.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether any material was supplied. `true` for an anonymous identity.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SessionMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionMaterial(<redacted {} bytes>)", self.0.len())
    }
}

impl std::fmt::Display for SessionMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted {} bytes>", self.0.len())
    }
}

/// Connector-local map from identity `label` to its [`SessionMaterial`].
///
/// Held on [`ToolContext`](crate::tools::ToolContext) so any tool can resolve a
/// `label` referenced by the LLM to the real auth material and inject it at
/// execution time. Never serialized; the whole point is that it does not leave
/// the connector.
#[derive(Clone, Default)]
pub struct IdentityStore {
    by_label: HashMap<String, SessionMaterial>,
}

impl IdentityStore {
    /// An empty store (no identities provisioned).
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a store from `(label, material)` pairs. Later entries win on a
    /// duplicate label.
    pub fn from_pairs<I, L>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (L, SessionMaterial)>,
        L: Into<String>,
    {
        let by_label = pairs
            .into_iter()
            .map(|(label, material)| (label.into(), material))
            .collect();
        Self { by_label }
    }

    /// Insert or replace the material for `label`.
    pub fn insert(&mut self, label: impl Into<String>, material: SessionMaterial) {
        self.by_label.insert(label.into(), material);
    }

    /// Resolve a label referenced by the LLM to its session material.
    ///
    /// Returns `None` when the label is unknown (typo, or an identity that was
    /// never provisioned) - callers must treat a miss as "cannot authenticate
    /// as this identity" and fail loudly rather than silently running
    /// unauthenticated, which would misreport an authz result.
    pub fn resolve(&self, label: &str) -> Option<&SessionMaterial> {
        self.by_label.get(label)
    }

    /// Number of provisioned identities.
    pub fn len(&self) -> usize {
        self.by_label.len()
    }

    /// Whether no identities have been provisioned.
    pub fn is_empty(&self) -> bool {
        self.by_label.is_empty()
    }
}

/// The store never reveals its secrets through `Debug` - it reports only the
/// set of known labels (non-sensitive) and a count, so it is safe to include in
/// a `#[derive(Debug)]` parent (e.g. `ToolContext`).
impl std::fmt::Debug for IdentityStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut labels: Vec<&str> = self.by_label.keys().map(String::as_str).collect();
        labels.sort_unstable();
        f.debug_struct("IdentityStore")
            .field("labels", &labels)
            .field("count", &self.by_label.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_material_redacts_in_debug_and_display() {
        let secret = "super-secret-session-token";
        let session = SessionMaterial::new(secret);

        let debug = format!("{session:?}");
        let display = format!("{session}");
        assert!(
            !debug.contains(secret),
            "Debug must not leak the secret: {debug}"
        );
        assert!(
            !display.contains(secret),
            "Display must not leak the secret: {display}"
        );
        // Only the raw exposure path yields the value.
        assert_eq!(session.expose(), secret);
    }

    #[test]
    fn anonymous_identity_has_empty_material() {
        let default = SessionMaterial::default();
        assert!(default.is_empty());
        assert_eq!(default.expose(), "");
    }

    #[test]
    fn store_resolves_known_label() {
        let store = IdentityStore::from_pairs([
            ("user_a", SessionMaterial::new("Cookie: sid=aaa")),
            ("admin", SessionMaterial::new("Authorization: Bearer zzz")),
        ]);
        assert_eq!(store.len(), 2);
        assert_eq!(
            store.resolve("admin").map(SessionMaterial::expose),
            Some("Authorization: Bearer zzz")
        );
    }

    #[test]
    fn store_miss_returns_none_not_empty() {
        // A miss must be distinguishable from "resolved to empty" so callers can
        // fail loudly instead of silently replaying unauthenticated.
        let store = IdentityStore::from_pairs([("user_a", SessionMaterial::new("Cookie: sid=a"))]);
        assert!(store.resolve("nonexistent").is_none());
    }

    #[test]
    fn insert_replaces_existing_label() {
        let mut store = IdentityStore::new();
        store.insert("user_a", SessionMaterial::new("old"));
        store.insert("user_a", SessionMaterial::new("new"));
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.resolve("user_a").map(SessionMaterial::expose),
            Some("new")
        );
    }

    #[test]
    fn store_debug_never_leaks_material_but_shows_labels() {
        let store = IdentityStore::from_pairs([
            ("user_a", SessionMaterial::new("secret-aaa")),
            ("admin", SessionMaterial::new("secret-zzz")),
        ]);
        let debug = format!("{store:?}");
        assert!(
            !debug.contains("secret-aaa") && !debug.contains("secret-zzz"),
            "Debug must not leak material: {debug}"
        );
        // Labels are non-sensitive and useful for diagnostics.
        assert!(debug.contains("user_a") && debug.contains("admin"));
    }
}

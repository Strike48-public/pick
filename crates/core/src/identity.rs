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

use crate::error::{Error, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::specialist_spawner::{IdentityRole, TestIdentity};

/// Environment variable naming the identities file, overriding the default
/// location. Lets an operator (or `run-pentest.sh`) point at an engagement-
/// specific file without touching the config dir.
pub const IDENTITIES_FILE_ENV: &str = "PICK_IDENTITIES_FILE";

/// One entry in the operator-provided identities file.
///
/// This DTO is the **one** boundary where session material legitimately enters
/// the process from a persisted source: the file is operator-owned and
/// gitignored (see `.gitignore` `.env*` / dedicated secrets convention). The
/// raw `session` string is read here and immediately wrapped in the
/// non-serializable [`SessionMaterial`]; it is never re-serialized.
#[derive(Debug, Deserialize)]
struct IdentityFileEntry {
    label: String,
    role: IdentityRole,
    #[serde(default)]
    tenant: Option<String>,
    /// Raw session material (cookie/JWT/header bundle). Omitted/empty for an
    /// anonymous identity.
    #[serde(default)]
    session: String,
}

/// Parsed identities file: the reference set (labels/roles/tenants) plus the
/// connector-side store of their secrets.
///
/// Splitting the two is deliberate: `references` is safe to hand to the
/// specialist context, `store` stays connector-local.
#[derive(Debug, Default)]
pub struct LoadedIdentities {
    /// Reference set to place in [`SpecialistContext`](crate::specialist_spawner::SpecialistContext).
    pub references: Vec<TestIdentity>,
    /// Connector-local secret store.
    pub store: IdentityStore,
}

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

/// Resolve the identities-file path: the [`IDENTITIES_FILE_ENV`] override if
/// set, otherwise `identities.json` in the connector's config dir. The path is
/// not required to exist - a missing file simply means no identities.
pub fn identities_file_path() -> PathBuf {
    let env_override = std::env::var(IDENTITIES_FILE_ENV).ok();
    let cwd_candidate = PathBuf::from("identities.json");
    let cwd_present = cwd_candidate.is_file();
    resolve_identities_path(
        env_override.as_deref(),
        cwd_present,
        cwd_candidate,
        crate::settings::settings_dir().join("identities.json"),
    )
}

/// Pure resolution logic for [`identities_file_path`], split out so the
/// precedence rules are testable without mutating process-global cwd/env.
///
/// Precedence: explicit `PICK_IDENTITIES_FILE` (if non-blank) > a cwd
/// `identities.json` that exists > the per-user settings-dir path. Preferring
/// the cwd file when present is what makes the natural "copy the template and
/// edit it in place" workflow load, and aligns the loaded path with the one the
/// repo `.gitignore` protects (#317 H3).
fn resolve_identities_path(
    env_override: Option<&str>,
    cwd_present: bool,
    cwd_path: PathBuf,
    settings_path: PathBuf,
) -> PathBuf {
    if let Some(p) = env_override {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    if cwd_present {
        return cwd_path;
    }
    settings_path
}

/// Load operator-provided identities from a JSON file.
///
/// A **missing** file is not an error - it yields empty [`LoadedIdentities`], so
/// standalone runs without identities behave exactly as before. A file that
/// exists but is malformed (bad JSON, unknown role) **fails loudly** rather than
/// silently degrading to zero identities, which would misreport authz coverage.
///
/// The file schema is a JSON array of objects:
/// `[{"label":"user_a","role":"user","tenant":null,"session":"Cookie: sid=..."}]`
/// (`role` is one of `anonymous` | `user` | `privileged`; `tenant`/`session`
/// optional). The file is operator-owned and must be gitignored - it holds real
/// credentials.
pub fn load_identities_from_file(path: &Path) -> Result<LoadedIdentities> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LoadedIdentities::default());
        }
        Err(e) => {
            return Err(Error::Config(format!(
                "failed to read identities file {}: {e}",
                path.display()
            )));
        }
    };

    let entries: Vec<IdentityFileEntry> = serde_json::from_str(&contents)
        .map_err(|e| Error::Config(format!("malformed identities file {}: {e}", path.display())))?;

    let mut references = Vec::with_capacity(entries.len());
    let mut store = IdentityStore::new();
    for entry in entries {
        // Every provisioned label gets a store slot - anonymous identities with
        // an empty `session` get an empty [`SessionMaterial`]. This keeps a
        // resolvable-but-empty identity distinct from an unknown label: the
        // former injects nothing and runs (that IS the anonymous identity), the
        // latter still misses and fails loud. Skipping empty entries here made
        // the LLM-instructed `identity_ref: "unauth"` unreachable (it resolved
        // to `None` and errored "not a provisioned test identity").
        store.insert(entry.label.clone(), SessionMaterial::new(entry.session));
        references.push(TestIdentity {
            label: entry.label,
            role: entry.role,
            tenant: entry.tenant,
        });
    }

    Ok(LoadedIdentities { references, store })
}

/// Convenience: load from the default [`identities_file_path`].
pub fn load_default_identities() -> Result<LoadedIdentities> {
    load_identities_from_file(&identities_file_path())
}

/// SDK `InstanceMetadata` key under which the connector advertises available
/// test-identity *references* to the Matrix Red Team orchestrator (matrix#3354).
///
/// Mirrors the `host_interfaces` self-exclusion metadata (matrix#2274): the
/// connector reports a connector-side fact the orchestrator reads to shape its
/// reasoning - here, which identities exist so it can pass them to
/// `spawn_specialist`. Only references (label/role/tenant) travel; the session
/// material never leaves the connector.
pub const IDENTITIES_METADATA_KEY: &str = "authz_identities";

/// Serialize identity *references* for the SDK metadata value (matrix#3354).
///
/// Emits a JSON array of `{label, role, tenant}` - the same non-secret shape
/// `TestIdentity` serializes to. There is no session material here by
/// construction: `TestIdentity` carries none (the secret lives in the
/// [`IdentityStore`]). Returns `None` when there are no references, so the
/// caller can skip inserting an empty key.
pub fn references_metadata_value(references: &[TestIdentity]) -> Option<String> {
    if references.is_empty() {
        return None;
    }
    // TestIdentity serialization is infallible for these fields; fall back to
    // skipping the key rather than failing startup on the unreachable error.
    serde_json::to_string(references).ok()
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

    // ---- file loader ----

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        // Unique-per-name temp path; tests use distinct names so no clash.
        let path = std::env::temp_dir().join(format!("pick-identities-test-{name}.json"));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn missing_file_yields_empty_not_error() {
        let path = std::env::temp_dir().join("pick-identities-does-not-exist-xyz.json");
        let _ = std::fs::remove_file(&path);
        let loaded = load_identities_from_file(&path).expect("missing file is not an error");
        assert!(loaded.references.is_empty());
        assert!(loaded.store.is_empty());
    }

    #[test]
    fn valid_file_splits_references_from_secrets() {
        let path = write_temp(
            "valid",
            r#"[
                {"label":"unauth","role":"anonymous"},
                {"label":"user_a","role":"user","tenant":"t1","session":"Cookie: sid=aaa"},
                {"label":"admin","role":"privileged","session":"Authorization: Bearer zzz"}
            ]"#,
        );
        let loaded = load_identities_from_file(&path).expect("valid file loads");

        // References carry no secret and include all three identities.
        assert_eq!(loaded.references.len(), 3);
        let admin = loaded
            .references
            .iter()
            .find(|r| r.label == "admin")
            .unwrap();
        assert_eq!(admin.role, IdentityRole::Privileged);

        // Every label gets a store slot; anonymous resolves to empty material.
        assert_eq!(loaded.store.len(), 3);
        assert_eq!(
            loaded.store.resolve("user_a").map(SessionMaterial::expose),
            Some("Cookie: sid=aaa")
        );
        assert_eq!(
            loaded
                .store
                .resolve("unauth")
                .map(SessionMaterial::is_empty),
            Some(true),
            "anonymous identity resolves to empty material, not a miss"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn anonymous_entry_resolves_to_empty_material_not_a_miss() {
        // Regression for #317 H1: the LLM emits `identity_ref: "unauth"` (both
        // specialist prompts instruct it). A provisioned anonymous identity must
        // resolve to Some(empty) so the injection fast-path injects nothing and
        // runs - NOT `None`, which the tool treats as "unprovisioned" and errors.
        let path = write_temp("anon", r#"[{"label":"unauth","role":"anonymous"}]"#);
        let loaded = load_identities_from_file(&path).expect("loads");
        assert_eq!(loaded.references.len(), 1);
        let material = loaded
            .store
            .resolve("unauth")
            .expect("anonymous identity is provisioned in the store");
        assert!(
            material.is_empty(),
            "anonymous identity carries no session material"
        );
        // An unprovisioned label still misses - fail-loud path is intact.
        assert!(loaded.store.resolve("never-provisioned").is_none());
        std::fs::remove_file(&path).ok();
    }

    // ---- path resolution (#317 H3) ----

    #[test]
    fn path_prefers_env_override_when_set() {
        let got = resolve_identities_path(
            Some("/explicit/override.json"),
            true, // cwd file present - env must still win
            PathBuf::from("identities.json"),
            PathBuf::from("/settings/identities.json"),
        );
        assert_eq!(got, PathBuf::from("/explicit/override.json"));
    }

    #[test]
    fn path_ignores_blank_env_override() {
        let got = resolve_identities_path(
            Some("   "),
            false,
            PathBuf::from("identities.json"),
            PathBuf::from("/settings/identities.json"),
        );
        assert_eq!(got, PathBuf::from("/settings/identities.json"));
    }

    #[test]
    fn path_prefers_cwd_file_over_settings_dir() {
        // #317 H3: a cwd `identities.json` (the gitignore-protected path) must be
        // loaded in preference to the settings-dir path when it exists.
        let got = resolve_identities_path(
            None,
            true,
            PathBuf::from("identities.json"),
            PathBuf::from("/settings/identities.json"),
        );
        assert_eq!(got, PathBuf::from("identities.json"));
    }

    #[test]
    fn path_falls_back_to_settings_dir_without_cwd_file() {
        let got = resolve_identities_path(
            None,
            false,
            PathBuf::from("identities.json"),
            PathBuf::from("/settings/identities.json"),
        );
        assert_eq!(got, PathBuf::from("/settings/identities.json"));
    }

    #[test]
    fn malformed_file_fails_loudly() {
        let path = write_temp("malformed", r#"{ not an array"#);
        let err = load_identities_from_file(&path).expect_err("malformed file must error");
        assert!(
            err.to_string().contains("malformed identities file"),
            "unexpected error: {err}"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unknown_role_fails_loudly_not_silently_dropped() {
        let path = write_temp(
            "badrole",
            r#"[{"label":"x","role":"superuser","session":"s"}]"#,
        );
        let err = load_identities_from_file(&path).expect_err("unknown role must error");
        assert!(err.to_string().contains("malformed identities file"));
        std::fs::remove_file(&path).ok();
    }

    // ---- metadata advertisement (matrix#3354) ----

    #[test]
    fn references_metadata_is_none_when_empty() {
        assert!(references_metadata_value(&[]).is_none());
    }

    #[test]
    fn references_metadata_carries_refs_but_no_secret() {
        // The metadata value advertised to the orchestrator must contain the
        // labels/roles but never any session material - the file loader put the
        // secret in the store, not the references, and this proves it stays out
        // of the metadata surface too.
        let path = write_temp(
            "meta",
            r#"[
                {"label":"user_a","role":"user","session":"Cookie: sid=SECRET-DO-NOT-LEAK"},
                {"label":"admin","role":"privileged","session":"Bearer SECRET-TOKEN"}
            ]"#,
        );
        let loaded = load_identities_from_file(&path).expect("loads");
        let value = references_metadata_value(&loaded.references).expect("some");

        assert!(value.contains("user_a") && value.contains("admin"));
        assert!(value.contains("privileged"));
        assert!(
            !value.contains("SECRET-DO-NOT-LEAK") && !value.contains("SECRET-TOKEN"),
            "metadata value leaked session material: {value}"
        );
        std::fs::remove_file(&path).ok();
    }
}

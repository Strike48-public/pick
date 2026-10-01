//! Agent-callable package installation (Strike48-public/pick#447).
//!
//! Exposes the tool catalog's install machinery — the same code path the
//! Settings "Tools" panel drives — as a structured tool the Strike48 agent
//! can call during engagement execution when a scan tool reports
//! "command not found". The matrix-side gate classification and the prompt
//! that references this tool are tracked as Strike48/matrix#4466 (parent
//! decision: Strike48/matrix#4361).
//!
//! ## Why a catalog key and not a shell command
//!
//! Matrix's Engagement Gateway hard-denies freeform `execute_command` on any
//! engagement that declares scope, and that deny is non-overridable by design.
//! Pattern-matching install commands out of the deny was considered and
//! rejected: `pacman -S nmap; nmap 10.0.0.0/8` defeats any matcher. A tool
//! whose argument is a **closed enumeration of catalog keys** is checkable by
//! construction; an arbitrary shell string never is. There is no shell
//! interpolation of caller-supplied text anywhere on this path: the key only
//! *selects* a catalog entry, and the install method is resolved by the
//! catalog ([`InstallMethod`]) — the platform decides how to install, the
//! caller never does.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::{
    execute_timed, InstallMethod, ParamType, PentestTool, Platform, ToolContext, ToolParam,
    ToolResult, ToolSchema,
};
use serde_json::{json, Value};

use crate::catalog::{build_catalog, install_entry, CatalogEntry, InstallState};
use crate::installers::{InstallEvent, ProgressSink};

/// Install a missing external tool from the connector's tool catalog.
pub struct InstallToolTool;

#[async_trait]
impl PentestTool for InstallToolTool {
    fn name(&self) -> &str {
        "install_tool"
    }

    fn description(&self) -> &str {
        "Install a missing external tool from this connector's tool catalog. \
         Pass a catalog key (`binary_name`), NOT a package name and NOT a shell \
         command: unknown keys are rejected with the list of valid keys, and the \
         install method (sandbox pacman / host package manager / bespoke \
         installer) is resolved by the platform, never chosen by you. Tools that \
         can only be installed manually (licensed, EULA, sandbox disabled) are \
         refused with the operator instructions. Use this when a scan tool \
         returns \"command not found\"; if the key is refused or the install \
         fails, report the missing tool and the key you tried as a blocker \
         instead of retrying."
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        // Installation mutates connector-host state. The catalog install
        // machinery (sandbox pacman / host package manager / bespoke
        // installers) is a desktop-side capability.
        vec![Platform::Desktop, Platform::Tui]
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description()).param(ToolParam::required(
            "binary_name",
            ParamType::String,
            "Catalog key of the tool to install — the `binary_name` the catalog is \
             keyed on (e.g. \"nmap\"). This is a closed enumeration: anything not \
             in the catalog is rejected with the list of valid keys.",
        ))
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let key = params
                .get("binary_name")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    Error::ToolExecution(
                        "Missing required argument 'binary_name' (a tool-catalog key, \
                         e.g. \"nmap\")"
                            .to_string(),
                    )
                })?;

            let catalog = build_catalog().await;
            let entry = resolve_entry(&catalog, key)?;

            // Already present → short-circuit before any install work: re-running
            // install_entry would cost a redundant `-Sy` refresh / installer run
            // (up to the 600s timeout) for the same result. Review SHOULD-FIX 2,
            // Strike48-public/pick#478.
            if let Some(payload) = already_installed_payload(entry) {
                return Ok(payload);
            }

            // Collect progress steps so the caller sees how far an install got.
            let steps: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let sink_steps = Arc::clone(&steps);
            let progress: Arc<ProgressSink> =
                Arc::new(move |event: InstallEvent| {
                    sink_steps
                        .lock()
                        .expect("install progress log poisoned")
                        .push(event.message);
                });

            let started = Instant::now();
            if let Err(e) = install_entry(entry, progress.as_ref()).await {
                let log = steps.lock().expect("install progress log poisoned").join("; ");
                return Err(Error::ToolExecution(format!(
                    "Installing '{}' failed after {}s: {e}{}",
                    entry.binary_name,
                    started.elapsed().as_secs(),
                    if log.is_empty() {
                        String::new()
                    } else {
                        format!(" (progress: {log})")
                    }
                )));
            }
            let duration_secs = started.elapsed().as_secs();

            // Re-probe so the reported state reflects post-install reality rather
            // than the pre-install snapshot.
            let reloaded = build_catalog().await;
            let state = reloaded
                .iter()
                .find(|e| e.binary_name == entry.binary_name)
                .map(|e| e.state)
                .unwrap_or(InstallState::Unknown);
            let installed = state == InstallState::Installed;

            Ok(json!({
                "binary_name": entry.binary_name,
                "display_name": entry.display_name,
                "install_method": method_label(&entry.install_method),
                "install_state": state_label(state),
                "duration_secs": duration_secs,
                "used_by": entry.used_by,
                "progress": steps.lock().expect("install progress log poisoned").clone(),
                "note": if installed {
                    "Installed. Re-run the original command that reported \"command not found\"."
                } else {
                    "Install command finished but the binary did not verify as present. Report this as a phase blocker with the progress above."
                },
            }))
        })
        .await
    }
}

/// Resolve a catalog key to its entry, rejecting unknown keys with the list of
/// valid keys (the closed enumeration the gateway and prompt rely on) and
/// refusing entries that cannot be installed automatically in the current mode.
fn resolve_entry<'a>(catalog: &'a [CatalogEntry], key: &str) -> Result<&'a CatalogEntry> {
    let Some(entry) = catalog.iter().find(|e| e.binary_name == key) else {
        let mut keys: Vec<&str> = catalog.iter().map(|e| e.binary_name.as_str()).collect();
        keys.sort_unstable();
        return Err(Error::ToolExecution(format!(
            "Unknown catalog key '{key}'. Valid keys: {}.",
            keys.join(", ")
        )));
    };

    // Installed is terminal regardless of install method — installability (the
    // refusal below) is moot when the binary is already present, and the caller
    // short-circuits with the installed payload. Without this, a Manual entry
    // already on PATH — or a pacman key probed Installed with the sandbox off —
    // returned "cannot be installed automatically" for a tool that IS present
    // (review LOW 2, pick#478).
    if entry.state == InstallState::Installed {
        return Ok(entry);
    }

    if !entry.is_auto_installable() {
        let instructions = entry
            .manual_instructions()
            .unwrap_or_else(|| "requires manual operator installation".to_string());
        return Err(Error::ToolExecution(format!(
            "'{key}' cannot be installed automatically from this connector ({}). {}",
            method_label(&entry.install_method),
            instructions
        )));
    }

    Ok(entry)
}

/// Human-readable install method for structured output. Derived from the
/// catalog entry — never from caller input.
fn method_label(method: &InstallMethod) -> String {
    match method {
        InstallMethod::Pacman => "pacman (sandbox)".to_string(),
        InstallMethod::AptHost => "host package manager (apt)".to_string(),
        InstallMethod::Custom { id } => format!("custom installer '{id}'"),
        InstallMethod::Manual { .. } => "manual".to_string(),
    }
}

/// Stable string form of [`InstallState`] for structured output, matching the
/// catalog's `"installed" | "missing" | "manual" | "unknown"` reporting.
fn state_label(state: InstallState) -> &'static str {
    match state {
        InstallState::Installed => "installed",
        InstallState::Missing => "missing",
        InstallState::Manual => "manual",
        InstallState::Unknown => "unknown",
    }
}

/// The early "already installed" response: the probed catalog state says the
/// binary is present, so no install work is scheduled. Returns `None` for any
/// other state so the caller proceeds with the install.
fn already_installed_payload(entry: &CatalogEntry) -> Option<Value> {
    if entry.state != InstallState::Installed {
        return None;
    }
    Some(json!({
        "binary_name": entry.binary_name,
        "display_name": entry.display_name,
        "install_method": method_label(&entry.install_method),
        "install_state": "installed",
        "duration_secs": 0,
        "used_by": entry.used_by,
        "note": "Already installed; nothing to do. Re-run the original command that reported \"command not found\".",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_tool_registry;

    #[test]
    fn schema_declares_a_single_required_catalog_key() {
        let tool = InstallToolTool;
        let schema = tool.schema();
        assert_eq!(schema.name, "install_tool");
        assert_eq!(schema.params.len(), 1);
        assert_eq!(schema.params[0].name, "binary_name");
        assert!(schema.params[0].required);
    }

    #[test]
    fn install_tool_is_registered() {
        let registry = create_tool_registry();
        let names = registry.names();
        assert!(
            names.contains(&"install_tool"),
            "install_tool implemented but not registered in create_tool_registry() \
             - its register() line was likely dropped (see pick#406's merge regression)"
        );
    }

    #[tokio::test]
    async fn unknown_key_is_rejected_with_the_list_of_valid_keys() {
        let catalog = build_catalog().await;
        assert!(
            !catalog.is_empty(),
            "catalog should expose at least one entry in test environments"
        );

        let err = resolve_entry(&catalog, "definitely-not-a-real-tool").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Unknown catalog key"), "{msg}");
        assert!(msg.contains("Valid keys"), "{msg}");
        // The closed enumeration must be actionable: a known key appears.
        assert!(
            catalog.iter().any(|e| msg.contains(e.binary_name.as_str())),
            "error should list catalog keys: {msg}"
        );
    }

    #[tokio::test]
    async fn hostile_keys_are_rejected_rather_than_interpreted() {
        // No key on the catalog path is ever interpreted as a command: the key
        // only selects an entry. Guard the rejection of metacharacter payloads.
        let catalog = build_catalog().await;
        for hostile in ["nmap; touch /tmp/pwned", "nmap && echo pwned", "$(id)"] {
            let err = resolve_entry(&catalog, hostile).unwrap_err();
            assert!(err.to_string().contains("Unknown catalog key"), "{err}");
        }
    }

    #[test]
    fn valid_auto_installable_key_resolves_with_catalog_method() {
        // pick#447's test criterion: a VALID key resolves successfully (not just
        // unknown/manual refusals). Custom{webwright} is auto-installable even
        // with the sandbox disabled (the installer works natively via pip/uv).
        let entry = CatalogEntry {
            binary_name: "webwright".into(),
            display_name: "WebWright".into(),
            description: "headless browser automation".into(),
            category: pentest_core::tools::ToolCategory::Web,
            install_method: InstallMethod::Custom {
                id: "webwright".into(),
            },
            recommended: false,
            used_by: vec![],
            state: InstallState::Missing,
        };

        let resolved =
            resolve_entry(std::slice::from_ref(&entry), "webwright").expect("must resolve");
        assert_eq!(resolved.binary_name, "webwright");
        assert!(
            matches!(&resolved.install_method, InstallMethod::Custom { id } if id == "webwright")
        );
    }

    #[test]
    fn installed_entry_short_circuits_without_install_work() {
        // Unit test for the already_installed_payload DECISION — the call site
        // in execute is the single `if let Some(payload)` that consults it
        // (guarded end-to-end by installed_entry_executes_without_install_work
        // below, where the environment provides an installed entry).
        let mut entry = CatalogEntry {
            binary_name: "webwright".into(),
            display_name: "WebWright".into(),
            description: "headless browser automation".into(),
            category: pentest_core::tools::ToolCategory::Web,
            install_method: InstallMethod::Custom {
                id: "webwright".into(),
            },
            recommended: false,
            used_by: vec!["webwright".into()],
            state: InstallState::Installed,
        };

        let payload =
            already_installed_payload(&entry).expect("installed entry must short-circuit");
        assert_eq!(payload["install_state"], "installed");
        assert_eq!(payload["duration_secs"], 0);
        assert_eq!(payload["binary_name"], "webwright");

        // A missing entry must NOT short-circuit — it proceeds to install.
        entry.state = InstallState::Missing;
        assert!(already_installed_payload(&entry).is_none());
    }

    #[tokio::test]
    async fn installed_entry_executes_without_install_work() {
        // Call-site guard (review LOW 1, pick#478): against the REAL catalog,
        // execute must return the installed payload without invoking
        // install_entry. Skipped when the test environment has no installed
        // catalog entry — the decision itself is covered by the helper test
        // above.
        let catalog = build_catalog().await;
        let Some(entry) = catalog
            .iter()
            .find(|e| e.state == InstallState::Installed)
            .map(|e| e.binary_name.clone())
        else {
            eprintln!(
                "skipping: no installed catalog entry in this environment — \
                 the short-circuit decision is covered by the helper test"
            );
            return;
        };

        let tool = InstallToolTool;
        let result = tool
            .execute(json!({"binary_name": entry}), &ToolContext::default())
            .await
            .expect("execute must succeed for an installed tool");

        assert!(result.success);
        assert_eq!(result.data["install_state"], "installed");
        assert_eq!(result.data["duration_secs"], 0);
    }

    #[test]
    fn installed_manual_entry_resolves_before_the_auto_installable_refusal() {
        // Review LOW 2 (pick#478): guards the `Installed` check INSIDE
        // resolve_entry. Without this, deleting `if entry.state == Installed { return
        // Ok(entry) }` leaves every test green while a tool that IS present regresses
        // to the bogus "cannot be installed automatically" blocker for
        // Manual-method or sandbox-disabled-pacman entries.
        let entry = CatalogEntry {
            binary_name: "burpsuite".into(),
            display_name: "Burp Suite".into(),
            description: "proxy".into(),
            category: pentest_core::tools::ToolCategory::Web,
            install_method: InstallMethod::Manual {
                url: None,
                instructions: "download from the vendor portal".into(),
            },
            recommended: false,
            used_by: vec![],
            state: InstallState::Installed,
        };

        let resolved = resolve_entry(std::slice::from_ref(&entry), "burpsuite")
            .expect("an installed entry must resolve: installability is moot when present");
        assert_eq!(resolved.binary_name, "burpsuite");

        // …and the caller then short-circuits with the installed payload.
        let payload =
            already_installed_payload(resolved).expect("installed entry must short-circuit");
        assert_eq!(payload["install_state"], "installed");
        assert_eq!(payload["duration_secs"], 0);
    }

    #[test]
    fn manual_entry_is_refused_with_operator_instructions() {
        let entry = CatalogEntry {
            binary_name: "burpsuite".into(),
            display_name: "Burp Suite".into(),
            description: "proxy".into(),
            category: pentest_core::tools::ToolCategory::Web,
            install_method: InstallMethod::Manual {
                url: None,
                instructions: "download from the vendor portal".into(),
            },
            recommended: false,
            used_by: vec![],
            state: InstallState::Manual,
        };
        let err = resolve_entry(std::slice::from_ref(&entry), "burpsuite").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cannot be installed automatically"), "{msg}");
        assert!(msg.contains("download from the vendor portal"), "{msg}");
    }

    #[test]
    fn method_and_state_labels_are_stable_strings() {
        assert_eq!(method_label(&InstallMethod::Pacman), "pacman (sandbox)");
        assert_eq!(
            method_label(&InstallMethod::AptHost),
            "host package manager (apt)"
        );
        assert_eq!(
            method_label(&InstallMethod::Custom { id: "zap".into() }),
            "custom installer 'zap'"
        );
        assert_eq!(
            method_label(&InstallMethod::Manual {
                url: None,
                instructions: String::new()
            }),
            "manual"
        );

        assert_eq!(state_label(InstallState::Installed), "installed");
        assert_eq!(state_label(InstallState::Missing), "missing");
        assert_eq!(state_label(InstallState::Manual), "manual");
        assert_eq!(state_label(InstallState::Unknown), "unknown");
    }
}

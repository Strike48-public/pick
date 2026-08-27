//! Bespoke tool installers.
//!
//! Most external tools install via a single `pacman -S <pkg>` inside the
//! BlackArch sandbox (see [`crate::external::install`]). A handful need more:
//! pip/uv installs, vendor installers, browser downloads, or service setup.
//! Those declare [`InstallMethod::Custom { id }`] on their
//! [`ExternalDependency`] and provide a [`ToolInstaller`] here, keyed by the
//! same `id`.
//!
//! The catalog service ([`crate::catalog`]) routes install requests:
//! - `Pacman` / `AptHost` -> generic package install
//! - `Manual` -> show instructions, no automated install
//! - `Custom { id }` -> look up the installer here and call [`ToolInstaller::install`]
//!
//! [`InstallMethod::Custom { id }`]: pentest_core::tools::InstallMethod::Custom
//! [`ExternalDependency`]: pentest_core::tools::ExternalDependency

mod bloodhound;
mod metasploit;
mod package;
pub(crate) mod pacman;
mod webwright;
mod zap;

use pentest_core::error::Result;
use std::collections::HashMap;
use std::sync::Arc;

pub use bloodhound::BloodHoundInstaller;
pub use metasploit::MetasploitInstaller;
pub use package::PackageInstaller;
pub use webwright::WebwrightInstaller;
pub use zap::ZapInstaller;

/// A single progress update emitted during an install. `fraction` is `None`
/// for indeterminate steps (the common case: most installs can't report a
/// meaningful percentage), `Some(0.0..=1.0)` when a step has measurable size.
#[derive(Debug, Clone)]
pub struct InstallEvent {
    pub message: String,
    pub fraction: Option<f32>,
}

impl InstallEvent {
    /// An indeterminate progress message.
    pub fn step(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fraction: None,
        }
    }
}

/// Sink for [`InstallEvent`]s. The UI wires this to the process-global progress
/// state ([`crate`] callers pass a closure that updates `GLOBAL_PROGRESS`);
/// headless callers can pass a no-op or a logging sink.
pub type ProgressSink = dyn Fn(InstallEvent) + Send + Sync;

/// A no-op progress sink for headless / test callers.
pub fn noop_progress() -> Arc<ProgressSink> {
    Arc::new(|_| {})
}

/// Whether the command sandbox is active. `pentest_platform::is_sandbox_enabled`
/// is desktop-only (the sandbox doesn't exist on Android/iOS); on those targets
/// there is no sandbox, so callers must always treat tools as host-installed.
#[cfg(not(target_os = "android"))]
pub(crate) fn sandbox_enabled() -> bool {
    pentest_platform::is_sandbox_enabled()
}

#[cfg(target_os = "android")]
pub(crate) fn sandbox_enabled() -> bool {
    false
}

/// Return true if `binary` resolves on PATH in the current execution
/// environment (sandbox when enabled, host otherwise).
///
/// Uses the POSIX `command -v` shell builtin rather than the `which` binary:
/// the minimal BlackArch sandbox rootfs does **not** ship `which`, so a
/// `which <bin>` probe fails with "command not found" even for a tool that is
/// correctly installed (e.g. certipy/kerbrute land in `/usr/sbin` but the
/// post-install check reported them missing). `command -v` is a builtin of
/// every POSIX shell, so it works in both the sandbox and on the host.
///
/// The binary name is passed as a positional shell argument (`sh -c '...' _ <bin>`
/// referenced as `$1`), never interpolated into the script, so no shell-escaping
/// of the name is required.
pub(crate) async fn binary_on_path(binary: &str) -> bool {
    let platform = pentest_platform::get_platform();
    pentest_platform::CommandExec::execute_command(
        &platform,
        "sh",
        &["-c", "command -v \"$1\" > /dev/null 2>&1", "sh", binary],
        std::time::Duration::from_secs(5),
    )
    .await
    .map(|r| r.exit_code == 0)
    .unwrap_or(false)
}

/// A bespoke installer for one tool (or tool bundle) that cannot be installed
/// by a single package-manager command.
///
/// Implementations are responsible for branching on sandbox vs native mode
/// themselves (via [`pentest_platform::is_sandbox_enabled`]) because the right
/// action differs: in-sandbox they typically `pacman -S`, natively they run a
/// pip/uv/vendor installer or surface manual instructions.
#[async_trait::async_trait]
pub trait ToolInstaller: Send + Sync {
    /// Stable identifier matching `InstallMethod::Custom { id }`.
    fn id(&self) -> &str;

    /// Human-friendly name for the catalog UI.
    fn display_name(&self) -> &str;

    /// Whether the tool is currently usable. Cheap check (typically `which`
    /// or an import probe); must not perform installation.
    async fn is_installed(&self) -> bool;

    /// Install the tool, emitting progress to `progress`. Returns `Ok(())` only
    /// when the tool is verified installed afterwards.
    async fn install(&self, progress: &ProgressSink) -> Result<()>;

    /// Optional manual instructions, shown when automated install is not
    /// possible in the current mode (e.g. native mode for a sandbox-only path).
    fn manual_instructions(&self) -> Option<String> {
        None
    }

    /// Whether this tool can **only** be installed inside the sandbox.
    ///
    /// When `true` (the default), the catalog will mark the tool as
    /// non-auto-installable when the sandbox is disabled, and show the
    /// manual instructions instead of an "Install" button.
    ///
    /// Override to `false` for tools that install natively (e.g.
    /// [`WebwrightInstaller`], which installs via pip/uv on the host).
    fn sandbox_required(&self) -> bool {
        true
    }
}

/// Process-global installer registry, built once on first access. The
/// installers are zero-sized / cheap structs and the `Arc`s are cheap to clone,
/// so callers ([`get_installer`], the catalog) pay only a map lookup + `Arc`
/// clone rather than rebuilding the whole map each time.
static INSTALLER_REGISTRY: std::sync::LazyLock<HashMap<String, Arc<dyn ToolInstaller>>> =
    std::sync::LazyLock::new(build_installer_registry);

/// Construct the registry of all bespoke installers, keyed by `id`.
fn build_installer_registry() -> HashMap<String, Arc<dyn ToolInstaller>> {
    let installers: Vec<Arc<dyn ToolInstaller>> = vec![
        Arc::new(WebwrightInstaller),
        Arc::new(ZapInstaller),
        Arc::new(MetasploitInstaller),
        Arc::new(BloodHoundInstaller),
        // AD suite: pacman-in-sandbox, pipx/go-on-host natively.
        Arc::new(PackageInstaller::certipy()),
        Arc::new(PackageInstaller::netexec()),
        Arc::new(PackageInstaller::kerbrute()),
    ];

    installers
        .into_iter()
        .map(|i| (i.id().to_string(), i))
        .collect()
}

/// The bespoke-installer registry, keyed by `id`.
///
/// The catalog service consults this for any dependency whose `install_method`
/// is `Custom { id }`.
pub fn installer_registry() -> &'static HashMap<String, Arc<dyn ToolInstaller>> {
    &INSTALLER_REGISTRY
}

/// Look up a single installer by `id`.
pub fn get_installer(id: &str) -> Option<Arc<dyn ToolInstaller>> {
    INSTALLER_REGISTRY.get(id).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_keys_match_installer_ids() {
        let reg = installer_registry();
        for (key, inst) in reg {
            assert_eq!(key, inst.id(), "registry key must equal installer id");
        }
    }

    #[test]
    fn registry_contains_all_custom_installers() {
        let reg = installer_registry();
        for id in [
            "webwright",
            "zap",
            "metasploit",
            "bloodhound",
            "certipy",
            "netexec",
            "kerbrute",
        ] {
            assert!(reg.contains_key(id), "missing installer: {id}");
        }
    }

    #[test]
    fn get_installer_returns_matching_id() {
        assert_eq!(get_installer("zap").unwrap().id(), "zap");
        assert!(get_installer("does-not-exist").is_none());
    }

    #[test]
    fn ids_are_unique() {
        let reg = installer_registry();
        // installer_registry collapses duplicates into the map, so compare the
        // map size against the constructed count by rebuilding the id list.
        let ids: Vec<String> = reg.keys().cloned().collect();
        let mut deduped = ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len(), "installer ids must be unique");
    }

    #[test]
    fn sandbox_required_default_is_true() {
        // Every sandbox-only installer (bloodhound, zap, metasploit,
        // certipy, netexec, kerbrute) must report sandbox_required() = true
        // so the catalog hides their Install button when sandbox is off.
        let reg = installer_registry();
        let sandbox_only_ids = [
            "bloodhound",
            "zap",
            "metasploit",
            "certipy",
            "netexec",
            "kerbrute",
        ];
        for id in &sandbox_only_ids {
            let installer = reg
                .get(*id)
                .unwrap_or_else(|| panic!("missing installer: {id}"));
            assert!(
                installer.sandbox_required(),
                "{id} must be sandbox-required (default true)"
            );
        }
    }

    #[test]
    fn webwright_is_not_sandbox_required() {
        // Webwright installs via pip/uv on the host and works natively,
        // so the catalog must still show an Install button when sandbox
        // is disabled.
        let installer = get_installer("webwright")
            .expect("webwright installer must be registered");
        assert!(
            !installer.sandbox_required(),
            "webwright must not be sandbox-required"
        );
    }
}

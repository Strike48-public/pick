//! Tool catalog: discover external dependencies, probe their install state,
//! and route install requests to the right mechanism.
//!
//! This is the backend for the Settings "Tools" panel and for any headless
//! "install everything" command. It is intentionally UI-agnostic: it returns
//! plain data ([`CatalogEntry`]) and performs installs through a caller-
//! supplied progress sink.
//!
//! ## How it works
//! 1. Enumerate `create_tool_registry().schemas()` and collect every
//!    [`ExternalDependency`] that has one.
//! 2. Deduplicate by `binary_name` — many tools share a binary (e.g. several
//!    impacket tools), and the catalog presents one entry per installable
//!    thing, not one per tool.
//! 3. For each unique dependency, derive a [`CatalogEntry`] describing how it
//!    installs and whether it is currently present.
//! 4. [`install_entry`] routes by [`InstallMethod`]:
//!    - `Pacman`/`AptHost` -> generic package install (sandbox pacman or host check)
//!    - `Custom { id }`   -> the matching [`ToolInstaller`]
//!    - `Manual`          -> never auto-installs; returns the instructions
//!
//! [`ExternalDependency`]: pentest_core::tools::ExternalDependency
//! [`InstallMethod`]: pentest_core::tools::InstallMethod

use pentest_core::error::{Error, Result};
use pentest_core::tools::{ExternalDependency, InstallMethod, ToolCategory};
use pentest_platform::{get_platform, CommandExec};
use std::collections::BTreeMap;
use std::time::Duration;

use crate::installers::{get_installer, sandbox_enabled, InstallEvent, ProgressSink};

/// Installation state of a single catalog entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallState {
    /// Verified present (binary on PATH or importable).
    Installed,
    /// Not present and installable in the current mode.
    Missing,
    /// Not present and only installable manually (licensed / EULA / operator
    /// choice, or a sandbox-only path while running natively).
    Manual,
    /// Could not determine (probe failed). Treated as not-installed by callers
    /// but surfaced distinctly so the UI doesn't claim a tool is missing when
    /// the check itself errored.
    Unknown,
}

/// One installable item in the catalog. Derived from one or more tool schemas
/// that share the same `binary_name`.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    /// The binary the dependency is keyed on (the dedupe key).
    pub binary_name: String,
    /// Human-friendly display name (installer display name when a custom
    /// installer exists, else the dependency description).
    pub display_name: String,
    /// Free-text description from the dependency.
    pub description: String,
    pub category: ToolCategory,
    pub install_method: InstallMethod,
    pub recommended: bool,
    /// Names of the registered tools that declared this dependency. Lets the UI
    /// show "used by: nmap, autopwn" and lets callers explain why a tool matters.
    pub used_by: Vec<String>,
    pub state: InstallState,
}

/// Rough expected install duration, in seconds, for a dependency. Used only to
/// drive the UI's elapsed-vs-estimate progress bar — it is a soft hint, never a
/// guarantee. The command layer runs installs to completion without streaming
/// byte-level progress, so a true percentage is not available; a labeled
/// estimate is the honest signal we can give.
///
/// Values are deliberately generous (a bar that fills slightly slow reads
/// better than one that pins at 100% and keeps spinning). The default covers a
/// single `pacman`/`apt` package fetch on a warm mirror; heavyweight custom
/// installers override by `id`.
pub fn estimated_install_secs(method: &InstallMethod, binary_name: &str) -> u32 {
    // Sensible per-mechanism defaults.
    let base = match method {
        // Manual installs are operator-driven; no automated timer applies.
        InstallMethod::Manual { .. } => 0,
        // A single package plus the -Sy DB refresh on the sandbox rootfs.
        InstallMethod::Pacman => 90,
        InstallMethod::AptHost => 60,
        // Bespoke installers vary widely; refined by binary below.
        InstallMethod::Custom { .. } => 120,
    };

    // Per-tool overrides for the installers whose real-world duration is far
    // from the mechanism default. Keyed by the catalog binary name.
    match binary_name {
        // Metasploit pulls a very large package set + Ruby gems.
        "msfconsole" => 360,
        // ZAP downloads a sizable Java app bundle.
        "zaproxy" | "zap" => 150,
        // webwright installs a Python env plus a Playwright Chromium download.
        "webwright" => 180,
        _ => base,
    }
}

impl CatalogEntry {
    /// Rough expected install duration in seconds. See
    /// [`estimated_install_secs`]. `0` means no automated install (manual).
    pub fn estimated_install_secs(&self) -> u32 {
        estimated_install_secs(&self.install_method, &self.binary_name)
    }

    /// Whether this entry can be installed automatically in the current mode.
    pub fn is_auto_installable(&self) -> bool {
        match &self.install_method {
            InstallMethod::Manual { .. } => false,
            // Pacman is only automatic inside the sandbox; on the host the
            // operator installs packages themselves.
            InstallMethod::Pacman => sandbox_enabled(),
            InstallMethod::AptHost => !sandbox_enabled(),
            InstallMethod::Custom { id } => {
                // A custom installer is auto-installable when either:
                //   - the sandbox is enabled (it can run pacman inside), OR
                //   - the installer itself works natively (e.g. pip/uv).
                // Sandbox-required installers (bloodhound, zap, metasploit,
                // certipy, netexec, kerbrute) are NOT auto-installable when
                // the sandbox is disabled => the UI shows manual instructions
                // instead of an "Install" button that would fail.
                if sandbox_enabled() {
                    return true;
                }
                get_installer(id)
                    .map(|i| !i.sandbox_required())
                    .unwrap_or(false)
            }
        }
    }

    /// Manual instructions to show when auto-install isn't possible.
    pub fn manual_instructions(&self) -> Option<String> {
        match &self.install_method {
            InstallMethod::Manual { instructions, .. } => Some(instructions.clone()),
            InstallMethod::Custom { id } => get_installer(id).and_then(|i| i.manual_instructions()),
            _ => None,
        }
    }
}

/// Binaries that are install prerequisites for other tools rather than
/// operator-facing tools in their own right. They are hidden from the catalog
/// UI (no one "installs Python" as a pentest tool), but remain real
/// `external_dependency` declarations so the tools that need them still pull
/// them in through their own installer: `python3`/`playwright` for webwright,
/// `node` (Node.js) for the CyberChef recipe runner.
const HIDDEN_CATALOG_BINARIES: &[&str] = &["python3", "playwright", "node"];

/// Collect the unique external dependencies declared across all registered
/// tools, mapping each `binary_name` to its dependency plus the tools that use
/// it. Uses a `BTreeMap` for deterministic ordering.
fn collect_dependencies() -> BTreeMap<String, (ExternalDependency, Vec<String>)> {
    let registry = crate::create_tool_registry();
    let mut deps: BTreeMap<String, (ExternalDependency, Vec<String>)> = BTreeMap::new();

    // Intentionally unfiltered (`schemas()`, not `supported_schemas()`): the
    // catalog enumerates every installable dependency across all desktop OSes,
    // not just the current host. This is an install/inventory surface, not the
    // agent-facing capability list — host gating happens where tools are
    // advertised/executed, not here. See #183.
    for schema in registry.schemas() {
        for dep in &schema.external_dependencies {
            if HIDDEN_CATALOG_BINARIES.contains(&dep.binary_name.as_str()) {
                continue;
            }
            let entry = deps
                .entry(dep.binary_name.clone())
                .or_insert_with(|| (dep.clone(), Vec::new()));
            // The FIRST non-default install method wins. Tools' metadata is
            // taken from the first declaration; the install method is upgraded
            // exactly once, from the `Pacman` default to whatever the first tool
            // that opts into a richer method (Custom/Manual/AptHost) declares.
            // Once upgraded, later declarations don't override it. In a
            // well-formed registry only one tool declares a non-default method
            // for a given binary, so conflicts don't arise in practice; if two
            // ever did, the first-seen (BTreeMap is keyed by binary, iteration
            // is over schemas in registry order) non-default method is used.
            if matches!(entry.0.install_method, InstallMethod::Pacman)
                && !matches!(dep.install_method, InstallMethod::Pacman)
            {
                entry.0.install_method = dep.install_method.clone();
            }
            if !entry.1.contains(&schema.name) {
                entry.1.push(schema.name.clone());
            }
        }
    }

    deps
}

/// Probe whether a single binary is present on PATH.
///
/// Uses the POSIX `command -v` shell builtin, not the `which` binary: the
/// minimal BlackArch sandbox rootfs does not ship `which`, so a `which` probe
/// reports every tool as Missing even when installed (certipy/kerbrute landed
/// in `/usr/sbin` but read as absent). `command -v` is a shell builtin and
/// works in both the sandbox and on the host. The binary name is passed as a
/// positional arg (`$1`), never interpolated, so no shell-escaping is needed.
async fn binary_present(binary: &str) -> InstallState {
    let platform = get_platform();
    match platform
        .execute_command(
            "sh",
            &["-c", "command -v \"$1\" > /dev/null 2>&1", "sh", binary],
            Duration::from_secs(5),
        )
        .await
    {
        Ok(r) if r.exit_code == 0 => InstallState::Installed,
        Ok(_) => InstallState::Missing,
        Err(_) => InstallState::Unknown,
    }
}

/// Determine the install state for one dependency, consulting a custom
/// installer's own probe when present (e.g. webwright checks an import, not a
/// binary on PATH).
async fn probe_state(dep: &ExternalDependency) -> InstallState {
    match &dep.install_method {
        InstallMethod::Custom { id } => {
            if let Some(installer) = get_installer(id) {
                if installer.is_installed().await {
                    InstallState::Installed
                } else {
                    InstallState::Missing
                }
            } else {
                // Declared a custom installer that doesn't exist — fall back to
                // a binary probe rather than silently claiming installed.
                binary_present(&dep.binary_name).await
            }
        }
        InstallMethod::Manual { .. } => match binary_present(&dep.binary_name).await {
            InstallState::Installed => InstallState::Installed,
            // Not present and can't auto-install -> Manual.
            _ => InstallState::Manual,
        },
        InstallMethod::Pacman | InstallMethod::AptHost => binary_present(&dep.binary_name).await,
    }
}

/// Build the full catalog with current install state for every entry. Probes
/// run sequentially; the set is small (tens of binaries) and `which` is cheap.
pub async fn build_catalog() -> Vec<CatalogEntry> {
    let deps = collect_dependencies();
    let mut entries = Vec::with_capacity(deps.len());

    for (binary_name, (dep, used_by)) in deps {
        let state = probe_state(&dep).await;
        let display_name = match &dep.install_method {
            InstallMethod::Custom { id } => get_installer(id)
                .map(|i| i.display_name().to_string())
                .unwrap_or_else(|| binary_name.clone()),
            _ => binary_name.clone(),
        };

        entries.push(CatalogEntry {
            binary_name,
            display_name,
            description: dep.description.clone(),
            category: dep.category,
            install_method: dep.install_method.clone(),
            recommended: dep.recommended,
            used_by,
            state,
        });
    }

    entries
}

/// Install a single catalog entry, routing by its install method. Emits
/// progress through `progress`. Returns an error (rather than silently
/// succeeding) for `Manual` entries so callers surface the instructions.
pub async fn install_entry(entry: &CatalogEntry, progress: &ProgressSink) -> Result<()> {
    match &entry.install_method {
        InstallMethod::Custom { id } => {
            let installer = get_installer(id).ok_or_else(|| {
                Error::ToolExecution(format!("No installer registered for '{id}'"))
            })?;
            installer.install(progress).await
        }
        InstallMethod::Manual { instructions, .. } => Err(Error::ToolExecution(format!(
            "{} must be installed manually: {instructions}",
            entry.display_name
        ))),
        InstallMethod::Pacman => install_pacman(entry, progress).await,
        InstallMethod::AptHost => install_apt_host(entry, progress).await,
    }
}

/// Install a Pacman entry inside the sandbox. In native mode pacman isn't the
/// host's package manager, so we surface a manual hint instead of running it.
async fn install_pacman(entry: &CatalogEntry, progress: &ProgressSink) -> Result<()> {
    if !sandbox_enabled() {
        return Err(Error::ToolExecution(format!(
            "{} installs via the BlackArch sandbox. With the sandbox disabled, install it on the \
             host (e.g. your distro's package manager) so '{}' is on PATH.",
            entry.display_name, entry.binary_name
        )));
    }
    progress(InstallEvent::step(format!(
        "Installing {} via pacman...",
        entry.display_name
    )));
    // package_name is keyed by binary in the catalog; look it up fresh from the
    // dependency to get the real package name.
    let pkg = pacman_package_for(&entry.binary_name).unwrap_or_else(|| entry.binary_name.clone());
    validate_package_name(&pkg)?;
    // -Sy refreshes the package DBs first; a bare -S fails on a rootfs whose
    // sync DBs have gone stale (see installers::pacman).
    crate::installers::pacman::install(&pkg, Duration::from_secs(600)).await?;
    progress(InstallEvent::step(format!(
        "{} installed",
        entry.display_name
    )));
    Ok(())
}

/// Install an apt-host entry (native mode). Only attempts when the sandbox is
/// disabled; in sandbox mode such tools would come from pacman instead.
async fn install_apt_host(entry: &CatalogEntry, progress: &ProgressSink) -> Result<()> {
    progress(InstallEvent::step(format!(
        "Installing {} via apt-get...",
        entry.display_name
    )));
    let platform = get_platform();
    let pkg = entry.binary_name.clone();
    validate_package_name(&pkg)?;
    let result = platform
        .execute_command(
            "apt-get",
            &["install", "-y", &pkg],
            Duration::from_secs(600),
        )
        .await?;
    if result.exit_code != 0 {
        return Err(Error::ToolExecution(format!(
            "Failed to apt-get install {pkg}: {}",
            result.stderr
        )));
    }
    progress(InstallEvent::step(format!(
        "{} installed",
        entry.display_name
    )));
    Ok(())
}

/// Validate a package name before passing it to `pacman`/`apt-get`. Package
/// names come from tool schemas (not user input), so this is defense-in-depth
/// against a buggy or malicious schema declaring a name with shell
/// metacharacters that could matter on the sandbox's shell-escaped exec path.
/// Allows the conservative set of characters real package names use.
fn validate_package_name(pkg: &str) -> Result<()> {
    // A leading '-' would be parsed by pacman/apt-get as a flag rather than a
    // package (argument injection): a name like "-Syu" or "--purge" would
    // change the command's behavior. Real package names never start with '-',
    // so reject it explicitly. This matters most on the uninstall path, where
    // "--purge" would escalate `apt-get remove` into config deletion.
    if pkg.is_empty()
        || pkg.starts_with('-')
        || !pkg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
    {
        return Err(Error::ToolExecution(format!(
            "Refusing to install package with unexpected name: {pkg:?}"
        )));
    }
    Ok(())
}

/// Look up the real pacman package name for a binary by scanning the registry
/// dependencies again (the catalog dedupes on binary but keeps package name in
/// the underlying dependency).
fn pacman_package_for(binary: &str) -> Option<String> {
    let deps = collect_dependencies();
    deps.get(binary).map(|(d, _)| d.package_name.clone())
}

/// Install all entries that are recommended and auto-installable in the current
/// mode. Returns the list of (binary, error) for entries that failed, so the
/// caller can report partial success. Already-installed entries are skipped.
pub async fn install_all_recommended(progress: &ProgressSink) -> Vec<(String, String)> {
    let catalog = build_catalog().await;
    let selected: Vec<CatalogEntry> = catalog
        .into_iter()
        .filter(|e| e.recommended && e.state != InstallState::Installed && e.is_auto_installable())
        .collect();
    install_entries(&selected, progress).await
}

/// Install a pre-selected set of entries, aggregating per-entry failures as
/// `(binary_name, error)` so the caller can report partial success. Shared by
/// [`install_all_recommended`] and [`install_all_in_category`] so the loop and
/// its failure-aggregation are defined (and tested) once.
async fn install_entries(
    entries: &[CatalogEntry],
    progress: &ProgressSink,
) -> Vec<(String, String)> {
    let mut failures = Vec::new();
    for entry in entries {
        if let Err(e) = install_entry(entry, progress).await {
            failures.push((entry.binary_name.clone(), e.to_string()));
        }
    }
    failures
}

/// The auto-installable, not-yet-installed entries in a category, as
/// `(binary_name, estimated_secs)`. Lets the UI preview how many tools an
/// "Install all" for that category will fetch (and their summed time estimate)
/// before the operator commits — the count/size confirm for category installs.
/// `category` is the stable snake_case key (e.g. "network"), matching
/// [`CatalogItem::category`].
pub async fn pending_installs_in_category(category: &str) -> Vec<(String, u32)> {
    build_catalog()
        .await
        .into_iter()
        .filter(|e| {
            category_key(e.category) == category
                && e.state != InstallState::Installed
                && e.is_auto_installable()
        })
        .map(|e| (e.binary_name.clone(), e.estimated_install_secs()))
        .collect()
}

/// Install every auto-installable, not-yet-installed tool in one category.
/// Mirrors [`install_all_recommended`] but scopes to a single category key
/// (the "Install all" action on a category header). Already-installed and
/// non-auto-installable entries are skipped; returns `(binary, error)` for any
/// that failed so the caller can report partial success.
pub async fn install_all_in_category(
    category: &str,
    progress: &ProgressSink,
) -> Vec<(String, String)> {
    let catalog = build_catalog().await;
    let selected: Vec<CatalogEntry> = catalog
        .into_iter()
        .filter(|e| {
            category_key(e.category) == category
                && e.state != InstallState::Installed
                && e.is_auto_installable()
        })
        .collect();
    install_entries(&selected, progress).await
}

/// A flat, serializable, UI-facing view of one catalog entry. The Dioxus
/// settings panel holds a `Vec<CatalogItem>` in a signal; keeping this separate
/// from [`CatalogEntry`] avoids leaking `InstallMethod`/`ToolCategory` into the
/// UI and gives a stable, string-based shape for rendering and round-tripping.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CatalogItem {
    pub binary_name: String,
    pub display_name: String,
    pub description: String,
    /// Category as a stable lowercase string (e.g. "active_directory").
    pub category: String,
    /// One of: "installed", "missing", "manual", "unknown".
    pub state: String,
    /// Whether this tool is part of the recommended default set.
    pub recommended: bool,
    /// Whether an Install button should be offered (auto-installable in mode).
    pub auto_installable: bool,
    /// Whether the UI should offer to uninstall this tool (removable in the
    /// current mode). Only meaningful when `state == "installed"`.
    #[serde(default)]
    pub uninstallable: bool,
    /// Manual instructions to show when not auto-installable.
    pub manual_instructions: Option<String>,
    /// Tools that declared this dependency.
    pub used_by: Vec<String>,
    /// Rough expected install duration in seconds, for the UI's
    /// elapsed-vs-estimate progress bar. `0` for manual-only entries. Soft hint.
    #[serde(default)]
    pub estimated_secs: u32,
}

impl From<&CatalogEntry> for CatalogItem {
    fn from(e: &CatalogEntry) -> Self {
        let state = match e.state {
            InstallState::Installed => "installed",
            InstallState::Missing => "missing",
            InstallState::Manual => "manual",
            InstallState::Unknown => "unknown",
        };
        let category = serde_json::to_value(e.category)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "other".to_string());
        Self {
            binary_name: e.binary_name.clone(),
            display_name: e.display_name.clone(),
            description: e.description.clone(),
            category,
            state: state.to_string(),
            recommended: e.recommended,
            auto_installable: e.is_auto_installable(),
            uninstallable: is_uninstallable(&e.install_method),
            manual_instructions: e.manual_instructions(),
            used_by: e.used_by.clone(),
            estimated_secs: e.estimated_install_secs(),
        }
    }
}

/// Build the catalog as flat [`CatalogItem`]s, sorted by category then display
/// name, ready for the settings UI to hold in a signal.
pub async fn build_catalog_items() -> Vec<CatalogItem> {
    let mut items: Vec<CatalogItem> = build_catalog()
        .await
        .iter()
        .map(CatalogItem::from)
        .collect();
    items.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then_with(|| a.display_name.cmp(&b.display_name))
    });
    items
}

/// A single tool as shown on the read-only Tools overview page: its registered
/// name, description, and a display category. Unlike [`CatalogItem`], this
/// covers EVERY registered tool — including built-ins with no external
/// dependency (port_scan, device_info, ...) — and does not probe install state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ToolOverviewItem {
    pub name: String,
    pub description: String,
    /// Stable lowercase category key (e.g. "active_directory", "other").
    pub category: String,
}

/// Stable lowercase key for a [`ToolCategory`], matching its serde rename.
///
/// This is the single source of truth for category string keys shared by the
/// catalog and the read-only overview. It is an exhaustive match on purpose:
/// adding a `ToolCategory` variant without a key here is a compile error, so a
/// new category can never silently fall through to a wrong bucket.
fn category_key(cat: ToolCategory) -> &'static str {
    match cat {
        ToolCategory::Network => "network",
        ToolCategory::Web => "web",
        ToolCategory::WebDiscovery => "web_discovery",
        ToolCategory::Proxy => "proxy",
        ToolCategory::ActiveDirectory => "active_directory",
        ToolCategory::Credentials => "credentials",
        ToolCategory::Exploitation => "exploitation",
        ToolCategory::PostExploit => "post_exploit",
        ToolCategory::Sniffing => "sniffing",
        ToolCategory::Wireless => "wireless",
        ToolCategory::Recon => "recon",
        ToolCategory::Crypto => "crypto",
        ToolCategory::Forensics => "forensics",
        ToolCategory::Utilities => "utilities",
        ToolCategory::Other => "other",
    }
}

/// Map a tool's name + its (optional) declared category to a display category.
///
/// Tools that declare an `ExternalDependency` carry an explicit
/// [`ToolCategory`]. Built-in tools (no external dep) get a best-effort category
/// from a small name-based heuristic so the overview page can still group them
/// sensibly rather than dumping everything in "other".
fn overview_category(name: &str, declared: Option<ToolCategory>) -> &'static str {
    if let Some(cat) = declared {
        // Reuse the serde rename for a stable key. Deriving it from serde
        // (rather than a hand-written match) keeps this in lockstep with the
        // enum: new `ToolCategory` variants are covered automatically and can
        // never silently fall through.
        return category_key(cat);
    }
    // Heuristic for built-ins with no declared category.
    match name {
        "port_scan" | "network_discover" | "ssdp_discover" | "arp_table" => "network",
        "wifi_scan" | "wifi_scan_detailed" => "wireless",
        "device_info" | "screenshot" | "execute_command" | "safety_check" => "system",
        "list_files" | "read_file" | "write_file" | "session_export" => "files",
        "web_vuln_scan" => "web",
        "smb_enum" => "active_directory",
        "cve_lookup" | "default_creds" | "service_banner" => "recon",
        _ => "other",
    }
}

/// Build the read-only tools overview: registered tools with a display
/// category, sorted by (category, name). Drives the Tools page so it always
/// reflects the live registry instead of a hand-maintained list.
pub fn tools_overview() -> Vec<ToolOverviewItem> {
    tools_overview_for(pentest_core::tools::Platform::current())
}

/// Platform-parameterized core of [`tools_overview`] (kept separate so the
/// filtering is testable off-target).
///
/// On iOS the app sandbox can't run most tools, so surface only those that
/// declare `Platform::Ios` support — otherwise the agent/UI would advertise
/// capabilities that only fail at runtime. Every other platform keeps the full
/// unfiltered list: their `supported_platforms` sets aren't audited tightly
/// enough to gate on yet (e.g. Android runs many external tools via proot that
/// don't list `Android`), so this stays a no-op off iOS.
fn tools_overview_for(platform: pentest_core::tools::Platform) -> Vec<ToolOverviewItem> {
    use pentest_core::tools::Platform;
    let registry = crate::create_tool_registry();
    // On iOS, gate on the trait-level supported_platforms (via the registry);
    // everywhere else keep the full unfiltered list.
    let schemas = if platform == Platform::Ios {
        registry.schemas_for_platform(Platform::Ios)
    } else {
        registry.schemas()
    };
    let mut items: Vec<ToolOverviewItem> = schemas
        .into_iter()
        .map(|schema| {
            let declared = schema.external_dependencies.first().map(|d| d.category);
            ToolOverviewItem {
                category: overview_category(&schema.name, declared).to_string(),
                name: schema.name,
                description: schema.description,
            }
        })
        .collect();
    items.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then_with(|| a.name.cmp(&b.name))
    });
    items
}

/// Distinct categories present in [`tools_overview`], in display order.
pub fn tools_overview_categories(items: &[ToolOverviewItem]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for item in items {
        if !seen.iter().any(|c| c == &item.category) {
            seen.push(item.category.clone());
        }
    }
    seen
}

/// Install a single catalog entry identified by its `binary_name`, emitting
/// progress through `progress`. Rebuilds the catalog to resolve the entry so
/// callers (e.g. the UI) only need to pass a string. Errors if no such entry
/// exists or the entry is manual-only.
///
/// Note: this intentionally does NOT gate on `recommended`. `recommended=false`
/// only excludes a tool from the bulk [`install_all_recommended`] sweep; an
/// explicit, operator-initiated install (a per-tool "Install" button) is always
/// honored — that is the deliberate way to opt into heavyweight/dual-use tools
/// like Metasploit.
pub async fn install_by_binary(binary_name: &str, progress: &ProgressSink) -> Result<()> {
    let catalog = build_catalog().await;
    let entry = catalog
        .iter()
        .find(|e| e.binary_name == binary_name)
        .ok_or_else(|| Error::ToolExecution(format!("Unknown tool '{binary_name}'")))?;
    install_entry(entry, progress).await
}

/// Whether a catalog entry can be uninstalled from the UI in the current mode.
///
/// Mirrors [`CatalogEntry::is_auto_installable`]: we only offer removal for
/// mechanisms we can actually drive here.
/// - `Pacman`: only inside the sandbox (that's where the package lives).
/// - `AptHost`: only in native mode (the host's package manager).
/// - `Custom`: never (bespoke installers have no standard teardown; a future
///   `ToolInstaller::uninstall` could enable this per-installer).
/// - `Manual`: never (we didn't install it, so we won't remove it).
pub fn is_uninstallable(method: &InstallMethod) -> bool {
    match method {
        InstallMethod::Pacman => sandbox_enabled(),
        InstallMethod::AptHost => !sandbox_enabled(),
        InstallMethod::Custom { .. } | InstallMethod::Manual { .. } => false,
    }
}

/// Remove a single catalog entry, routing by its install method. Emits progress
/// through `progress`. Refuses methods that [`is_uninstallable`] rejects rather
/// than attempting a removal it cannot safely perform.
pub async fn uninstall_entry(entry: &CatalogEntry, progress: &ProgressSink) -> Result<()> {
    if !is_uninstallable(&entry.install_method) {
        return Err(Error::ToolExecution(format!(
            "{} cannot be uninstalled from here.",
            entry.display_name
        )));
    }
    match &entry.install_method {
        InstallMethod::Pacman => uninstall_pacman(entry, progress).await,
        InstallMethod::AptHost => uninstall_apt_host(entry, progress).await,
        // Guarded by is_uninstallable above; unreachable in practice.
        InstallMethod::Custom { .. } | InstallMethod::Manual { .. } => Err(Error::ToolExecution(
            format!("{} cannot be uninstalled from here.", entry.display_name),
        )),
    }
}

/// Remove a Pacman entry from the sandbox via `pacman -Rns`.
async fn uninstall_pacman(entry: &CatalogEntry, progress: &ProgressSink) -> Result<()> {
    progress(InstallEvent::step(format!(
        "Removing {} via pacman...",
        entry.display_name
    )));
    let pkg = pacman_package_for(&entry.binary_name).unwrap_or_else(|| entry.binary_name.clone());
    validate_package_name(&pkg)?;
    crate::installers::pacman::uninstall(&pkg, Duration::from_secs(300)).await?;
    progress(InstallEvent::step(format!(
        "{} removed",
        entry.display_name
    )));
    Ok(())
}

/// Remove an apt-host entry (native mode) via `apt-get remove`.
async fn uninstall_apt_host(entry: &CatalogEntry, progress: &ProgressSink) -> Result<()> {
    progress(InstallEvent::step(format!(
        "Removing {} via apt-get...",
        entry.display_name
    )));
    let platform = get_platform();
    let pkg = entry.binary_name.clone();
    validate_package_name(&pkg)?;
    let result = platform
        .execute_command("apt-get", &["remove", "-y", &pkg], Duration::from_secs(300))
        .await?;
    if result.exit_code != 0 {
        return Err(Error::ToolExecution(format!(
            "Failed to apt-get remove {pkg}: {}",
            result.stderr
        )));
    }
    progress(InstallEvent::step(format!(
        "{} removed",
        entry.display_name
    )));
    Ok(())
}

/// Uninstall the catalog entry keyed by `binary_name`. UI entrypoint mirroring
/// [`install_by_binary`].
pub async fn uninstall_by_binary(binary_name: &str, progress: &ProgressSink) -> Result<()> {
    let catalog = build_catalog().await;
    let entry = catalog
        .iter()
        .find(|e| e.binary_name == binary_name)
        .ok_or_else(|| Error::ToolExecution(format!("Unknown tool '{binary_name}'")))?;
    uninstall_entry(entry, progress).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_dependencies_dedupes_by_binary() {
        let deps = collect_dependencies();
        // The registry has many tools; the deduped map must have no duplicate
        // keys by construction, and must be non-empty (nmap et al. declare deps).
        assert!(
            !deps.is_empty(),
            "expected external dependencies in registry"
        );
        // nmap is a known dependency.
        assert!(
            deps.contains_key("nmap"),
            "nmap dependency should be present"
        );
        // Every value's stored dependency binary matches its key.
        for (binary, (dep, used_by)) in &deps {
            assert_eq!(binary, &dep.binary_name);
            assert!(
                !used_by.is_empty(),
                "{binary} should have at least one user"
            );
        }
    }

    #[test]
    fn pacman_package_lookup_resolves_nmap() {
        assert_eq!(pacman_package_for("nmap").as_deref(), Some("nmap"));
        assert_eq!(pacman_package_for("does-not-exist"), None);
    }

    #[test]
    fn validate_package_name_accepts_real_names_rejects_metacharacters() {
        for ok in [
            "nmap",
            "python-bloodhound",
            "zaproxy",
            "metasploit",
            "lib32-glibc",
        ] {
            assert!(validate_package_name(ok).is_ok(), "should accept {ok}");
        }
        for bad in [
            "pkg; rm -rf /",
            "a b",
            "$(id)",
            "",
            "pkg|nc",
            "../evil",
            // Flag injection: a leading dash would be read as a pacman/apt-get
            // option, not a package (e.g. -Syu, --purge). Must be rejected.
            "-Syu",
            "--purge",
        ] {
            assert!(validate_package_name(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn all_registry_package_names_pass_validation() {
        // Guard: every package name declared in the live registry must satisfy
        // the installer's package-name validator, or a real install would fail
        // the safety check.
        for (_binary, (dep, _)) in collect_dependencies() {
            assert!(
                validate_package_name(&dep.package_name).is_ok(),
                "registry package name failed validation: {:?}",
                dep.package_name
            );
        }
    }

    #[tokio::test]
    async fn build_catalog_produces_entries_with_used_by() {
        // Probe install-state on the host, not the sandbox. build_catalog runs
        // `command -v` per tool via execute_command; with the sandbox enabled
        // and no system proot, that triggers a proot download + rootfs setup
        // that hangs on a CI runner (no backend, no rootfs). The host probe is
        // equally valid for the catalog-shape assertions here.
        pentest_platform::set_use_sandbox(false);
        let catalog = build_catalog().await;
        assert!(!catalog.is_empty());
        let nmap = catalog.iter().find(|e| e.binary_name == "nmap");
        assert!(nmap.is_some(), "nmap should be in the catalog");
        let nmap = nmap.unwrap();
        assert!(!nmap.used_by.is_empty());
        assert_eq!(nmap.category, ToolCategory::Network);
    }

    #[tokio::test]
    async fn manual_entry_is_never_auto_installable() {
        // Construct a synthetic manual entry to exercise the routing guard.
        let entry = CatalogEntry {
            binary_name: "burpsuite".into(),
            display_name: "Burp Suite".into(),
            description: "proxy".into(),
            category: ToolCategory::Web,
            install_method: InstallMethod::Manual {
                url: None,
                instructions: "install manually".into(),
            },
            recommended: false,
            used_by: vec![],
            state: InstallState::Manual,
        };
        assert!(!entry.is_auto_installable());
        let progress = crate::installers::noop_progress();
        let result = install_entry(&entry, progress.as_ref()).await;
        assert!(result.is_err(), "manual entries must not auto-install");
        assert!(entry.manual_instructions().unwrap().contains("manually"));
    }

    #[tokio::test]
    async fn manual_and_custom_entries_are_never_uninstallable() {
        // We never installed Manual tools (Burp) and have no standard teardown
        // for Custom installers, so the UI must not offer to remove them.
        assert!(!is_uninstallable(&InstallMethod::Manual {
            url: None,
            instructions: "x".into(),
        }));
        assert!(!is_uninstallable(&InstallMethod::Custom {
            id: "zap".into()
        }));

        // uninstall_entry must refuse a Manual entry rather than shell out.
        let entry = CatalogEntry {
            binary_name: "burpsuite".into(),
            display_name: "Burp Suite".into(),
            description: "proxy".into(),
            category: ToolCategory::Proxy,
            install_method: InstallMethod::Manual {
                url: None,
                instructions: "install manually".into(),
            },
            recommended: false,
            used_by: vec![],
            state: InstallState::Installed,
        };
        let progress = crate::installers::noop_progress();
        let result = uninstall_entry(&entry, progress.as_ref()).await;
        assert!(result.is_err(), "manual entries must not be uninstalled");
    }

    #[test]
    fn catalog_item_maps_state_and_category_to_strings() {
        // Use webwright — the one custom installer that is NOT sandbox-required
        // and should therefore be auto-installable in any sandbox state.
        let entry = CatalogEntry {
            binary_name: "webwright".into(),
            display_name: "Webwright".into(),
            description: "browser automation".into(),
            category: ToolCategory::Web,
            install_method: InstallMethod::Custom {
                id: "webwright".into(),
            },
            recommended: true,
            used_by: vec!["webwright".into()],
            state: InstallState::Missing,
        };
        let item = CatalogItem::from(&entry);
        assert_eq!(item.category, "web");
        assert_eq!(item.state, "missing");
        assert!(
            item.auto_installable,
            "webwright must be auto-installable (not sandbox-required)"
        );
        assert_eq!(item.binary_name, "webwright");
    }

    #[test]
    fn catalog_item_round_trips_through_json() {
        let item = CatalogItem {
            binary_name: "zaproxy".into(),
            display_name: "OWASP ZAP".into(),
            description: "dast".into(),
            category: "web".into(),
            state: "installed".into(),
            recommended: true,
            auto_installable: true,
            uninstallable: false,
            manual_instructions: None,
            used_by: vec!["zap".into()],
            estimated_secs: 150,
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: CatalogItem = serde_json::from_str(&json).unwrap();
        assert_eq!(item, back);
    }

    #[test]
    fn tools_overview_covers_whole_registry_and_is_sorted() {
        let overview = tools_overview();
        let registry_count = crate::create_tool_registry().names().len();
        // Every registered tool appears exactly once.
        assert_eq!(
            overview.len(),
            registry_count,
            "overview must include every registered tool"
        );
        // Includes both a built-in (no external dep) and an external tool.
        assert!(overview.iter().any(|t| t.name == "port_scan"));
        assert!(overview.iter().any(|t| t.name == "nmap"));
        assert!(overview.iter().any(|t| t.name == "zap"));
        // Sorted by (category, name).
        for pair in overview.windows(2) {
            assert!(
                (pair[0].category.as_str(), pair[0].name.as_str())
                    <= (pair[1].category.as_str(), pair[1].name.as_str()),
                "overview must be sorted by (category, name)"
            );
        }
    }

    #[test]
    fn ios_overview_keeps_only_ios_native_tools() {
        use pentest_core::tools::Platform;
        let ios = tools_overview_for(Platform::Ios);
        let desktop = tools_overview_for(Platform::Desktop);
        let names: Vec<&str> = ios.iter().map(|t| t.name.as_str()).collect();

        // Native / in-process tools survive on iOS. ARP, SSDP and mDNS
        // discovery are native on iOS (BSD route-socket sysctl + outbound UDP
        // multicast with the local-network entitlement).
        for t in [
            "port_scan",
            "cyberchef",
            "device_info",
            "read_file",
            "write_file",
            "list_files",
            "safety_check",
            "arp_table",
            "ssdp_discover",
            "network_discover",
        ] {
            assert!(names.contains(&t), "iOS overview should include {t}");
        }
        // Sandbox-blocked tools are filtered out on iOS.
        for t in [
            "nmap",
            "wifi_scan",
            "execute_command",
            "traffic_capture",
            "screenshot",
        ] {
            assert!(!names.contains(&t), "iOS overview must not include {t}");
        }
        // Desktop is unchanged (full unfiltered list), and iOS is a strict subset.
        assert_eq!(
            desktop.len(),
            tools_overview().len(),
            "desktop must be a no-op"
        );
        assert!(
            ios.len() < desktop.len(),
            "iOS list must be smaller than desktop"
        );
    }

    #[test]
    fn overview_category_uses_declared_then_heuristic() {
        // Declared category wins.
        assert_eq!(
            overview_category("nxc", Some(ToolCategory::ActiveDirectory)),
            "active_directory"
        );
        // Built-in heuristic for a tool with no declared category.
        assert_eq!(overview_category("port_scan", None), "network");
        assert_eq!(overview_category("read_file", None), "files");
        // Unknown built-in falls back to "other".
        assert_eq!(overview_category("some_new_builtin", None), "other");
    }

    #[test]
    fn category_key_covers_new_taxonomy_variants() {
        // The curated taxonomy keys must match the enum's serde rename so the
        // UI's humanize_category lookups line up.
        assert_eq!(category_key(ToolCategory::WebDiscovery), "web_discovery");
        assert_eq!(category_key(ToolCategory::Proxy), "proxy");
        assert_eq!(category_key(ToolCategory::Exploitation), "exploitation");
        assert_eq!(category_key(ToolCategory::Sniffing), "sniffing");
        assert_eq!(category_key(ToolCategory::Crypto), "crypto");
        assert_eq!(category_key(ToolCategory::Utilities), "utilities");
    }

    #[tokio::test]
    async fn runtime_dep_binaries_are_hidden_from_catalog() {
        // python3 / playwright are install prerequisites, not operator-facing
        // tools; they must not appear as catalog entries even though tools
        // (webwright) declare them as dependencies.
        // Host probe: avoid the sandbox proot-download hang on CI (see
        // build_catalog_produces_entries_with_used_by).
        pentest_platform::set_use_sandbox(false);
        let catalog = build_catalog().await;
        for hidden in HIDDEN_CATALOG_BINARIES {
            assert!(
                !catalog.iter().any(|e| &e.binary_name == hidden),
                "{hidden} should be hidden from the catalog"
            );
        }
    }

    #[tokio::test]
    async fn pending_installs_in_category_scopes_to_that_category() {
        // Every entry the "network" install-all would touch must actually be a
        // network-category, not-installed, auto-installable tool — the exact
        // set install_all_in_category will act on. Guards against a filter that
        // leaks other categories (or already-installed tools) into a bulk
        // install. The set can legitimately be empty (e.g. everything already
        // installed, or nothing auto-installable in native mode), so we assert
        // the scoping property, not a fixed count.
        // Host probe: avoid the sandbox proot-download hang on CI (see
        // build_catalog_produces_entries_with_used_by).
        pentest_platform::set_use_sandbox(false);
        let full = build_catalog().await;
        let pending = pending_installs_in_category("network").await;
        for (bin, _secs) in &pending {
            let entry = full
                .iter()
                .find(|e| &e.binary_name == bin)
                .unwrap_or_else(|| panic!("{bin} not in catalog"));
            assert_eq!(category_key(entry.category), "network", "{bin} not network");
            assert_ne!(
                entry.state,
                InstallState::Installed,
                "{bin} already installed"
            );
            assert!(entry.is_auto_installable(), "{bin} not auto-installable");
        }
        // A category with no matching tools yields an empty set (not an error).
        assert!(pending_installs_in_category("no_such_category")
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn install_entries_aggregates_per_entry_failures() {
        // The shared bulk-install loop (used by both install_all_recommended
        // and install_all_in_category) must collect a (binary, error) entry for
        // each failure and skip the rest silently. A Manual entry fails
        // deterministically in install_entry without shelling out, so it's the
        // stable way to exercise the failure-aggregation offline.
        let progress = crate::installers::noop_progress();

        // Empty input -> no failures.
        assert!(install_entries(&[], progress.as_ref()).await.is_empty());

        // One Manual entry -> exactly one failure, keyed by its binary name.
        let manual = CatalogEntry {
            binary_name: "burpsuite".into(),
            display_name: "Burp Suite".into(),
            description: "proxy".into(),
            category: ToolCategory::Proxy,
            install_method: InstallMethod::Manual {
                url: None,
                instructions: "install manually".into(),
            },
            recommended: false,
            used_by: vec![],
            state: InstallState::Manual,
        };
        let failures = install_entries(std::slice::from_ref(&manual), progress.as_ref()).await;
        assert_eq!(
            failures.len(),
            1,
            "manual entry must be reported as a failure"
        );
        assert_eq!(failures[0].0, "burpsuite", "failure keyed by binary name");
        assert!(
            !failures[0].1.is_empty(),
            "failure must carry a non-empty error message"
        );
    }

    #[test]
    fn tools_overview_categories_are_distinct_and_ordered() {
        let overview = tools_overview();
        let cats = tools_overview_categories(&overview);
        let mut deduped = cats.clone();
        deduped.dedup();
        assert_eq!(cats.len(), deduped.len(), "categories must be distinct");
        assert!(cats.iter().any(|c| c == "active_directory"));
    }

    #[test]
    fn estimated_secs_defaults_by_method_and_overrides_by_binary() {
        // Mechanism defaults.
        assert_eq!(
            estimated_install_secs(&InstallMethod::Pacman, "nmap"),
            90,
            "pacman default"
        );
        assert_eq!(
            estimated_install_secs(&InstallMethod::AptHost, "some-apt-tool"),
            60,
            "apt default"
        );
        assert_eq!(
            estimated_install_secs(
                &InstallMethod::Custom {
                    id: "certipy".into()
                },
                "certipy"
            ),
            120,
            "custom default"
        );
        // Manual has no automated timer.
        assert_eq!(
            estimated_install_secs(
                &InstallMethod::Manual {
                    url: None,
                    instructions: "x".into()
                },
                "burpsuite"
            ),
            0,
            "manual = 0"
        );
        // Heavyweight per-binary overrides beat the mechanism default.
        assert_eq!(
            estimated_install_secs(
                &InstallMethod::Custom {
                    id: "metasploit".into()
                },
                "msfconsole"
            ),
            360,
            "metasploit override"
        );
        assert_eq!(
            estimated_install_secs(
                &InstallMethod::Custom {
                    id: "webwright".into()
                },
                "webwright"
            ),
            180,
            "webwright override (Python env + Playwright Chromium download)"
        );
        assert!(
            estimated_install_secs(&InstallMethod::Custom { id: "zap".into() }, "zaproxy")
                > estimated_install_secs(&InstallMethod::Pacman, "nmap"),
            "zap should estimate longer than a plain pacman package"
        );
    }

    #[tokio::test]
    async fn ad_suite_is_not_in_recommended_default_set() {
        // Specialized AD-engagement tooling must not be swept in by the bulk
        // "install all recommended" action (the operator installs it on demand).
        // Host probe: avoid the sandbox proot-download hang on CI (see
        // build_catalog_produces_entries_with_used_by).
        pentest_platform::set_use_sandbox(false);
        let catalog = build_catalog().await;
        for bin in ["bloodhound-python", "certipy", "kerbrute", "nxc"] {
            // Assert the entry EXISTS before checking its flag: without this the
            // test would pass vacuously if a rename/refactor dropped the binary
            // from the catalog, silently retiring the regression guard.
            let entry = catalog
                .iter()
                .find(|e| e.binary_name == bin)
                .unwrap_or_else(|| panic!("{bin} should be present in the catalog"));
            assert!(
                !entry.recommended,
                "{bin} must be opt-in, not part of the recommended default set"
            );
        }
    }

    #[tokio::test]
    async fn build_catalog_items_is_sorted_and_nonempty() {
        // Host probe: avoid the sandbox proot-download hang on CI (see
        // build_catalog_produces_entries_with_used_by).
        pentest_platform::set_use_sandbox(false);
        let items = build_catalog_items().await;
        assert!(!items.is_empty());
        // Sorted by (category, display_name).
        for pair in items.windows(2) {
            let a = &pair[0];
            let b = &pair[1];
            assert!(
                (a.category.as_str(), a.display_name.as_str())
                    <= (b.category.as_str(), b.display_name.as_str()),
                "catalog items must be sorted"
            );
        }
    }
}

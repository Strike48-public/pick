//! Tool trait definitions and schemas

use crate::error::Result;
use crate::provenance::Provenance;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Platform identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Platform {
    Desktop,
    Web,
    Android,
    Ios,
    Tui,
}

/// Default platforms supported by most tools (all except Web).
pub const DEFAULT_TOOL_PLATFORMS: &[Platform] = &[
    Platform::Desktop,
    Platform::Android,
    Platform::Ios,
    Platform::Tui,
];

impl Platform {
    /// Get the current platform
    #[cfg(target_arch = "wasm32")]
    pub fn current() -> Self {
        Platform::Web
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        not(target_os = "android"),
        not(target_os = "ios")
    ))]
    pub fn current() -> Self {
        Platform::Desktop
    }

    #[cfg(target_os = "android")]
    pub fn current() -> Self {
        Platform::Android
    }

    #[cfg(target_os = "ios")]
    pub fn current() -> Self {
        Platform::Ios
    }
}

/// Desktop operating system, used for per-OS capability gating.
///
/// `Platform::Desktop` deliberately collapses every desktop OS into one
/// variant so tools do not have to enumerate three OSes just to say
/// "runs on the desktop." `DesktopOs` is the orthogonal axis that lets a
/// tool declare it only works on a subset of desktop OSes (e.g. Linux-only
/// tools that shell out to `iw`/`aircrack-ng`). See GitHub issue #183.
///
/// The `Other` variant covers desktop targets that are neither Linux, macOS,
/// nor Windows (e.g. the BSDs). It is treated as Linux-like for capability
/// purposes since those tools are POSIX shell based.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DesktopOs {
    Linux,
    MacOS,
    Windows,
    Other,
}

/// Every desktop OS. This is the default `supported_os` for a tool: unless a
/// tool opts into a narrower set, it is assumed to run on all desktop OSes,
/// which preserves the historical "everything is `Platform::Desktop`" behavior.
pub const ALL_DESKTOP_OS: &[DesktopOs] = &[
    DesktopOs::Linux,
    DesktopOs::MacOS,
    DesktopOs::Windows,
    DesktopOs::Other,
];

impl DesktopOs {
    /// The desktop OS this binary was compiled for.
    ///
    /// Returns `None` on non-desktop targets (wasm/Android/iOS), where the
    /// desktop-OS axis is not meaningful and gating is driven by `Platform`.
    pub fn current() -> Option<Self> {
        #[cfg(any(target_arch = "wasm32", target_os = "android", target_os = "ios"))]
        {
            None
        }

        #[cfg(not(any(target_arch = "wasm32", target_os = "android", target_os = "ios")))]
        {
            #[cfg(target_os = "linux")]
            {
                Some(DesktopOs::Linux)
            }
            #[cfg(target_os = "macos")]
            {
                Some(DesktopOs::MacOS)
            }
            #[cfg(target_os = "windows")]
            {
                Some(DesktopOs::Windows)
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            {
                Some(DesktopOs::Other)
            }
        }
    }
}

/// Parameter type for tool schemas
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
}

/// Parameter definition for a tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolParam {
    pub name: String,
    pub param_type: ParamType,
    pub description: String,
    pub required: bool,
    pub default: Option<Value>,
}

impl ToolParam {
    /// Create a new required parameter
    pub fn required(
        name: impl Into<String>,
        param_type: ParamType,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            param_type,
            description: description.into(),
            required: true,
            default: None,
        }
    }

    /// Create a new optional parameter with default
    pub fn optional(
        name: impl Into<String>,
        param_type: ParamType,
        description: impl Into<String>,
        default: Value,
    ) -> Self {
        Self {
            name: name.into(),
            param_type,
            description: description.into(),
            required: false,
            default: Some(default),
        }
    }
}

/// How an external dependency is installed on the host or in the sandbox.
///
/// The default (`Pacman`) preserves the historical behavior: every tool that
/// only called [`ExternalDependency::new`] installs via `pacman` inside the
/// BlackArch sandbox and is expected on the host PATH in native mode. Tools
/// that need a different mechanism (pip/uv, a vendor installer, or a
/// license-gated download) opt into it with the builder methods below.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InstallMethod {
    /// Install from the BlackArch/Arch repos via `pacman -S` (sandbox only).
    /// The package name is [`ExternalDependency::package_name`].
    #[default]
    Pacman,
    /// Install on the host via `apt-get install <pkg>` when sandbox is disabled.
    /// Used for tools that are not BlackArch packages but are apt-installable.
    AptHost,
    /// A bespoke installer keyed by `id`, dispatched through the installer
    /// registry (e.g. "webwright", "metasploit", "zap"). Use for anything that
    /// is not a single repo package — pip/uv installs, multi-step setups,
    /// services that need initialization.
    Custom { id: String },
    /// Cannot be auto-installed (licensing, EULA click-through, or operator
    /// choice). The UI shows `instructions` and an optional download `url`;
    /// no automated install is attempted. Burp Suite is the canonical example.
    Manual {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        instructions: String,
    },
}

/// Broad grouping used to organize tools in the catalog UI. Free-form-ish but
/// kept as an enum so the UI can render stable section headers and so we don't
/// accumulate typo'd category strings across ~80 tools.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    /// Host/port/service discovery and network mapping.
    Network,
    /// Web application scanning and fuzzing.
    Web,
    /// Active Directory, SMB, Kerberos, LDAP.
    ActiveDirectory,
    /// Credential attacks: cracking, spraying, dumping.
    Credentials,
    /// Post-exploitation, C2, lateral movement, payload generation.
    PostExploit,
    /// Wireless.
    Wireless,
    /// OSINT and reconnaissance.
    Recon,
    /// Forensics and evidence handling.
    Forensics,
    /// Anything that doesn't fit a more specific group.
    #[default]
    Other,
}

/// External dependency information for tools that require installation.
///
/// The first three fields are the historical contract used by every external
/// tool. `install_method`, `category`, and `recommended` were added for the
/// tool catalog (issue: unified installer) and all default such that the ~80
/// existing `ExternalDependency::new(...)` call sites keep their original
/// pacman-in-sandbox behavior with zero changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalDependency {
    pub binary_name: String,
    pub package_name: String,
    pub description: String,
    /// How to install this dependency. Defaults to [`InstallMethod::Pacman`].
    #[serde(default)]
    pub install_method: InstallMethod,
    /// Catalog grouping for the UI. Defaults to [`ToolCategory::Other`].
    #[serde(default)]
    pub category: ToolCategory,
    /// Whether this tool is part of the default "install all recommended" set.
    /// Dual-use / heavyweight / licensed tools set this to `false` so they are
    /// only installed on explicit operator action.
    #[serde(default = "default_recommended")]
    pub recommended: bool,
}

/// Default for [`ExternalDependency::recommended`]: standard tooling is
/// recommended unless a tool explicitly opts out (C2, licensed, very large).
fn default_recommended() -> bool {
    true
}

impl ExternalDependency {
    /// Create a dependency installed via `pacman` in the sandbox (the default
    /// for the vast majority of BlackArch-packaged tools). This is the
    /// historical constructor — its three-argument shape is unchanged.
    pub fn new(
        binary_name: impl Into<String>,
        package_name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            binary_name: binary_name.into(),
            package_name: package_name.into(),
            description: description.into(),
            install_method: InstallMethod::default(),
            category: ToolCategory::default(),
            recommended: true,
        }
    }

    /// Set an explicit install method (builder).
    pub fn install_method(mut self, method: InstallMethod) -> Self {
        self.install_method = method;
        self
    }

    /// Mark this dependency as installed by a bespoke installer registered
    /// under `id` (shorthand for `.install_method(InstallMethod::Custom{id})`).
    pub fn custom_installer(mut self, id: impl Into<String>) -> Self {
        self.install_method = InstallMethod::Custom { id: id.into() };
        self
    }

    /// Mark this dependency as manual-install only (licensing / EULA / operator
    /// choice). `instructions` is shown verbatim in the catalog UI.
    pub fn manual(mut self, instructions: impl Into<String>, url: Option<String>) -> Self {
        self.install_method = InstallMethod::Manual {
            url,
            instructions: instructions.into(),
        };
        self
    }

    /// Set the catalog category (builder).
    pub fn category(mut self, category: ToolCategory) -> Self {
        self.category = category;
        self
    }

    /// Set whether this tool is part of the recommended default set (builder).
    pub fn recommended(mut self, recommended: bool) -> Self {
        self.recommended = recommended;
        self
    }
}

/// Schema for a pentest tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub params: Vec<ToolParam>,
    pub supported_platforms: Vec<Platform>,
    /// Desktop OSes this tool runs on. Only consulted when the current
    /// platform is `Platform::Desktop`; ignored on Android/iOS/Web where the
    /// `Platform` axis already gates support. Defaults to every desktop OS so
    /// existing tools keep advertising everywhere they did before. See #183.
    #[serde(default = "default_supported_os")]
    pub supported_os: Vec<DesktopOs>,
    #[serde(default)]
    pub external_dependencies: Vec<ExternalDependency>,
}

/// Serde default for [`ToolSchema::supported_os`] — every desktop OS.
fn default_supported_os() -> Vec<DesktopOs> {
    ALL_DESKTOP_OS.to_vec()
}

impl ToolSchema {
    /// Create a new tool schema
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            params: Vec::new(),
            supported_platforms: DEFAULT_TOOL_PLATFORMS.to_vec(),
            supported_os: ALL_DESKTOP_OS.to_vec(),
            external_dependencies: Vec::new(),
        }
    }

    /// Add a parameter
    pub fn param(mut self, param: ToolParam) -> Self {
        self.params.push(param);
        self
    }

    /// Set supported platforms
    pub fn platforms(mut self, platforms: Vec<Platform>) -> Self {
        self.supported_platforms = platforms;
        self
    }

    /// Restrict the desktop OSes this tool runs on (e.g. `[DesktopOs::Linux]`
    /// for tools that shell out to Linux-only binaries). See #183.
    pub fn os(mut self, os: Vec<DesktopOs>) -> Self {
        self.supported_os = os;
        self
    }

    /// Add an external dependency
    pub fn external_dependency(mut self, dep: ExternalDependency) -> Self {
        self.external_dependencies.push(dep);
        self
    }

    /// Check if supported on the current platform *and* desktop OS.
    ///
    /// On desktop, a tool is supported only if the current `DesktopOs` is in
    /// its `supported_os` set. On non-desktop platforms the OS axis does not
    /// apply, so only `supported_platforms` is consulted.
    pub fn is_supported(&self) -> bool {
        if !self.supported_platforms.contains(&Platform::current()) {
            return false;
        }
        match DesktopOs::current() {
            Some(os) => self.supported_os.contains(&os),
            None => true,
        }
    }

    /// Check if this tool has external dependencies
    pub fn has_external_dependencies(&self) -> bool {
        !self.external_dependencies.is_empty()
    }

    /// Convert to JSON schema format (for Strike48 SDK)
    pub fn to_json_schema(&self) -> Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        for param in &self.params {
            let type_str = match param.param_type {
                ParamType::String => "string",
                ParamType::Number => "number",
                ParamType::Integer => "integer",
                ParamType::Boolean => "boolean",
                ParamType::Array => "array",
                ParamType::Object => "object",
            };

            let mut prop = serde_json::json!({
                "type": type_str,
                "description": param.description
            });

            if let Some(default) = &param.default {
                prop["default"] = default.clone();
            }

            properties.insert(param.name.clone(), prop);

            if param.required {
                required.push(Value::String(param.name.clone()));
            }
        }

        let mut schema = serde_json::json!({
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        });

        if !self.external_dependencies.is_empty() {
            schema["external_dependencies"] =
                serde_json::to_value(&self.external_dependencies).unwrap();
        }

        schema
    }
}

/// Result from a tool execution.
///
/// `provenance` is `Option` because not every tool produces a finding —
/// utilities like `device_info` or `list_files` have nothing to reproduce.
/// Tools that produce findings (scanners, probes, exploits) must attach a
/// `Provenance` so the Report Agent can render a reproducible evidence
/// block. See [`crate::provenance`] and GitHub issue #52.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub success: bool,
    pub data: Value,
    pub error: Option<String>,
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
}

impl ToolResult {
    /// Create a successful result
    pub fn success(data: Value) -> Self {
        Self {
            success: true,
            data,
            error: None,
            duration_ms: 0,
            provenance: None,
        }
    }

    /// Create a successful result with duration
    pub fn success_with_duration(data: Value, duration_ms: u64) -> Self {
        Self {
            success: true,
            data,
            error: None,
            duration_ms,
            provenance: None,
        }
    }

    /// Create an error result
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: Value::Null,
            error: Some(message.into()),
            duration_ms: 0,
            provenance: None,
        }
    }

    /// Create an error result with duration
    pub fn error_with_duration(message: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            success: false,
            data: Value::Null,
            error: Some(message.into()),
            duration_ms,
            provenance: None,
        }
    }

    /// Attach provenance to this result. Finding-producing tools must call
    /// this before returning.
    pub fn with_provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = Some(provenance);
        self
    }
}

/// Execute an async tool body, automatically timing the execution and wrapping
/// the result in a `ToolResult` with the elapsed duration.
pub async fn execute_timed<F, Fut>(f: F) -> Result<ToolResult>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<serde_json::Value, crate::error::Error>>,
{
    let start = std::time::Instant::now();
    match f().await {
        Ok(data) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            Ok(ToolResult::success_with_duration(data, duration_ms))
        }
        Err(e) => Ok(ToolResult::error(e.to_string())),
    }
}

/// Like [`execute_timed`], but the tool body also returns `Provenance` so
/// finding-producing tools can attach reproducibility metadata.
pub async fn execute_timed_with_provenance<F, Fut>(f: F) -> Result<ToolResult>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<
        Output = std::result::Result<(serde_json::Value, Provenance), crate::error::Error>,
    >,
{
    let start = std::time::Instant::now();
    match f().await {
        Ok((data, provenance)) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            Ok(ToolResult::success_with_duration(data, duration_ms).with_provenance(provenance))
        }
        Err(e) => Ok(ToolResult::error(e.to_string())),
    }
}

/// Context provided to tool execution
#[derive(Clone)]
pub struct ToolContext {
    pub platform: Platform,
    pub metadata: HashMap<String, String>,
    pub workspace_path: Option<PathBuf>,

    /// Matrix chat client for spawning specialist agents.
    /// Available when the connector is connected to Strike48.
    matrix_client: Option<Arc<crate::matrix::MatrixChatClient>>,

    /// Aggression level controlling specialist spawning behavior.
    aggression_level: crate::aggression::AggressionLevel,

    /// Name of the parent agent executing tools (e.g., "pentest-connector-red-team").
    /// Used by spawn_specialist to name spawned agents.
    agent_name: String,
}

impl std::fmt::Debug for ToolContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolContext")
            .field("platform", &self.platform)
            .field("metadata", &self.metadata)
            .field("workspace_path", &self.workspace_path)
            .field("has_matrix_client", &self.matrix_client.is_some())
            .field("aggression_level", &self.aggression_level)
            .field("agent_name", &self.agent_name)
            .finish()
    }
}

impl Default for ToolContext {
    fn default() -> Self {
        Self {
            platform: Platform::current(),
            metadata: HashMap::new(),
            workspace_path: None,
            matrix_client: None,
            aggression_level: crate::aggression::AggressionLevel::default(),
            agent_name: "pentest-connector".to_string(),
        }
    }
}

impl ToolContext {
    /// Set the workspace path for this context
    pub fn with_workspace(mut self, path: PathBuf) -> Self {
        self.workspace_path = Some(path);
        self
    }

    /// Set the Matrix client for specialist spawning
    pub fn with_matrix_client(mut self, client: Arc<crate::matrix::MatrixChatClient>) -> Self {
        self.matrix_client = Some(client);
        self
    }

    /// Set the aggression level
    pub fn with_aggression_level(mut self, level: crate::aggression::AggressionLevel) -> Self {
        self.aggression_level = level;
        self
    }

    /// Set the agent name
    pub fn with_agent_name(mut self, name: impl Into<String>) -> Self {
        self.agent_name = name.into();
        self
    }

    /// Get the Matrix client if available
    pub fn matrix_client(&self) -> Option<&Arc<crate::matrix::MatrixChatClient>> {
        self.matrix_client.as_ref()
    }

    /// Get the aggression level
    pub fn aggression_level(&self) -> crate::aggression::AggressionLevel {
        self.aggression_level
    }

    /// Get the agent name
    pub fn agent_name(&self) -> &str {
        &self.agent_name
    }
}

/// Trait for pentest tools
#[async_trait]
pub trait PentestTool: Send + Sync {
    /// Get the tool name
    fn name(&self) -> &str;

    /// Get the tool description
    fn description(&self) -> &str;

    /// Get the tool schema
    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .platforms(self.supported_platforms())
            .os(self.supported_os())
    }

    /// Get supported platforms
    fn supported_platforms(&self) -> Vec<Platform> {
        DEFAULT_TOOL_PLATFORMS.to_vec()
    }

    /// Get supported desktop OSes.
    ///
    /// Defaults to every desktop OS. Tools that only work on a subset (e.g.
    /// Linux-only tools that require `iw`/`aircrack-ng`) override this to
    /// return a narrower set so they are not advertised on unsupported hosts.
    /// See GitHub issue #183.
    fn supported_os(&self) -> Vec<DesktopOs> {
        ALL_DESKTOP_OS.to_vec()
    }

    /// Check if supported on the current platform and desktop OS.
    fn is_supported(&self) -> bool {
        if !self.supported_platforms().contains(&Platform::current()) {
            return false;
        }
        match DesktopOs::current() {
            Some(os) => self.supported_os().contains(&os),
            None => true,
        }
    }

    /// Execute the tool with the given parameters
    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult>;
}

/// Type alias for a boxed tool
pub type BoxedTool = Arc<dyn PentestTool>;

/// Tool registry for managing available tools
#[derive(Default)]
pub struct ToolRegistry {
    tools: HashMap<String, BoxedTool>,
}

impl ToolRegistry {
    /// Create a new tool registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tool
    pub fn register<T: PentestTool + 'static>(&mut self, tool: T) {
        let name = tool.name().to_string();
        self.tools.insert(name, Arc::new(tool));
    }

    /// Get a tool by name
    pub fn get(&self, name: &str) -> Option<&BoxedTool> {
        self.tools.get(name)
    }

    /// Get all tools
    pub fn tools(&self) -> &HashMap<String, BoxedTool> {
        &self.tools
    }

    /// Get all tool schemas
    pub fn schemas(&self) -> Vec<ToolSchema> {
        self.tools.values().map(|t| t.schema()).collect()
    }

    /// Get schemas for tools supported on the current host (platform + desktop
    /// OS). This is what should be advertised to Strike48: a Linux-only tool
    /// must not appear in the tool list on a Windows host, otherwise the agent
    /// believes it can call a capability that will only fail (or worse, return
    /// a plausible empty) at runtime. See GitHub issue #183.
    pub fn supported_schemas(&self) -> Vec<ToolSchema> {
        self.tools
            .values()
            .filter(|t| t.is_supported())
            .map(|t| t.schema())
            .collect()
    }

    /// Get tool names
    pub fn names(&self) -> Vec<&str> {
        self.tools.keys().map(|s| s.as_str()).collect()
    }

    /// Get names of tools supported on the current host, matching
    /// [`Self::supported_schemas`]. See GitHub issue #183.
    pub fn supported_names(&self) -> Vec<&str> {
        self.tools
            .values()
            .filter(|t| t.is_supported())
            .map(|t| t.name())
            .collect()
    }

    /// Execute a tool by name
    pub async fn execute(
        &self,
        name: &str,
        params: Value,
        ctx: &ToolContext,
    ) -> Result<ToolResult> {
        match self.get(name) {
            Some(tool) => tool.execute(params, ctx).await,
            None => {
                // Find similar tool names for suggestions
                let suggestions = self.find_similar_tools(name);

                tracing::error!("✗ Tool '{}' not found in registry", name);

                if !suggestions.is_empty() {
                    tracing::error!("");
                    tracing::error!("Did you mean one of these?");
                    for suggestion in &suggestions {
                        tracing::error!("  - {}", suggestion);
                    }
                }

                tracing::error!("");
                tracing::error!("Available tools:");
                let mut names: Vec<&str> = self.names();
                names.sort();
                for tool_name in names.iter().take(10) {
                    tracing::error!("  - {}", tool_name);
                }
                if names.len() > 10 {
                    tracing::error!("  ... and {} more", names.len() - 10);
                }
                tracing::error!("");

                Err(crate::error::Error::ToolNotFound(format!(
                    "Tool '{}' not found. See logs for available tools.",
                    name
                )))
            }
        }
    }

    /// Find similar tool names using Levenshtein distance
    fn find_similar_tools(&self, name: &str) -> Vec<String> {
        let mut scored: Vec<(String, usize)> = self
            .names()
            .iter()
            .map(|&tool_name| {
                let distance = levenshtein_distance(name, tool_name);
                (tool_name.to_string(), distance)
            })
            .collect();

        // Sort by distance (lower is better)
        scored.sort_by_key(|(_, dist)| *dist);

        // Return tools with distance <= 3 (close matches)
        scored
            .into_iter()
            .filter(|(_, dist)| *dist <= 3)
            .take(5)
            .map(|(name, _)| name)
            .collect()
    }
}

/// Calculate Levenshtein distance between two strings
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let len1 = s1.len();
    let len2 = s2.len();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

    #[allow(clippy::needless_range_loop)]
    for (i, row) in matrix.iter_mut().enumerate().take(len1 + 1) {
        row[0] = i;
    }
    #[allow(clippy::needless_range_loop)]
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    for (i, c1) in s1.chars().enumerate() {
        for (j, c2) in s2.chars().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            matrix[i + 1][j + 1] = std::cmp::min(
                std::cmp::min(
                    matrix[i][j + 1] + 1, // deletion
                    matrix[i + 1][j] + 1, // insertion
                ),
                matrix[i][j] + cost, // substitution
            );
        }
    }

    matrix[len1][len2]
}

#[cfg(test)]
mod external_dependency_tests {
    //! Tests for the tool-catalog extensions to `ExternalDependency`.
    //!
    //! The central invariant is backward compatibility: ~80 existing tools
    //! construct dependencies with the three-argument `new(...)` and serialize
    //! schemas onto the Matrix wire. The new fields must default such that
    //! those tools are unaffected, and old serialized schemas (no
    //! install_method/category/recommended) must still deserialize.
    use super::*;

    #[test]
    fn new_defaults_to_pacman_recommended_other() {
        let dep = ExternalDependency::new("nmap", "nmap", "scanner");
        assert_eq!(dep.install_method, InstallMethod::Pacman);
        assert_eq!(dep.category, ToolCategory::Other);
        assert!(dep.recommended);
    }

    #[test]
    fn builders_compose() {
        let dep = ExternalDependency::new("zaproxy", "zaproxy", "DAST")
            .custom_installer("zap")
            .category(ToolCategory::Web)
            .recommended(true);
        assert_eq!(
            dep.install_method,
            InstallMethod::Custom { id: "zap".into() }
        );
        assert_eq!(dep.category, ToolCategory::Web);
    }

    #[test]
    fn manual_method_carries_instructions_and_url() {
        let dep = ExternalDependency::new("burpsuite", "burpsuite", "proxy").manual(
            "Download from PortSwigger and run the installer.",
            Some("https://portswigger.net/burp/releases".into()),
        );
        match dep.install_method {
            InstallMethod::Manual { url, instructions } => {
                assert!(instructions.contains("PortSwigger"));
                assert_eq!(
                    url.as_deref(),
                    Some("https://portswigger.net/burp/releases")
                );
            }
            other => panic!("expected Manual, got {other:?}"),
        }
    }

    #[test]
    fn old_schema_without_new_fields_still_deserializes() {
        // A schema serialized before the catalog fields existed.
        let legacy = serde_json::json!({
            "binary_name": "ffuf",
            "package_name": "ffuf",
            "description": "web fuzzer"
        });
        let dep: ExternalDependency = serde_json::from_value(legacy).expect("deserialize legacy");
        assert_eq!(dep.install_method, InstallMethod::Pacman);
        assert_eq!(dep.category, ToolCategory::Other);
        assert!(dep.recommended);
    }

    #[test]
    fn install_method_round_trips_through_json() {
        for method in [
            InstallMethod::Pacman,
            InstallMethod::AptHost,
            InstallMethod::Custom {
                id: "metasploit".into(),
            },
            InstallMethod::Manual {
                url: None,
                instructions: "manual".into(),
            },
        ] {
            let json = serde_json::to_value(&method).expect("serialize");
            let back: InstallMethod = serde_json::from_value(json).expect("deserialize");
            assert_eq!(method, back);
        }
    }

    #[test]
    fn schema_json_includes_new_dependency_fields() {
        // to_json_schema serializes the full dependency; the catalog UI and the
        // Matrix metadata both read these, so pin that the new fields appear.
        let schema = ToolSchema::new("zap", "DAST").external_dependency(
            ExternalDependency::new("zaproxy", "zaproxy", "DAST")
                .custom_installer("zap")
                .category(ToolCategory::Web),
        );
        let json = schema.to_json_schema();
        let dep = &json["external_dependencies"][0];
        assert_eq!(dep["install_method"]["kind"], "custom");
        assert_eq!(dep["install_method"]["id"], "zap");
        assert_eq!(dep["category"], "web");
        assert_eq!(dep["recommended"], true);
    }
}

#[cfg(test)]
mod transport_tests {
    //! Round-trip tests covering the Matrix transport contract.
    //!
    //! `connector.rs` forwards `ToolResult` to Matrix as JSON via
    //! `serde_json::to_value(&result)`. These tests pin the on-wire shape
    //! so the Report Agent can always locate `provenance` and its fields
    //! at the documented path.
    use super::*;
    use crate::provenance::{ProbeCommand, Provenance};

    #[test]
    fn tool_result_without_provenance_omits_the_field() {
        // Contract: tools that don't emit provenance (list_files,
        // device_info, ...) must not ship a null `provenance` key. The
        // Report Agent keys off presence, not nullness.
        let result = ToolResult::success(serde_json::json!({"ok": true}));
        let wire = serde_json::to_value(&result).expect("serialize");
        assert!(
            !wire.as_object().unwrap().contains_key("provenance"),
            "absent provenance must be omitted, got: {wire}"
        );
    }

    #[test]
    fn tool_result_with_provenance_round_trips_through_json() {
        // Contract: once a tool attaches provenance, every field must
        // survive a JSON round-trip intact — this is exactly what the
        // SDK does at connector.rs:237 before sending over the wire.
        let prov = Provenance::new(
            "nmap",
            "7.95",
            ProbeCommand::from_exact("nmap -sV 192.168.1.1"),
            "Nmap scan report for 192.168.1.1",
        );
        let original = ToolResult::success(serde_json::json!({
            "hosts": [{"ip": "192.168.1.1"}]
        }))
        .with_provenance(prov.clone());

        let wire = serde_json::to_value(&original).expect("serialize");

        // Verify the documented JSON path exists.
        let prov_json = wire
            .get("provenance")
            .expect("provenance key present on the wire");
        assert_eq!(prov_json["underlying_tool"], "nmap");
        assert_eq!(prov_json["tool_version"], "7.95");
        assert_eq!(prov_json["probe_commands"].as_array().unwrap().len(), 1);
        assert_eq!(
            prov_json["probe_commands"][0]["command"],
            "nmap -sV 192.168.1.1"
        );

        // Round-trip: Report Agent parses this back into a typed Provenance.
        let back: ToolResult = serde_json::from_value(wire).expect("deserialize");
        assert_eq!(back.provenance, Some(prov));
    }

    #[test]
    fn tool_result_with_provenance_strips_secrets_on_the_wire() {
        // Contract: what goes over the wire in `effective_command` must
        // never contain secrets, even if the `command` field does. This
        // is the end-to-end property the Report Agent relies on when it
        // publishes probe steps into a customer-facing report.
        let prov = Provenance::new(
            "curl",
            "8.5.0",
            ProbeCommand::from_exact("curl -u admin:hunter2 https://internal.example.com"),
            "200 OK",
        );
        let result = ToolResult::success(serde_json::json!({})).with_provenance(prov);

        let wire = serde_json::to_value(&result).expect("serialize");
        let eff = wire["provenance"]["probe_commands"][0]["effective_command"]
            .as_str()
            .expect("effective_command string");
        assert!(!eff.contains("hunter2"), "secret on the wire: {eff}");
        assert!(eff.contains("<REDACTED>"));
    }
}

#[cfg(test)]
mod os_capability_tests {
    //! Tests for OS-aware capability gating (GitHub issue #183, Child A).
    //!
    //! Invariants:
    //! - The desktop-OS axis is additive: a tool that doesn't opt in defaults
    //!   to every desktop OS, so Linux behavior is preserved exactly.
    //! - `supported_os` never crosses the Matrix wire (`to_json_schema` is
    //!   hand-built and omits it), and old serialized schemas still deserialize.
    //! - The registry advertises only host-supported tools.
    use super::*;

    /// A tool that runs everywhere (uses all trait defaults).
    struct UbiquitousTool;
    #[async_trait]
    impl PentestTool for UbiquitousTool {
        fn name(&self) -> &str {
            "ubiquitous"
        }
        fn description(&self) -> &str {
            "runs on every desktop OS"
        }
        async fn execute(&self, _params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
            Ok(ToolResult::success(Value::Null))
        }
    }

    /// A tool that only runs on Linux (e.g. shells out to `iw`/`aircrack-ng`).
    struct LinuxOnlyTool;
    #[async_trait]
    impl PentestTool for LinuxOnlyTool {
        fn name(&self) -> &str {
            "linux_only"
        }
        fn description(&self) -> &str {
            "requires Linux-only binaries"
        }
        fn supported_os(&self) -> Vec<DesktopOs> {
            vec![DesktopOs::Linux]
        }
        async fn execute(&self, _params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
            Ok(ToolResult::success(Value::Null))
        }
    }

    #[test]
    fn desktop_os_current_matches_compile_target() {
        // On any desktop build this is Some; only wasm/mobile yield None.
        #[cfg(not(any(target_arch = "wasm32", target_os = "android", target_os = "ios")))]
        {
            let os = DesktopOs::current().expect("desktop build has a DesktopOs");
            #[cfg(target_os = "linux")]
            assert_eq!(os, DesktopOs::Linux);
            #[cfg(target_os = "macos")]
            assert_eq!(os, DesktopOs::MacOS);
            #[cfg(target_os = "windows")]
            assert_eq!(os, DesktopOs::Windows);
        }
        #[cfg(any(target_arch = "wasm32", target_os = "android", target_os = "ios"))]
        assert_eq!(DesktopOs::current(), None);
    }

    #[test]
    fn default_supported_os_is_every_desktop_os() {
        // A tool with no opt-in advertises on all desktop OSes: this is the
        // backward-compat guarantee (nothing regresses on Linux).
        let tool = UbiquitousTool;
        assert_eq!(tool.supported_os(), ALL_DESKTOP_OS.to_vec());
        assert_eq!(tool.schema().supported_os, ALL_DESKTOP_OS.to_vec());
        assert!(tool.is_supported(), "ubiquitous tool must run on this host");
    }

    #[test]
    fn linux_only_tool_is_supported_only_on_linux() {
        let tool = LinuxOnlyTool;
        assert_eq!(tool.supported_os(), vec![DesktopOs::Linux]);
        let expect_supported = matches!(DesktopOs::current(), Some(DesktopOs::Linux) | None);
        assert_eq!(tool.is_supported(), expect_supported);
    }

    #[test]
    fn schema_is_supported_agrees_with_trait_is_supported() {
        // The registry filters on trait `is_supported`; the schema carries the
        // same data. They must agree so the advertised list is coherent.
        for supported in [
            tool_supported(&UbiquitousTool),
            tool_supported(&LinuxOnlyTool),
        ] {
            assert_eq!(supported.0, supported.1);
        }
    }

    fn tool_supported<T: PentestTool>(tool: &T) -> (bool, bool) {
        (tool.is_supported(), tool.schema().is_supported())
    }

    #[test]
    fn supported_os_is_not_serialized_to_the_wire() {
        // to_json_schema is what reaches Strike48. It must not carry the OS
        // axis (the host filter already applied), keeping the wire unchanged.
        let json = LinuxOnlyTool.schema().to_json_schema();
        assert!(
            json.get("supported_os").is_none(),
            "supported_os leaked onto the wire: {json}"
        );
    }

    #[test]
    fn old_schema_without_supported_os_still_deserializes() {
        // A ToolSchema serialized before the field existed must round-trip in
        // and default to every desktop OS.
        let legacy = serde_json::json!({
            "name": "legacy_tool",
            "description": "pre-#183 schema",
            "params": [],
            "supported_platforms": ["Desktop"]
        });
        let schema: ToolSchema = serde_json::from_value(legacy).expect("deserialize legacy");
        assert_eq!(schema.supported_os, ALL_DESKTOP_OS.to_vec());
    }

    #[test]
    fn registry_advertises_only_host_supported_tools() {
        let mut registry = ToolRegistry::new();
        registry.register(UbiquitousTool);
        registry.register(LinuxOnlyTool);

        let names = registry.supported_names();
        assert!(
            names.contains(&"ubiquitous"),
            "ubiquitous tool must always be advertised"
        );

        // On Linux both are advertised; on macOS/Windows the Linux-only tool
        // is filtered out. Assert the exact host-appropriate behavior.
        let linux_only_advertised = names.contains(&"linux_only");
        let expect = matches!(DesktopOs::current(), Some(DesktopOs::Linux) | None);
        assert_eq!(
            linux_only_advertised, expect,
            "linux_only advertised={linux_only_advertised}, expected={expect}"
        );

        // supported_schemas and supported_names must agree in cardinality.
        assert_eq!(registry.supported_schemas().len(), names.len());
    }
}

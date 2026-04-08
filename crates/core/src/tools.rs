//! Tool trait definitions and schemas

use crate::error::Result;
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

/// External dependency information for tools that require installation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalDependency {
    pub binary_name: String,
    pub package_name: String,
    pub description: String,
}

impl ExternalDependency {
    pub fn new(
        binary_name: impl Into<String>,
        package_name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            binary_name: binary_name.into(),
            package_name: package_name.into(),
            description: description.into(),
        }
    }
}

/// Schema for a pentest tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub params: Vec<ToolParam>,
    pub supported_platforms: Vec<Platform>,
    #[serde(default)]
    pub external_dependencies: Vec<ExternalDependency>,
}

impl ToolSchema {
    /// Create a new tool schema
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            params: Vec::new(),
            supported_platforms: DEFAULT_TOOL_PLATFORMS.to_vec(),
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

    /// Add an external dependency
    pub fn external_dependency(mut self, dep: ExternalDependency) -> Self {
        self.external_dependencies.push(dep);
        self
    }

    /// Check if supported on current platform
    pub fn is_supported(&self) -> bool {
        self.supported_platforms.contains(&Platform::current())
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

/// Result from a tool execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub success: bool,
    pub data: Value,
    pub error: Option<String>,
    pub duration_ms: u64,
}

impl ToolResult {
    /// Create a successful result
    pub fn success(data: Value) -> Self {
        Self {
            success: true,
            data,
            error: None,
            duration_ms: 0,
        }
    }

    /// Create a successful result with duration
    pub fn success_with_duration(data: Value, duration_ms: u64) -> Self {
        Self {
            success: true,
            data,
            error: None,
            duration_ms,
        }
    }

    /// Create an error result
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: Value::Null,
            error: Some(message.into()),
            duration_ms: 0,
        }
    }

    /// Create an error result with duration
    pub fn error_with_duration(message: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            success: false,
            data: Value::Null,
            error: Some(message.into()),
            duration_ms,
        }
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

/// Context provided to tool execution
#[derive(Debug, Clone)]
pub struct ToolContext {
    pub platform: Platform,
    pub metadata: HashMap<String, String>,
    pub workspace_path: Option<PathBuf>,
}

impl Default for ToolContext {
    fn default() -> Self {
        Self {
            platform: Platform::current(),
            metadata: HashMap::new(),
            workspace_path: None,
        }
    }
}

impl ToolContext {
    /// Set the workspace path for this context
    pub fn with_workspace(mut self, path: PathBuf) -> Self {
        self.workspace_path = Some(path);
        self
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
        ToolSchema::new(self.name(), self.description()).platforms(self.supported_platforms())
    }

    /// Get supported platforms
    fn supported_platforms(&self) -> Vec<Platform> {
        DEFAULT_TOOL_PLATFORMS.to_vec()
    }

    /// Check if supported on current platform
    fn is_supported(&self) -> bool {
        self.supported_platforms().contains(&Platform::current())
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

    /// Get tool names
    pub fn names(&self) -> Vec<&str> {
        self.tools.keys().map(|s| s.as_str()).collect()
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

    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    for (i, c1) in s1.chars().enumerate() {
        for (j, c2) in s2.chars().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            matrix[i + 1][j + 1] = std::cmp::min(
                std::cmp::min(
                    matrix[i][j + 1] + 1,      // deletion
                    matrix[i + 1][j] + 1,      // insertion
                ),
                matrix[i][j] + cost,            // substitution
            );
        }
    }

    matrix[len1][len2]
}

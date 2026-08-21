//! TOOL behavior connector for callable functions/tools.
//!
//! TOOL connectors expose callable functions to Strike48 with JSON schemas.
//! They are designed for AI agent integration, providing structured interfaces
//! for operations like calculations, API calls, data transformations, etc.
//!
//! # Example
//!
//! ```rust,ignore
//! use strike48_connector::behaviors::tool::*;
//! use async_trait::async_trait;
//!
//! struct Calculator;
//!
//! #[async_trait]
//! impl ToolConnector for Calculator {
//!     fn tools(&self) -> Vec<ToolSchema> {
//!         vec![
//!             ToolSchema::new("add", "Add two numbers")
//!                 .param("a", ParamType::Number, "First number", true)
//!                 .param("b", ParamType::Number, "Second number", true),
//!             ToolSchema::new("multiply", "Multiply two numbers")
//!                 .param("a", ParamType::Number, "First number", true)
//!                 .param("b", ParamType::Number, "Second number", true),
//!         ]
//!     }
//!
//!     async fn execute(&self, tool_name: &str, params: serde_json::Value) -> ToolResult {
//!         // Tool arguments are nested under `params["parameters"]`; sibling
//!         // keys `metadata` and `tool` carry server-supplied per-request data.
//!         match tool_name {
//!             "add" => {
//!                 let a = params["parameters"]["a"].as_f64().unwrap();
//!                 let b = params["parameters"]["b"].as_f64().unwrap();
//!                 ToolResult::success(serde_json::json!({ "result": a + b }))
//!             }
//!             "multiply" => {
//!                 let a = params["parameters"]["a"].as_f64().unwrap();
//!                 let b = params["parameters"]["b"].as_f64().unwrap();
//!                 ToolResult::success(serde_json::json!({ "result": a * b }))
//!             }
//!             _ => ToolResult::error("Unknown tool"),
//!         }
//!     }
//! }
//! ```
//!
//! To run a [`ToolConnector`], wrap it in [`crate::ToolAdapter`] and pass it
//! to [`crate::simple::run_tool`]. See `examples/calculator_tool.rs`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Tool Schema
// =============================================================================

/// Parameter type for tool schemas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
}

impl ParamType {
    fn as_str(&self) -> &'static str {
        match self {
            ParamType::String => "string",
            ParamType::Number => "number",
            ParamType::Integer => "integer",
            ParamType::Boolean => "boolean",
            ParamType::Array => "array",
            ParamType::Object => "object",
        }
    }
}

/// A parameter definition in a tool schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolParam {
    /// Parameter type.
    #[serde(rename = "type")]
    pub param_type: String,

    /// Parameter description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Default value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,

    /// Enum values (for constrained strings).
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
}

/// JSON Schema for a tool's parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    /// Tool name (unique identifier).
    pub name: String,

    /// Tool description.
    pub description: String,

    /// Parameter schema (JSON Schema format).
    pub parameters: ParameterSchema,
}

/// JSON Schema for tool parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterSchema {
    /// Schema type (always "object" for tool parameters).
    #[serde(rename = "type")]
    pub schema_type: String,

    /// Parameter definitions.
    pub properties: HashMap<String, ToolParam>,

    /// Required parameter names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
}

impl ToolSchema {
    /// Create a new tool schema.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters: ParameterSchema {
                schema_type: "object".to_string(),
                properties: HashMap::new(),
                required: vec![],
            },
        }
    }

    /// Add a parameter to the schema.
    pub fn param(
        mut self,
        name: impl Into<String>,
        param_type: ParamType,
        description: impl Into<String>,
        required: bool,
    ) -> Self {
        let name = name.into();
        self.parameters.properties.insert(
            name.clone(),
            ToolParam {
                param_type: param_type.as_str().to_string(),
                description: Some(description.into()),
                default: None,
                enum_values: None,
            },
        );
        if required {
            self.parameters.required.push(name);
        }
        self
    }

    /// Add an optional parameter with a default value.
    pub fn param_with_default(
        mut self,
        name: impl Into<String>,
        param_type: ParamType,
        description: impl Into<String>,
        default: serde_json::Value,
    ) -> Self {
        let name = name.into();
        self.parameters.properties.insert(
            name,
            ToolParam {
                param_type: param_type.as_str().to_string(),
                description: Some(description.into()),
                default: Some(default),
                enum_values: None,
            },
        );
        self
    }

    /// Add an enum parameter (constrained to specific values).
    pub fn param_enum(
        mut self,
        name: impl Into<String>,
        values: &[&str],
        description: impl Into<String>,
        required: bool,
    ) -> Self {
        let name = name.into();
        self.parameters.properties.insert(
            name.clone(),
            ToolParam {
                param_type: "string".to_string(),
                description: Some(description.into()),
                default: None,
                enum_values: Some(values.iter().map(|s| s.to_string()).collect()),
            },
        );
        if required {
            self.parameters.required.push(name);
        }
        self
    }

    /// Validate the schema.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Tool name cannot be empty".to_string());
        }
        if self.description.is_empty() {
            return Err(format!("Tool '{}' must have a description", self.name));
        }
        Ok(())
    }
}

// =============================================================================
// Tool Result
// =============================================================================

/// Result of a tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Whether the execution succeeded.
    pub success: bool,

    /// Result data (for successful execution).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,

    /// Error message (for failed execution).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Error code (for categorization).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

impl ToolResult {
    /// Create a successful result.
    pub fn success(result: serde_json::Value) -> Self {
        Self {
            success: true,
            result: Some(result),
            error: None,
            error_code: None,
        }
    }

    /// Create a successful result with no data.
    pub fn ok() -> Self {
        Self {
            success: true,
            result: Some(serde_json::json!({})),
            error: None,
            error_code: None,
        }
    }

    /// Create a failed result.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            result: None,
            error: Some(message.into()),
            error_code: None,
        }
    }

    /// Create a failed result with an error code.
    pub fn error_with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            success: false,
            result: None,
            error: Some(message.into()),
            error_code: Some(code.into()),
        }
    }
}

// =============================================================================
// Tool Connector Trait
// =============================================================================

/// Trait for TOOL behavior connectors.
///
/// TOOL connectors expose callable functions to Strike48 with JSON schemas.
/// They are designed for AI agent integration.
///
/// # Required Methods
///
/// - `tools()`: Return the list of tool schemas.
/// - `execute()`: Execute a tool with the given parameters.
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::behaviors::tool::*;
///
/// struct MyTools;
///
/// #[async_trait]
/// impl ToolConnector for MyTools {
///     fn tools(&self) -> Vec<ToolSchema> {
///         vec![
///             ToolSchema::new("greet", "Greet a user")
///                 .param("name", ParamType::String, "User's name", true)
///         ]
///     }
///
///     async fn execute(&self, tool: &str, params: serde_json::Value) -> ToolResult {
///         // Tool arguments are nested under `params["parameters"]`; sibling
///         // keys `metadata` and `tool` carry server-supplied per-request data.
///         match tool {
///             "greet" => {
///                 let name = params["parameters"]["name"].as_str().unwrap_or("World");
///                 ToolResult::success(serde_json::json!({
///                     "message": format!("Hello, {}!", name)
///                 }))
///             }
///             _ => ToolResult::error_with_code("Unknown tool", "UNKNOWN_TOOL")
///         }
///     }
/// }
/// ```
#[async_trait]
pub trait ToolConnector: Send + Sync {
    /// Return the list of tool schemas.
    fn tools(&self) -> Vec<ToolSchema>;

    /// Execute a tool with the given parameters.
    ///
    /// This is the required execution entry point. Override
    /// [`Self::execute_with_context`] instead when your tool needs the
    /// per-caller context map (tenant id, subject, attributes) — the SDK
    /// always calls the context-aware variant and the default
    /// implementation of `execute_with_context` delegates here.
    async fn execute(&self, tool_name: &str, params: serde_json::Value) -> ToolResult;

    /// Execute a tool with server-supplied per-request context.
    ///
    /// The wire-level [`crate::types::ExecuteRequest`] carries a `context`
    /// map populated by the server with caller metadata. Override this
    /// method when your tool needs that metadata (for example, to scope
    /// storage by `context["tenant_id"]`). The default
    /// implementation discards `context` and delegates to [`Self::execute`]
    /// so existing tools continue to work unchanged.
    ///
    /// See [`crate::BaseConnector::execute_with_context`] for the
    /// well-known keys the Strike48 server populates and the relationship
    /// between `execute` and `execute_with_context`. Use the
    /// [`crate::context::keys`] constants when reading well-known keys.
    ///
    /// Note on `params` shape: the JSON object passed in `params` has tool
    /// arguments nested under `params["parameters"]`. Sibling keys
    /// `params["metadata"]` (a JSON-decoded mirror of `context`) and
    /// `params["tool"]` (the invoked tool name) carry server-supplied
    /// per-request data.
    ///
    /// # Debug-build tripwire
    ///
    /// In debug builds (`#[cfg(debug_assertions)]`) the default impl emits a
    /// `tracing::warn!` on the `strike48_connector::context_drop` target
    /// whenever a non-empty `context` is dropped. Silence with
    /// `RUST_LOG=strike48_connector::context_drop=off`. Production
    /// (`--release`) builds keep zero overhead.
    async fn execute_with_context(
        &self,
        tool_name: &str,
        params: serde_json::Value,
        context: &HashMap<String, String>,
    ) -> ToolResult {
        #[cfg(debug_assertions)]
        if !context.is_empty() {
            tracing::warn!(
                target: "strike48_connector::context_drop",
                context_keys = ?context.keys().collect::<Vec<_>>(),
                "ToolConnector::execute_with_context default impl is dropping non-empty context. \
                 Override execute_with_context (not execute) if your tool needs caller metadata \
                 (tenant_id, user_id, etc.)."
            );
        }
        #[cfg(not(debug_assertions))]
        let _ = context;
        self.execute(tool_name, params).await
    }

    /// Return tool-specific metadata for registration.
    fn tool_metadata(&self) -> HashMap<String, String> {
        let schemas = self.tools();
        let mut meta = HashMap::new();
        meta.insert(
            "tool_schemas".to_string(),
            serde_json::to_string(&schemas).unwrap_or_default(),
        );
        meta.insert("tool_count".to_string(), schemas.len().to_string());
        meta.insert(
            "tool_names".to_string(),
            schemas
                .iter()
                .map(|s| s.name.clone())
                .collect::<Vec<_>>()
                .join(","),
        );
        meta.insert("timeout_ms".to_string(), self.timeout_ms().to_string());
        meta
    }

    /// Timeout in milliseconds (default: 5 seconds).
    fn timeout_ms(&self) -> u64 {
        5000
    }

    /// Validate all tool schemas.
    fn validate_tools(&self) -> Result<(), String> {
        let schemas = self.tools();
        if schemas.is_empty() {
            return Err("ToolConnector must define at least one tool".to_string());
        }
        for schema in &schemas {
            schema.validate()?;
        }
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_schema_builder() {
        let schema = ToolSchema::new("calculate", "Perform calculations")
            .param("a", ParamType::Number, "First operand", true)
            .param("b", ParamType::Number, "Second operand", true)
            .param_enum("op", &["add", "subtract", "multiply"], "Operation", true);

        assert_eq!(schema.name, "calculate");
        assert_eq!(schema.parameters.properties.len(), 3);
        assert_eq!(schema.parameters.required.len(), 3);
        assert!(schema.validate().is_ok());
    }

    #[test]
    fn test_tool_schema_with_default() {
        let schema = ToolSchema::new("greet", "Greet someone")
            .param("name", ParamType::String, "Name to greet", true)
            .param_with_default(
                "greeting",
                ParamType::String,
                "Greeting word",
                serde_json::json!("Hello"),
            );

        assert_eq!(schema.parameters.required.len(), 1);
        let greeting_param = schema.parameters.properties.get("greeting").unwrap();
        assert_eq!(greeting_param.default, Some(serde_json::json!("Hello")));
    }

    #[test]
    fn test_tool_result_success() {
        let result = ToolResult::success(serde_json::json!({ "value": 42 }));
        assert!(result.success);
        assert_eq!(result.result.unwrap()["value"], 42);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_tool_result_error() {
        let result = ToolResult::error_with_code("Invalid input", "INVALID_INPUT");
        assert!(!result.success);
        assert!(result.result.is_none());
        assert_eq!(result.error, Some("Invalid input".to_string()));
        assert_eq!(result.error_code, Some("INVALID_INPUT".to_string()));
    }

    #[test]
    fn test_tool_schema_validation() {
        let empty_name = ToolSchema::new("", "Description");
        assert!(empty_name.validate().is_err());

        let empty_desc = ToolSchema::new("tool", "");
        assert!(empty_desc.validate().is_err());

        let valid = ToolSchema::new("tool", "Valid tool");
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn test_tool_schema_serialization() {
        let schema = ToolSchema::new("test", "Test tool").param(
            "input",
            ParamType::String,
            "Input value",
            true,
        );

        let json = serde_json::to_string(&schema).unwrap();
        assert!(json.contains("\"name\":\"test\""));
        assert!(json.contains("\"type\":\"string\""));
    }
}

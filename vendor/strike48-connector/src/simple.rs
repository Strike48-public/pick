//! Simplified API for Strike48 Connectors.
//!
//! This module provides the simplest possible way to create connectors.
//! For most use cases, this is all you need.
//!
//! # Quick Start
//!
//! ## Echo Connector (~20 lines)
//!
//! ```rust,ignore
//! use strike48_connector::prelude::*;
//!
//! struct EchoConnector;
//!
//! #[async_trait]
//! impl SimpleConnector for EchoConnector {
//!     fn name(&self) -> &str { "echo" }
//!     fn version(&self) -> &str { "1.0.0" }
//!     async fn handle(&self, request: Value) -> Result<Value> {
//!         Ok(json!({ "echo": request }))
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     EchoConnector.run().await.unwrap();
//! }
//! ```
//!
//! ## Static Site (3 lines)
//!
//! ```rust,ignore
//! use strike48_connector::prelude::*;
//!
//! #[tokio::main]
//! async fn main() {
//!     serve_static("./dist", "My React App").await.unwrap();
//! }
//! ```
//!
//! ## Dynamic App (10 lines)
//!
//! ```rust,ignore
//! use strike48_connector::prelude::*;
//!
//! #[tokio::main]
//! async fn main() {
//!     serve_app("Dashboard", |req| async move {
//!         match req.path.as_str() {
//!             "/" => html("<h1>Welcome</h1>"),
//!             _ => not_found(),
//!         }
//!     }).await.unwrap();
//! }
//! ```

use crate::behaviors::app::{AppPageRequest, AppPageResponse};
use crate::behaviors::tool::ToolConnector;
use crate::behaviors::tool_adapter::ToolAdapter;
use crate::connector::{BaseConnector, ConnectorConfig, ConnectorRunner};
use crate::error::Result;
use crate::types::{ConnectorBehavior, PayloadEncoding, TaskTypeSchema};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

// =============================================================================
// SIMPLE CONNECTOR TRAIT
// =============================================================================

/// Simplified connector trait using async_trait.
///
/// This is the easiest way to create a connector. Just implement `handle()`.
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::prelude::*;
///
/// struct MyConnector;
///
/// #[async_trait]
/// impl SimpleConnector for MyConnector {
///     fn name(&self) -> &str { "my-connector" }
///     fn version(&self) -> &str { "1.0.0" }
///
///     async fn handle(&self, request: Value) -> Result<Value> {
///         Ok(json!({ "processed": request }))
///     }
/// }
///
/// #[tokio::main]
/// async fn main() {
///     MyConnector.run().await.unwrap();
/// }
/// ```
#[async_trait]
pub trait SimpleConnector: Send + Sync + 'static {
    /// Connector name (e.g., "echo", "lookup", "enrichment")
    fn name(&self) -> &str;

    /// Connector version (e.g., "1.0.0")
    fn version(&self) -> &str;

    /// Handle a request and return a response.
    ///
    /// This is the main method you need to implement.
    async fn handle(&self, request: Value) -> Result<Value>;

    /// Handle a request with a specific capability ID.
    ///
    /// Override this for multi-capability connectors.
    async fn handle_capability(&self, request: Value, _capability_id: &str) -> Result<Value> {
        self.handle(request).await
    }

    /// Get connector behavior (default: RequestResponse)
    fn behavior(&self) -> ConnectorBehavior {
        ConnectorBehavior::RequestResponse
    }

    /// Get supported encodings
    fn encodings(&self) -> Vec<PayloadEncoding> {
        vec![PayloadEncoding::Json]
    }

    /// Get connector metadata
    fn metadata(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    /// Get connector capabilities/tools
    fn capabilities(&self) -> Vec<TaskTypeSchema> {
        Vec::new()
    }

    /// Run the connector with default configuration from environment.
    ///
    /// Reads connection settings from `STRIKE48_URL` (preferred) or
    /// `STRIKE48_HOST`, with `MATRIX_HOST` honored as a legacy fallback,
    /// plus `TENANT_ID`, `INSTANCE_ID`, `AUTH_TOKEN`, and `USE_TLS`. Display
    /// metadata (`CONNECTOR_DISPLAY_NAME`, `CONNECTOR_TAGS`) and metrics
    /// settings (`STRIKE48_METRICS_ENABLED`, `STRIKE48_METRICS_INTERVAL_MS`)
    /// are also respected. See [`ConnectorConfig::from_env`] for the full
    /// list and defaults.
    async fn run(self) -> Result<()>
    where
        Self: Sized,
    {
        self.run_with_config(ConnectorConfig::from_env()).await
    }

    /// Run the connector with custom configuration.
    async fn run_with_config(self, mut config: ConnectorConfig) -> Result<()>
    where
        Self: Sized,
    {
        // Override connector type and version from trait
        config.connector_type = self.name().to_string();
        config.version = self.version().to_string();

        // Generate instance_id if still default
        if config.instance_id.starts_with("unknown-") {
            config.instance_id =
                format!("{}-{}", self.name(), chrono::Utc::now().timestamp_millis());
        }

        // Initialize logger
        crate::logger::init_logger();

        // Create adapter and run
        let adapter = SimpleConnectorAdapter { inner: self };
        let runner = ConnectorRunner::new(config, Arc::new(adapter));

        // Setup signal handler for graceful shutdown
        // Get shutdown handle before running to avoid deadlock
        let shutdown_handle = runner.shutdown_handle();

        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Received shutdown signal");
            shutdown_handle.shutdown();
        });

        runner.run().await
    }
}

/// Adapter that converts SimpleConnector to BaseConnector
struct SimpleConnectorAdapter<C: SimpleConnector> {
    inner: C,
}

impl<C: SimpleConnector> BaseConnector for SimpleConnectorAdapter<C> {
    fn connector_type(&self) -> &str {
        self.inner.name()
    }

    fn version(&self) -> &str {
        self.inner.version()
    }

    fn execute(
        &self,
        request: Value,
        capability_id: Option<&str>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Value>> + Send + '_>> {
        // Clone capability_id to own it in the async block
        let cap_id = capability_id.map(|s| s.to_string());
        Box::pin(async move {
            if let Some(ref id) = cap_id {
                self.inner.handle_capability(request, id).await
            } else {
                self.inner.handle(request).await
            }
        })
    }

    fn behavior(&self) -> ConnectorBehavior {
        self.inner.behavior()
    }

    fn supported_encodings(&self) -> Vec<PayloadEncoding> {
        self.inner.encodings()
    }

    fn metadata(&self) -> HashMap<String, String> {
        self.inner.metadata()
    }

    fn capabilities(&self) -> Vec<TaskTypeSchema> {
        self.inner.capabilities()
    }
}

// =============================================================================
// CONVENIENCE FUNCTIONS
// =============================================================================

/// Serve a static site to Strike48.
///
/// This is the simplest way to serve a React/Vue/Angular app.
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::prelude::*;
///
/// #[tokio::main]
/// async fn main() {
///     serve_static("./dist", "My React App").await.unwrap();
/// }
/// ```
pub async fn serve_static(directory: &str, name: &str) -> Result<()> {
    use crate::behaviors::serve::App;
    App::static_files(directory).display_name(name).run().await
}

/// Serve a dynamic app to Strike48.
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::prelude::*;
///
/// #[tokio::main]
/// async fn main() {
///     serve_app("Dashboard", |req| async move {
///         match req.path.as_str() {
///             "/" => html("<h1>Welcome</h1>"),
///             _ => not_found(),
///         }
///     }).await.unwrap();
/// }
/// ```
pub async fn serve_app<F, Fut>(name: &str, handler: F) -> Result<()>
where
    F: Fn(AppPageRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = AppPageResponse> + Send + 'static,
{
    use crate::behaviors::serve::App;
    App::builder()
        .display_name(name)
        .handler(handler)
        .run()
        .await
}

/// Create an HTML response (convenience function).
pub fn html(content: &str) -> AppPageResponse {
    AppPageResponse::html(content)
}

/// Create a JSON response (convenience function).
pub fn json(content: &str) -> AppPageResponse {
    AppPageResponse::json(content)
}

/// Create a not found response (convenience function).
pub fn not_found() -> AppPageResponse {
    AppPageResponse::not_found()
}

// =============================================================================
// FUNCTION CONNECTOR
// =============================================================================

/// Create a connector from a simple function.
///
/// This is the absolute simplest way to create a connector.
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::prelude::*;
///
/// #[tokio::main]
/// async fn main() {
///     run_connector("echo", "1.0.0", |req| async move {
///         Ok(json!({ "echo": req }))
///     }).await.unwrap();
/// }
/// ```
pub async fn run_connector<F, Fut>(name: &str, version: &str, handler: F) -> Result<()>
where
    F: Fn(Value) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Value>> + Send + 'static,
{
    struct FnConnector<F> {
        name: String,
        version: String,
        handler: F,
    }

    #[async_trait]
    impl<F, Fut> SimpleConnector for FnConnector<F>
    where
        F: Fn(Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value>> + Send + 'static,
    {
        fn name(&self) -> &str {
            &self.name
        }

        fn version(&self) -> &str {
            &self.version
        }

        async fn handle(&self, request: Value) -> Result<Value> {
            (self.handler)(request).await
        }
    }

    let connector = FnConnector {
        name: name.to_string(),
        version: version.to_string(),
        handler,
    };

    connector.run().await
}

/// Run a [`ToolConnector`] against the Strike48 server with config from env.
///
/// Wraps your `ToolConnector` in a [`ToolAdapter`] (declares `Tool` behavior,
/// maps `tools()` → registration capabilities, dispatches by tool name),
/// reads connection settings via [`ConnectorConfig::from_env`] (which
/// covers `STRIKE48_URL` / `STRIKE48_HOST` / legacy `MATRIX_HOST`,
/// `TENANT_ID`, `INSTANCE_ID`, `AUTH_TOKEN`, `USE_TLS`,
/// `CONNECTOR_DISPLAY_NAME`, `CONNECTOR_TAGS`, `STRIKE48_METRICS_ENABLED`,
/// and `STRIKE48_METRICS_INTERVAL_MS`), runs a single [`ConnectorRunner`],
/// and shuts down gracefully on `Ctrl-C`.
///
/// For full builder customization (`category`, `icon`, extra metadata),
/// construct the adapter explicitly and pass it in.
///
/// # Example — minimal main
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use serde_json::{Value, json};
/// use strike48_connector::*;
///
/// struct Calculator;
///
/// #[async_trait]
/// impl ToolConnector for Calculator {
///     fn tools(&self) -> Vec<ToolSchema> {
///         vec![ToolSchema::new("add", "Add two numbers")
///             .param("a", ParamType::Number, "First operand", true)
///             .param("b", ParamType::Number, "Second operand", true)]
///     }
///     async fn execute(&self, tool: &str, params: Value) -> ToolResult {
///         match tool {
///             "add" => ToolResult::success(json!({
///                 "result": params["a"].as_f64().unwrap_or(0.0)
///                         + params["b"].as_f64().unwrap_or(0.0)
///             })),
///             _ => ToolResult::error_with_code("unknown tool", "UNKNOWN_TOOL"),
///         }
///     }
/// }
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     simple::run_tool(ToolAdapter::new("calculator", Calculator).with_version("1.0.0")).await
/// }
/// ```
pub async fn run_tool<T>(adapter: ToolAdapter<T>) -> Result<()>
where
    T: ToolConnector + 'static,
{
    run_tool_connector(Arc::new(adapter)).await
}

/// Inner runner shared by [`run_tool`] and any future tool-flavored helpers.
/// Reads [`ConnectorConfig::from_env`], adopts the adapter's `connector_type`
/// and `version`, generates an `instance_id` if absent, wires Ctrl-C, and
/// drives a single [`ConnectorRunner`] to completion.
async fn run_tool_connector(connector: Arc<dyn BaseConnector>) -> Result<()> {
    crate::logger::init_logger();

    let mut config = ConnectorConfig::from_env();
    config.connector_type = connector.connector_type().to_string();
    config.version = connector.version().to_string();
    if config.instance_id.starts_with("unknown-") {
        config.instance_id = format!(
            "{}-{}",
            connector.connector_type(),
            chrono::Utc::now().timestamp_millis()
        );
    }

    let runner = ConnectorRunner::new(config, connector);
    let shutdown_handle = runner.shutdown_handle();

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Received shutdown signal");
        shutdown_handle.shutdown();
    });

    runner.run().await
}

// =============================================================================
// PRELUDE MODULE
// =============================================================================

/// Prelude module - import everything you need with one line.
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::prelude::*;
/// ```
pub mod prelude {
    // Re-export the simplified traits and functions
    pub use super::{
        SimpleConnector, html, json, not_found, run_connector, run_tool, serve_app, serve_static,
    };

    // Re-export async_trait for implementing SimpleConnector / ToolConnector
    pub use async_trait::async_trait;

    // Re-export commonly used types
    pub use crate::behaviors::app::{AppPageRequest, AppPageResponse};
    pub use crate::behaviors::tool::{
        ParamType, ParameterSchema, ToolConnector, ToolParam, ToolResult, ToolSchema,
    };
    pub use crate::behaviors::tool_adapter::ToolAdapter;
    pub use crate::error::Result;
    pub use serde_json::{Value, json};

    // Re-export logger initialization
    pub use crate::logger::init_logger;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct TestConnector;

    #[async_trait]
    impl SimpleConnector for TestConnector {
        fn name(&self) -> &str {
            "test"
        }
        fn version(&self) -> &str {
            "1.0.0"
        }
        async fn handle(&self, request: Value) -> Result<Value> {
            Ok(json!({ "echo": request }))
        }
    }

    #[tokio::test]
    async fn test_simple_connector_handle() {
        let connector = TestConnector;
        let result = connector.handle(json!({"hello": "world"})).await.unwrap();
        assert_eq!(result["echo"]["hello"], "world");
    }

    #[test]
    fn test_simple_connector_metadata() {
        let connector = TestConnector;
        assert_eq!(connector.name(), "test");
        assert_eq!(connector.version(), "1.0.0");
        assert_eq!(connector.behavior(), ConnectorBehavior::RequestResponse);
    }

    #[test]
    fn test_html_response() {
        let response = html("<h1>Hello</h1>");
        assert_eq!(response.content_type, "text/html");
    }

    #[test]
    fn test_json_response() {
        let response = json(r#"{"key": "value"}"#);
        assert_eq!(response.content_type, "application/json");
    }

    #[test]
    fn test_not_found_response() {
        let response = not_found();
        assert_eq!(response.status, 404);
    }
}

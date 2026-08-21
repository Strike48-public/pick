//! Strike48 Connector SDK for Rust.
//!
//! Build connectors for the Strike48 platform: tool connectors
//! (LLM-callable functions), request/response handlers, static or dynamic
//! web apps, or several of the above running in one process sharing a
//! single transport.
//!
//! # Quick start: a tool connector
//!
//! ```no_run
//! # async fn _example() -> strike48_connector::Result<()> {
//! use async_trait::async_trait;
//! use serde_json::{Value, json};
//! use strike48_connector::*;
//!
//! struct Calculator;
//!
//! #[async_trait]
//! impl ToolConnector for Calculator {
//!     fn tools(&self) -> Vec<ToolSchema> {
//!         vec![ToolSchema::new("add", "Add two numbers")
//!             .param("a", ParamType::Number, "First operand", true)
//!             .param("b", ParamType::Number, "Second operand", true)]
//!     }
//!     async fn execute(&self, _tool: &str, p: Value) -> ToolResult {
//!         let a = p["a"].as_f64().unwrap_or(0.0);
//!         let b = p["b"].as_f64().unwrap_or(0.0);
//!         ToolResult::success(json!({ "result": a + b }))
//!     }
//! }
//!
//! simple::run_tool(
//!     ToolAdapter::new("calculator", Calculator).with_version("1.0.0"),
//! ).await
//! # }
//! ```
//!
//! # Choosing an entry point
//!
//! - **Tools (LLM-callable functions)** — implement [`ToolConnector`], wrap
//!   in [`ToolAdapter`], hand to [`simple::run_tool`].
//! - **Request/response** — implement [`SimpleConnector`] and call its
//!   `run` method.
//! - **Web apps** — call [`simple::serve_static`] for a static directory or
//!   [`simple::serve_app`] for a dynamic handler (or use [`behaviors::serve::App::builder`]
//!   for full control).
//! - **Multiple connectors in one process** — use [`MultiConnectorRunner`]
//!   to share a single transport (gRPC: one HTTP/2 channel, N streams).
//! - **Advanced: raw stream callbacks** — implement [`BaseConnector`] and
//!   drive it with [`ConnectorRunner`]. Required for App connectors that
//!   proxy WebSocket frames.
//!
//! ## Per-request context (multi-tenant deployments)
//!
//! Both runners forward the server-supplied `ExecuteRequest.context` map
//! to connectors via [`BaseConnector::execute_with_context`] (and, for
//! tool connectors, [`ToolConnector::execute_with_context`]). Override the
//! context-aware variant when your connector needs caller metadata such
//! as `tenant_id`. The default implementations delegate to the
//! existing `execute` methods, so connectors that don't care about
//! context continue to work unchanged.
//!
//! # Configuration
//!
//! All entry points read connection settings from the environment via
//! [`ConnectorConfig::from_env`]. The most common variables are
//! `STRIKE48_HOST` (or `STRIKE48_URL`), `TENANT_ID`, `INSTANCE_ID`,
//! `AUTH_TOKEN`, and `USE_TLS`. See [`ConnectorConfig::from_env`] for the
//! full list, and the README for storage paths and TLS overrides.
//!
//! # Examples in this repo
//!
//! - `examples/calculator_tool.rs` — minimal `ToolConnector` + `ToolAdapter`.
//! - `examples/simple_echo.rs` — minimal `SimpleConnector` request/response.
//! - `examples/system_command_tool.rs` — fuller TOOL example.
//! - `examples/app_connector.rs` — APP behavior with `App::builder`.
//! - `examples/auth_app.rs` — APP with custom authentication.
//! - `examples/mixed_connectors.rs` — N **distinct** tools sharing one
//!   transport via `MultiConnectorRunner`.
//! - `examples/multi_connector.rs` — N copies of one connector type
//!   (shared-channel vs independent-runner benchmark).
//! - `examples/echo_connector.rs` — low-level `BaseConnector` reference.
//! - `examples/one_liner.rs` — `run_connector` / `serve_static` one-liners.

// Internal modules -- not accessible to external consumers
pub(crate) mod auth;
pub(crate) mod client;
pub(crate) mod constants;
pub(crate) mod logger;
pub(crate) mod metrics_recorder;
pub(crate) mod sdk_metadata;
pub(crate) mod system_metrics;
pub(crate) mod transport;

// Public modules
pub mod behaviors;
pub mod connector;
pub mod context;
pub mod error;
pub mod multi;
pub mod process;
pub mod simple;
pub mod types;
pub mod url_parser;
pub mod utils;

// =============================================================================
// PRELUDE - The simplest way to use this SDK
// =============================================================================
//
// Just add: `use strike48_connector::prelude::*;`
//
// This gives you everything you need to build connectors quickly.
//
pub use simple::prelude;

// Core types
pub use connector::{
    BaseConnector, ConnectorConfig, ConnectorHandle, ConnectorRunner, InvokeCapabilityOptions,
    ShutdownHandle,
};

// Multi-registration runner (additive; existing single-registration API unchanged).
pub use error::{ConnectorError, Result};
pub use multi::{
    ConnectorRegistration, MultiConnectorRunner, MultiTransportOptions,
    MultiTransportOptionsBuilder, RegistrationKey,
};
pub use types::*;
pub use utils::{deserialize_payload, error_response, serialize_payload, success_response};

// App behavior
pub use behaviors::app::{
    AppConnector, AppManifest, AppPageRequest, AppPageResponse, BodyEncoding, NavigationConfig,
    NavigationPlacement, StaticFileConfig,
};
pub use behaviors::serve::{App, AppBuilder};

// Source behavior
pub use behaviors::source::{FetchRequest, FetchResponse, SourceConfig, SourceConnector};

// Sink behavior
pub use behaviors::sink::{IdempotentSink, ItemError, SinkConfig, SinkConnector, WriteResult};

// Tool behavior
pub use behaviors::tool::{
    ParamType, ParameterSchema, ToolConnector, ToolParam, ToolResult, ToolSchema,
};
pub use behaviors::tool_adapter::ToolAdapter;

// PubSub behavior
pub use behaviors::pubsub::{
    InMemoryPubSub, Message, PubSubConfig, PubSubConnector, PublishOptions, SubscribeOptions,
    Subscription, SubscriptionError, TopicPattern,
};

// RequestResponse behavior
pub use behaviors::request_response::{
    BatchRequest, BatchResponse, ConcurrentRequestHandler, RequestContext, RequestError,
    RequestMetrics, RequestResponseConfig, RequestResponseConnector, Response,
};

// Utilities
pub use behaviors::utilities::{
    Cache, CacheStats, OperationMetrics, RetryConfig, Timer, ValidationError, retry_async, timed,
    validate_against_schema, validate_json,
};

// Async process execution (non-blocking command runner)
pub use process::{
    CommandBuilder, CommandOptions, CommandOutput, run_command, run_command_opts,
    run_command_stdout, run_command_with_timeout, run_shell, run_shell_with_timeout,
};

// URL parser for auto-detecting transport from URL scheme
pub use url_parser::{ParsedEndpoint, get_transport_from_url, is_valid_url, parse_url};

// Transport config types (re-exported from internal module)
pub use transport::{TransportOptions, TransportType};

// Invoke options for ConnectorHandle (re-exported from internal module)
pub use client::InvokeOptions;

// Logger initialization (re-exported from internal module)
pub use logger::init_logger;

// Advanced: low-level client for connectors that manage their own gRPC streams.
// Prefer `ToolConnector`+`ToolAdapter` (tools) or `SimpleConnector`
// (request/response). `ConnectorRunner`+`BaseConnector` is for advanced cases
// that need raw stream callbacks (e.g. App connectors proxying WebSocket frames).
pub use client::{ClientOptions, ConnectorClient};

/// Authentication primitives.
///
/// [`OttProvider`] is the SDK's One-Time-Token / `private_key_jwt` auth
/// provider. It supports four deployment modes (pre-approval OTT,
/// post-approval, Kubernetes cert-manager, direct auth) selected
/// automatically from the environment — see the auth section of the
/// README and the env vars `STRIKE48_REGISTRATION_TOKEN`,
/// `STRIKE48_REGISTRATION_TOKEN_FILE`, `STRIKE48_PRIVATE_KEY_PATH`,
/// `STRIKE48_CLIENT_ID`, `STRIKE48_AUTH_URL`, and `STRIKE48_KEYS_DIR`.
/// Most connectors should not interact with `OttProvider` directly:
/// [`ConnectorRunner`] and [`MultiConnectorRunner`] manage it for you.
///
/// [`OAuthManager`] / [`OAuthError`] cover the user-facing OAuth/PKCE
/// flow used by App connectors that authenticate end users.
pub use auth::{OAuthError, OAuthManager, OttProvider};

// Re-export the `metrics` crate so connector authors can use
// `strike48_connector::metrics::{counter, gauge, histogram}` without
// adding `metrics` to their own Cargo.toml.
pub use metrics;

// =============================================================================
// SIMPLIFIED API - For developers who want the easiest possible experience
// =============================================================================

// Simple connector trait and helpers
pub use simple::{
    SimpleConnector, html, json, not_found, run_connector, run_tool, serve_app, serve_static,
};

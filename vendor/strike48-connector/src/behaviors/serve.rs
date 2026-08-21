//! High-level API for serving apps to Strike48.
//!
//! This module provides ergonomic builders and macros for quickly spinning up
//! app connectors in Rust.
//!
//! # Example: Static Site
//!
//! ```rust,ignore
//! use strike48_connector::behaviors::serve::App;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     App::static_files("./dist")
//!         .display_name("My React App")
//!         .icon("hero-sparkles")
//!         .run()
//!         .await?;
//!     Ok(())
//! }
//! ```
//!
//! # Example: Dynamic App
//!
//! ```rust,ignore
//! use strike48_connector::behaviors::serve::App;
//! use strike48_connector::behaviors::app::{AppPageRequest, AppPageResponse};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     App::builder()
//!         .display_name("My Dashboard")
//!         .entry_path("/")
//!         .handler(|req: AppPageRequest| async move {
//!             match req.path.as_str() {
//!                 "/" => AppPageResponse::html("<h1>Welcome</h1>"),
//!                 _ => AppPageResponse::not_found(),
//!             }
//!         })
//!         .run()
//!         .await?;
//!     Ok(())
//! }
//! ```

use super::app::{
    AppConnector, AppManifest, AppPageRequest, AppPageResponse, NavigationConfig, StaticFileConfig,
};
use crate::connector::{ConnectorConfig, ConnectorRunner};
use crate::error::{ConnectorError, Result};
use crate::types::{ConnectorBehavior, PayloadEncoding};
use async_trait::async_trait;
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

// =============================================================================
// App Builder
// =============================================================================

/// High-level builder for creating and running app connectors.
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::behaviors::serve::App;
///
/// App::static_files("./public")
///     .display_name("My App")
///     .icon("hero-sparkles")
///     .run()
///     .await?;
/// ```
pub struct App {
    /// App manifest
    manifest: AppManifest,
    /// Static file configuration
    static_config: Option<StaticFileConfig>,
    /// Custom handler for page requests
    handler: Option<HandlerFn>,
    /// Connector configuration overrides
    connector_config: ConnectorConfig,
    /// Local development port (optional, for future use)
    #[allow(dead_code)]
    local_port: Option<u16>,
}

/// Type alias for page handler function.
type HandlerFn = Arc<
    dyn Fn(AppPageRequest) -> Pin<Box<dyn Future<Output = AppPageResponse> + Send>> + Send + Sync,
>;

impl App {
    /// Create a new App builder.
    pub fn builder() -> AppBuilder {
        AppBuilder::default()
    }

    /// Create an app that serves static files from a directory.
    ///
    /// This is the simplest way to serve a pre-built SPA or static site.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// App::static_files("./dist")
    ///     .display_name("My SPA")
    ///     .run()
    ///     .await?;
    /// ```
    pub fn static_files(dir: impl Into<PathBuf>) -> AppBuilder {
        let static_dir = dir.into();
        AppBuilder {
            static_dir: Some(static_dir),
            serve_index_for_spa: true,
            ..Default::default()
        }
    }

    /// Create an app from environment variables.
    ///
    /// Reads configuration from:
    /// - `STRIKE48_HOST`: Strike48 server address
    /// - `TENANT_ID`: Tenant identifier
    /// - `APP_NAME`: App name (optional)
    /// - `APP_STATIC_DIR`: Static files directory (optional)
    pub fn from_env() -> Result<AppBuilder> {
        let host = std::env::var("STRIKE48_HOST").map_err(|_| {
            ConnectorError::InvalidConfig("STRIKE48_HOST environment variable not set".to_string())
        })?;

        let tenant_id = std::env::var("TENANT_ID").map_err(|_| {
            ConnectorError::InvalidConfig("TENANT_ID environment variable not set".to_string())
        })?;

        let display_name = std::env::var("APP_NAME").ok();
        let static_dir = std::env::var("APP_STATIC_DIR").ok().map(PathBuf::from);
        let local_port = std::env::var("APP_LOCAL_PORT")
            .ok()
            .and_then(|p| p.parse().ok());

        Ok(AppBuilder {
            host: Some(host),
            tenant_id: Some(tenant_id),
            display_name,
            static_dir,
            local_port,
            ..Default::default()
        })
    }

    /// Run the app connector.
    pub async fn run(self) -> Result<()> {
        let connector = BuiltAppConnector {
            manifest: self.manifest,
            static_config: self.static_config,
            handler: self.handler,
            connector_type: self.connector_config.connector_type.clone(),
        };

        let runner = ConnectorRunner::new(self.connector_config, Arc::new(connector));
        runner.run().await
    }
}

// =============================================================================
// App Builder (Type-State Pattern)
// =============================================================================

/// Builder for constructing App instances.
#[derive(Default)]
pub struct AppBuilder {
    // Manifest fields
    display_name: Option<String>,
    entry_path: Option<String>,
    description: Option<String>,
    icon: Option<String>,
    version: Option<String>,
    routes: Option<Vec<String>>,
    navigation: Option<NavigationConfig>,
    api_access: bool,

    // Static file config
    static_dir: Option<PathBuf>,
    /// Serve index.html for SPA routes (for future use)
    #[allow(dead_code)]
    serve_index_for_spa: bool,

    // Handler
    handler: Option<HandlerFn>,

    // Connector config
    host: Option<String>,
    tenant_id: Option<String>,
    instance_id: Option<String>,
    connector_name: Option<String>,
    use_tls: Option<bool>,
    local_port: Option<u16>,
}

impl AppBuilder {
    /// Set the app display name (REQUIRED).
    ///
    /// This is the human-readable name shown in the UI and used to derive the
    /// default `connector_name` (as `"app-{display_name}"`) when no explicit
    /// `.connector_name()` is provided.
    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Alias for [`display_name`](Self::display_name) for backwards compatibility.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Set the entry path (default: "/").
    pub fn entry_path(mut self, path: impl Into<String>) -> Self {
        self.entry_path = Some(path.into());
        self
    }

    /// Set the app description.
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set the app icon.
    pub fn icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    /// Set the app version.
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the available routes.
    pub fn routes(mut self, routes: &[&str]) -> Self {
        self.routes = Some(routes.iter().map(|s| s.to_string()).collect());
        self
    }

    /// Set the navigation configuration.
    pub fn navigation(mut self, nav: NavigationConfig) -> Self {
        self.navigation = Some(nav);
        self
    }

    /// Declare that this app needs GraphQL API access on behalf of the user.
    pub fn api_access(mut self) -> Self {
        self.api_access = true;
        self
    }

    /// Set the static files directory.
    pub fn static_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.static_dir = Some(dir.into());
        self
    }

    /// Set a custom page handler.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// .handler(|req| async move {
    ///     AppPageResponse::html("<h1>Hello</h1>")
    /// })
    /// ```
    pub fn handler<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(AppPageRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AppPageResponse> + Send + 'static,
    {
        self.handler = Some(Arc::new(move |req| Box::pin(f(req))));
        self
    }

    /// Set the Strike48 server host.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Set the tenant ID.
    pub fn tenant_id(mut self, id: impl Into<String>) -> Self {
        self.tenant_id = Some(id.into());
        self
    }

    /// Set the instance ID.
    pub fn instance_id(mut self, id: impl Into<String>) -> Self {
        self.instance_id = Some(id.into());
        self
    }

    /// Override the connector name used for server registration.
    ///
    /// This determines the server-side `gateway_id`. By default it is
    /// derived as `"app-{display_name}"`. Use this to dynamically
    /// customise the gateway identity at runtime (e.g. append a hostname).
    ///
    /// Priority: `.connector_name()` > derived from `APP_NAME` env / `.display_name()`.
    pub fn connector_name(mut self, name: impl Into<String>) -> Self {
        self.connector_name = Some(name.into());
        self
    }

    /// Enable/disable TLS.
    pub fn use_tls(mut self, enabled: bool) -> Self {
        self.use_tls = Some(enabled);
        self
    }

    /// Set a local development port (serves app locally for testing).
    pub fn local_port(mut self, port: u16) -> Self {
        self.local_port = Some(port);
        self
    }

    /// Build the App.
    ///
    /// The connector name (which determines the server-side `gateway_id`) is
    /// resolved with the following priority:
    /// 1. `.connector_name()` builder method (highest — programmatic override)
    /// 2. Derived from display name: `APP_NAME` env var > `.display_name()` → `"app-{display_name}"`
    pub fn build(self) -> Result<App> {
        // APP_NAME env var overrides the builder-provided display name.
        let display_name = std::env::var("APP_NAME")
            .ok()
            .filter(|s| !s.is_empty())
            .or(self.display_name)
            .ok_or_else(|| {
                ConnectorError::InvalidConfig("App display_name is required".to_string())
            })?;

        let entry_path = self.entry_path.unwrap_or_else(|| "/".to_string());

        // Build manifest
        let mut manifest = AppManifest::new(&display_name, &entry_path);
        manifest.description = self.description;
        manifest.icon = self.icon;
        manifest.version = self.version;
        manifest.routes = self.routes;
        manifest.navigation = self.navigation;
        manifest.api_access = self.api_access;

        // Build static config
        let static_config = self.static_dir.map(StaticFileConfig::new);

        // Use from_env() as base — it already parses URL schemes (ws://, wss://,
        // grpc://, grpcs://) from MATRIX_HOST / STRIKE48_HOST and stores the
        // resolved host:port, use_tls, and transport_type.
        let env_config = ConnectorConfig::from_env();

        let (resolved_host, use_tls, transport_type) = if let Some(explicit_host) = self.host {
            // Builder had an explicit host — parse it for scheme detection
            match crate::url_parser::parse_url(&explicit_host) {
                Ok(parsed) => (
                    parsed.host_port(),
                    self.use_tls.unwrap_or(parsed.use_tls),
                    parsed.transport,
                ),
                Err(_) => (
                    explicit_host,
                    self.use_tls.unwrap_or(env_config.use_tls),
                    env_config.transport_type,
                ),
            }
        } else {
            // No explicit host — use env_config's already-parsed values
            (
                env_config.host,
                self.use_tls.unwrap_or(env_config.use_tls),
                env_config.transport_type,
            )
        };

        let tenant_id = self.tenant_id.unwrap_or(env_config.tenant_id);

        // Prefer explicit instance_id, then INSTANCE_ID env var (via env_config),
        // then fall back to a display_name-based auto-generated id.
        let instance_id = self.instance_id.unwrap_or_else(|| {
            let env_instance = std::env::var("INSTANCE_ID").unwrap_or_default();
            if !env_instance.is_empty() {
                env_instance
            } else {
                format!(
                    "{}-{}",
                    display_name.to_lowercase().replace(' ', "-"),
                    chrono::Utc::now().timestamp_millis()
                )
            }
        });

        // .connector_name() builder override takes priority over display_name-derived value.
        let connector_name = self
            .connector_name
            .unwrap_or_else(|| format!("app-{}", display_name.to_lowercase().replace(' ', "-")));

        let connector_config = ConnectorConfig {
            host: resolved_host,
            tenant_id,
            connector_type: connector_name,
            instance_id,
            version: manifest
                .version
                .clone()
                .unwrap_or_else(|| "1.0.0".to_string()),
            auth_token: env_config.auth_token,
            use_tls,
            transport_type,
            max_concurrent_requests: 100,
            reconnect_enabled: true,
            reconnect_delay_ms: 500,
            max_backoff_delay_ms: 60000,
            reconnect_jitter_ms: 500,
            display_name: Some(display_name.clone()),
            tags: Vec::new(),
            metadata: std::collections::HashMap::new(),
            metrics_enabled: env_config.metrics_enabled,
            metrics_interval_ms: env_config.metrics_interval_ms,
            heartbeat_interval: None,
            heartbeat_timeout: None,
        };

        Ok(App {
            manifest,
            static_config,
            handler: self.handler,
            connector_config,
            local_port: self.local_port,
        })
    }

    /// Build and run the app.
    ///
    /// This is a convenience method that combines `build()` and `run()`.
    pub async fn run(self) -> Result<()> {
        self.build()?.run().await
    }
}

// =============================================================================
// Built App Connector (Internal)
// =============================================================================

/// Internal connector implementation created by App.
struct BuiltAppConnector {
    manifest: AppManifest,
    static_config: Option<StaticFileConfig>,
    handler: Option<HandlerFn>,
    /// Unique connector type derived from app name (e.g. "app-my-dashboard").
    /// This determines the gateway_id on the server, so each distinctly-named
    /// app gets its own gateway and sidebar entry.
    connector_type: String,
}

impl crate::connector::BaseConnector for BuiltAppConnector {
    fn connector_type(&self) -> &str {
        &self.connector_type
    }

    fn version(&self) -> &str {
        self.manifest.version.as_deref().unwrap_or("1.0.0")
    }

    fn behavior(&self) -> ConnectorBehavior {
        ConnectorBehavior::App
    }

    fn supported_encodings(&self) -> Vec<PayloadEncoding> {
        vec![PayloadEncoding::Json]
    }

    fn metadata(&self) -> HashMap<String, String> {
        let manifest_json = serde_json::to_string(&self.manifest).unwrap_or_default();
        let mut meta = HashMap::new();
        meta.insert("app_manifest".to_string(), manifest_json);
        meta.insert("timeout_ms".to_string(), "10000".to_string());
        meta
    }

    fn execute(
        &self,
        request: serde_json::Value,
        _capability_id: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value>> + Send + '_>> {
        Box::pin(async move {
            // Parse the request
            let page_request: AppPageRequest =
                serde_json::from_value(request).unwrap_or_else(|_| AppPageRequest {
                    path: "/".to_string(),
                    params: HashMap::new(),
                });

            // Try static file first
            if let Some(ref static_config) = self.static_config
                && let Some(response) = static_config.try_serve(&page_request.path)
            {
                return Ok(serde_json::to_value(response)?);
            }

            // Call handler if available
            if let Some(ref handler) = self.handler {
                let response = handler(page_request).await;
                return Ok(serde_json::to_value(response)?);
            }

            // Default 404
            Ok(serde_json::to_value(AppPageResponse::not_found())?)
        })
    }
}

#[async_trait]
impl AppConnector for BuiltAppConnector {
    fn app_manifest(&self) -> AppManifest {
        self.manifest.clone()
    }

    fn static_file_config(&self) -> Option<&StaticFileConfig> {
        self.static_config.as_ref()
    }

    async fn render_page(&self, request: AppPageRequest) -> AppPageResponse {
        if let Some(ref handler) = self.handler {
            handler(request).await
        } else {
            AppPageResponse::not_found()
        }
    }
}

// =============================================================================
// Macros
// =============================================================================

/// Macro for quickly serving a static site to Strike48.
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::serve_app;
///
/// #[tokio::main]
/// async fn main() {
///     serve_app!("./dist", name = "My React App").await.unwrap();
/// }
/// ```
#[macro_export]
macro_rules! serve_app {
    ($dir:expr) => {
        $crate::behaviors::serve::App::static_files($dir)
            .display_name(env!("CARGO_PKG_NAME"))
            .run()
    };
    ($dir:expr, name = $name:expr) => {
        $crate::behaviors::serve::App::static_files($dir)
            .display_name($name)
            .run()
    };
    ($dir:expr, name = $name:expr, icon = $icon:expr) => {
        $crate::behaviors::serve::App::static_files($dir)
            .display_name($name)
            .icon($icon)
            .run()
    };
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_basic() {
        let app = App::builder()
            .display_name("Test App")
            .entry_path("/")
            .build();

        assert!(app.is_ok());
        let app = app.unwrap();
        assert_eq!(app.manifest.name, "Test App");
        assert_eq!(app.manifest.entry_path, "/");
        // Default connector_type derived from display_name
        assert_eq!(app.connector_config.connector_type, "app-test-app");
    }

    #[test]
    fn test_builder_requires_name() {
        let result = App::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_with_static_files() {
        let app = App::static_files("./test")
            .display_name("Static App")
            .build();

        assert!(app.is_ok());
        let app = app.unwrap();
        assert!(app.static_config.is_some());
    }

    #[test]
    fn test_builder_with_connector_name() {
        let app = App::builder()
            .display_name("My App")
            .connector_name("app-my-app-prod-host1")
            .build();

        assert!(app.is_ok());
        let app = app.unwrap();
        assert_eq!(app.manifest.name, "My App");
        assert_eq!(app.connector_config.connector_type, "app-my-app-prod-host1");
    }

    #[test]
    fn test_builder_name_alias() {
        // .name() should work as alias for .display_name()
        let app = App::builder().name("Legacy Name").build();
        assert!(app.is_ok());
        let app = app.unwrap();
        assert_eq!(app.manifest.name, "Legacy Name");
    }

    #[test]
    fn test_builder_with_options() {
        let app = App::builder()
            .display_name("Full App")
            .description("A fully configured app")
            .icon("hero-star")
            .version("2.0.0")
            .navigation(NavigationConfig::top_level())
            .host("example.com:443")
            .tenant_id("my-tenant")
            .use_tls(true)
            .build();

        assert!(app.is_ok());
        let app = app.unwrap();
        assert_eq!(app.manifest.name, "Full App");
        assert_eq!(
            app.manifest.description,
            Some("A fully configured app".to_string())
        );
        assert_eq!(app.manifest.icon, Some("hero-star".to_string()));
        assert_eq!(app.manifest.version, Some("2.0.0".to_string()));
        assert!(app.manifest.navigation.is_some());
    }
}

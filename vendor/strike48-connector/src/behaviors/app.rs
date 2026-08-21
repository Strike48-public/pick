//! APP behavior connector for serving web application UIs within Strike48 Studio.
//!
//! # Overview
//!
//! APP connectors serve web application UIs within Strike48 Studio. They handle page
//! requests and can automatically serve static assets.
//!
//! # Example
//!
//! ```rust,ignore
//! use strike48_connector::behaviors::app::*;
//! use async_trait::async_trait;
//!
//! struct MyDashboard;
//!
//! #[async_trait]
//! impl AppConnector for MyDashboard {
//!     fn app_manifest(&self) -> AppManifest {
//!         AppManifest::new("My Dashboard", "/")
//!             .icon("hero-chart-bar")
//!             .description("Custom analytics dashboard")
//!             .navigation(NavigationConfig::nested(&["Analytics"]))
//!     }
//!
//!     async fn render_page(&self, request: AppPageRequest) -> AppPageResponse {
//!         match request.path.as_str() {
//!             "/" => AppPageResponse::html("<h1>Welcome</h1>"),
//!             _ => AppPageResponse::not_found(),
//!         }
//!     }
//! }
//! ```

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// =============================================================================
// Navigation Configuration
// =============================================================================

/// Navigation placement in Strike48 Studio's sidebar.
///
/// Controls how and where an app appears in the navigation menu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "placement", rename_all = "kebab-case")]
pub enum NavigationPlacement {
    /// Top-level navigation (parallel to Jobs, Workflows, Documents).
    /// Ignores any path configuration.
    TopLevel,

    /// Nested under a menu hierarchy defined by path.
    /// Each element in path creates/uses a menu level.
    Nested {
        /// Path in nav hierarchy as array of menu names.
        /// - `["Apps"]` → Apps > MyApp
        /// - `["Security"]` → Security > MyApp
        /// - `["Acme", "Dashboards"]` → Acme > Dashboards > MyApp
        #[serde(default)]
        path: Vec<String>,
    },

    /// Hidden from navigation (accessible via URL only).
    Hidden,
}

impl Default for NavigationPlacement {
    fn default() -> Self {
        NavigationPlacement::Nested {
            path: vec!["Apps".to_string()],
        }
    }
}

/// Navigation configuration for how an app appears in Strike48 Studio's nav menu.
///
/// # Examples
///
/// ```rust
/// use strike48_connector::behaviors::app::NavigationConfig;
///
/// // Top-level (parallel to Jobs, Workflows)
/// let nav = NavigationConfig::top_level()
///     .order(50)
///     .icon("hero-shield-check");
///
/// // Nested under "Apps" (default)
/// let nav = NavigationConfig::default();
///
/// // Deeply nested: Acme > Dashboards > MyApp
/// let nav = NavigationConfig::nested(&["Acme", "Dashboards"]);
///
/// // Hidden (URL access only)
/// let nav = NavigationConfig::hidden();
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NavigationConfig {
    /// Where to place in navigation.
    #[serde(flatten)]
    pub placement: NavigationPlacement,

    /// Custom icon for nav item (e.g., "hero-chart-bar").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,

    /// Display order within parent (lower = higher priority, default: 100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<u32>,

    /// Custom label in nav (defaults to app name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl NavigationConfig {
    /// Create a top-level navigation config (parallel to Jobs, Workflows).
    pub fn top_level() -> Self {
        Self {
            placement: NavigationPlacement::TopLevel,
            ..Default::default()
        }
    }

    /// Create a nested navigation config under the given path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use strike48_connector::behaviors::app::NavigationConfig;
    ///
    /// // Under "Apps" menu
    /// let nav = NavigationConfig::nested(&["Apps"]);
    ///
    /// // Under Security > SOC
    /// let nav = NavigationConfig::nested(&["Security", "SOC"]);
    /// ```
    pub fn nested(path: &[&str]) -> Self {
        Self {
            placement: NavigationPlacement::Nested {
                path: path.iter().map(|s| s.to_string()).collect(),
            },
            ..Default::default()
        }
    }

    /// Create a hidden navigation config (URL access only).
    pub fn hidden() -> Self {
        Self {
            placement: NavigationPlacement::Hidden,
            ..Default::default()
        }
    }

    /// Set the icon.
    pub fn icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    /// Set the display order.
    pub fn order(mut self, order: u32) -> Self {
        self.order = Some(order);
        self
    }

    /// Set a custom label.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

// =============================================================================
// App Manifest
// =============================================================================

/// App manifest describing an app for Strike48 Studio UI.
///
/// # Required Fields
///
/// - `name`: Human-readable app name
/// - `entry_path`: Default entry path (e.g., "/")
///
/// # Example
///
/// ```rust
/// use strike48_connector::behaviors::app::{AppManifest, NavigationConfig};
///
/// let manifest = AppManifest::new("My Dashboard", "/")
///     .description("Custom analytics dashboard")
///     .icon("hero-chart-bar")
///     .version("1.0.0")
///     .routes(&["/", "/settings", "/reports"])
///     .navigation(NavigationConfig::nested(&["Analytics"]));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppManifest {
    /// Human-readable app name (REQUIRED).
    pub name: String,

    /// Default entry path (REQUIRED, e.g., "/").
    pub entry_path: String,

    /// App description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Icon identifier (e.g., "hero-shield-check").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,

    /// List of available routes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routes: Option<Vec<String>>,

    /// App version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Navigation configuration for Strike48 Studio's sidebar.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub navigation: Option<NavigationConfig>,

    /// Whether the app needs GraphQL API access on behalf of the user.
    /// When true, users will be prompted for consent before the app loads.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub api_access: bool,
}

impl AppManifest {
    /// Create a new app manifest with required fields.
    pub fn new(name: impl Into<String>, entry_path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entry_path: entry_path.into(),
            description: None,
            icon: None,
            routes: None,
            version: None,
            navigation: None,
            api_access: false,
        }
    }

    /// Set the description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the icon.
    pub fn icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    /// Set the version.
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
    /// Users will be prompted for consent before the app loads.
    pub fn api_access(mut self) -> Self {
        self.api_access = true;
        self
    }

    /// Validate the manifest, returning an error if invalid.
    pub fn validate(&self) -> Result<()> {
        use crate::error::ConnectorError;

        if self.name.is_empty() {
            return Err(ConnectorError::InvalidConfig(
                "App manifest must have a non-empty 'name' field".to_string(),
            ));
        }

        if self.entry_path.is_empty() {
            return Err(ConnectorError::InvalidConfig(
                "App manifest must have a non-empty 'entry_path' field".to_string(),
            ));
        }

        Ok(())
    }
}

// =============================================================================
// App Page Request/Response
// =============================================================================

/// Body encoding for app page responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BodyEncoding {
    /// UTF-8 text encoding (default for text content).
    #[default]
    Utf8,
    /// Base64 encoding (for binary files like images, fonts).
    Base64,
}

/// App page request containing the path and query parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppPageRequest {
    /// The requested path (e.g., "/", "/dashboard").
    pub path: String,

    /// Query parameters.
    #[serde(default)]
    pub params: HashMap<String, String>,
}

impl AppPageRequest {
    /// Create a new request for a path.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            params: HashMap::new(),
        }
    }

    /// Add a query parameter.
    pub fn param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }
}

/// App page response with content type, body, status, and encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPageResponse {
    /// MIME type (e.g., "text/html", "application/javascript").
    pub content_type: String,

    /// Content body (HTML, CSS, JS, or base64-encoded binary).
    pub body: String,

    /// HTTP-like status code (default: 200).
    #[serde(default = "default_status")]
    pub status: u16,

    /// Body encoding: UTF-8 (default for text) or Base64 (for binary files).
    #[serde(default)]
    pub encoding: BodyEncoding,

    /// Optional response headers.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
}

fn default_status() -> u16 {
    200
}

impl AppPageResponse {
    /// Create an HTML response.
    pub fn html(body: impl Into<String>) -> Self {
        Self {
            content_type: "text/html".to_string(),
            body: body.into(),
            status: 200,
            encoding: BodyEncoding::Utf8,
            headers: HashMap::new(),
        }
    }

    /// Create a JSON response.
    pub fn json(body: impl Into<String>) -> Self {
        Self {
            content_type: "application/json".to_string(),
            body: body.into(),
            status: 200,
            encoding: BodyEncoding::Utf8,
            headers: HashMap::new(),
        }
    }

    /// Create a CSS response.
    pub fn css(body: impl Into<String>) -> Self {
        Self {
            content_type: "text/css".to_string(),
            body: body.into(),
            status: 200,
            encoding: BodyEncoding::Utf8,
            headers: HashMap::new(),
        }
    }

    /// Create a JavaScript response.
    pub fn javascript(body: impl Into<String>) -> Self {
        Self {
            content_type: "application/javascript".to_string(),
            body: body.into(),
            status: 200,
            encoding: BodyEncoding::Utf8,
            headers: HashMap::new(),
        }
    }

    /// Create a not found (404) response.
    pub fn not_found() -> Self {
        Self {
            content_type: "text/html".to_string(),
            body: "<h1>404 - Not Found</h1>".to_string(),
            status: 404,
            encoding: BodyEncoding::Utf8,
            headers: HashMap::new(),
        }
    }

    /// Create a not found response with custom body.
    pub fn not_found_with(body: impl Into<String>) -> Self {
        Self {
            content_type: "text/html".to_string(),
            body: body.into(),
            status: 404,
            encoding: BodyEncoding::Utf8,
            headers: HashMap::new(),
        }
    }

    /// Create an error response.
    pub fn error(status: u16, message: impl Into<String>) -> Self {
        Self {
            content_type: "text/html".to_string(),
            body: format!("<h1>Error {status}</h1><p>{}</p>", message.into()),
            status,
            encoding: BodyEncoding::Utf8,
            headers: HashMap::new(),
        }
    }

    /// Create a binary response with base64-encoded body.
    pub fn binary(content_type: impl Into<String>, base64_body: impl Into<String>) -> Self {
        Self {
            content_type: content_type.into(),
            body: base64_body.into(),
            status: 200,
            encoding: BodyEncoding::Base64,
            headers: HashMap::new(),
        }
    }

    /// Set the status code.
    pub fn status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    /// Add a response header.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }
}

// =============================================================================
// Static File Serving
// =============================================================================

use std::sync::LazyLock;

/// Binary file extensions (served with base64 encoding).
static BINARY_EXTENSIONS: LazyLock<std::collections::HashSet<&'static str>> = LazyLock::new(|| {
    [
        "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "woff", "woff2", "ttf", "eot", "otf",
        "pdf", "zip", "tar", "gz", "mp3", "mp4", "webm", "ogg", "wav",
    ]
    .into_iter()
    .collect()
});

/// Content-type mapping by file extension.
static CONTENT_TYPE_MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    [
        ("html", "text/html"),
        ("htm", "text/html"),
        ("css", "text/css"),
        ("js", "application/javascript"),
        ("mjs", "application/javascript"),
        ("json", "application/json"),
        ("xml", "application/xml"),
        ("txt", "text/plain"),
        ("md", "text/markdown"),
        ("csv", "text/csv"),
        ("svg", "image/svg+xml"),
        ("png", "image/png"),
        ("jpg", "image/jpeg"),
        ("jpeg", "image/jpeg"),
        ("gif", "image/gif"),
        ("webp", "image/webp"),
        ("ico", "image/x-icon"),
        ("bmp", "image/bmp"),
        ("woff", "font/woff"),
        ("woff2", "font/woff2"),
        ("ttf", "font/ttf"),
        ("eot", "application/vnd.ms-fontobject"),
        ("otf", "font/otf"),
        ("pdf", "application/pdf"),
        ("zip", "application/zip"),
        ("mp3", "audio/mpeg"),
        ("mp4", "video/mp4"),
        ("webm", "video/webm"),
        ("ogg", "audio/ogg"),
        ("wav", "audio/wav"),
    ]
    .into_iter()
    .collect()
});

/// Configuration for static file serving.
#[derive(Debug, Clone, Default)]
pub struct StaticFileConfig {
    /// Directory containing static assets.
    pub static_dir: Option<PathBuf>,
    /// Resolved static directory (after path.canonicalize()).
    resolved_dir: Option<PathBuf>,
}

impl StaticFileConfig {
    /// Create a new static file config with the given directory.
    pub fn new(static_dir: impl Into<PathBuf>) -> Self {
        let static_dir: PathBuf = static_dir.into();
        let resolved_dir = std::fs::canonicalize(&static_dir).ok();

        Self {
            static_dir: Some(static_dir),
            resolved_dir,
        }
    }

    /// Check if static serving is enabled.
    pub fn is_enabled(&self) -> bool {
        self.resolved_dir.is_some()
    }

    /// Try to serve a static file for the given path.
    ///
    /// Returns `Some(AppPageResponse)` if a file was found and served,
    /// or `None` if the path doesn't match a static file.
    pub fn try_serve(&self, request_path: &str) -> Option<AppPageResponse> {
        let resolved_dir = self.resolved_dir.as_ref()?;

        // Normalize path: remove leading slash, prevent directory traversal
        let relative_path = request_path.trim_start_matches('/');

        // Security: prevent directory traversal
        if relative_path.contains("..") || relative_path.contains('\\') {
            return None;
        }

        let file_path = resolved_dir.join(relative_path);

        // Security: ensure resolved path is within static directory
        let canonical = std::fs::canonicalize(&file_path).ok()?;
        if !canonical.starts_with(resolved_dir) {
            return None;
        }

        // Check if file exists and is a file (not directory)
        let metadata = std::fs::metadata(&canonical).ok()?;
        if !metadata.is_file() {
            return None;
        }

        // Determine content type and encoding
        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let content_type = CONTENT_TYPE_MAP
            .get(ext.as_str())
            .copied()
            .unwrap_or("application/octet-stream");

        let is_binary = BINARY_EXTENSIONS.contains(ext.as_str());

        // Read file with appropriate encoding
        let (body, encoding) = if is_binary {
            let bytes = std::fs::read(&canonical).ok()?;
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            (STANDARD.encode(&bytes), BodyEncoding::Base64)
        } else {
            let content = std::fs::read_to_string(&canonical).ok()?;
            (content, BodyEncoding::Utf8)
        };

        Some(AppPageResponse {
            content_type: content_type.to_string(),
            body,
            status: 200,
            encoding,
            headers: HashMap::new(),
        })
    }
}

// =============================================================================
// App Connector Trait
// =============================================================================

/// Trait for APP behavior connectors.
///
/// APP connectors serve web application UIs within Strike48 Studio. They handle
/// page requests and optionally serve static assets automatically.
///
/// # Required Methods
///
/// - `app_manifest()`: Return the app manifest describing the app
/// - `render_page()`: Handle page requests and return HTML/content
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::behaviors::app::*;
/// use async_trait::async_trait;
///
/// struct MyApp {
///     static_files: StaticFileConfig,
/// }
///
/// #[async_trait]
/// impl AppConnector for MyApp {
///     fn app_manifest(&self) -> AppManifest {
///         AppManifest::new("My App", "/")
///             .icon("hero-sparkles")
///     }
///
///     fn static_file_config(&self) -> Option<&StaticFileConfig> {
///         Some(&self.static_files)
///     }
///
///     async fn render_page(&self, request: AppPageRequest) -> AppPageResponse {
///         match request.path.as_str() {
///             "/" => AppPageResponse::html("<h1>Hello World</h1>"),
///             _ => AppPageResponse::not_found(),
///         }
///     }
/// }
/// ```
#[async_trait]
pub trait AppConnector: Send + Sync {
    /// Return the app manifest describing the app.
    fn app_manifest(&self) -> AppManifest;

    /// Return multiple app manifests for connectors serving multiple apps.
    ///
    /// Override this to serve multiple apps from a single connector.
    /// By default, returns a single-element vec with `app_manifest()`.
    fn app_manifests(&self) -> Vec<AppManifest> {
        vec![self.app_manifest()]
    }

    /// Return the static file configuration, if any.
    ///
    /// Override this to enable static file serving.
    fn static_file_config(&self) -> Option<&StaticFileConfig> {
        None
    }

    /// Render a page for the given request.
    ///
    /// This is called for all requests that don't match a static file.
    async fn render_page(&self, request: AppPageRequest) -> AppPageResponse;

    /// Handle incoming requests. Automatically serves static files if configured.
    ///
    /// You typically don't need to override this - implement `render_page()` instead.
    async fn execute(&self, request: AppPageRequest) -> AppPageResponse {
        // First, try to serve as static file
        if let Some(config) = self.static_file_config()
            && let Some(response) = config.try_serve(&request.path)
        {
            return response;
        }

        // Not a static file - call subclass's page rendering logic
        self.render_page(request).await
    }

    /// Return app-specific metadata for registration.
    fn app_metadata(&self) -> HashMap<String, String> {
        let manifests = self.app_manifests();

        if manifests.len() > 1 {
            // Multiple apps - send as app_manifests array
            let manifests_json = serde_json::to_string(&manifests).unwrap_or_default();
            let mut meta = HashMap::new();
            meta.insert("app_manifests".to_string(), manifests_json);
            meta
        } else {
            // Single app - send as app_manifest
            let manifest = self.app_manifest();
            let manifest_json = serde_json::to_string(&manifest).unwrap_or_default();
            let mut meta = HashMap::new();
            meta.insert("app_manifest".to_string(), manifest_json);
            meta
        }
    }

    /// Timeout for app requests in milliseconds (default: 10000).
    fn timeout_ms(&self) -> u64 {
        10000
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_navigation_config_top_level() {
        let nav = NavigationConfig::top_level().icon("hero-home").order(10);

        assert!(matches!(nav.placement, NavigationPlacement::TopLevel));
        assert_eq!(nav.icon, Some("hero-home".to_string()));
        assert_eq!(nav.order, Some(10));
    }

    #[test]
    fn test_navigation_config_nested() {
        let nav = NavigationConfig::nested(&["Security", "SOC"]);

        match nav.placement {
            NavigationPlacement::Nested { path } => {
                assert_eq!(path, vec!["Security", "SOC"]);
            }
            _ => panic!("Expected nested placement"),
        }
    }

    #[test]
    fn test_navigation_config_hidden() {
        let nav = NavigationConfig::hidden();
        assert!(matches!(nav.placement, NavigationPlacement::Hidden));
    }

    #[test]
    fn test_app_manifest_builder() {
        let manifest = AppManifest::new("Test App", "/")
            .description("A test app")
            .icon("hero-beaker")
            .version("1.0.0")
            .routes(&["/", "/about"]);

        assert_eq!(manifest.name, "Test App");
        assert_eq!(manifest.entry_path, "/");
        assert_eq!(manifest.description, Some("A test app".to_string()));
        assert_eq!(manifest.icon, Some("hero-beaker".to_string()));
        assert_eq!(manifest.version, Some("1.0.0".to_string()));
        assert_eq!(
            manifest.routes,
            Some(vec!["/".to_string(), "/about".to_string()])
        );
    }

    #[test]
    fn test_app_manifest_validate() {
        let valid = AppManifest::new("Test", "/");
        assert!(valid.validate().is_ok());

        let empty_name = AppManifest::new("", "/");
        assert!(empty_name.validate().is_err());

        let empty_path = AppManifest::new("Test", "");
        assert!(empty_path.validate().is_err());
    }

    #[test]
    fn test_app_page_response_html() {
        let resp = AppPageResponse::html("<h1>Hello</h1>");
        assert_eq!(resp.content_type, "text/html");
        assert_eq!(resp.body, "<h1>Hello</h1>");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.encoding, BodyEncoding::Utf8);
    }

    #[test]
    fn test_app_page_response_not_found() {
        let resp = AppPageResponse::not_found();
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn test_app_page_response_binary() {
        let resp = AppPageResponse::binary("image/png", "base64data==");
        assert_eq!(resp.content_type, "image/png");
        assert_eq!(resp.encoding, BodyEncoding::Base64);
    }

    #[test]
    fn test_navigation_serialization() {
        let nav = NavigationConfig::nested(&["Apps"]).icon("hero-cog");

        let json = serde_json::to_string(&nav).unwrap();
        assert!(json.contains("nested"));
        assert!(json.contains("Apps"));
        assert!(json.contains("hero-cog"));
    }

    #[test]
    fn test_app_manifest_serialization() {
        let manifest = AppManifest::new("Test", "/").navigation(NavigationConfig::top_level());

        let json = serde_json::to_string(&manifest).unwrap();
        assert!(json.contains("Test"));
        assert!(json.contains("top-level"));
    }
}

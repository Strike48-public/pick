//! SOURCE behavior connector for pull-based data ingestion.
//!
//! SOURCE connectors fetch data from external sources (databases, APIs, files)
//! and send it to Strike48. They support batching, streaming, and cursor-based
//! pagination.
//!
//! # Example
//!
//! ```rust,ignore
//! use strike48_connector::behaviors::source::*;
//! use async_trait::async_trait;
//!
//! struct DatabaseSource {
//!     config: SourceConfig,
//! }
//!
//! #[async_trait]
//! impl SourceConnector for DatabaseSource {
//!     type Item = serde_json::Value;
//!
//!     async fn fetch(&self, request: FetchRequest) -> FetchResponse<Self::Item> {
//!         // Query database and return results
//!         FetchResponse::items(vec![...])
//!             .with_cursor("next-page-token")
//!     }
//!
//!     fn source_config(&self) -> &SourceConfig {
//!         &self.config
//!     }
//! }
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Source Configuration
// =============================================================================

/// Configuration for source connectors.
#[derive(Debug, Clone)]
pub struct SourceConfig {
    /// Maximum number of concurrent requests.
    pub max_concurrent_requests: usize,

    /// Whether batching is enabled.
    pub batching_enabled: bool,

    /// Maximum batch size.
    pub batch_size: usize,

    /// Batch timeout in milliseconds.
    pub batch_timeout_ms: u64,

    /// Whether this source supports streaming.
    pub supports_streaming: bool,

    /// Whether this source supports cursor-based pagination.
    pub supports_cursor: bool,

    /// Timeout for source operations in milliseconds.
    pub timeout_ms: u64,
}

impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 1000,
            batching_enabled: false,
            batch_size: 100,
            batch_timeout_ms: 10,
            supports_streaming: false,
            supports_cursor: false,
            timeout_ms: 30000, // 30 seconds for potentially slow sources
        }
    }
}

impl SourceConfig {
    /// Create a new source config with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable batching with the given size.
    pub fn with_batching(mut self, size: usize) -> Self {
        self.batching_enabled = true;
        self.batch_size = size;
        self
    }

    /// Set batch timeout.
    pub fn with_batch_timeout(mut self, timeout_ms: u64) -> Self {
        self.batch_timeout_ms = timeout_ms;
        self
    }

    /// Enable streaming support.
    pub fn with_streaming(mut self) -> Self {
        self.supports_streaming = true;
        self
    }

    /// Enable cursor-based pagination.
    pub fn with_cursor_support(mut self) -> Self {
        self.supports_cursor = true;
        self
    }

    /// Set operation timeout.
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Set max concurrent requests.
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent_requests = max;
        self
    }
}

// =============================================================================
// Fetch Request/Response
// =============================================================================

/// Request to fetch data from a source.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FetchRequest {
    /// Query or filter parameters.
    #[serde(default)]
    pub query: HashMap<String, serde_json::Value>,

    /// Cursor for pagination (if supported).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,

    /// Maximum number of items to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,

    /// Additional context.
    #[serde(default)]
    pub context: HashMap<String, String>,
}

impl FetchRequest {
    /// Create a new fetch request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a query parameter.
    pub fn query(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        self.query.insert(key.into(), value.into());
        self
    }

    /// Set the cursor for pagination.
    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    /// Set the limit.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Response from fetching data from a source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchResponse<T> {
    /// Fetched items.
    pub items: Vec<T>,

    /// Cursor for next page (if more data available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,

    /// Whether there are more items available.
    #[serde(default)]
    pub has_more: bool,

    /// Total count (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<usize>,

    /// Metadata about the fetch.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl<T> FetchResponse<T> {
    /// Create a response with items.
    pub fn items(items: Vec<T>) -> Self {
        Self {
            items,
            next_cursor: None,
            has_more: false,
            total_count: None,
            metadata: HashMap::new(),
        }
    }

    /// Create an empty response.
    pub fn empty() -> Self {
        Self::items(vec![])
    }

    /// Set the next cursor.
    pub fn with_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.next_cursor = Some(cursor.into());
        self.has_more = true;
        self
    }

    /// Set whether there are more items.
    pub fn with_has_more(mut self, has_more: bool) -> Self {
        self.has_more = has_more;
        self
    }

    /// Set the total count.
    pub fn with_total(mut self, total: usize) -> Self {
        self.total_count = Some(total);
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

impl<T> Default for FetchResponse<T> {
    fn default() -> Self {
        Self::empty()
    }
}

// =============================================================================
// Source Connector Trait
// =============================================================================

/// Trait for SOURCE behavior connectors.
///
/// SOURCE connectors pull data from external sources and send it to Strike48.
/// They support batching, streaming, and cursor-based pagination.
///
/// # Associated Type
///
/// - `Item`: The type of items fetched by this source.
///
/// # Required Methods
///
/// - `fetch()`: Fetch items from the source.
/// - `source_config()`: Return the source configuration.
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::behaviors::source::*;
///
/// struct MySource {
///     config: SourceConfig,
/// }
///
/// #[async_trait]
/// impl SourceConnector for MySource {
///     type Item = MyDataType;
///
///     async fn fetch(&self, req: FetchRequest) -> FetchResponse<Self::Item> {
///         // Fetch data from external source
///         let items = fetch_from_api(&req.query).await;
///         FetchResponse::items(items)
///     }
///
///     fn source_config(&self) -> &SourceConfig {
///         &self.config
///     }
/// }
/// ```
#[async_trait]
pub trait SourceConnector: Send + Sync {
    /// The type of items fetched by this source.
    type Item: Send + Serialize + for<'de> Deserialize<'de>;

    /// Fetch items from the source.
    async fn fetch(&self, request: FetchRequest) -> FetchResponse<Self::Item>;

    /// Return the source configuration.
    fn source_config(&self) -> &SourceConfig;

    /// Return source-specific metadata for registration.
    fn source_metadata(&self) -> HashMap<String, String> {
        let config = self.source_config();
        let mut meta = HashMap::new();
        meta.insert(
            "supports_streaming".to_string(),
            config.supports_streaming.to_string(),
        );
        meta.insert(
            "supports_cursor".to_string(),
            config.supports_cursor.to_string(),
        );
        meta.insert("max_batch_size".to_string(), config.batch_size.to_string());
        meta.insert(
            "batching_enabled".to_string(),
            config.batching_enabled.to_string(),
        );
        meta.insert("timeout_ms".to_string(), config.timeout_ms.to_string());
        meta
    }

    /// Timeout in milliseconds.
    fn timeout_ms(&self) -> u64 {
        self.source_config().timeout_ms
    }
}

// =============================================================================
// Streaming Support (Future Extension)
// =============================================================================

// Future: Add streaming support using `futures::Stream` when needed.
// This would enable continuous data flow from sources:
//
// ```rust,ignore
// pub trait SourceStream: futures::Stream<Item = Self::Item> + Send {
//     type Item: Send + Serialize;
// }
// ```

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_config_builder() {
        let config = SourceConfig::new()
            .with_batching(500)
            .with_streaming()
            .with_cursor_support()
            .with_timeout(60000);

        assert!(config.batching_enabled);
        assert_eq!(config.batch_size, 500);
        assert!(config.supports_streaming);
        assert!(config.supports_cursor);
        assert_eq!(config.timeout_ms, 60000);
    }

    #[test]
    fn test_fetch_request_builder() {
        let req = FetchRequest::new()
            .query("filter", "active")
            .cursor("page-2")
            .limit(50);

        assert_eq!(req.query.get("filter").unwrap(), "active");
        assert_eq!(req.cursor, Some("page-2".to_string()));
        assert_eq!(req.limit, Some(50));
    }

    #[test]
    fn test_fetch_response_builder() {
        let resp: FetchResponse<String> =
            FetchResponse::items(vec!["a".to_string(), "b".to_string()])
                .with_cursor("next-token")
                .with_total(100)
                .with_metadata("source", "database");

        assert_eq!(resp.items.len(), 2);
        assert_eq!(resp.next_cursor, Some("next-token".to_string()));
        assert!(resp.has_more);
        assert_eq!(resp.total_count, Some(100));
        assert_eq!(resp.metadata.get("source").unwrap(), "database");
    }
}

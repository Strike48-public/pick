//! SINK behavior connector for push-based data export.
//!
//! SINK connectors write data to external destinations (databases, APIs, files).
//! They support batching and idempotent writes.
//!
//! # Example
//!
//! ```rust,ignore
//! use strike48_connector::behaviors::sink::*;
//! use async_trait::async_trait;
//!
//! struct DatabaseSink {
//!     config: SinkConfig,
//! }
//!
//! #[async_trait]
//! impl SinkConnector for DatabaseSink {
//!     type Item = serde_json::Value;
//!
//!     async fn write(&self, items: Vec<Self::Item>) -> WriteResult {
//!         // Write items to database
//!         WriteResult::success(items.len())
//!     }
//!
//!     fn sink_config(&self) -> &SinkConfig {
//!         &self.config
//!     }
//! }
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Sink Configuration
// =============================================================================

/// Configuration for sink connectors.
#[derive(Debug, Clone)]
pub struct SinkConfig {
    /// Maximum number of concurrent requests.
    pub max_concurrent_requests: usize,

    /// Whether batching is enabled.
    pub batching_enabled: bool,

    /// Maximum batch size.
    pub batch_size: usize,

    /// Batch timeout in milliseconds.
    pub batch_timeout_ms: u64,

    /// Whether writes are idempotent (safe to retry).
    pub is_idempotent: bool,

    /// Timeout for sink operations in milliseconds.
    pub timeout_ms: u64,
}

impl Default for SinkConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 1000,
            batching_enabled: false,
            batch_size: 1000,
            batch_timeout_ms: 100,
            is_idempotent: false,
            timeout_ms: 5000, // 5 seconds for fast writes
        }
    }
}

impl SinkConfig {
    /// Create a new sink config with defaults.
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

    /// Mark writes as idempotent.
    pub fn idempotent(mut self) -> Self {
        self.is_idempotent = true;
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
// Write Result
// =============================================================================

/// Result of a write operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResult {
    /// Whether the write succeeded.
    pub success: bool,

    /// Number of items written.
    pub items_written: usize,

    /// Number of items that failed.
    pub items_failed: usize,

    /// Error message if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Per-item errors (if tracking individual failures).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub item_errors: Vec<ItemError>,

    /// Metadata about the write.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

/// Error for a specific item in a batch write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemError {
    /// Index of the failed item in the batch.
    pub index: usize,

    /// Error message.
    pub error: String,

    /// Whether this item can be retried.
    #[serde(default)]
    pub retryable: bool,
}

impl WriteResult {
    /// Create a successful write result.
    pub fn success(items_written: usize) -> Self {
        Self {
            success: true,
            items_written,
            items_failed: 0,
            error: None,
            item_errors: vec![],
            metadata: HashMap::new(),
        }
    }

    /// Create a failed write result.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            items_written: 0,
            items_failed: 0,
            error: Some(error.into()),
            item_errors: vec![],
            metadata: HashMap::new(),
        }
    }

    /// Create a partial success result.
    pub fn partial(items_written: usize, items_failed: usize) -> Self {
        Self {
            success: items_failed == 0,
            items_written,
            items_failed,
            error: None,
            item_errors: vec![],
            metadata: HashMap::new(),
        }
    }

    /// Add an item error.
    pub fn with_item_error(
        mut self,
        index: usize,
        error: impl Into<String>,
        retryable: bool,
    ) -> Self {
        self.item_errors.push(ItemError {
            index,
            error: error.into(),
            retryable,
        });
        self.items_failed += 1;
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

// =============================================================================
// Sink Connector Trait
// =============================================================================

/// Trait for SINK behavior connectors.
///
/// SINK connectors push data to external destinations. They support batching
/// and can be marked as idempotent for safe retries.
///
/// # Associated Type
///
/// - `Item`: The type of items written by this sink.
///
/// # Required Methods
///
/// - `write()`: Write items to the destination.
/// - `sink_config()`: Return the sink configuration.
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::behaviors::sink::*;
///
/// struct MySink {
///     config: SinkConfig,
/// }
///
/// #[async_trait]
/// impl SinkConnector for MySink {
///     type Item = MyDataType;
///
///     async fn write(&self, items: Vec<Self::Item>) -> WriteResult {
///         // Write items to destination
///         match write_to_api(&items).await {
///             Ok(count) => WriteResult::success(count),
///             Err(e) => WriteResult::failure(e.to_string()),
///         }
///     }
///
///     fn sink_config(&self) -> &SinkConfig {
///         &self.config
///     }
/// }
/// ```
#[async_trait]
pub trait SinkConnector: Send + Sync {
    /// The type of items written by this sink.
    type Item: Send + for<'de> Deserialize<'de>;

    /// Write items to the destination.
    async fn write(&self, items: Vec<Self::Item>) -> WriteResult;

    /// Return the sink configuration.
    fn sink_config(&self) -> &SinkConfig;

    /// Write a single item (convenience method).
    async fn write_one(&self, item: Self::Item) -> WriteResult {
        self.write(vec![item]).await
    }

    /// Return sink-specific metadata for registration.
    fn sink_metadata(&self) -> HashMap<String, String> {
        let config = self.sink_config();
        let mut meta = HashMap::new();
        meta.insert(
            "supports_batching".to_string(),
            config.batching_enabled.to_string(),
        );
        meta.insert("max_batch_size".to_string(), config.batch_size.to_string());
        meta.insert(
            "is_idempotent".to_string(),
            config.is_idempotent.to_string(),
        );
        meta.insert(
            "batching_enabled".to_string(),
            config.batching_enabled.to_string(),
        );
        meta.insert("timeout_ms".to_string(), config.timeout_ms.to_string());
        meta
    }

    /// Timeout in milliseconds.
    fn timeout_ms(&self) -> u64 {
        self.sink_config().timeout_ms
    }
}

/// Marker trait for idempotent sinks.
///
/// Implement this trait to indicate that writes are safe to retry.
/// This is used by Strike48 for automatic retry logic.
pub trait IdempotentSink: SinkConnector {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sink_config_builder() {
        let config = SinkConfig::new()
            .with_batching(500)
            .with_batch_timeout(200)
            .idempotent()
            .with_timeout(10000);

        assert!(config.batching_enabled);
        assert_eq!(config.batch_size, 500);
        assert_eq!(config.batch_timeout_ms, 200);
        assert!(config.is_idempotent);
        assert_eq!(config.timeout_ms, 10000);
    }

    #[test]
    fn test_write_result_success() {
        let result = WriteResult::success(100);
        assert!(result.success);
        assert_eq!(result.items_written, 100);
        assert_eq!(result.items_failed, 0);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_write_result_failure() {
        let result = WriteResult::failure("Connection failed");
        assert!(!result.success);
        assert_eq!(result.items_written, 0);
        assert_eq!(result.error, Some("Connection failed".to_string()));
    }

    #[test]
    fn test_write_result_partial() {
        let result = WriteResult::partial(80, 20)
            .with_item_error(5, "Duplicate key", true)
            .with_item_error(10, "Invalid format", false);

        assert!(!result.success);
        assert_eq!(result.items_written, 80);
        assert_eq!(result.items_failed, 22); // 20 + 2 added
        assert_eq!(result.item_errors.len(), 2);
        assert!(result.item_errors[0].retryable);
        assert!(!result.item_errors[1].retryable);
    }
}

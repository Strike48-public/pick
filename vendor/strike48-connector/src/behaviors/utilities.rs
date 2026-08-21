//! Utility types and functions for connector development.
//!
//! This module provides Rust-idiomatic utilities for:
//! - **Caching**: TTL-based caching with async support
//! - **Timing**: Execution timing and metrics
//! - **Validation**: JSON Schema validation via schemars
//! - **Retry**: Retry with exponential backoff (already in utils.rs)
//!
//! # Examples
//!
//! ## Caching
//!
//! ```rust,ignore
//! use strike48_connector::behaviors::Cache;
//! use std::time::Duration;
//!
//! let cache: Cache<String, User> = Cache::new(Duration::from_secs(60));
//!
//! // Get or insert with async factory
//! let user = cache.get_or_insert("user-123".to_string(), || async {
//!     fetch_user_from_db("user-123").await
//! }).await;
//! ```
//!
//! ## Timing
//!
//! ```rust,ignore
//! use strike48_connector::behaviors::Timer;
//!
//! let timer = Timer::start("database_query");
//! // ... do work ...
//! let elapsed = timer.stop();  // Logs and returns duration
//! ```
//!
//! ## Validation
//!
//! ```rust,ignore
//! use strike48_connector::behaviors::{validate_json, ValidationError};
//! use schemars::JsonSchema;
//!
//! #[derive(Deserialize, JsonSchema)]
//! struct QueryParams {
//!     query: String,
//!     limit: Option<u32>,
//! }
//!
//! let value: serde_json::Value = get_input();
//! let params: QueryParams = validate_json::<QueryParams>(&value)?;
//! ```

use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

// ============================================================================
// CACHING
// ============================================================================

/// A simple TTL-based cache for async operations.
///
/// This cache stores values with an expiration time and automatically
/// evicts expired entries on access.
///
/// # Example
///
/// ```rust
/// use strike48_connector::behaviors::Cache;
/// use std::time::Duration;
///
/// let cache: Cache<String, i32> = Cache::new(Duration::from_secs(60));
///
/// // Insert a value
/// cache.insert("key".to_string(), 42);
///
/// // Get a value
/// if let Some(value) = cache.get(&"key".to_string()) {
///     println!("Got: {}", value);
/// }
/// ```
#[derive(Debug)]
pub struct Cache<K, V> {
    entries: Arc<RwLock<HashMap<K, CacheEntry<V>>>>,
    ttl: Duration,
    stats: CacheStats,
}

#[derive(Debug, Clone)]
struct CacheEntry<V> {
    value: V,
    expires_at: Instant,
}

/// Cache statistics
#[derive(Debug, Default)]
pub struct CacheStats {
    hits: AtomicU64,
    misses: AtomicU64,
    insertions: AtomicU64,
    evictions: AtomicU64,
}

impl CacheStats {
    /// Get the number of cache hits
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Get the number of cache misses
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Get the hit rate as a percentage
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits() as f64;
        let total = hits + self.misses() as f64;
        if total == 0.0 {
            0.0
        } else {
            hits / total * 100.0
        }
    }

    /// Get total insertions
    pub fn insertions(&self) -> u64 {
        self.insertions.load(Ordering::Relaxed)
    }

    /// Get total evictions
    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }
}

impl<K: Eq + Hash + Clone, V: Clone> Cache<K, V> {
    /// Create a new cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            stats: CacheStats::default(),
        }
    }

    /// Insert a value into the cache.
    pub fn insert(&self, key: K, value: V) {
        let entry = CacheEntry {
            value,
            expires_at: Instant::now() + self.ttl,
        };

        let mut entries = self.entries.write().unwrap();
        entries.insert(key, entry);
        self.stats.insertions.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a value from the cache.
    ///
    /// Returns `None` if the key doesn't exist or has expired.
    pub fn get(&self, key: &K) -> Option<V> {
        let entries = self.entries.read().unwrap();

        if let Some(entry) = entries.get(key)
            && Instant::now() < entry.expires_at
        {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entry.value.clone());
        }

        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Get a value from the cache, or insert it if not present.
    ///
    /// The factory function is only called if the key is missing or expired.
    pub fn get_or_insert_with<F>(&self, key: K, factory: F) -> V
    where
        F: FnOnce() -> V,
    {
        // Try to get first (read lock)
        if let Some(value) = self.get(&key) {
            return value;
        }

        // Need to insert (write lock)
        let mut entries = self.entries.write().unwrap();

        // Double-check after acquiring write lock
        if let Some(entry) = entries.get(&key)
            && Instant::now() < entry.expires_at
        {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            return entry.value.clone();
        }

        // Create and insert
        let value = factory();
        let entry = CacheEntry {
            value: value.clone(),
            expires_at: Instant::now() + self.ttl,
        };
        entries.insert(key, entry);
        self.stats.insertions.fetch_add(1, Ordering::Relaxed);

        value
    }

    /// Get a value from the cache, or insert it asynchronously if not present.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let user = cache.get_or_insert("user-123".to_string(), || async {
    ///     fetch_user_from_db("user-123").await
    /// }).await;
    /// ```
    pub async fn get_or_insert<F, Fut>(&self, key: K, factory: F) -> V
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V>,
    {
        // Try to get first
        if let Some(value) = self.get(&key) {
            return value;
        }

        // Create value asynchronously
        let value = factory().await;

        // Insert
        self.insert(key, value.clone());

        value
    }

    /// Remove a value from the cache.
    pub fn remove(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.write().unwrap();
        entries.remove(key).map(|entry| {
            self.stats.evictions.fetch_add(1, Ordering::Relaxed);
            entry.value
        })
    }

    /// Clear all entries from the cache.
    pub fn clear(&self) {
        let mut entries = self.entries.write().unwrap();
        let count = entries.len() as u64;
        entries.clear();
        self.stats.evictions.fetch_add(count, Ordering::Relaxed);
    }

    /// Remove expired entries from the cache.
    pub fn evict_expired(&self) {
        let mut entries = self.entries.write().unwrap();
        let now = Instant::now();
        let before = entries.len();
        entries.retain(|_, entry| entry.expires_at > now);
        let evicted = before - entries.len();
        self.stats
            .evictions
            .fetch_add(evicted as u64, Ordering::Relaxed);
    }

    /// Get the number of entries in the cache.
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get cache statistics.
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }
}

impl<K, V> Clone for Cache<K, V> {
    fn clone(&self) -> Self {
        Self {
            entries: Arc::clone(&self.entries),
            ttl: self.ttl,
            stats: CacheStats::default(), // Stats are per-instance
        }
    }
}

// ============================================================================
// TIMING
// ============================================================================

/// A timer for measuring execution duration.
///
/// When dropped, logs the elapsed time using the `tracing` crate.
///
/// # Example
///
/// ```rust
/// use strike48_connector::behaviors::Timer;
///
/// fn do_work() {
///     let _timer = Timer::start("expensive_operation");
///     // Work happens here...
///     // Timer logs duration when it goes out of scope
/// }
///
/// // Or manually stop:
/// fn do_work_manual() {
///     let timer = Timer::start("query");
///     // ... work ...
///     let elapsed = timer.stop();
///     println!("Query took {:?}", elapsed);
/// }
/// ```
pub struct Timer {
    label: String,
    start: Instant,
    stopped: bool,
}

impl Timer {
    /// Start a new timer with the given label.
    pub fn start(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            start: Instant::now(),
            stopped: false,
        }
    }

    /// Stop the timer and return the elapsed duration.
    ///
    /// Also logs the duration at debug level.
    pub fn stop(mut self) -> Duration {
        self.stopped = true;
        let elapsed = self.start.elapsed();
        debug!(
            label = %self.label,
            elapsed_ms = elapsed.as_millis() as u64,
            "Timer completed"
        );
        elapsed
    }

    /// Get the elapsed time without stopping the timer.
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if !self.stopped {
            let elapsed = self.start.elapsed();
            debug!(
                label = %self.label,
                elapsed_ms = elapsed.as_millis() as u64,
                "Timer completed (on drop)"
            );
        }
    }
}

/// Execute an async function with timing.
///
/// # Example
///
/// ```rust,ignore
/// let (result, duration) = timed("fetch_users", fetch_users()).await;
/// ```
pub async fn timed<F, T>(label: &str, future: F) -> (T, Duration)
where
    F: Future<Output = T>,
{
    let start = Instant::now();
    let result = future.await;
    let elapsed = start.elapsed();

    debug!(
        label = %label,
        elapsed_ms = elapsed.as_millis() as u64,
        "Operation completed"
    );

    (result, elapsed)
}

/// Execution metrics for tracking operation performance.
#[derive(Debug, Default)]
pub struct OperationMetrics {
    /// Total number of operations
    pub total: AtomicU64,
    /// Number of successful operations
    pub success: AtomicU64,
    /// Number of failed operations
    pub failure: AtomicU64,
    /// Total time in microseconds
    pub total_time_us: AtomicU64,
    /// Minimum time in microseconds
    pub min_time_us: AtomicU64,
    /// Maximum time in microseconds
    pub max_time_us: AtomicU64,
}

impl OperationMetrics {
    /// Create new metrics
    pub fn new() -> Self {
        Self {
            min_time_us: AtomicU64::new(u64::MAX),
            ..Default::default()
        }
    }

    /// Record a successful operation with the given duration.
    pub fn record_success(&self, duration: Duration) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.success.fetch_add(1, Ordering::Relaxed);
        self.record_time(duration);
    }

    /// Record a failed operation with the given duration.
    pub fn record_failure(&self, duration: Duration) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.failure.fetch_add(1, Ordering::Relaxed);
        self.record_time(duration);
    }

    fn record_time(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.total_time_us.fetch_add(us, Ordering::Relaxed);

        // Update min (relaxed because we don't need strict ordering)
        let mut current_min = self.min_time_us.load(Ordering::Relaxed);
        while us < current_min {
            match self.min_time_us.compare_exchange_weak(
                current_min,
                us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new) => current_min = new,
            }
        }

        // Update max
        let mut current_max = self.max_time_us.load(Ordering::Relaxed);
        while us > current_max {
            match self.max_time_us.compare_exchange_weak(
                current_max,
                us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new) => current_max = new,
            }
        }
    }

    /// Get the average operation time in milliseconds.
    pub fn avg_time_ms(&self) -> f64 {
        let total = self.total.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let total_us = self.total_time_us.load(Ordering::Relaxed);
        (total_us as f64 / total as f64) / 1000.0
    }

    /// Get the success rate as a percentage.
    pub fn success_rate(&self) -> f64 {
        let total = self.total.load(Ordering::Relaxed);
        if total == 0 {
            return 100.0;
        }
        let success = self.success.load(Ordering::Relaxed);
        (success as f64 / total as f64) * 100.0
    }

    /// Export metrics as a map.
    pub fn to_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert(
            "total".to_string(),
            self.total.load(Ordering::Relaxed).to_string(),
        );
        map.insert(
            "success".to_string(),
            self.success.load(Ordering::Relaxed).to_string(),
        );
        map.insert(
            "failure".to_string(),
            self.failure.load(Ordering::Relaxed).to_string(),
        );
        map.insert(
            "avg_time_ms".to_string(),
            format!("{:.2}", self.avg_time_ms()),
        );
        map.insert(
            "success_rate".to_string(),
            format!("{:.2}", self.success_rate()),
        );

        let min_us = self.min_time_us.load(Ordering::Relaxed);
        if min_us != u64::MAX {
            map.insert(
                "min_time_ms".to_string(),
                format!("{:.2}", min_us as f64 / 1000.0),
            );
        }

        let max_us = self.max_time_us.load(Ordering::Relaxed);
        map.insert(
            "max_time_ms".to_string(),
            format!("{:.2}", max_us as f64 / 1000.0),
        );

        map
    }
}

// ============================================================================
// VALIDATION
// ============================================================================

/// Error returned when JSON validation fails.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Error messages describing what failed
    pub errors: Vec<String>,
    /// The path in the JSON where the error occurred
    pub path: Option<String>,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Validation failed: {}", self.errors.join(", "))
    }
}

impl std::error::Error for ValidationError {}

impl ValidationError {
    /// Create a new validation error
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            errors: vec![error.into()],
            path: None,
        }
    }

    /// Create a validation error with multiple errors
    pub fn multiple(errors: Vec<String>) -> Self {
        Self { errors, path: None }
    }

    /// Add a path to the error
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }
}

/// Validate a JSON value against a type that implements `schemars::JsonSchema`.
///
/// This uses the type's JSON Schema to validate the input and returns
/// a deserialized value if successful.
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::behaviors::validate_json;
/// use schemars::JsonSchema;
/// use serde::Deserialize;
///
/// #[derive(Deserialize, JsonSchema)]
/// struct QueryParams {
///     query: String,
///     limit: Option<u32>,
/// }
///
/// let value = serde_json::json!({
///     "query": "SELECT * FROM users",
///     "limit": 100
/// });
///
/// let params: QueryParams = validate_json::<QueryParams>(&value)?;
/// ```
pub fn validate_json<T>(value: &serde_json::Value) -> Result<T, ValidationError>
where
    T: DeserializeOwned + schemars::JsonSchema,
{
    // First, try to deserialize
    match serde_json::from_value::<T>(value.clone()) {
        Ok(result) => Ok(result),
        Err(e) => Err(ValidationError::new(format!("Deserialization failed: {e}"))),
    }
}

/// Validate a JSON value against a provided JSON Schema.
///
/// # Example
///
/// ```rust
/// use strike48_connector::behaviors::validate_against_schema;
///
/// let schema = serde_json::json!({
///     "type": "object",
///     "required": ["name"],
///     "properties": {
///         "name": { "type": "string" },
///         "age": { "type": "number" }
///     }
/// });
///
/// let valid_value = serde_json::json!({ "name": "Alice", "age": 30 });
/// assert!(validate_against_schema(&valid_value, &schema).is_ok());
///
/// let invalid_value = serde_json::json!({ "age": 30 });
/// assert!(validate_against_schema(&invalid_value, &schema).is_err());
/// ```
pub fn validate_against_schema(
    value: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), ValidationError> {
    let mut errors = Vec::new();

    // Check type
    if let Some(expected_type) = schema.get("type").and_then(|t| t.as_str()) {
        let actual_type = json_type(value);
        if actual_type != expected_type {
            errors.push(format!("Expected type {expected_type}, got {actual_type}"));
        }
    }

    // Check required fields
    if let Some(required) = schema.get("required").and_then(|r| r.as_array())
        && let Some(obj) = value.as_object()
    {
        for field in required {
            if let Some(field_name) = field.as_str()
                && !obj.contains_key(field_name)
            {
                errors.push(format!("Missing required field: {field_name}"));
            }
        }
    }

    // Check property types
    if let (Some(properties), Some(obj)) = (
        schema.get("properties").and_then(|p| p.as_object()),
        value.as_object(),
    ) {
        for (key, prop_schema) in properties {
            if let Some(prop_value) = obj.get(key)
                && let Some(expected_type) = prop_schema.get("type").and_then(|t| t.as_str())
            {
                let actual_type = json_type(prop_value);
                if actual_type != expected_type {
                    errors.push(format!(
                        "Field '{key}': expected type {expected_type}, got {actual_type}"
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ValidationError::multiple(errors))
    }
}

/// Get the JSON type name for a value.
fn json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// ============================================================================
// RETRY (Re-export from utils with better documentation)
// ============================================================================

/// Configuration for retry operations.
///
/// # Example
///
/// ```rust
/// use strike48_connector::behaviors::RetryConfig;
/// use std::time::Duration;
///
/// let config = RetryConfig::new()
///     .with_max_attempts(5)
///     .with_initial_delay(Duration::from_millis(100))
///     .with_exponential_backoff()
///     .with_max_delay(Duration::from_secs(30));
/// ```
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of attempts (default: 3)
    pub max_attempts: usize,
    /// Initial delay between retries (default: 1s)
    pub initial_delay: Duration,
    /// Whether to use exponential backoff (default: true)
    pub exponential: bool,
    /// Maximum delay between retries (default: 30s)
    pub max_delay: Duration,
    /// Jitter factor (0.0 - 1.0) to add randomness to delays (default: 0.1)
    pub jitter: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_secs(1),
            exponential: true,
            max_delay: Duration::from_secs(30),
            jitter: 0.1,
        }
    }
}

impl RetryConfig {
    /// Create a new retry config with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum attempts.
    pub fn with_max_attempts(mut self, attempts: usize) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Set initial delay.
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Enable exponential backoff.
    pub fn with_exponential_backoff(mut self) -> Self {
        self.exponential = true;
        self
    }

    /// Use fixed delay instead of exponential backoff.
    pub fn with_fixed_delay(mut self) -> Self {
        self.exponential = false;
        self
    }

    /// Set maximum delay.
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Set jitter factor.
    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter.clamp(0.0, 1.0);
        self
    }

    /// Calculate the delay for a given attempt number (1-indexed).
    pub fn delay_for_attempt(&self, attempt: usize) -> Duration {
        let base_delay = if self.exponential {
            self.initial_delay * 2_u32.saturating_pow(attempt.saturating_sub(1) as u32)
        } else {
            self.initial_delay
        };

        // Apply max delay cap
        let capped = std::cmp::min(base_delay, self.max_delay);

        // Apply jitter
        if self.jitter > 0.0 {
            let jitter_amount = capped.as_millis() as f64 * self.jitter;
            let random_jitter = rand::random::<f64>() * jitter_amount * 2.0 - jitter_amount;
            let jittered_ms = (capped.as_millis() as f64 + random_jitter).max(0.0);
            Duration::from_millis(jittered_ms as u64)
        } else {
            capped
        }
    }
}

/// Execute an async operation with retry logic.
///
/// # Example
///
/// ```rust,ignore
/// use strike48_connector::behaviors::{retry_async, RetryConfig};
///
/// let config = RetryConfig::new().with_max_attempts(3);
///
/// let result = retry_async(config, || async {
///     fetch_from_api().await
/// }).await?;
/// ```
pub async fn retry_async<F, Fut, T, E>(config: RetryConfig, mut operation: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    let mut last_error = None;

    for attempt in 1..=config.max_attempts {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                warn!(
                    attempt = attempt,
                    max_attempts = config.max_attempts,
                    error = ?e,
                    "Operation failed, will retry"
                );

                last_error = Some(e);

                // Don't delay after the last attempt
                if attempt < config.max_attempts {
                    let delay = config.delay_for_attempt(attempt);
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    Err(last_error.expect("At least one attempt must have failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cache tests
    #[test]
    fn test_cache_insert_and_get() {
        let cache: Cache<String, i32> = Cache::new(Duration::from_secs(60));

        cache.insert("key".to_string(), 42);
        assert_eq!(cache.get(&"key".to_string()), Some(42));
        assert_eq!(cache.get(&"missing".to_string()), None);
    }

    #[test]
    fn test_cache_expiry() {
        let cache: Cache<String, i32> = Cache::new(Duration::from_millis(10));

        cache.insert("key".to_string(), 42);
        assert_eq!(cache.get(&"key".to_string()), Some(42));

        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(cache.get(&"key".to_string()), None);
    }

    #[test]
    fn test_cache_get_or_insert_with() {
        let cache: Cache<String, i32> = Cache::new(Duration::from_secs(60));

        let value = cache.get_or_insert_with("key".to_string(), || 42);
        assert_eq!(value, 42);

        // Second call should return cached value
        let value = cache.get_or_insert_with("key".to_string(), || 100);
        assert_eq!(value, 42);

        assert_eq!(cache.stats().hits(), 1);
        assert_eq!(cache.stats().misses(), 1);
    }

    #[tokio::test]
    async fn test_cache_get_or_insert_async() {
        let cache: Cache<String, i32> = Cache::new(Duration::from_secs(60));

        let value = cache
            .get_or_insert("key".to_string(), || async { 42 })
            .await;
        assert_eq!(value, 42);
    }

    // Timer tests
    #[test]
    fn test_timer_elapsed() {
        let timer = Timer::start("test");
        std::thread::sleep(Duration::from_millis(10));
        let elapsed = timer.elapsed();
        assert!(elapsed >= Duration::from_millis(10));
    }

    // Metrics tests
    #[test]
    fn test_operation_metrics() {
        let metrics = OperationMetrics::new();

        metrics.record_success(Duration::from_millis(100));
        metrics.record_success(Duration::from_millis(200));
        metrics.record_failure(Duration::from_millis(50));

        assert_eq!(metrics.total.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.success.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.failure.load(Ordering::Relaxed), 1);
        assert!((metrics.avg_time_ms() - 116.67).abs() < 1.0);
        assert!((metrics.success_rate() - 66.67).abs() < 1.0);
    }

    // Validation tests
    #[test]
    fn test_validate_against_schema_valid() {
        let schema = serde_json::json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" },
                "age": { "type": "number" }
            }
        });

        let value = serde_json::json!({ "name": "Alice", "age": 30 });
        assert!(validate_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn test_validate_against_schema_missing_required() {
        let schema = serde_json::json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        });

        let value = serde_json::json!({ "age": 30 });
        let result = validate_against_schema(&value, &schema);
        assert!(result.is_err());
        assert!(result.unwrap_err().errors[0].contains("Missing required field"));
    }

    #[test]
    fn test_validate_against_schema_wrong_type() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "age": { "type": "number" }
            }
        });

        let value = serde_json::json!({ "age": "thirty" });
        let result = validate_against_schema(&value, &schema);
        assert!(result.is_err());
    }

    // Retry config tests
    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::new();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_delay, Duration::from_secs(1));
        assert!(config.exponential);
    }

    #[test]
    fn test_retry_config_delay_calculation() {
        let config = RetryConfig::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_jitter(0.0); // Disable jitter for deterministic test

        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(100));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(200));
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(400));
    }

    #[test]
    fn test_retry_config_max_delay() {
        let config = RetryConfig::new()
            .with_initial_delay(Duration::from_secs(10))
            .with_max_delay(Duration::from_secs(20))
            .with_jitter(0.0);

        // Attempt 3 would be 40s (10 * 2^2), but capped at 20s
        assert_eq!(config.delay_for_attempt(3), Duration::from_secs(20));
    }

    #[tokio::test]
    async fn test_retry_async_success() {
        let config = RetryConfig::new().with_max_attempts(3);
        let mut attempts = 0;

        let result = retry_async(config, || {
            attempts += 1;
            async move {
                if attempts < 2 {
                    Err::<i32, _>("not yet")
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert_eq!(result, Ok(42));
        assert_eq!(attempts, 2);
    }

    #[tokio::test]
    async fn test_retry_async_exhausted() {
        let config = RetryConfig::new()
            .with_max_attempts(2)
            .with_initial_delay(Duration::from_millis(1));

        let mut attempts = 0;

        let result: Result<i32, &str> = retry_async(config, || {
            attempts += 1;
            async move { Err("always fails") }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(attempts, 2);
    }
}

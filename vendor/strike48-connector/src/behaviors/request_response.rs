//! Request-Response Connector Behavior
//!
//! Provides traits and types for implementing synchronous RPC-style operations
//! with concurrency control.
//!
//! # Examples
//!
//! ```rust,ignore
//! use strike48_connector::behaviors::{
//!     RequestResponseConnector, RequestResponseConfig, RequestContext, Response,
//! };
//!
//! struct DatabaseConnector {
//!     config: RequestResponseConfig,
//!     pool: sqlx::PgPool,
//! }
//!
//! #[async_trait]
//! impl RequestResponseConnector for DatabaseConnector {
//!     type Request = SqlQuery;
//!     type Response = QueryResult;
//!     type Error = sqlx::Error;
//!     
//!     async fn handle(&self, ctx: RequestContext<Self::Request>) -> Result<Self::Response, Self::Error> {
//!         let result = sqlx::query(&ctx.request.sql)
//!             .fetch_all(&self.pool)
//!             .await?;
//!         Ok(QueryResult { rows: result })
//!     }
//! }
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Configuration for RequestResponse connectors
#[derive(Debug, Clone)]
pub struct RequestResponseConfig {
    /// Maximum concurrent requests
    pub max_concurrent: usize,
    /// Default timeout for operations
    pub timeout: Duration,
    /// Whether to track metrics
    pub track_metrics: bool,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl Default for RequestResponseConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 1000,
            timeout: Duration::from_secs(5),
            track_metrics: true,
            metadata: HashMap::new(),
        }
    }
}

impl RequestResponseConfig {
    /// Create a new config with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum concurrent requests
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Disable metrics tracking
    pub fn without_metrics(mut self) -> Self {
        self.track_metrics = false;
        self
    }

    /// Add custom metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Build metadata map for connector registration
    pub fn to_metadata(&self) -> HashMap<String, String> {
        let mut meta = self.metadata.clone();
        meta.insert(
            "timeout_ms".to_string(),
            self.timeout.as_millis().to_string(),
        );
        meta.insert(
            "max_concurrent".to_string(),
            self.max_concurrent.to_string(),
        );
        meta
    }
}

/// Context provided to request handlers
#[derive(Debug, Clone)]
pub struct RequestContext<T> {
    /// The request payload
    pub request: T,
    /// Unique request ID
    pub request_id: String,
    /// Request headers/metadata
    pub headers: HashMap<String, String>,
    /// When the request was received
    pub received_at: Instant,
    /// Timeout for this request
    pub timeout: Duration,
}

impl<T> RequestContext<T> {
    /// Create a new request context
    pub fn new(request: T) -> Self {
        Self {
            request,
            request_id: uuid::Uuid::new_v4().to_string(),
            headers: HashMap::new(),
            received_at: Instant::now(),
            timeout: Duration::from_secs(5),
        }
    }

    /// Set the request ID
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = id.into();
        self
    }

    /// Add a header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get remaining time before timeout
    pub fn remaining_time(&self) -> Duration {
        let elapsed = self.received_at.elapsed();
        self.timeout.saturating_sub(elapsed)
    }

    /// Check if the request has timed out
    pub fn is_timed_out(&self) -> bool {
        self.received_at.elapsed() >= self.timeout
    }

    /// Map the request to a different type
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> RequestContext<U> {
        RequestContext {
            request: f(self.request),
            request_id: self.request_id,
            headers: self.headers,
            received_at: self.received_at,
            timeout: self.timeout,
        }
    }
}

/// Response wrapper with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response<T> {
    /// The response payload
    pub data: T,
    /// Response metadata
    pub metadata: HashMap<String, String>,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
}

impl<T> Response<T> {
    /// Create a new response
    pub fn new(data: T) -> Self {
        Self {
            data,
            metadata: HashMap::new(),
            processing_time_ms: 0,
        }
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set processing time
    pub fn with_processing_time(mut self, duration: Duration) -> Self {
        self.processing_time_ms = duration.as_millis() as u64;
        self
    }

    /// Map the response data
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Response<U> {
        Response {
            data: f(self.data),
            metadata: self.metadata,
            processing_time_ms: self.processing_time_ms,
        }
    }
}

/// Metrics for request/response operations
#[derive(Debug, Default)]
pub struct RequestMetrics {
    /// Total requests processed
    pub total_requests: AtomicU64,
    /// Successful requests
    pub successful_requests: AtomicU64,
    /// Failed requests
    pub failed_requests: AtomicU64,
    /// Total processing time in microseconds
    pub total_processing_time_us: AtomicU64,
    /// Currently in-flight requests
    pub in_flight: AtomicU64,
}

impl RequestMetrics {
    /// Create new metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request starting
    pub fn start_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.in_flight.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful request completion
    pub fn complete_success(&self, duration: Duration) {
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
        self.total_processing_time_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a failed request
    pub fn complete_failure(&self, duration: Duration) {
        self.failed_requests.fetch_add(1, Ordering::Relaxed);
        self.total_processing_time_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get average processing time in milliseconds
    pub fn avg_processing_time_ms(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let total_us = self.total_processing_time_us.load(Ordering::Relaxed);
        (total_us as f64 / total as f64) / 1000.0
    }

    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 100.0;
        }
        let successful = self.successful_requests.load(Ordering::Relaxed);
        (successful as f64 / total as f64) * 100.0
    }

    /// Export metrics as a map
    pub fn to_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert(
            "total_requests".to_string(),
            self.total_requests.load(Ordering::Relaxed).to_string(),
        );
        map.insert(
            "successful_requests".to_string(),
            self.successful_requests.load(Ordering::Relaxed).to_string(),
        );
        map.insert(
            "failed_requests".to_string(),
            self.failed_requests.load(Ordering::Relaxed).to_string(),
        );
        map.insert(
            "avg_processing_time_ms".to_string(),
            format!("{:.2}", self.avg_processing_time_ms()),
        );
        map.insert(
            "success_rate".to_string(),
            format!("{:.2}", self.success_rate()),
        );
        map.insert(
            "in_flight".to_string(),
            self.in_flight.load(Ordering::Relaxed).to_string(),
        );
        map
    }
}

/// RequestResponse connector trait
///
/// Implement this trait to create connectors that handle synchronous
/// RPC-style operations with built-in concurrency control.
#[async_trait]
pub trait RequestResponseConnector: Send + Sync {
    /// The request type this connector handles
    type Request: Send + Sync + 'static;

    /// The response type this connector returns
    type Response: Send + Sync + 'static;

    /// The error type for connector operations
    type Error: std::error::Error + Send + Sync + 'static;

    /// Get the connector configuration
    fn config(&self) -> &RequestResponseConfig;

    /// Handle a request
    ///
    /// This is the main method to implement. It receives a request context
    /// and should return a response or error.
    async fn handle(
        &self,
        ctx: RequestContext<Self::Request>,
    ) -> Result<Self::Response, Self::Error>;

    /// Called before each request (for logging, validation, etc.)
    ///
    /// Return `Err` to reject the request before processing.
    async fn before_request(
        &self,
        _ctx: &RequestContext<Self::Request>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called after each successful request (for logging, cleanup, etc.)
    async fn after_success(&self, _response: &Self::Response) {
        // Default: no-op
    }

    /// Called after a failed request (for logging, cleanup, etc.)
    async fn after_failure(&self, _error: &Self::Error) {
        // Default: no-op
    }

    /// Check if the connector is healthy
    async fn health_check(&self) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A wrapper that adds concurrency control to any RequestResponse connector
pub struct ConcurrentRequestHandler<C: RequestResponseConnector> {
    connector: C,
    semaphore: Arc<Semaphore>,
    metrics: Arc<RequestMetrics>,
}

impl<C: RequestResponseConnector> ConcurrentRequestHandler<C> {
    /// Create a new concurrent handler wrapping the given connector
    pub fn new(connector: C) -> Self {
        let max_concurrent = connector.config().max_concurrent;
        Self {
            connector,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            metrics: Arc::new(RequestMetrics::new()),
        }
    }

    /// Create with custom semaphore permits
    pub fn with_concurrency(connector: C, max_concurrent: usize) -> Self {
        Self {
            connector,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            metrics: Arc::new(RequestMetrics::new()),
        }
    }

    /// Handle a request with concurrency control
    pub async fn handle(
        &self,
        ctx: RequestContext<C::Request>,
    ) -> Result<Response<C::Response>, RequestError<C::Error>> {
        // Acquire permit
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| RequestError::Shutdown)?;

        let start = Instant::now();
        self.metrics.start_request();

        // Apply timeout
        let timeout_duration = ctx.timeout;
        let result = tokio::time::timeout(timeout_duration, async {
            // Before hook
            self.connector.before_request(&ctx).await?;

            // Handle request

            self.connector.handle(ctx).await
        })
        .await;

        let duration = start.elapsed();

        match result {
            Ok(Ok(response)) => {
                self.connector.after_success(&response).await;
                self.metrics.complete_success(duration);
                Ok(Response::new(response).with_processing_time(duration))
            }
            Ok(Err(e)) => {
                self.connector.after_failure(&e).await;
                self.metrics.complete_failure(duration);
                Err(RequestError::Handler(e))
            }
            Err(_) => {
                self.metrics.complete_failure(duration);
                Err(RequestError::Timeout)
            }
        }
    }

    /// Get current metrics
    pub fn metrics(&self) -> &RequestMetrics {
        &self.metrics
    }

    /// Get available permits
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Get access to the underlying connector
    pub fn connector(&self) -> &C {
        &self.connector
    }
}

/// Errors that can occur during request handling
#[derive(Debug)]
pub enum RequestError<E> {
    /// The request timed out
    Timeout,
    /// The connector is shutting down
    Shutdown,
    /// Error from the handler
    Handler(E),
}

impl<E: std::fmt::Display> std::fmt::Display for RequestError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "Request timed out"),
            Self::Shutdown => write!(f, "Connector is shutting down"),
            Self::Handler(e) => write!(f, "Handler error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for RequestError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Handler(e) => Some(e),
            _ => None,
        }
    }
}

/// A batch request for processing multiple items
#[derive(Debug, Clone)]
pub struct BatchRequest<T> {
    /// The items to process
    pub items: Vec<T>,
    /// Whether to stop on first error
    pub stop_on_error: bool,
    /// Maximum concurrent items
    pub max_concurrent: usize,
}

impl<T> BatchRequest<T> {
    /// Create a new batch request
    pub fn new(items: Vec<T>) -> Self {
        Self {
            items,
            stop_on_error: false,
            max_concurrent: 10,
        }
    }

    /// Stop processing on first error
    pub fn stop_on_error(mut self) -> Self {
        self.stop_on_error = true;
        self
    }

    /// Set max concurrent items
    pub fn with_concurrency(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }
}

/// Result of a batch operation
#[derive(Debug)]
pub struct BatchResponse<T, E> {
    /// Successful results
    pub successes: Vec<T>,
    /// Failed items with errors
    pub failures: Vec<(usize, E)>,
    /// Total processing time
    pub processing_time: Duration,
}

impl<T, E> BatchResponse<T, E> {
    /// Check if all items succeeded
    pub fn all_succeeded(&self) -> bool {
        self.failures.is_empty()
    }

    /// Get success count
    pub fn success_count(&self) -> usize {
        self.successes.len()
    }

    /// Get failure count
    pub fn failure_count(&self) -> usize {
        self.failures.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_response_config() {
        let config = RequestResponseConfig::new()
            .with_max_concurrent(500)
            .with_timeout(Duration::from_secs(10))
            .with_metadata("env", "test");

        assert_eq!(config.max_concurrent, 500);
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.metadata.get("env"), Some(&"test".to_string()));

        let meta = config.to_metadata();
        assert_eq!(meta.get("max_concurrent"), Some(&"500".to_string()));
    }

    #[test]
    fn test_request_context() {
        let ctx = RequestContext::new("test request")
            .with_id("req-123")
            .with_header("trace-id", "abc")
            .with_timeout(Duration::from_secs(30));

        assert_eq!(ctx.request, "test request");
        assert_eq!(ctx.request_id, "req-123");
        assert_eq!(ctx.headers.get("trace-id"), Some(&"abc".to_string()));
        assert_eq!(ctx.timeout, Duration::from_secs(30));
        assert!(!ctx.is_timed_out());
    }

    #[test]
    fn test_response() {
        let response = Response::new("success")
            .with_metadata("cached", "true")
            .with_processing_time(Duration::from_millis(50));

        assert_eq!(response.data, "success");
        assert_eq!(response.metadata.get("cached"), Some(&"true".to_string()));
        assert_eq!(response.processing_time_ms, 50);

        // Test map
        let mapped = response.map(|s| s.to_uppercase());
        assert_eq!(mapped.data, "SUCCESS");
    }

    #[test]
    fn test_request_metrics() {
        let metrics = RequestMetrics::new();

        metrics.start_request();
        metrics.complete_success(Duration::from_millis(100));

        metrics.start_request();
        metrics.complete_failure(Duration::from_millis(50));

        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.successful_requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.failed_requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.success_rate(), 50.0);
    }

    #[test]
    fn test_batch_request() {
        let batch = BatchRequest::new(vec![1, 2, 3, 4, 5])
            .stop_on_error()
            .with_concurrency(3);

        assert_eq!(batch.items.len(), 5);
        assert!(batch.stop_on_error);
        assert_eq!(batch.max_concurrent, 3);
    }

    #[tokio::test]
    async fn test_concurrent_handler() {
        struct EchoConnector {
            config: RequestResponseConfig,
        }

        #[async_trait]
        impl RequestResponseConnector for EchoConnector {
            type Request = String;
            type Response = String;
            type Error = std::io::Error;

            fn config(&self) -> &RequestResponseConfig {
                &self.config
            }

            async fn handle(
                &self,
                ctx: RequestContext<Self::Request>,
            ) -> Result<Self::Response, Self::Error> {
                Ok(format!("Echo: {}", ctx.request))
            }
        }

        let connector = EchoConnector {
            config: RequestResponseConfig::new().with_max_concurrent(10),
        };
        let handler = ConcurrentRequestHandler::new(connector);

        let ctx = RequestContext::new("hello".to_string());
        let response = handler.handle(ctx).await.unwrap();

        assert_eq!(response.data, "Echo: hello");
        assert!(response.processing_time_ms < 1000);

        assert_eq!(handler.metrics().total_requests.load(Ordering::Relaxed), 1);
        assert_eq!(
            handler
                .metrics()
                .successful_requests
                .load(Ordering::Relaxed),
            1
        );
    }
}

//! PubSub Connector Behavior
//!
//! Provides traits and types for implementing event streaming patterns with
//! topic-based publish/subscribe semantics.
//!
//! # Examples
//!
//! ```rust,ignore
//! use strike48_connector::behaviors::{
//!     PubSubConnector, PubSubConfig, TopicPattern, Message, Subscription,
//! };
//!
//! struct EventBusConnector {
//!     config: PubSubConfig,
//! }
//!
//! #[async_trait]
//! impl PubSubConnector for EventBusConnector {
//!     type Message = serde_json::Value;
//!     type Error = Box<dyn std::error::Error + Send + Sync>;
//!     
//!     async fn publish(&self, topic: &str, message: Self::Message) -> Result<(), Self::Error> {
//!         println!("Publishing to {}: {:?}", topic, message);
//!         Ok(())
//!     }
//!     
//!     async fn subscribe(&self, patterns: Vec<TopicPattern>) -> Result<Subscription<Self::Message>, Self::Error> {
//!         // Return a subscription stream
//!         todo!()
//!     }
//! }
//! ```

use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::broadcast;

/// Topic pattern for subscriptions
///
/// Supports exact matching or glob patterns for flexible subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopicPattern {
    /// Exact topic name match
    Exact(String),
    /// Glob pattern (e.g., "events.*", "user.*.created")
    Glob(String),
    /// Match all topics
    All,
}

impl TopicPattern {
    /// Create an exact topic pattern
    pub fn exact(topic: impl Into<String>) -> Self {
        Self::Exact(topic.into())
    }

    /// Create a glob pattern
    pub fn glob(pattern: impl Into<String>) -> Self {
        Self::Glob(pattern.into())
    }

    /// Check if this pattern matches a topic
    pub fn matches(&self, topic: &str) -> bool {
        match self {
            TopicPattern::Exact(t) => t == topic,
            TopicPattern::Glob(pattern) => Self::glob_matches(pattern, topic),
            TopicPattern::All => true,
        }
    }

    /// Simple glob matching (supports * and **)
    fn glob_matches(pattern: &str, topic: &str) -> bool {
        let pattern_parts: Vec<&str> = pattern.split('.').collect();
        let topic_parts: Vec<&str> = topic.split('.').collect();

        let mut pi = 0;
        let mut ti = 0;

        while pi < pattern_parts.len() && ti < topic_parts.len() {
            match pattern_parts[pi] {
                "**" => {
                    // ** matches zero or more segments
                    if pi == pattern_parts.len() - 1 {
                        return true; // ** at end matches everything
                    }
                    // Try matching remaining pattern at each position
                    for offset in 0..=(topic_parts.len() - ti) {
                        let remaining_pattern = pattern_parts[pi + 1..].join(".");
                        let remaining_topic = topic_parts[ti + offset..].join(".");
                        if Self::glob_matches(&remaining_pattern, &remaining_topic) {
                            return true;
                        }
                    }
                    return false;
                }
                "*" => {
                    // * matches exactly one segment
                    pi += 1;
                    ti += 1;
                }
                segment => {
                    if segment != topic_parts[ti] {
                        return false;
                    }
                    pi += 1;
                    ti += 1;
                }
            }
        }

        pi == pattern_parts.len() && ti == topic_parts.len()
    }
}

impl From<&str> for TopicPattern {
    fn from(s: &str) -> Self {
        if s == "*" || s == "**" {
            TopicPattern::All
        } else if s.contains('*') {
            TopicPattern::Glob(s.to_string())
        } else {
            TopicPattern::Exact(s.to_string())
        }
    }
}

/// A message received from a subscription
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message<T> {
    /// The topic this message was published to
    pub topic: String,
    /// The message payload
    pub payload: T,
    /// Message ID (for deduplication/acknowledgment)
    pub message_id: String,
    /// Timestamp when the message was published
    pub timestamp: u64,
    /// Optional message headers/metadata
    pub headers: HashMap<String, String>,
}

impl<T> Message<T> {
    /// Create a new message
    pub fn new(topic: impl Into<String>, payload: T) -> Self {
        Self {
            topic: topic.into(),
            payload,
            message_id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            headers: HashMap::new(),
        }
    }

    /// Add a header to the message
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set message ID (useful for idempotency)
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.message_id = id.into();
        self
    }
}

/// Publish options for fine-grained control
#[derive(Debug, Clone, Default)]
pub struct PublishOptions {
    /// Custom message ID (for idempotency)
    pub message_id: Option<String>,
    /// Message headers
    pub headers: HashMap<String, String>,
    /// Partition key (for ordered delivery)
    pub partition_key: Option<String>,
    /// Time-to-live for the message
    pub ttl: Option<Duration>,
}

impl PublishOptions {
    /// Create new publish options
    pub fn new() -> Self {
        Self::default()
    }

    /// Set custom message ID
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.message_id = Some(id.into());
        self
    }

    /// Add a header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set partition key for ordering
    pub fn with_partition_key(mut self, key: impl Into<String>) -> Self {
        self.partition_key = Some(key.into());
        self
    }

    /// Set TTL for the message
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }
}

/// Subscription options
#[derive(Debug, Clone, Default)]
pub struct SubscribeOptions {
    /// Start from this message ID (exclusive)
    pub from_id: Option<String>,
    /// Start from this timestamp
    pub from_timestamp: Option<u64>,
    /// Consumer group name (for load balancing)
    pub consumer_group: Option<String>,
    /// Whether to auto-acknowledge messages
    pub auto_ack: bool,
    /// Maximum messages to buffer
    pub buffer_size: usize,
}

impl SubscribeOptions {
    /// Create new subscribe options
    pub fn new() -> Self {
        Self {
            buffer_size: 1000,
            auto_ack: true,
            ..Default::default()
        }
    }

    /// Start from a specific message ID
    pub fn from_id(mut self, id: impl Into<String>) -> Self {
        self.from_id = Some(id.into());
        self
    }

    /// Start from a specific timestamp
    pub fn from_timestamp(mut self, ts: u64) -> Self {
        self.from_timestamp = Some(ts);
        self
    }

    /// Set consumer group
    pub fn with_consumer_group(mut self, group: impl Into<String>) -> Self {
        self.consumer_group = Some(group.into());
        self
    }

    /// Disable auto-acknowledgment
    pub fn manual_ack(mut self) -> Self {
        self.auto_ack = false;
        self
    }

    /// Set buffer size
    pub fn with_buffer(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }
}

/// A subscription to one or more topics
///
/// Implements `Stream` for async iteration over messages.
pub type Subscription<T> =
    Pin<Box<dyn Stream<Item = Result<Message<T>, SubscriptionError>> + Send>>;

/// Errors that can occur during subscription
#[derive(Debug, Clone)]
pub enum SubscriptionError {
    /// Connection to the message broker was lost
    ConnectionLost(String),
    /// The subscription was cancelled
    Cancelled,
    /// Message deserialization failed
    DeserializationError(String),
    /// Other error
    Other(String),
}

impl std::fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionLost(msg) => write!(f, "Connection lost: {msg}"),
            Self::Cancelled => write!(f, "Subscription cancelled"),
            Self::DeserializationError(msg) => write!(f, "Deserialization error: {msg}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for SubscriptionError {}

/// Configuration for PubSub connectors
#[derive(Debug, Clone)]
pub struct PubSubConfig {
    /// Default timeout for operations
    pub timeout: Duration,
    /// Maximum concurrent subscriptions
    pub max_subscriptions: usize,
    /// Buffer size for subscription channels
    pub buffer_size: usize,
    /// Whether to guarantee message ordering
    pub guarantee_ordering: bool,
    /// Whether to support topic patterns
    pub support_patterns: bool,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl Default for PubSubConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_subscriptions: 100,
            buffer_size: 1000,
            guarantee_ordering: false,
            support_patterns: true,
            max_message_size: 1024 * 1024, // 1MB
            metadata: HashMap::new(),
        }
    }
}

impl PubSubConfig {
    /// Create a new PubSubConfig with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set maximum subscriptions
    pub fn with_max_subscriptions(mut self, max: usize) -> Self {
        self.max_subscriptions = max;
        self
    }

    /// Set buffer size
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Enable ordering guarantees
    pub fn with_ordering(mut self) -> Self {
        self.guarantee_ordering = true;
        self
    }

    /// Disable pattern support
    pub fn without_patterns(mut self) -> Self {
        self.support_patterns = false;
        self
    }

    /// Set maximum message size
    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
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
        meta.insert("supports_topics".to_string(), "true".to_string());
        meta.insert(
            "supports_patterns".to_string(),
            self.support_patterns.to_string(),
        );
        meta.insert(
            "guarantees_ordering".to_string(),
            self.guarantee_ordering.to_string(),
        );
        meta.insert(
            "timeout_ms".to_string(),
            self.timeout.as_millis().to_string(),
        );
        meta.insert("buffer_size".to_string(), self.buffer_size.to_string());
        meta
    }
}

/// PubSub connector trait
///
/// Implement this trait to create connectors that handle event streaming
/// with topic-based publish/subscribe semantics.
#[async_trait]
pub trait PubSubConnector: Send + Sync {
    /// The message type this connector handles
    type Message: Send + Sync + Clone + Serialize + for<'de> Deserialize<'de> + 'static;

    /// The error type for connector operations
    type Error: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static;

    /// Get the connector configuration
    fn config(&self) -> &PubSubConfig;

    /// Publish a message to a topic
    async fn publish(&self, topic: &str, message: Self::Message) -> Result<(), Self::Error>;

    /// Publish a message with options
    async fn publish_with_options(
        &self,
        topic: &str,
        message: Self::Message,
        options: PublishOptions,
    ) -> Result<String, Self::Error> {
        // Default implementation ignores options
        self.publish(topic, message).await?;
        Ok(options
            .message_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()))
    }

    /// Subscribe to topics matching the given patterns
    async fn subscribe(
        &self,
        patterns: Vec<TopicPattern>,
    ) -> Result<Subscription<Self::Message>, Self::Error>;

    /// Subscribe with options
    async fn subscribe_with_options(
        &self,
        patterns: Vec<TopicPattern>,
        _options: SubscribeOptions,
    ) -> Result<Subscription<Self::Message>, Self::Error> {
        // Default implementation ignores options
        self.subscribe(patterns).await
    }

    /// Unsubscribe from topics
    ///
    /// Default implementation does nothing.
    async fn unsubscribe(&self, _patterns: Vec<TopicPattern>) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Acknowledge a message (for manual ack mode)
    ///
    /// Default implementation does nothing.
    async fn acknowledge(&self, _message_id: &str) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Reject/NACK a message (for redelivery)
    ///
    /// Default implementation does nothing.
    async fn reject(&self, _message_id: &str) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Get list of active topics (if supported)
    async fn list_topics(&self) -> Result<Vec<String>, Self::Error>;

    /// Check if the connector is healthy
    async fn health_check(&self) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// In-memory PubSub implementation for testing and development
pub struct InMemoryPubSub<T: Clone + Send + Sync + 'static> {
    config: PubSubConfig,
    sender: broadcast::Sender<Message<T>>,
}

impl<T: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static> InMemoryPubSub<T> {
    /// Create a new in-memory pubsub with default config
    pub fn new() -> Self {
        Self::with_config(PubSubConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: PubSubConfig) -> Self {
        let (sender, _) = broadcast::channel(config.buffer_size);
        Self { config, sender }
    }
}

impl<T: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static> Default
    for InMemoryPubSub<T>
{
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<T> PubSubConnector for InMemoryPubSub<T>
where
    T: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static,
{
    type Message = T;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn config(&self) -> &PubSubConfig {
        &self.config
    }

    async fn publish(&self, topic: &str, message: T) -> Result<(), Self::Error> {
        let msg = Message::new(topic, message);
        // Ignore send errors (no receivers)
        let _ = self.sender.send(msg);
        Ok(())
    }

    async fn subscribe(&self, patterns: Vec<TopicPattern>) -> Result<Subscription<T>, Self::Error> {
        let mut receiver = self.sender.subscribe();

        let stream = async_stream::stream! {
            loop {
                match receiver.recv().await {
                    Ok(msg) => {
                        // Check if message matches any pattern
                        if patterns.iter().any(|p| p.matches(&msg.topic)) {
                            yield Ok(msg);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Skip lagged messages
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        yield Err(SubscriptionError::ConnectionLost("Channel closed".to_string()));
                        break;
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }

    async fn list_topics(&self) -> Result<Vec<String>, Self::Error> {
        // In-memory implementation doesn't track topics
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use tokio::time::timeout;

    #[test]
    fn test_topic_pattern_exact() {
        let pattern = TopicPattern::exact("events.user.created");
        assert!(pattern.matches("events.user.created"));
        assert!(!pattern.matches("events.user.deleted"));
    }

    #[test]
    fn test_topic_pattern_glob() {
        let pattern = TopicPattern::glob("events.*");
        assert!(pattern.matches("events.user"));
        assert!(!pattern.matches("events.user.created")); // * only matches one segment

        let pattern = TopicPattern::glob("events.*.created");
        assert!(pattern.matches("events.user.created"));
        assert!(pattern.matches("events.order.created")); // Both match the pattern
        assert!(!pattern.matches("events.user.updated")); // Different suffix
    }

    #[test]
    fn test_topic_pattern_all() {
        let pattern = TopicPattern::All;
        assert!(pattern.matches("anything"));
        assert!(pattern.matches("events.user.created"));
    }

    #[test]
    fn test_message_builder() {
        let msg: Message<String> = Message::new("topic", "payload".to_string())
            .with_header("key", "value")
            .with_id("custom-id");

        assert_eq!(msg.topic, "topic");
        assert_eq!(msg.payload, "payload");
        assert_eq!(msg.message_id, "custom-id");
        assert_eq!(msg.headers.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_pubsub_config() {
        let config = PubSubConfig::new()
            .with_timeout(Duration::from_secs(30))
            .with_ordering()
            .with_buffer_size(500);

        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(config.guarantee_ordering);
        assert_eq!(config.buffer_size, 500);

        let meta = config.to_metadata();
        assert_eq!(meta.get("guarantees_ordering"), Some(&"true".to_string()));
    }

    #[tokio::test]
    async fn test_in_memory_pubsub() {
        let pubsub: InMemoryPubSub<String> = InMemoryPubSub::new();

        // Subscribe first
        let patterns = vec![TopicPattern::exact("test.topic")];
        let mut subscription = pubsub.subscribe(patterns).await.unwrap();

        // Publish a message
        pubsub
            .publish("test.topic", "hello".to_string())
            .await
            .unwrap();

        // Receive the message
        let result = timeout(Duration::from_millis(100), subscription.next()).await;
        assert!(result.is_ok());
        let msg = result.unwrap().unwrap().unwrap();
        assert_eq!(msg.topic, "test.topic");
        assert_eq!(msg.payload, "hello");
    }

    #[test]
    fn test_publish_options() {
        let opts = PublishOptions::new()
            .with_id("msg-123")
            .with_header("trace-id", "abc")
            .with_partition_key("user-1")
            .with_ttl(Duration::from_secs(60));

        assert_eq!(opts.message_id, Some("msg-123".to_string()));
        assert_eq!(opts.headers.get("trace-id"), Some(&"abc".to_string()));
        assert_eq!(opts.partition_key, Some("user-1".to_string()));
        assert_eq!(opts.ttl, Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_subscribe_options() {
        let opts = SubscribeOptions::new()
            .from_id("start-here")
            .with_consumer_group("my-group")
            .manual_ack()
            .with_buffer(2000);

        assert_eq!(opts.from_id, Some("start-here".to_string()));
        assert_eq!(opts.consumer_group, Some("my-group".to_string()));
        assert!(!opts.auto_ack);
        assert_eq!(opts.buffer_size, 2000);
    }
}

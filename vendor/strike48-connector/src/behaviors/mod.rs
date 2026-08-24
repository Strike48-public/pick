//! Behavior-specific connectors for Strike48.
//!
//! This module provides typed connector traits for each connector behavior.
//! Some behaviors have an adapter or runner shortcut that handles the
//! `BaseConnector` boilerplate; others currently still require implementing
//! [`crate::BaseConnector`] directly and driving it with
//! [`crate::ConnectorRunner`].
//!
//! | Behavior | Trait | Recommended entry point |
//! |---|---|---|
//! | `Tool` | [`tool::ToolConnector`] | wrap in [`tool_adapter::ToolAdapter`] and call [`crate::simple::run_tool`] |
//! | `RequestResponse` | [`crate::SimpleConnector`] | call its `run` method |
//! | `App` | [`app::AppConnector`] | use [`serve::App::builder`], or [`crate::simple::serve_app`] / [`crate::simple::serve_static`] |
//! | `Source` | [`source::SourceConnector`] | implement [`crate::BaseConnector`] directly (no adapter yet) |
//! | `Sink` | [`sink::SinkConnector`] | implement [`crate::BaseConnector`] directly (no adapter yet) |
//! | `PubSub` | [`pubsub::PubSubConnector`] | implement [`crate::BaseConnector`] directly (no adapter yet) |

pub mod app;
pub mod pubsub;
pub mod request_response;
pub mod serve;
pub mod sink;
pub mod source;
pub mod tool;
pub mod tool_adapter;
pub mod utilities;

// App behavior
pub use app::*;
pub use serve::{App, AppBuilder};

// Source behavior
pub use source::{FetchRequest, FetchResponse, SourceConfig, SourceConnector};

// Sink behavior
pub use sink::{IdempotentSink, ItemError, SinkConfig, SinkConnector, WriteResult};

// Tool behavior
pub use tool::{ParamType, ParameterSchema, ToolConnector, ToolParam, ToolResult, ToolSchema};
pub use tool_adapter::ToolAdapter;

// PubSub behavior
pub use pubsub::{
    InMemoryPubSub, Message, PubSubConfig, PubSubConnector, PublishOptions, SubscribeOptions,
    Subscription, SubscriptionError, TopicPattern,
};

// RequestResponse behavior
pub use request_response::{
    BatchRequest, BatchResponse, ConcurrentRequestHandler, RequestContext, RequestError,
    RequestMetrics, RequestResponseConfig, RequestResponseConnector, Response,
};

// Utilities
pub use utilities::{
    Cache, CacheStats, OperationMetrics, RetryConfig, Timer, ValidationError, retry_async, timed,
    validate_against_schema, validate_json,
};

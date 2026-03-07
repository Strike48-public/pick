//! Public types and the `ChatClient` trait.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Status enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentStatus {
    Idle,
    Processing,
    Streaming,
    ExecutingTools,
    AwaitingConsent,
    AwaitingClientTools,
    StreamEnd,
    Error,
    Unknown,
}

impl AgentStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Idle | Self::StreamEnd | Self::Error)
    }
}

impl std::str::FromStr for AgentStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "IDLE" => Ok(Self::Idle),
            "PROCESSING" => Ok(Self::Processing),
            "STREAMING" => Ok(Self::Streaming),
            "EXECUTING_TOOLS" => Ok(Self::ExecutingTools),
            "AWAITING_CONSENT" => Ok(Self::AwaitingConsent),
            "AWAITING_CLIENT_TOOLS" => Ok(Self::AwaitingClientTools),
            "STREAM_END" => Ok(Self::StreamEnd),
            "ERROR" => Ok(Self::Error),
            _ => Ok(Self::Unknown),
        }
    }
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "IDLE"),
            Self::Processing => write!(f, "PROCESSING"),
            Self::Streaming => write!(f, "STREAMING"),
            Self::ExecutingTools => write!(f, "EXECUTING_TOOLS"),
            Self::AwaitingConsent => write!(f, "AWAITING_CONSENT"),
            Self::AwaitingClientTools => write!(f, "AWAITING_CLIENT_TOOLS"),
            Self::StreamEnd => write!(f, "STREAM_END"),
            Self::Error => write!(f, "ERROR"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCallStatus {
    Pending,
    Running,
    Success,
    Failed,
    Unknown,
}

impl std::str::FromStr for ToolCallStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "running" | "in_progress" => Ok(Self::Running),
            "success" | "completed" => Ok(Self::Success),
            "failed" | "error" => Ok(Self::Failed),
            _ => Ok(Self::Unknown),
        }
    }
}

impl std::fmt::Display for ToolCallStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Success => write!(f, "success"),
            Self::Failed => write!(f, "failed"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Minimal agent info surfaced to the UI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub greeting: Option<String>,
}

/// A tool call attached to a message.
#[derive(Debug, Clone)]
pub struct ToolCallInfo {
    pub id: String,
    pub name: String,
    pub arguments: Option<String>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub status: ToolCallStatus,
}

/// A single part of a chat message (text, tool call, or thinking).
#[derive(Debug, Clone)]
pub enum MessagePart {
    Text(String),
    ToolCall(ToolCallInfo),
    Thinking(String),
}

/// A single chat message.
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub id: String,
    /// "USER" or "AGENT" (or other profile types the API returns).
    pub sender_type: String,
    pub sender_name: String,
    pub text: String,
    /// Rich parts (text, tool calls, thinking blocks).
    pub parts: Vec<MessagePart>,
}

/// Result of polling a conversation.
#[derive(Debug, Clone)]
pub struct ConversationState {
    pub messages: Vec<ChatMessage>,
    /// Agent status: Idle, Processing, StreamEnd, Error, or Unknown.
    pub agent_status: AgentStatus,
}

/// Lightweight conversation summary for the history list.
#[derive(Debug, Clone, PartialEq)]
pub struct ConversationInfo {
    pub id: String,
    pub title: String,
    pub summary: Option<String>,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// CreateAgentInput
// ---------------------------------------------------------------------------

/// Input for creating an agent persona via the Matrix API.
///
/// The `context` and `tools` fields hold raw JSON values.  They are
/// serialized as JSON **strings** for the GraphQL `Json` scalar when
/// sent to the API (see `CreateAgentInput::to_gql_variables`).
#[derive(Debug, Clone)]
pub struct CreateAgentInput {
    pub name: String,
    pub description: Option<String>,
    pub system_message: Option<String>,
    pub agent_greeting: Option<String>,
    pub context: Option<serde_json::Value>,
    pub tools: Option<serde_json::Value>,
}

impl CreateAgentInput {
    /// Convert to a `serde_json::Value` suitable for GraphQL variables.
    /// Json scalar fields (`context`, `tools`) are stringified.
    pub(crate) fn to_gql_variables(&self) -> serde_json::Value {
        let mut input = serde_json::Map::new();
        input.insert("name".into(), serde_json::json!(self.name));
        if let Some(ref d) = self.description {
            input.insert("description".into(), serde_json::json!(d));
        }
        if let Some(ref s) = self.system_message {
            input.insert("systemMessage".into(), serde_json::json!(s));
        }
        if let Some(ref g) = self.agent_greeting {
            input.insert("agentGreeting".into(), serde_json::json!(g));
        }
        if let Some(ref c) = self.context {
            input.insert("context".into(), serde_json::json!(c.to_string()));
        }
        if let Some(ref t) = self.tools {
            input.insert("tools".into(), serde_json::json!(t.to_string()));
        }
        serde_json::json!({ "input": input })
    }
}

// ---------------------------------------------------------------------------
// UpdateAgentInput
// ---------------------------------------------------------------------------

/// Input for updating an existing agent's configuration via the Matrix API.
#[derive(Debug, Clone)]
pub struct UpdateAgentInput {
    pub id: String,
    pub tools: Option<serde_json::Value>,
}

impl UpdateAgentInput {
    pub(crate) fn to_gql_variables(&self) -> serde_json::Value {
        let mut input = serde_json::Map::new();
        input.insert("id".into(), serde_json::json!(self.id));
        if let Some(ref t) = self.tools {
            input.insert("tools".into(), serde_json::json!(t.to_string()));
        }
        serde_json::json!({ "input": input })
    }
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstraction over the chat backend. Implement this trait to swap Matrix
/// for another provider without touching the UI layer.
#[async_trait]
pub trait ChatClient: Send + Sync {
    async fn list_agents(&self) -> crate::error::Result<Vec<AgentInfo>>;
    async fn find_agent_by_name(&self, name: &str) -> crate::error::Result<Option<AgentInfo>>;
    async fn create_agent(&self, input: CreateAgentInput) -> crate::error::Result<AgentInfo>;
    async fn update_agent(&self, input: UpdateAgentInput) -> crate::error::Result<AgentInfo>;
    async fn create_conversation(&self, title: Option<&str>) -> crate::error::Result<String>;
    async fn send_message(
        &self,
        conversation_id: &str,
        agent_id: &str,
        message: &str,
    ) -> crate::error::Result<String>;
    async fn get_conversation(
        &self,
        conversation_id: &str,
    ) -> crate::error::Result<ConversationState>;
    async fn poll_for_response(
        &self,
        conversation_id: &str,
        poll_interval_ms: u64,
        max_polls: u32,
    ) -> crate::error::Result<ConversationState>;
    async fn list_conversations(
        &self,
        agent_id: Option<&str>,
    ) -> crate::error::Result<Vec<ConversationInfo>>;
    async fn delete_conversation(&self, conversation_id: &str) -> crate::error::Result<()>;
}

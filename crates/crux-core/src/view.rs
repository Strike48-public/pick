//! Platform-agnostic, render-ready view types. A native (Swift/Kotlin) or
//! Dioxus view is a pure function of `ViewModel`. No Rust-only types leak;
//! markdown stays a String; timestamps are pre-formatted.

use facet::Facet;
use serde::{Deserialize, Serialize};

use crate::markdown::MarkdownBlock;

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[repr(C)]
pub enum Screen {
    #[default]
    Scan,
    Chat,
    Documents,
    DocViewer,
    NeedsSignIn,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[repr(C)]
pub enum ConnectionPhase {
    SigningIn,
    #[default]
    Connecting,
    Registering,
    Connected,
    NeedsSignIn,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConnectionView {
    pub phase: ConnectionPhase,
    pub label: String,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum MessageKind {
    User,
    AgentText,
    ToolCall,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum ToolStatus {
    Running,
    Success,
    Error,
}

/// What the agent is currently doing, projected from the server's AgentStatus.
/// Drives the animated status line (never a spinner) while a scan/chat is live.
/// `Idle` means no activity (terminal / not running).
#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[repr(C)]
pub enum AgentActivity {
    #[default]
    Idle,
    Thinking,
    Responding,
    RunningTools,
    AwaitingConsent,
}

impl AgentActivity {
    /// Human label for the status line (matches the Dioxus wording).
    pub fn label(&self) -> &'static str {
        match self {
            AgentActivity::Idle => "",
            AgentActivity::Thinking => "Thinking...",
            AgentActivity::Responding => "Responding...",
            AgentActivity::RunningTools => "Running tools...",
            AgentActivity::AwaitingConsent => "Awaiting approval...",
        }
    }
    pub fn is_active(&self) -> bool {
        !matches!(self, AgentActivity::Idle)
    }
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ToolCallView {
    pub name: String,
    pub status: ToolStatus,
    /// Raw JSON arguments the agent invoked the tool with, when available.
    pub arguments: Option<String>,
    /// Raw tool result payload, when the call has completed.
    pub result: Option<String>,
    /// Error text, when the call failed.
    pub error: Option<String>,
}

/// One ordered part of an agent message. The shells render these IN ORDER so a
/// message reads exactly as it does in the Dioxus app: interleaved prose,
/// thinking blocks, and tool cards.
#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum MessagePartView {
    /// A run of prose, pre-parsed into render-ready markdown blocks.
    Text { blocks: Vec<MarkdownBlock> },
    /// A collapsible "thinking" block (raw text, not markdown-styled).
    Thinking { text: String },
    /// A tool-call card.
    Tool { tool: ToolCallView },
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MessageView {
    pub sender: String,
    pub kind: MessageKind,
    /// Ordered parts (text/thinking/tool). Shells prefer this over the legacy
    /// flattened `markdown`/`blocks`/`tool` fields, which are kept for a smooth
    /// migration and are derived from the same source message.
    pub parts: Vec<MessagePartView>,
    pub markdown: String,
    /// Pre-parsed markdown blocks for native rendering. Derived from `markdown`.
    pub blocks: Vec<MarkdownBlock>,
    pub tool: Option<ToolCallView>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DocRef {
    pub id: String,
    pub title: String,
    pub conversation_id: String,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConversationRef {
    pub id: String,
    pub title: String,
    pub relative_time: String,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DocView {
    pub id: String,
    pub title: String,
    pub markdown_body: String,
    /// Pre-parsed markdown blocks for native rendering. Derived from `markdown_body`.
    pub blocks: Vec<MarkdownBlock>,
    pub share_url: Option<String>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ViewModel {
    pub screen: Screen,
    pub connection: ConnectionView,
    pub messages: Vec<MessageView>,
    pub scan_in_progress: bool,
    pub show_scan_card: bool,
    pub conversation_docs: Vec<DocRef>,
    pub all_documents: Vec<DocRef>,
    pub history: Vec<ConversationRef>,
    pub open_document: Option<DocView>,
    pub needs_sign_in: bool,
    pub error: Option<String>,
    pub tool_calls: Vec<ToolCallView>,
    /// What the agent is doing right now. Shells render an animated status line
    /// (never a spinner) whenever this is not `Idle`.
    pub agent_activity: AgentActivity,
    /// Pre-formatted human label for `agent_activity` (empty when Idle).
    pub activity_label: String,
}

impl Default for ConnectionView {
    fn default() -> Self {
        ConnectionView {
            phase: ConnectionPhase::Connecting,
            label: "Connecting...".to_string(),
        }
    }
}

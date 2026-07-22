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

/// Severity for an inline notice surfaced when the agent backend errors.
/// Mirrors pentest-core's `ChatNoticeKind`; drives styling, not behaviour.
#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum NoticeKind {
    /// The server hit a hard limit (token/rate). User action required.
    TokenLimit,
    /// Some other upstream failure — usually transient.
    UpstreamError,
}

/// A render-ready notice describing why a scan/chat stopped without a reply.
/// Mirrors pentest-core's `ChatNotice` across the ViewModel boundary.
#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NoticeView {
    pub kind: NoticeKind,
    pub title: String,
    pub detail: String,
    /// Optional URL to the Studio session (e.g. for checking token usage).
    pub studio_url: Option<String>,
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

/// A contextual "Next Steps" suggested action, surfaced after a successful tool
/// call. Tapping the chip sends `message` as a follow-up. Derived in the
/// middleware from `pentest_tools::registry` `get_actions(tool, result)`; the
/// shell renders `label` and fires `SendMessage(message)` on tap.
#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct QuickActionView {
    pub label: String,
    pub message: String,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DocRef {
    pub id: String,
    pub title: String,
    pub conversation_id: String,
    /// ISO-8601 creation time (the document's `created_at`). Used to order the
    /// Reports list newest-first and dedup repeated scans. ISO-8601 sorts
    /// lexically in chronological order. Empty when the server omitted it.
    pub timestamp: String,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConversationRef {
    pub id: String,
    pub title: String,
    pub relative_time: String,
}

/// A social-share destination for a report's public link. `url` opens a
/// pre-filled compose window for `label`'s network (X/LinkedIn/Facebook); the
/// shell just opens the given URL. Built in the middleware from
/// `pentest_core::social_share::share_intent_url` so shells never rebuild it.
#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SocialLink {
    pub label: String,
    pub url: String,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DocView {
    pub id: String,
    pub title: String,
    pub markdown_body: String,
    /// Pre-parsed markdown blocks for native rendering. Derived from `markdown_body`.
    pub blocks: Vec<MarkdownBlock>,
    pub share_url: Option<String>,
    /// The public link transformed for inline browser preview (`?preview=1`).
    /// Set alongside `share_url`; the shell opens this in the system browser for
    /// "Open in browser". `None` until a share link exists.
    pub preview_url: Option<String>,
    /// Per-network share destinations (X/LinkedIn/Facebook), each carrying a
    /// ready-to-open compose URL. Empty until a share link exists.
    pub social_links: Vec<SocialLink>,
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
    /// Inline notice surfaced when the agent backend errored (token limit or a
    /// generic upstream failure) instead of producing a reply. `None` normally.
    pub notice: Option<NoticeView>,
    /// Contextual "Next Steps" chips computed from the last successful tool call.
    /// Shells render a row of pill buttons below the message list when non-empty;
    /// tapping one fires `SendMessage(message)`. Cleared on send/new-chat.
    pub next_steps: Vec<QuickActionView>,
}

impl Default for ConnectionView {
    fn default() -> Self {
        ConnectionView {
            phase: ConnectionPhase::Connecting,
            label: "Connecting...".to_string(),
        }
    }
}

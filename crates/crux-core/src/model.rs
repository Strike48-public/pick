//! Private App state. Never crosses the FFI boundary; `view()` projects it into
//! the ViewModel.

use crate::view::{ConnectionPhase, ConversationRef, DocRef, DocView, MessageView, NoticeView};

#[derive(Default)]
pub struct Model {
    pub phase: Phase,
    pub api_url: String,
    pub conversation_id: Option<String>,
    pub messages: Vec<MessageView>,
    pub conversation_docs: Vec<DocRef>,
    pub all_documents: Vec<DocRef>,
    pub history: Vec<ConversationRef>,
    pub open_document: Option<DocView>,
    pub scan_active: bool,
    pub history_open: bool,
    pub error: Option<String>,
    pub opening_document_id: Option<String>,
    pub tool_calls: Vec<crate::view::ToolCallView>,
    /// What the agent is doing right now — drives the animated status line.
    pub activity: crate::view::AgentActivity,
    /// Inline notice set when the agent backend errored (token limit / upstream
    /// failure) instead of producing a reply. Cleared on new scan/message/chat.
    pub notice: Option<NoticeView>,
    /// Contextual "Next Steps" chips from the last successful tool call (built by
    /// the middleware). Set from each Delta; cleared on send/new-chat.
    pub next_steps: Vec<crate::view::QuickActionView>,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub enum Phase {
    SigningIn,
    #[default]
    Connecting,
    Registering,
    Connected,
    NeedsSignIn,
}

impl Phase {
    pub fn to_view(&self) -> ConnectionPhase {
        match self {
            Phase::SigningIn => ConnectionPhase::SigningIn,
            Phase::Connecting => ConnectionPhase::Connecting,
            Phase::Registering => ConnectionPhase::Registering,
            Phase::Connected => ConnectionPhase::Connected,
            Phase::NeedsSignIn => ConnectionPhase::NeedsSignIn,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Phase::SigningIn => "Signing in to Strike48...",
            Phase::Connecting => "Connecting...",
            Phase::Registering => "Registering connector...",
            Phase::Connected => "Connected",
            Phase::NeedsSignIn => "Sign in to connect",
        }
    }
}

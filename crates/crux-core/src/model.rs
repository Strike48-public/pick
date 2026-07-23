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
    /// Stall backstop for a scan that never reaches a terminal signal. A healthy
    /// agent emits *something* (a new message, tool call, or activity change)
    /// every poll; if `POLL_STALL_LIMIT` consecutive polls show zero change we
    /// treat the turn as dead and surface an error. This is the belt-and-braces
    /// guard for a hard backend crash that leaves no `stream_error` / `Error`
    /// status (a crashed ConversationServer reports IDLE). `(fingerprint, count)`
    /// where the fingerprint is a cheap snapshot of observable progress; reset
    /// on send / new-chat / conversation-load.
    pub poll_progress: (u64, u32),
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

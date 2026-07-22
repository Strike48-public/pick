//! The custom side-effect the App emits; the middleware (or a future shell)
//! fulfills it using pentest-core. The App itself performs no I/O.

use crux_core::capability::Operation;
use facet::Facet;
use serde::{Deserialize, Serialize};

use crate::view::{
    ConversationRef, DocRef, MessageView, NoticeView, QuickActionView, SocialLink, ToolCallView,
};

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum PentestOperation {
    SignIn {
        api_url: String,
    },
    Connect {
        api_url: String,
        tenant: String,
        token: String,
    },
    SendScan {
        conversation_id: Option<String>,
        prompt: String,
    },
    SendMessage {
        conversation_id: Option<String>,
        text: String,
    },
    PollConversation {
        conversation_id: String,
    },
    ListConversations,
    LoadConversation {
        conversation_id: String,
    },
    ListDocuments {
        agent_id: Option<String>,
    },
    GetDocumentContent {
        document_id: String,
        conversation_id: String,
    },
    CreateSharedLink {
        conversation_id: String,
        document_id: String,
        /// The document title, so the middleware can build social-share compose
        /// URLs (e.g. X's pre-filled text) alongside the raw share link.
        title: String,
    },
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub struct ConversationDelta {
    pub messages: Vec<MessageView>,
    pub tool_calls: Vec<ToolCallView>,
    pub done: bool,
    /// What the agent is doing right now (Thinking/Responding/RunningTools/...),
    /// projected from the server's AgentStatus. Drives the animated status line.
    pub activity: crate::view::AgentActivity,
    /// Set when the poll observed `AgentStatus::Error`: an inline notice built
    /// from `tokenUsageStats` distinguishing a token-limit hit from a generic
    /// upstream failure. `None` on a normal (success) delta. When present the
    /// App treats the delta as terminal and surfaces the notice.
    pub notice: Option<NoticeView>,
    /// Contextual next-step suggestions computed by the middleware from the last
    /// successful tool call's (name, result) via the quick-action registry. The
    /// App stores these on the model and projects them into the ViewModel.
    pub next_steps: Vec<QuickActionView>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum PentestOutcome {
    SignedIn { token: String },
    Connected,
    ScanQueued { conversation_id: String },
    Delta(ConversationDelta),
    Conversations { list: Vec<ConversationRef> },
    LoadedMessages { messages: Vec<MessageView> },
    Documents { list: Vec<DocRef> },
    DocumentContent { markdown: String },
    SharedLink {
        url: String,
        /// Browser-preview transform of `url` (`?preview=1`), precomputed in the
        /// middleware via `pentest_core::matrix::preview_url`.
        preview_url: String,
        /// Per-network share destinations built from `url` + the document title.
        social_links: Vec<SocialLink>,
    },
    Error { message: String },
}

impl Operation for PentestOperation {
    type Output = PentestOutcome;
}

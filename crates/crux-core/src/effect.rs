//! The custom side-effect the App emits; the middleware (or a future shell)
//! fulfills it using pentest-core. The App itself performs no I/O.

use crux_core::capability::Operation;
use facet::Facet;
use serde::{Deserialize, Serialize};

use crate::view::{ConversationRef, DocRef, MessageView, ToolCallView};

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
    },
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub struct ConversationDelta {
    pub messages: Vec<MessageView>,
    pub tool_calls: Vec<ToolCallView>,
    pub done: bool,
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
    SharedLink { url: String },
    Error { message: String },
}

impl Operation for PentestOperation {
    type Output = PentestOutcome;
}

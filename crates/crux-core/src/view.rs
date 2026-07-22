//! Platform-agnostic, render-ready view types. A native (Swift/Kotlin) or
//! Dioxus view is a pure function of `ViewModel`. No Rust-only types leak;
//! markdown stays a String; timestamps are pre-formatted.

use facet::Facet;
use serde::{Deserialize, Serialize};

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

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ToolCallView {
    pub name: String,
    pub status: ToolStatus,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MessageView {
    pub sender: String,
    pub kind: MessageKind,
    pub markdown: String,
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
}

impl Default for ConnectionView {
    fn default() -> Self {
        ConnectionView {
            phase: ConnectionPhase::Connecting,
            label: "Connecting...".to_string(),
        }
    }
}

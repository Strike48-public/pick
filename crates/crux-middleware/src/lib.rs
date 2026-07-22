//! EffectMiddleware fulfilling PentestOperation via pentest-core. The App is
//! pure; this crate owns all I/O, on a background tokio runtime.

use crux_core::middleware::{EffectMiddleware, EffectResolver};
use pentest_core::matrix::{ChatClient, ChatMessage, ConversationState, MessagePart, ToolCallStatus};
use pick_crux_core::effect::{ConversationDelta, PentestOperation, PentestOutcome};
use pick_crux_core::view::{
    ConversationRef, DocRef, MessageKind, MessageView, ToolCallView, ToolStatus,
};

#[cfg(test)]
use pentest_core::matrix::{AgentStatus, ToolCallInfo};

#[async_trait::async_trait]
pub trait MatrixApi: Send + Sync {
    async fn send(&self, conversation_id: Option<String>, text: String) -> Result<String, String>;
    async fn poll(&self, conversation_id: String) -> Result<ConversationDelta, String>;
    async fn list_documents(&self, agent_id: Option<String>) -> Result<Vec<DocRef>, String>;
    async fn sign_in(&self, api_url: String) -> Result<String, String>;
    async fn doc_content(
        &self,
        document_id: String,
        conversation_id: String,
    ) -> Result<String, String>;
    async fn shared_link(
        &self,
        conversation_id: String,
        document_id: String,
    ) -> Result<String, String>;
    async fn list_conversations(&self) -> Result<Vec<ConversationRef>, String>;
    async fn load_conversation(&self, conversation_id: String) -> Result<Vec<MessageView>, String>;
}

/// Pure mapping from an operation to an outcome via the injected api. Unit-tested.
pub async fn map_operation(api: &dyn MatrixApi, op: PentestOperation) -> PentestOutcome {
    match op {
        PentestOperation::SendScan {
            conversation_id,
            prompt,
        } => match api.send(conversation_id, prompt).await {
            Ok(c) => PentestOutcome::ScanQueued { conversation_id: c },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::SendMessage {
            conversation_id,
            text,
        } => match api.send(conversation_id, text).await {
            Ok(c) => PentestOutcome::ScanQueued { conversation_id: c },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::PollConversation { conversation_id } => {
            match api.poll(conversation_id).await {
                Ok(d) => PentestOutcome::Delta(d),
                Err(m) => PentestOutcome::Error { message: m },
            }
        }
        PentestOperation::ListDocuments { agent_id } => match api.list_documents(agent_id).await {
            Ok(l) => PentestOutcome::Documents { list: l },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::SignIn { api_url } => match api.sign_in(api_url).await {
            Ok(t) => PentestOutcome::SignedIn { token: t },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::Connect { .. } => PentestOutcome::Connected,
        PentestOperation::GetDocumentContent {
            document_id,
            conversation_id,
        } => match api.doc_content(document_id, conversation_id).await {
            Ok(md) => PentestOutcome::DocumentContent { markdown: md },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::CreateSharedLink {
            conversation_id,
            document_id,
        } => match api.shared_link(conversation_id, document_id).await {
            Ok(u) => PentestOutcome::SharedLink { url: u },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::ListConversations => match api.list_conversations().await {
            Ok(l) => PentestOutcome::Conversations { list: l },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::LoadConversation { conversation_id } => {
            match api.load_conversation(conversation_id).await {
                Ok(m) => PentestOutcome::LoadedMessages { messages: m },
                Err(e) => PentestOutcome::Error { message: e },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pure mapping helpers (unit-testable)
// ---------------------------------------------------------------------------

/// Map pentest-core ToolCallStatus to crux ToolStatus.
fn map_tool_status(status: ToolCallStatus) -> ToolStatus {
    match status {
        ToolCallStatus::Running | ToolCallStatus::Pending => ToolStatus::Running,
        ToolCallStatus::Success => ToolStatus::Success,
        ToolCallStatus::Failed => ToolStatus::Error,
        ToolCallStatus::Unknown => ToolStatus::Running,
    }
}

/// Extract all tool calls from a message's parts.
fn extract_tool_calls(parts: &[MessagePart]) -> Vec<ToolCallView> {
    parts
        .iter()
        .filter_map(|p| match p {
            MessagePart::ToolCall(tc) => Some(ToolCallView {
                name: tc.name.clone(),
                status: map_tool_status(tc.status),
            }),
            _ => None,
        })
        .collect()
}

/// Find the first tool call in a message's parts, if any.
fn first_tool_call(parts: &[MessagePart]) -> Option<ToolCallView> {
    parts.iter().find_map(|p| match p {
        MessagePart::ToolCall(tc) => Some(ToolCallView {
            name: tc.name.clone(),
            status: map_tool_status(tc.status),
        }),
        _ => None,
    })
}

/// Map a single ChatMessage to a MessageView.
fn message_to_view(msg: &ChatMessage) -> MessageView {
    let kind = if msg.sender_type.to_uppercase() == "USER" {
        MessageKind::User
    } else {
        MessageKind::AgentText
    };
    MessageView {
        sender: msg.sender_name.clone(),
        kind,
        markdown: msg.text.clone(),
        tool: first_tool_call(&msg.parts),
    }
}

/// Map a Vec of ChatMessages to MessageViews.
fn messages_to_views(messages: &[ChatMessage]) -> Vec<MessageView> {
    messages.iter().map(message_to_view).collect()
}

/// Map ConversationState to ConversationDelta (for poll).
fn state_to_delta(state: ConversationState) -> ConversationDelta {
    let messages = messages_to_views(&state.messages);
    let tool_calls: Vec<ToolCallView> = state
        .messages
        .iter()
        .flat_map(|m| extract_tool_calls(&m.parts))
        .collect();
    let done = state.agent_status.is_terminal();
    ConversationDelta {
        messages,
        tool_calls,
        done,
    }
}

// ---------------------------------------------------------------------------
// CoreMatrixApi
// ---------------------------------------------------------------------------

/// The real MatrixApi backed by pentest-core (constructed with api_url + token).
pub struct CoreMatrixApi {
    pub api_url: String,
    pub token: String,
    pub agent_id: Option<String>,
}

#[async_trait::async_trait]
impl MatrixApi for CoreMatrixApi {
    async fn send(&self, conversation_id: Option<String>, text: String) -> Result<String, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        let agent = self.agent_id.clone().unwrap_or_default();
        let conv = conversation_id.unwrap_or_default();
        // send_message returns a message_id; we return the conversation_id.
        // When conv is empty, server creates a new conversation, but send_message doesn't
        // return the conversation id - we'd need to poll or create explicitly. For slice-1
        // this just returns the same conv id.
        client
            .send_message(&conv, &agent, &text)
            .await
            .map_err(|e| e.to_string())?;
        Ok(conv)
    }

    async fn poll(&self, conversation_id: String) -> Result<ConversationDelta, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        let state = client
            .get_conversation(&conversation_id)
            .await
            .map_err(|e| e.to_string())?;
        Ok(state_to_delta(state))
    }

    async fn list_documents(&self, agent_id: Option<String>) -> Result<Vec<DocRef>, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        let docs = client
            .list_documents(agent_id.as_deref())
            .await
            .map_err(|e| e.to_string())?;
        Ok(docs
            .into_iter()
            .map(|d| DocRef {
                id: d.id,
                title: d.title,
                conversation_id: d.conversation_id,
            })
            .collect())
    }

    async fn sign_in(&self, api_url: String) -> Result<String, String> {
        pentest_core::matrix::fetch_matrix_token_browser(&api_url)
            .await
            .map_err(|e| e.to_string())
    }

    async fn doc_content(
        &self,
        document_id: String,
        conversation_id: String,
    ) -> Result<String, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        client
            .get_document_content(&conversation_id, &document_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn shared_link(
        &self,
        conversation_id: String,
        document_id: String,
    ) -> Result<String, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        client
            .create_shared_link(&conversation_id, &document_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn list_conversations(&self) -> Result<Vec<ConversationRef>, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        let convs = client
            .list_conversations(self.agent_id.as_deref())
            .await
            .map_err(|e| e.to_string())?;
        Ok(convs
            .into_iter()
            .map(|c| ConversationRef {
                id: c.id,
                title: c.title,
                relative_time: c.updated_at, // TODO: format to "2h ago" in future polish
            })
            .collect())
    }

    async fn load_conversation(
        &self,
        conversation_id: String,
    ) -> Result<Vec<MessageView>, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        let state = client
            .get_conversation(&conversation_id)
            .await
            .map_err(|e| e.to_string())?;
        Ok(messages_to_views(&state.messages))
    }
}

pub struct PentestMiddleware {
    runtime: tokio::runtime::Handle,
    api: std::sync::Arc<dyn MatrixApi>,
}

impl PentestMiddleware {
    pub fn new(runtime: tokio::runtime::Handle, api: std::sync::Arc<dyn MatrixApi>) -> Self {
        Self { runtime, api }
    }
}

impl EffectMiddleware for PentestMiddleware {
    type Op = PentestOperation;
    fn try_process_effect(
        &self,
        operation: PentestOperation,
        mut resolver: EffectResolver<PentestOutcome>,
    ) {
        let api = self.api.clone();
        self.runtime.spawn(async move {
            let out = map_operation(api.as_ref(), operation).await;
            resolver.resolve(out);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pick_crux_core::effect::{PentestOperation, PentestOutcome};

    struct FakeApi;
    #[async_trait::async_trait]
    impl MatrixApi for FakeApi {
        async fn send(&self, _c: Option<String>, _t: String) -> Result<String, String> {
            Ok("conv-9".into())
        }
        async fn poll(
            &self,
            _c: String,
        ) -> Result<pick_crux_core::effect::ConversationDelta, String> {
            Ok(pick_crux_core::effect::ConversationDelta {
                messages: vec![],
                tool_calls: vec![],
                done: true,
            })
        }
        async fn list_documents(
            &self,
            _a: Option<String>,
        ) -> Result<Vec<pick_crux_core::view::DocRef>, String> {
            Ok(vec![])
        }
        async fn sign_in(&self, _u: String) -> Result<String, String> {
            Ok("tok".into())
        }
        async fn doc_content(&self, _id: String, _c: String) -> Result<String, String> {
            Ok("# report".into())
        }
        async fn shared_link(&self, _c: String, _d: String) -> Result<String, String> {
            Ok("https://s/x".into())
        }
        async fn list_conversations(
            &self,
        ) -> Result<Vec<pick_crux_core::view::ConversationRef>, String> {
            Ok(vec![])
        }
        async fn load_conversation(
            &self,
            _c: String,
        ) -> Result<Vec<pick_crux_core::view::MessageView>, String> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn send_scan_maps_to_scan_queued() {
        let api = FakeApi;
        let out = map_operation(
            &api,
            PentestOperation::SendScan {
                conversation_id: None,
                prompt: "p".into(),
            },
        )
        .await;
        assert!(
            matches!(out, PentestOutcome::ScanQueued { conversation_id } if conversation_id == "conv-9")
        );
    }
    #[tokio::test]
    async fn final_poll_maps_to_delta_done() {
        let api = FakeApi;
        let out = map_operation(
            &api,
            PentestOperation::PollConversation {
                conversation_id: "c".into(),
            },
        )
        .await;
        assert!(matches!(out, PentestOutcome::Delta(d) if d.done));
    }
    #[tokio::test]
    async fn signin_maps_to_signed_in() {
        let api = FakeApi;
        let out = map_operation(
            &api,
            PentestOperation::SignIn {
                api_url: "u".into(),
            },
        )
        .await;
        assert!(matches!(out, PentestOutcome::SignedIn { token } if token == "tok"));
    }

    // ---------------------------------------------------------------------------
    // Mapping tests
    // ---------------------------------------------------------------------------

    #[test]
    fn user_message_maps_to_user_kind() {
        let msg = ChatMessage {
            id: "m1".into(),
            sender_type: "USER".into(),
            sender_name: "Alice".into(),
            text: "hello".into(),
            parts: vec![MessagePart::Text("hello".into())],
        };
        let view = message_to_view(&msg);
        assert_eq!(view.kind, MessageKind::User);
        assert_eq!(view.sender, "Alice");
        assert_eq!(view.markdown, "hello");
        assert!(view.tool.is_none());
    }

    #[test]
    fn agent_message_with_tool_call_maps_correctly() {
        let msg = ChatMessage {
            id: "m2".into(),
            sender_type: "AGENT".into(),
            sender_name: "Bot".into(),
            text: "scanning".into(),
            parts: vec![MessagePart::ToolCall(ToolCallInfo {
                id: "tc1".into(),
                name: "nmap".into(),
                arguments: None,
                result: None,
                error: None,
                status: ToolCallStatus::Running,
            })],
        };
        let view = message_to_view(&msg);
        assert_eq!(view.kind, MessageKind::AgentText);
        assert!(view.tool.is_some());
        let tool = view.tool.unwrap();
        assert_eq!(tool.name, "nmap");
        assert_eq!(tool.status, ToolStatus::Running);
    }

    #[test]
    fn terminal_agent_status_produces_done_true() {
        let state = ConversationState {
            messages: vec![],
            agent_status: AgentStatus::StreamEnd,
        };
        let delta = state_to_delta(state);
        assert!(delta.done);
    }

    #[test]
    fn non_terminal_agent_status_produces_done_false() {
        let state = ConversationState {
            messages: vec![],
            agent_status: AgentStatus::Processing,
        };
        let delta = state_to_delta(state);
        assert!(!delta.done);
    }

    #[test]
    fn tool_calls_extracted_from_all_messages() {
        let state = ConversationState {
            messages: vec![
                ChatMessage {
                    id: "m1".into(),
                    sender_type: "AGENT".into(),
                    sender_name: "Bot".into(),
                    text: "scan1".into(),
                    parts: vec![MessagePart::ToolCall(ToolCallInfo {
                        id: "tc1".into(),
                        name: "nmap".into(),
                        arguments: None,
                        result: None,
                        error: None,
                        status: ToolCallStatus::Success,
                    })],
                },
                ChatMessage {
                    id: "m2".into(),
                    sender_type: "AGENT".into(),
                    sender_name: "Bot".into(),
                    text: "scan2".into(),
                    parts: vec![MessagePart::ToolCall(ToolCallInfo {
                        id: "tc2".into(),
                        name: "nikto".into(),
                        arguments: None,
                        result: None,
                        error: None,
                        status: ToolCallStatus::Running,
                    })],
                },
            ],
            agent_status: AgentStatus::ExecutingTools,
        };
        let delta = state_to_delta(state);
        assert_eq!(delta.tool_calls.len(), 2);
        assert_eq!(delta.tool_calls[0].name, "nmap");
        assert_eq!(delta.tool_calls[0].status, ToolStatus::Success);
        assert_eq!(delta.tool_calls[1].name, "nikto");
        assert_eq!(delta.tool_calls[1].status, ToolStatus::Running);
    }

    #[test]
    fn tool_status_mapping() {
        assert_eq!(map_tool_status(ToolCallStatus::Running), ToolStatus::Running);
        assert_eq!(
            map_tool_status(ToolCallStatus::Pending),
            ToolStatus::Running
        );
        assert_eq!(
            map_tool_status(ToolCallStatus::Success),
            ToolStatus::Success
        );
        assert_eq!(map_tool_status(ToolCallStatus::Failed), ToolStatus::Error);
        assert_eq!(
            map_tool_status(ToolCallStatus::Unknown),
            ToolStatus::Running
        );
    }
}

//! EffectMiddleware fulfilling PentestOperation via pentest-core. The App is
//! pure; this crate owns all I/O, on a background tokio runtime.

use crux_core::middleware::{EffectMiddleware, EffectResolver};
use pentest_core::matrix::{
    AgentStatus, ChatClient, ChatMessage, ConversationState, MessagePart, ToolCallStatus,
};
use pick_crux_core::effect::{ConversationDelta, PentestOperation, PentestOutcome};
use pick_crux_core::view::{
    AgentActivity, ConversationRef, DocRef, MessageKind, MessagePartView, MessageView, ToolCallView,
    ToolStatus,
};

#[cfg(test)]
use pentest_core::matrix::ToolCallInfo;

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

    /// Adopt an auth token obtained out-of-band (e.g. the shell performed native
    /// OAuth and captured the `__st` session token). Default no-op for fakes.
    fn set_token(&self, _token: String) {}
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

/// Map a pentest-core ToolCallInfo to a crux ToolCallView, carrying the detail
/// fields (args/result/error) so a shell can render a tool card with detail.
fn tool_call_view(tc: &pentest_core::matrix::ToolCallInfo) -> ToolCallView {
    ToolCallView {
        name: tc.name.clone(),
        status: map_tool_status(tc.status),
        arguments: tc.arguments.clone(),
        result: tc.result.clone(),
        error: tc.error.clone(),
    }
}

/// Extract all tool calls from a message's parts.
fn extract_tool_calls(parts: &[MessagePart]) -> Vec<ToolCallView> {
    parts
        .iter()
        .filter_map(|p| match p {
            MessagePart::ToolCall(tc) => Some(tool_call_view(tc)),
            _ => None,
        })
        .collect()
}

/// Find the first tool call in a message's parts, if any.
fn first_tool_call(parts: &[MessagePart]) -> Option<ToolCallView> {
    parts.iter().find_map(|p| match p {
        MessagePart::ToolCall(tc) => Some(tool_call_view(tc)),
        _ => None,
    })
}

/// Map a message's ordered parts to ordered view parts, mirroring how the
/// Dioxus app renders `msg.parts` (text -> markdown, thinking -> block,
/// tool -> card) so native shells render the same structure.
fn parts_to_views(parts: &[MessagePart]) -> Vec<MessagePartView> {
    parts
        .iter()
        .map(|p| match p {
            MessagePart::Text(s) => MessagePartView::Text {
                blocks: pick_crux_core::markdown::parse_markdown(s),
            },
            MessagePart::Thinking(s) => MessagePartView::Thinking { text: s.clone() },
            MessagePart::ToolCall(tc) => MessagePartView::Tool {
                tool: tool_call_view(tc),
            },
        })
        .collect()
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
        parts: parts_to_views(&msg.parts),
        markdown: msg.text.clone(),
        blocks: pick_crux_core::markdown::parse_markdown(&msg.text),
        tool: first_tool_call(&msg.parts),
    }
}

/// Map a Vec of ChatMessages to MessageViews.
fn messages_to_views(messages: &[ChatMessage]) -> Vec<MessageView> {
    messages.iter().map(message_to_view).collect()
}

/// Map the server's AgentStatus to the crux AgentActivity that drives the
/// animated status line (mirrors the Dioxus status-label mapping).
fn map_activity(status: AgentStatus) -> AgentActivity {
    match status {
        AgentStatus::Processing => AgentActivity::Thinking,
        AgentStatus::Streaming => AgentActivity::Responding,
        AgentStatus::ExecutingTools => AgentActivity::RunningTools,
        AgentStatus::AwaitingConsent | AgentStatus::AwaitingClientTools => {
            AgentActivity::AwaitingConsent
        }
        // Terminal / unknown -> not actively working.
        AgentStatus::Idle
        | AgentStatus::StreamEnd
        | AgentStatus::Error
        | AgentStatus::Unknown => AgentActivity::Idle,
    }
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
    let activity = map_activity(state.agent_status);
    ConversationDelta {
        messages,
        tool_calls,
        done,
        activity,
    }
}

// ---------------------------------------------------------------------------
// CoreMatrixApi
// ---------------------------------------------------------------------------

/// The real MatrixApi backed by pentest-core.
///
/// `token` and `agent_id` are interior-mutable: the token starts empty (or a
/// bootstrap value) and is replaced once the native OAuth sign-in yields the
/// `__st` Studio session token; `agent_id` is resolved lazily on the first send
/// by listing the workspace agents (Easy Mode targets the pentest connector
/// agent, which the connector registration has already created).
pub struct CoreMatrixApi {
    pub api_url: String,
    token: std::sync::RwLock<String>,
    /// Cached resolved scan agent (id + display name). The name is used to title
    /// a new conversation the same way the Dioxus app does ("Chat with <name>").
    agent: std::sync::RwLock<Option<(String, String)>>,
}

/// The connector identity the auto-created scan agent binds to. This is the
/// connector's real name (matches how the shipping app registers), not a
/// placeholder — the tenant it pairs with is derived from the session token.
const SCAN_CONNECTOR_NAME: &str = "pentest-connector";

/// Extract the Keycloak realm from a session token's `iss` claim
/// (`https://<host>/realms/<realm>` -> `<realm>`). The realm is the tenant scope
/// the agent's connector key is built from. Returns None when the token is not a
/// decodable JWT (then the caller has no session-derived tenant).
pub fn realm_from_token(token: &str) -> Option<String> {
    use base64::Engine;
    let payload_b64 = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let iss = claims.get("iss")?.as_str()?;
    iss.rsplit_once("/realms/")
        .map(|(_, realm)| realm.to_string())
        .filter(|r| !r.is_empty())
}

impl CoreMatrixApi {
    pub fn new(api_url: String, token: String, agent_id: Option<String>) -> Self {
        Self {
            api_url,
            token: std::sync::RwLock::new(token),
            // A pre-seeded id has no known name yet; name is filled on resolve.
            agent: std::sync::RwLock::new(agent_id.map(|id| (id, String::new()))),
        }
    }

    /// Current auth token (cloned out so no lock is held across an await).
    fn token(&self) -> String {
        self.token.read().map(|t| t.clone()).unwrap_or_default()
    }

    /// Replace the auth token after a successful sign-in.
    fn store_token(&self, token: String) {
        if let Ok(mut t) = self.token.write() {
            *t = token;
        }
    }

    fn client(&self) -> pentest_core::matrix::MatrixChatClient {
        pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token())
    }

    /// Resolve the agent the scan/chat should target. Uses a cached id when set,
    /// otherwise lists the workspace agents and prefers the operational pentest
    /// agent (name contains "pentest" but not the report/validator specialists),
    /// falling back to the first agent. When the workspace has no agent yet, one
    /// is created (mirroring the Dioxus app, which auto-creates the pentest agent
    /// on first chat). The resolved id is cached.
    async fn resolve_agent(&self) -> Result<(String, String), String> {
        if let Some((id, name)) = self.agent.read().ok().and_then(|g| g.clone()) {
            if !id.is_empty() && !name.is_empty() {
                return Ok((id, name));
            }
        }
        let client = self.client();
        let agents = client.list_agents().await.map_err(|e| e.to_string())?;
        let (id, name) = match agents
            .iter()
            .find(|a| {
                let n = a.name.to_lowercase();
                n.contains("pentest") && !n.contains("report") && !n.contains("valid")
            })
            .or_else(|| agents.first())
        {
            Some(a) => (a.id.clone(), a.name.clone()),
            // Empty workspace: create the operational scan agent so a scan can
            // proceed, reusing the SHARED pentest-agent builder (the same one the
            // Dioxus app uses). The tenant is derived from the session token's
            // realm (never hardcoded); the connector name is the real connector
            // identity. tool_names is empty because this shell is a viewer, not
            // the registered connector — the connector's own registration seeds
            // the live tool set platform-side.
            None => {
                let tenant = realm_from_token(&self.token()).ok_or_else(|| {
                    "cannot derive tenant: session token has no realm (sign in first)".to_string()
                })?;
                let created = client
                    .create_agent(pentest_core::matrix::default_pentest_agent_input(
                        &tenant,
                        SCAN_CONNECTOR_NAME,
                        &[],
                    ))
                    .await
                    .map_err(|e| e.to_string())?;
                (created.id, created.name)
            }
        };
        if let Ok(mut g) = self.agent.write() {
            *g = Some((id.clone(), name.clone()));
        }
        Ok((id, name))
    }
}

#[async_trait::async_trait]
impl MatrixApi for CoreMatrixApi {
    fn set_token(&self, token: String) {
        self.store_token(token);
    }

    async fn send(&self, conversation_id: Option<String>, text: String) -> Result<String, String> {
        let client = self.client();
        let (agent_id, agent_name) = self.resolve_agent().await?;
        // Reuse an existing conversation, or create one titled the same way the
        // Dioxus app does ("Chat with <agent>"). A null title is rejected by the
        // server's changeset, so the title must be present.
        let conv = match conversation_id.filter(|c| !c.is_empty()) {
            Some(c) => c,
            None => client
                .create_conversation(Some(&format!("Chat with {agent_name}")))
                .await
                .map_err(|e| e.to_string())?,
        };
        client
            .send_message(&conv, &agent_id, &text)
            .await
            .map_err(|e| e.to_string())?;
        Ok(conv)
    }

    async fn poll(&self, conversation_id: String) -> Result<ConversationDelta, String> {
        // Match the Dioxus poll cadence (800ms) instead of hammering the server
        // with a tight re-emit loop; also gives the agent time to produce
        // incremental output between polls.
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        let state = self
            .client()
            .get_conversation(&conversation_id)
            .await
            .map_err(|e| e.to_string())?;
        let delta = state_to_delta(state);
        tracing::info!(
            "[poll] conv={} msgs={} tool_calls={} done={}",
            conversation_id,
            delta.messages.len(),
            delta.tool_calls.len(),
            delta.done,
        );
        Ok(delta)
    }

    async fn list_documents(&self, agent_id: Option<String>) -> Result<Vec<DocRef>, String> {
        // `None` means workspace-wide (matches the pentest-core client + the
        // Dioxus Reports list): do NOT auto-scope to the scan agent, or the
        // Reports list would hide docs created by other agents. Conversation
        // scoping happens in the App (DocumentsResult filters by conversation).
        let agent = agent_id.filter(|a| !a.is_empty());
        let docs = self
            .client()
            .list_documents(agent.as_deref())
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
        let token = pentest_core::matrix::fetch_matrix_token_browser(&api_url)
            .await
            .map_err(|e| e.to_string())?;
        // Adopt the freshly-obtained session token for all subsequent calls.
        self.store_token(token.clone());
        Ok(token)
    }

    async fn doc_content(
        &self,
        document_id: String,
        conversation_id: String,
    ) -> Result<String, String> {
        self.client()
            .get_document_content(&conversation_id, &document_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn shared_link(
        &self,
        conversation_id: String,
        document_id: String,
    ) -> Result<String, String> {
        self.client()
            .create_shared_link(&conversation_id, &document_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn list_conversations(&self) -> Result<Vec<ConversationRef>, String> {
        let agent = self.resolve_agent().await.ok().map(|(id, _name)| id);
        let convs = self
            .client()
            .list_conversations(agent.as_deref())
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
        let state = self
            .client()
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
                activity: Default::default(),
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

    #[test]
    fn realm_from_token_extracts_realm_from_iss() {
        use base64::Engine;
        // Build a minimal JWT (header.payload.sig) whose payload iss carries a realm.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"iss":"https://auth.strike48.test/realms/plg","sub":"x"}"#);
        let token = format!("{header}.{payload}.sig");
        assert_eq!(realm_from_token(&token).as_deref(), Some("plg"));

        // A personal-workspace realm slug round-trips too.
        let payload2 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"iss":"https://auth.strike48.test/realms/personal-abc123"}"#);
        assert_eq!(
            realm_from_token(&format!("{header}.{payload2}.s")).as_deref(),
            Some("personal-abc123")
        );

        // Non-JWT / no-realm tokens yield None (caller then errors, not scans wrong tenant).
        assert_eq!(realm_from_token("placeholder-token"), None);
        assert_eq!(realm_from_token(""), None);
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
    fn parts_map_in_order_with_thinking_and_multiple_tools() {
        let msg = ChatMessage {
            id: "m3".into(),
            sender_type: "AGENT".into(),
            sender_name: "Bot".into(),
            text: "intro final".into(),
            parts: vec![
                MessagePart::Text("intro".into()),
                MessagePart::Thinking("pondering".into()),
                MessagePart::ToolCall(ToolCallInfo {
                    id: "tc1".into(),
                    name: "nmap".into(),
                    arguments: Some("{\"target\":\"x\"}".into()),
                    result: Some("open".into()),
                    error: None,
                    status: ToolCallStatus::Success,
                }),
                MessagePart::ToolCall(ToolCallInfo {
                    id: "tc2".into(),
                    name: "nikto".into(),
                    arguments: None,
                    result: None,
                    error: Some("boom".into()),
                    status: ToolCallStatus::Failed,
                }),
                MessagePart::Text("final".into()),
            ],
        };
        let view = message_to_view(&msg);
        assert_eq!(view.parts.len(), 5);
        assert!(matches!(view.parts[0], MessagePartView::Text { .. }));
        match &view.parts[1] {
            MessagePartView::Thinking { text } => assert_eq!(text, "pondering"),
            other => panic!("expected thinking, got {other:?}"),
        }
        match &view.parts[2] {
            MessagePartView::Tool { tool } => {
                assert_eq!(tool.name, "nmap");
                assert_eq!(tool.status, ToolStatus::Success);
                assert_eq!(tool.arguments.as_deref(), Some("{\"target\":\"x\"}"));
                assert_eq!(tool.result.as_deref(), Some("open"));
            }
            other => panic!("expected tool, got {other:?}"),
        }
        match &view.parts[3] {
            MessagePartView::Tool { tool } => {
                assert_eq!(tool.name, "nikto");
                assert_eq!(tool.status, ToolStatus::Error);
                assert_eq!(tool.error.as_deref(), Some("boom"));
            }
            other => panic!("expected tool, got {other:?}"),
        }
        assert!(matches!(view.parts[4], MessagePartView::Text { .. }));
        // Legacy fields still populated: first tool + flattened text.
        assert_eq!(view.tool.as_ref().unwrap().name, "nmap");
        assert_eq!(view.markdown, "intro final");
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

//! Concrete Matrix GraphQL implementation of `ChatClient`.

use async_trait::async_trait;
use serde::Deserialize;

use super::types::*;

// ---------------------------------------------------------------------------
// MatrixChatClient
// ---------------------------------------------------------------------------

pub struct MatrixChatClient {
    api_url: String,
    client: reqwest::Client,
    auth_token: Option<String>,
}

impl MatrixChatClient {
    pub fn new(api_url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(
                std::env::var("MATRIX_TLS_INSECURE")
                    .or_else(|_| std::env::var("MATRIX_INSECURE"))
                    .map(|v| v == "1" || v == "true")
                    .unwrap_or(false),
            )
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            api_url: api_url.into(),
            client,
            auth_token: None,
        }
    }

    /// Create a new client that reuses the underlying HTTP connection pool
    /// from `other`. Avoids repeated `reqwest::Client::builder()` calls that
    /// can fail on Windows and wastes file descriptors elsewhere.
    pub fn from_shared(other: &Self) -> Self {
        Self {
            api_url: other.api_url.clone(),
            client: other.client.clone(),
            auth_token: None,
        }
    }

    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    pub fn set_auth_token(&mut self, token: impl Into<String>) {
        self.auth_token = Some(token.into());
    }

    /// Get the API URL this client is configured with.
    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    /// Build a POST request to the GraphQL endpoint with auth headers.
    fn authed_post(&self) -> reqwest::RequestBuilder {
        let url = format!("{}/api/v1alpha", super::normalize_url(&self.api_url));
        let mut req = self.client.post(&url);
        if let Some(ref token) = self.auth_token {
            req = req
                .query(&[("__st", token.as_str())])
                .header("Authorization", format!("Bearer {}", token))
                .header("Cookie", format!("__st={}", token));
        }
        req
    }

    /// Return an error if no auth token is set.
    fn require_auth(&self) -> crate::error::Result<()> {
        if self.auth_token.is_none() {
            return Err(crate::error::Error::Matrix("Auth token required".into()));
        }
        Ok(())
    }

    /// Execute a GraphQL request and return the typed `data` payload.
    ///
    /// Handles the full request lifecycle: send, status check, JSON decode,
    /// GraphQL-level error check, and `data` unwrap.
    async fn execute_gql<T: serde::de::DeserializeOwned>(
        &self,
        query: &str,
        variables: serde_json::Value,
    ) -> crate::error::Result<T> {
        let resp = self
            .authed_post()
            .json(&serde_json::json!({
                "query": query,
                "variables": variables,
            }))
            .send()
            .await
            .map_err(|e| crate::error::Error::Matrix(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(crate::error::Error::Matrix(format!(
                "GraphQL request failed: {} - {}",
                status, body
            )));
        }

        let body_text = resp
            .text()
            .await
            .map_err(|e| crate::error::Error::Matrix(e.to_string()))?;
        let gql: GqlResponse<T> = serde_json::from_str(&body_text).map_err(|e| {
            crate::error::Error::Matrix(format!(
                "GraphQL decode error: {} — body: {}",
                e,
                truncate_body(&body_text)
            ))
        })?;
        check_errors(gql.errors)?;

        gql.data
            .ok_or_else(|| crate::error::Error::Matrix("GraphQL response contained no data".into()))
    }
}

// ---------------------------------------------------------------------------
// Internal serde helpers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GqlResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GqlError>>,
}

#[derive(Deserialize)]
struct GqlError {
    message: String,
}

fn check_errors(errors: Option<Vec<GqlError>>) -> crate::error::Result<()> {
    if let Some(errs) = errors {
        let msgs: Vec<_> = errs.into_iter().map(|e| e.message).collect();
        return Err(crate::error::Error::Matrix(format!(
            "GraphQL errors: {}",
            msgs.join(", ")
        )));
    }
    Ok(())
}

fn truncate_body(body: &str) -> String {
    if body.len() <= 200 {
        body.to_string()
    } else {
        format!("{}…({} bytes total)", &body[..200], body.len())
    }
}

// ---------------------------------------------------------------------------
// JSON path helpers
// ---------------------------------------------------------------------------

/// Extract a string value from a JSON object by key.
fn json_str(obj: &serde_json::Value, key: &str) -> String {
    obj.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

// -- Agents --

#[derive(Deserialize)]
struct AgentsData {
    agents: Vec<AgentNode>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentNode {
    id: String,
    name: String,
    description: Option<String>,
    agent_greeting: Option<String>,
}

impl From<AgentNode> for AgentInfo {
    fn from(a: AgentNode) -> Self {
        AgentInfo {
            id: a.id,
            name: a.name,
            description: a.description,
            greeting: a.agent_greeting,
        }
    }
}

// -- CreateAgent --

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateAgentData {
    create_agent: AgentNode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateAgentData {
    update_agent: AgentNode,
}

// -- Conversation --

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateConvData {
    create_conversation: CreateConvNode,
}

#[derive(Deserialize)]
struct CreateConvNode {
    id: String,
}

// -- Ask --

#[derive(Deserialize)]
struct AskData {
    ask: AskNode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AskNode {
    user_message: Option<UserMsgRef>,
}

#[derive(Deserialize)]
struct UserMsgRef {
    id: String,
}

// -- GetConversation --

#[derive(Deserialize)]
struct GetConversationData {
    conversation: ConversationNode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConversationNode {
    agent_status: Option<String>,
    messages: Option<Vec<MessageNode>>,
}

#[derive(Deserialize)]
struct MessageNode {
    id: Option<String>,
    profile: Option<ProfileNode>,
    parts: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
struct ProfileNode {
    #[serde(rename = "type")]
    sender_type: Option<String>,
    name: Option<String>,
}

// -- ListConversations --

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListConversationsData {
    list_conversations: ListConversationsEdges,
}

#[derive(Deserialize)]
struct ListConversationsEdges {
    edges: Vec<ConversationEdge>,
}

#[derive(Deserialize)]
struct ConversationEdge {
    node: ConversationInfoNode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConversationInfoNode {
    id: String,
    title: Option<String>,
    summary: Option<String>,
    updated_at: Option<String>,
}

// ---------------------------------------------------------------------------
// Parse helpers for rich message parts
// ---------------------------------------------------------------------------

fn parse_message_parts(parts_json: &[serde_json::Value]) -> (String, Vec<MessagePart>) {
    let mut text_buf = String::new();
    let mut rich_parts = Vec::new();

    for part in parts_json {
        // TextPart
        if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
            if !text.is_empty() {
                if !text_buf.is_empty() {
                    text_buf.push('\n');
                }
                text_buf.push_str(text);
                rich_parts.push(MessagePart::Text(text.to_string()));
            }
        }

        // ThinkingPart
        if let Some(thinking_obj) = part.get("thinking").and_then(|t| t.as_object()) {
            if let Some(content) = thinking_obj.get("content").and_then(|c| c.as_str()) {
                if !content.is_empty() {
                    rich_parts.push(MessagePart::Thinking(content.to_string()));
                }
            }
        }

        // ToolCallPart
        if let Some(tc) = part.get("toolCall") {
            let tool = ToolCallInfo {
                id: json_str(tc, "id"),
                name: json_str(tc, "name"),
                arguments: tc
                    .get("arguments")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                result: tc
                    .get("result")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                error: tc
                    .get("error")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                status: tc
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .parse::<ToolCallStatus>()
                    .unwrap_or(ToolCallStatus::Unknown),
            };
            rich_parts.push(MessagePart::ToolCall(tool));
        }
    }

    (text_buf, rich_parts)
}

// ---------------------------------------------------------------------------
// GQL query constants
// ---------------------------------------------------------------------------

const LIST_AGENTS_QUERY: &str = r#"
    query ListAgents {
        agents(filter: { isEnabled: true }) {
            id
            name
            description
            agentGreeting
        }
    }
"#;

const CREATE_AGENT_QUERY: &str = r#"
    mutation CreateAgent($input: AgentInput!) {
        createAgent(input: $input) {
            id
            name
            description
            agentGreeting
        }
    }
"#;

const UPDATE_AGENT_QUERY: &str = r#"
    mutation UpdateAgent($input: UpdateAgentInput!) {
        updateAgent(input: $input) {
            id
            name
            description
            agentGreeting
        }
    }
"#;

const CREATE_CONVERSATION_QUERY: &str = r#"
    mutation CreateConversation($input: CreateConversationInput!) {
        createConversation(input: $input) { id }
    }
"#;

const ASK_QUERY: &str = r#"
    mutation Ask($input: ConversationInput!) {
        ask(input: $input) {
            userMessage { id }
        }
    }
"#;

const GET_CONVERSATION_QUERY: &str = r#"
    query GetConversation($id: ID!) {
        conversation(id: $id) {
            id
            agentStatus
            messages {
                id
                parts {
                    ... on TextPart { id text }
                    ... on ThinkingPart { id thinking { content } }
                    ... on ToolCallPart {
                        id
                        toolCall {
                            id
                            name
                            arguments
                            result
                            error
                            status
                        }
                    }
                }
                profile {
                    id
                    type
                    name
                }
            }
        }
    }
"#;

const LIST_CONVERSATIONS_QUERY: &str = r#"
    query ListConversations($first: Int, $filter: ListConversationsFilter) {
        listConversations(first: $first, filter: $filter) {
            edges {
                node {
                    id
                    title
                    summary
                    updatedAt
                }
            }
        }
    }
"#;

const DELETE_CONVERSATION_QUERY: &str = r#"
    mutation DeleteConversation($id: ID!) {
        deleteConversation(id: $id) { id }
    }
"#;

// ---------------------------------------------------------------------------
// Trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl ChatClient for MatrixChatClient {
    async fn list_agents(&self) -> crate::error::Result<Vec<AgentInfo>> {
        if self.auth_token.is_none() {
            return Ok(Vec::new());
        }

        let data: AgentsData = self
            .execute_gql(LIST_AGENTS_QUERY, serde_json::json!({}))
            .await?;

        Ok(data.agents.into_iter().map(AgentInfo::from).collect())
    }

    async fn find_agent_by_name(&self, name: &str) -> crate::error::Result<Option<AgentInfo>> {
        let agents = self.list_agents().await?;
        let lower = name.to_lowercase();
        Ok(agents
            .into_iter()
            .find(|a| a.name.to_lowercase().contains(&lower)))
    }

    async fn create_agent(&self, input: CreateAgentInput) -> crate::error::Result<AgentInfo> {
        self.require_auth()?;

        tracing::info!("Creating agent: {}", input.name);

        let data: CreateAgentData = self
            .execute_gql(CREATE_AGENT_QUERY, input.to_gql_variables())
            .await?;

        Ok(data.create_agent.into())
    }

    async fn update_agent(&self, input: UpdateAgentInput) -> crate::error::Result<AgentInfo> {
        self.require_auth()?;

        tracing::info!("Updating agent tools: id={}", input.id);

        let data: UpdateAgentData = self
            .execute_gql(UPDATE_AGENT_QUERY, input.to_gql_variables())
            .await?;

        Ok(data.update_agent.into())
    }

    async fn create_conversation(&self, title: Option<&str>) -> crate::error::Result<String> {
        tracing::info!("[Matrix] create_conversation title={:?}", title);
        self.require_auth()?;

        let variables = serde_json::json!({
            "input": {
                "title": title,
                "type": "CHAT",
            }
        });

        let data: CreateConvData = self
            .execute_gql(CREATE_CONVERSATION_QUERY, variables)
            .await?;

        Ok(data.create_conversation.id)
    }

    async fn send_message(
        &self,
        conversation_id: &str,
        agent_id: &str,
        message: &str,
    ) -> crate::error::Result<String> {
        tracing::info!(
            "[Matrix] send_message conv={} agent={} msg_len={}",
            conversation_id,
            agent_id,
            message.len()
        );
        self.require_auth()?;

        let variables = serde_json::json!({
            "input": {
                "conversationId": conversation_id,
                "agentId": agent_id,
                "parts": [{ "type": "TEXT", "text": message }],
            }
        });

        let data: AskData = self.execute_gql(ASK_QUERY, variables).await?;

        Ok(data.ask.user_message.map(|m| m.id).unwrap_or_default())
    }

    async fn get_conversation(
        &self,
        conversation_id: &str,
    ) -> crate::error::Result<ConversationState> {
        tracing::debug!("[Matrix] get_conversation id={}", conversation_id);
        self.require_auth()?;

        let variables = serde_json::json!({ "id": conversation_id });

        let data: GetConversationData = self.execute_gql(GET_CONVERSATION_QUERY, variables).await?;

        let conv = data.conversation;

        let agent_status = conv
            .agent_status
            .as_deref()
            .unwrap_or("IDLE")
            .parse::<AgentStatus>()
            .unwrap_or(AgentStatus::Idle);

        let messages = conv
            .messages
            .unwrap_or_default()
            .into_iter()
            .map(|m| {
                let id = m.id.unwrap_or_default();
                let (sender_type, sender_name) = match m.profile {
                    Some(p) => (
                        p.sender_type.unwrap_or_default(),
                        p.name.unwrap_or_default(),
                    ),
                    None => (String::new(), String::new()),
                };

                let parts_json = m.parts.unwrap_or_default();
                let (text, parts) = parse_message_parts(&parts_json);

                ChatMessage {
                    id,
                    sender_type,
                    sender_name,
                    text,
                    parts,
                }
            })
            .collect();

        Ok(ConversationState {
            messages,
            agent_status,
        })
    }

    async fn poll_for_response(
        &self,
        conversation_id: &str,
        poll_interval_ms: u64,
        max_polls: u32,
    ) -> crate::error::Result<ConversationState> {
        for _attempt in 0..max_polls {
            let result = self.get_conversation(conversation_id).await?;

            let done = result.agent_status.is_terminal();
            let has_agent_msg = result
                .messages
                .iter()
                .any(|m| m.sender_type != "USER" && !m.text.is_empty());

            if done && has_agent_msg {
                return Ok(result);
            }

            tokio::time::sleep(std::time::Duration::from_millis(poll_interval_ms)).await;
        }

        self.get_conversation(conversation_id).await
    }

    async fn list_conversations(
        &self,
        agent_id: Option<&str>,
    ) -> crate::error::Result<Vec<ConversationInfo>> {
        if self.auth_token.is_none() {
            return Ok(Vec::new());
        }

        let mut filter = serde_json::json!({ "type": "CHAT" });
        if let Some(aid) = agent_id {
            filter
                .as_object_mut()
                .expect("filter is a JSON object")
                .insert("agentIds".into(), serde_json::json!([aid]));
        }

        let variables = serde_json::json!({
            "first": 100,
            "filter": filter,
        });

        let data: ListConversationsData = self
            .execute_gql(LIST_CONVERSATIONS_QUERY, variables)
            .await?;

        let conversations = data
            .list_conversations
            .edges
            .into_iter()
            .map(|edge| ConversationInfo {
                id: edge.node.id,
                title: edge.node.title.unwrap_or_else(|| "Untitled".to_string()),
                summary: edge.node.summary,
                updated_at: edge.node.updated_at.unwrap_or_default(),
            })
            .collect();

        Ok(conversations)
    }

    async fn delete_conversation(&self, conversation_id: &str) -> crate::error::Result<()> {
        self.require_auth()?;

        let variables = serde_json::json!({ "id": conversation_id });

        let _: serde_json::Value = self
            .execute_gql(DELETE_CONVERSATION_QUERY, variables)
            .await?;

        Ok(())
    }
}

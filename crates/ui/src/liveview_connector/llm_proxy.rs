//! OpenAI-compatible LLM proxy that routes through Strike48 conversations.
//!
//! Webwright sends standard OpenAI chat completion requests to this endpoint.
//! The proxy translates them into conversation messages via the Matrix client,
//! waits for the response, and formats it back as an OpenAI response.

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use pentest_core::matrix::MatrixChatClient;

/// Shared state for the LLM proxy.
#[derive(Clone)]
pub struct LlmProxyState {
    pub matrix_client: Arc<RwLock<Option<MatrixChatClient>>>,
    /// Conversation ID for the browser automation agent.
    pub conversation_id: Arc<RwLock<Option<String>>>,
    /// Agent ID for the browser automation persona.
    pub agent_id: Arc<RwLock<Option<String>>>,
}

/// OpenAI ChatCompletion request format (subset Webwright uses).
#[derive(Debug, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub stream: Option<bool>,
}

/// OpenAI message format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// OpenAI ChatCompletion response format.
#[derive(Debug, Serialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<Choice>,
    pub usage: Usage,
}

#[derive(Debug, Serialize)]
pub struct Choice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: String,
}

#[derive(Debug, Serialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// POST /v1/chat/completions
async fn chat_completions(
    State(state): State<LlmProxyState>,
    Json(request): Json<ChatCompletionRequest>,
) -> Result<Json<ChatCompletionResponse>, StatusCode> {
    // Extract the last user message
    let user_message = request
        .messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.clone())
        .unwrap_or_default();

    if user_message.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Get Matrix client
    let client_guard = state.matrix_client.read().await;
    let client = match client_guard.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("LLM proxy: Matrix client not available");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    // Get conversation ID
    let conv_id = {
        let conv_guard = state.conversation_id.read().await;
        conv_guard.clone()
    };

    let conversation_id = match conv_id {
        Some(id) => id,
        None => {
            tracing::error!("LLM proxy: No conversation ID configured");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    let agent_id = {
        let agent_guard = state.agent_id.read().await;
        agent_guard.clone().unwrap_or_default()
    };

    // Send message and wait for response
    let response_text = match client
        .send_and_receive_message(&conversation_id, &agent_id, &user_message)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("LLM proxy: Failed to get response from Strike48: {}", e);
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    // Format as OpenAI response
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let response = ChatCompletionResponse {
        id: format!("chatcmpl-{}", uuid::Uuid::new_v4()),
        object: "chat.completion".to_string(),
        created: now,
        model: request.model,
        choices: vec![Choice {
            index: 0,
            message: ChatMessage {
                role: "assistant".to_string(),
                content: response_text,
            },
            finish_reason: "stop".to_string(),
        }],
        usage: Usage {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
        },
    };

    Ok(Json(response))
}

/// Create the LLM proxy router.
pub fn create_llm_proxy_routes(state: LlmProxyState) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_request_deserializes() {
        let json = serde_json::json!({
            "model": "strike48-default",
            "messages": [
                {"role": "system", "content": "You are a browser agent."},
                {"role": "user", "content": "Navigate to the login page."}
            ],
            "temperature": 0.7
        });

        let request: ChatCompletionRequest = serde_json::from_value(json).unwrap();
        assert_eq!(request.model, "strike48-default");
        assert_eq!(request.messages.len(), 2);
        assert_eq!(request.messages[1].role, "user");
    }

    #[test]
    fn chat_response_serializes() {
        let response = ChatCompletionResponse {
            id: "chatcmpl-test".to_string(),
            object: "chat.completion".to_string(),
            created: 1234567890,
            model: "strike48-default".to_string(),
            choices: vec![Choice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".to_string(),
                    content: "I'll navigate to the login page.".to_string(),
                },
                finish_reason: "stop".to_string(),
            }],
            usage: Usage {
                prompt_tokens: 50,
                completion_tokens: 20,
                total_tokens: 70,
            },
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["object"], "chat.completion");
        assert_eq!(json["choices"][0]["message"]["role"], "assistant");
    }
}

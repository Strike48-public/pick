//! OpenAI-compatible LLM proxy that routes through Strike48 conversations.
//!
//! Handles both the Responses API format (used by webwright) and the Chat
//! Completions format. Translates requests into conversation messages via
//! the Matrix client.

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;

use pentest_core::matrix::{ChatClient, MatrixChatClient};

/// Shared state for the LLM proxy.
#[derive(Clone)]
pub struct LlmProxyState {
    pub matrix_client: Arc<RwLock<Option<MatrixChatClient>>>,
    pub conversation_id: Arc<RwLock<Option<String>>>,
    pub agent_id: Arc<RwLock<Option<String>>>,
}

/// OpenAI Responses API request (what webwright sends).
/// Accepts any JSON — we extract what we need loosely.
#[derive(Debug, Deserialize)]
pub struct ResponsesApiRequest {
    #[serde(default)]
    pub model: String,
    /// "input" can be a string or array of message objects
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub max_output_tokens: Option<u32>,
    /// Catch-all for extra fields (text, instructions, etc.)
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, Value>,
}

/// OpenAI Responses API response format.
#[derive(Debug, Serialize)]
pub struct ResponsesApiResponse {
    pub id: String,
    pub output: Vec<OutputItem>,
    pub usage: ResponseUsage,
}

#[derive(Debug, Serialize)]
pub struct OutputItem {
    #[serde(rename = "type")]
    pub item_type: String,
    pub content: Vec<ContentBlock>,
}

#[derive(Debug, Serialize)]
pub struct ContentBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct ResponseUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

/// Extract the user's prompt from the Responses API input field.
/// Input can be a string or an array of message objects.
fn extract_prompt_from_input(input: &Value) -> String {
    // If it's a string, use directly
    if let Some(s) = input.as_str() {
        return s.to_string();
    }

    // If it's an array, find the last user message
    if let Some(arr) = input.as_array() {
        for msg in arr.iter().rev() {
            let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("");
            if role == "user" {
                // Content can be a string or array of content blocks
                if let Some(content) = msg.get("content") {
                    if let Some(s) = content.as_str() {
                        return s.to_string();
                    }
                    if let Some(blocks) = content.as_array() {
                        let texts: Vec<&str> = blocks
                            .iter()
                            .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                            .collect();
                        if !texts.is_empty() {
                            return texts.join("\n");
                        }
                    }
                }
            }
        }
        // Fallback: serialize the whole input as the prompt
        return serde_json::to_string(input).unwrap_or_default();
    }

    String::new()
}

/// POST /v1/chat/completions (also handles Responses API format)
///
/// Webwright posts the Responses API format here. We extract the prompt,
/// forward to Strike48 via conversation, and return a Responses-format reply.
async fn handle_llm_request(
    State(state): State<LlmProxyState>,
    Json(request): Json<ResponsesApiRequest>,
) -> Result<Json<ResponsesApiResponse>, StatusCode> {
    // Extract prompt from input
    let prompt = extract_prompt_from_input(&request.input);

    if prompt.is_empty() {
        tracing::warn!("LLM proxy: empty prompt from request");
        return Err(StatusCode::BAD_REQUEST);
    }

    tracing::info!(
        "LLM proxy: received request (model={}, prompt_len={})",
        request.model,
        prompt.len()
    );

    // Get Matrix client (try shared state first, fall back to session token)
    let client_guard = state.matrix_client.read().await;
    if client_guard.is_none() {
        drop(client_guard);
        // Try initializing from session token (set when iframe loads)
        let token = crate::session::get_auth_token();
        if !token.is_empty() {
            let api_url = std::env::var("MATRIX_API_URL").unwrap_or_default();
            if !api_url.is_empty() {
                let mut client = MatrixChatClient::new(&api_url);
                client.set_auth_token(&token);
                let mut guard = state.matrix_client.write().await;
                *guard = Some(client);
                tracing::info!("LLM proxy: initialized matrix client from session token");
            }
        }
    } else {
        drop(client_guard);
    }

    let client_guard = state.matrix_client.read().await;
    let client = match client_guard.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("LLM proxy: Matrix client not available (no session token)");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    // Get or create conversation (auto-create on first use)
    let conv_id = {
        let conv_guard = state.conversation_id.read().await;
        conv_guard.clone()
    };

    let conversation_id = match conv_id {
        Some(id) => id,
        None => {
            // Auto-create a conversation for webwright's LLM calls
            tracing::info!("LLM proxy: creating conversation for webwright");
            match client
                .create_conversation(Some("webwright-browser-agent"))
                .await
            {
                Ok(id) => {
                    let mut conv_guard = state.conversation_id.write().await;
                    *conv_guard = Some(id.clone());
                    id
                }
                Err(e) => {
                    tracing::error!("LLM proxy: failed to create conversation: {}", e);
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
            }
        }
    };

    // Get or upsert the webwright browser exploration agent
    let agent_id = {
        let agent_guard = state.agent_id.read().await;
        agent_guard.clone()
    };
    let agent_id = match agent_id {
        Some(id) => id,
        None => match upsert_webwright_agent(client).await {
            Ok(id) => {
                let mut guard = state.agent_id.write().await;
                *guard = Some(id.clone());
                id
            }
            Err(e) => {
                tracing::error!("LLM proxy: failed to upsert webwright agent: {}", e);
                String::new()
            }
        },
    };

    // Send to Strike48 and get response
    let response_text = match client
        .send_and_receive_message(&conversation_id, &agent_id, &prompt)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("LLM proxy: Strike48 error: {}", e);
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    // Format as Responses API response
    let response = ResponsesApiResponse {
        id: format!("resp_{}", uuid::Uuid::new_v4()),
        output: vec![OutputItem {
            item_type: "message".to_string(),
            content: vec![ContentBlock {
                block_type: "output_text".to_string(),
                text: response_text,
            }],
        }],
        usage: ResponseUsage {
            input_tokens: 0,
            output_tokens: 0,
        },
    };

    Ok(Json(response))
}

const WEBWRIGHT_AGENT_NAME: &str = "Webwright Browser Agent";

const WEBWRIGHT_SYSTEM_PROMPT: &str = "\
You are a web security testing agent controlling a headless browser via Playwright. \
Your job is to explore web applications, identify vulnerabilities, and generate \
replayable Python/Playwright scripts as proof-of-concept exploits.\n\n\
Focus on:\n\
- Mapping authentication flows (OAuth, SAML, 2FA)\n\
- Testing for XSS (reflected, stored, DOM-based)\n\
- CSRF token extraction and bypass\n\
- Client-side validation bypass\n\
- Session management weaknesses\n\
- JavaScript-heavy SPA testing\n\n\
Output your actions as structured JSON with thought, python_code, and done fields. \
Generate clean, replayable Playwright scripts for any vulnerabilities found.";

/// Find or create the webwright browser exploration agent.
async fn upsert_webwright_agent(client: &MatrixChatClient) -> pentest_core::error::Result<String> {
    use pentest_core::matrix::CreateAgentInput;

    // Check if the agent already exists
    if let Ok(Some(agent)) = client.find_agent_by_name(WEBWRIGHT_AGENT_NAME).await {
        tracing::info!("LLM proxy: found existing webwright agent: {}", agent.id);
        return Ok(agent.id);
    }

    // Create it
    tracing::info!("LLM proxy: creating webwright browser agent persona");
    let input = CreateAgentInput {
        name: WEBWRIGHT_AGENT_NAME.to_string(),
        description: Some(
            "AI-driven browser automation agent for web application security testing".to_string(),
        ),
        system_message: Some(WEBWRIGHT_SYSTEM_PROMPT.to_string()),
        agent_greeting: Some(
            "Browser agent ready. Give me a target URL and I'll explore it for vulnerabilities."
                .to_string(),
        ),
        context: None,
        tools: None,
    };

    let agent = client.create_agent(input).await?;
    tracing::info!("LLM proxy: created webwright agent: {}", agent.id);
    Ok(agent.id)
}

/// Create the LLM proxy router.
pub fn create_llm_proxy_routes(state: LlmProxyState) -> Router {
    Router::new()
        // Handle both paths — webwright posts directly to openai_endpoint
        .route("/v1/chat/completions", post(handle_llm_request))
        .route("/v1/responses", post(handle_llm_request))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_prompt_from_string_input() {
        let input = json!("Hello world");
        assert_eq!(extract_prompt_from_input(&input), "Hello world");
    }

    #[test]
    fn extract_prompt_from_message_array() {
        let input = json!([
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Test this page."}
        ]);
        assert_eq!(extract_prompt_from_input(&input), "Test this page.");
    }

    #[test]
    fn extract_prompt_from_content_blocks() {
        let input = json!([
            {"role": "user", "content": [{"type": "input_text", "text": "Navigate here"}]}
        ]);
        assert_eq!(extract_prompt_from_input(&input), "Navigate here");
    }

    #[test]
    fn responses_api_request_deserializes() {
        let json = json!({
            "model": "gpt-5.4",
            "input": [{"role": "user", "content": "test"}],
            "max_output_tokens": 4096,
            "text": {"format": {"type": "json_schema"}}
        });
        let req: ResponsesApiRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.model, "gpt-5.4");
        assert_eq!(req.max_output_tokens, Some(4096));
    }

    #[test]
    fn responses_api_response_serializes() {
        let resp = ResponsesApiResponse {
            id: "resp_test".to_string(),
            output: vec![OutputItem {
                item_type: "message".to_string(),
                content: vec![ContentBlock {
                    block_type: "output_text".to_string(),
                    text: "Hello".to_string(),
                }],
            }],
            usage: ResponseUsage {
                input_tokens: 10,
                output_tokens: 5,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["output"][0]["content"][0]["text"], "Hello");
    }
}

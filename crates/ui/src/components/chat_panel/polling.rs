//! Conversation polling helper with live status updates.

use dioxus::prelude::*;
use pentest_core::matrix::{AgentStatus, ChatClient, ChatMessage, MatrixChatClient};
use std::sync::Arc;

use super::constants::{MAX_POLL_ATTEMPTS, POLL_INTERVAL_MS};

/// Poll a conversation until the agent finishes, updating signals along the way.
pub async fn poll_and_update(
    client: Arc<MatrixChatClient>,
    conv_id: String,
    active_conversation_id: Signal<Option<String>>,
    mut messages: Signal<Vec<ChatMessage>>,
    mut agent_thinking: Signal<bool>,
    mut agent_status_text: Signal<String>,
    mut error_msg: Signal<Option<String>>,
) {
    /// Check if the UI is currently showing this conversation.
    fn is_active(active: &Signal<Option<String>>, conv_id: &str) -> bool {
        active
            .peek()
            .as_ref()
            .map(|c| c.as_str() == conv_id)
            .unwrap_or(false)
    }

    for _attempt in 0..MAX_POLL_ATTEMPTS {
        // Exit immediately if user switched away from this conversation
        if !is_active(&active_conversation_id, &conv_id) {
            tracing::info!(
                "[ChatPoll] Conversation {} no longer active, stopping poll",
                conv_id
            );
            return;
        }

        match client.get_conversation(&conv_id).await {
            Ok(state) => {
                let done = state.agent_status.is_terminal();
                let has_agent_msg = state
                    .messages
                    .iter()
                    .any(|m| m.sender_type != "USER" && !m.text.is_empty());
                if _attempt < 5 || _attempt % 10 == 0 {
                    tracing::info!(
                        "[ChatPoll] #{}: status={} msgs={} done={} has_agent_msg={}",
                        _attempt,
                        state.agent_status,
                        state.messages.len(),
                        done,
                        has_agent_msg,
                    );
                }

                // Only update UI if this conversation is currently displayed
                if is_active(&active_conversation_id, &conv_id) {
                    let status_label = match state.agent_status {
                        AgentStatus::Processing => "Thinking...",
                        AgentStatus::Streaming => "Responding...",
                        AgentStatus::ExecutingTools => "Running tools...",
                        AgentStatus::AwaitingConsent => "Awaiting approval...",
                        AgentStatus::AwaitingClientTools => "Running client tools...",
                        _ => "Thinking...",
                    };
                    agent_status_text.set(status_label.to_string());

                    if !state.messages.is_empty() {
                        let merged = merge_messages(&messages.peek(), &state.messages);
                        messages.set(merged);
                    }

                    if done && has_agent_msg {
                        let merged = merge_messages(&messages.peek(), &state.messages);
                        messages.set(merged);
                        agent_thinking.set(false);
                        agent_status_text.set(String::new());
                        return;
                    }
                } else if done && has_agent_msg {
                    // Conversation finished while user was viewing another one.
                    return;
                }
            }
            Err(e) => {
                if is_active(&active_conversation_id, &conv_id) {
                    error_msg.set(Some(format!("Failed to get response: {}", e)));
                    agent_thinking.set(false);
                    agent_status_text.set(String::new());
                }
                return;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS)).await;
    }

    // Final poll after timeout
    if is_active(&active_conversation_id, &conv_id) {
        match client.get_conversation(&conv_id).await {
            Ok(state) => {
                let merged = merge_messages(&messages.peek(), &state.messages);
                messages.set(merged);
            }
            Err(e) => error_msg.set(Some(format!("Polling timed out: {}", e))),
        }
        agent_thinking.set(false);
        agent_status_text.set(String::new());
    }
}

/// Merge server messages with local state.
/// Strategy: keep the current order as the base (user message was pushed first
/// at the correct position), then append any NEW messages from the server
/// that aren't already in the current list. This prevents server misordering
/// from placing the user's message after the agent's response.
fn merge_messages(current: &[ChatMessage], server: &[ChatMessage]) -> Vec<ChatMessage> {
    // If current is empty, just use server (initial load)
    if current.is_empty() {
        return server.to_vec();
    }

    // If server response is empty, keep current state
    if server.is_empty() {
        return current.to_vec();
    }

    // Start with current messages, replacing local placeholders with server versions
    let mut result: Vec<ChatMessage> = Vec::with_capacity(server.len());

    // First: keep local user messages at their positions, matched by text
    for msg in current.iter() {
        if msg.id.starts_with("local-") {
            // Try to find the server version of this local message
            if let Some(server_msg) = server
                .iter()
                .find(|s| s.sender_type == "USER" && s.text == msg.text)
            {
                result.push(server_msg.clone());
            } else {
                // Server hasn't caught up yet, keep local version
                result.push(msg.clone());
            }
        }
    }

    // Then: append all server messages not already in result (agent responses, etc.)
    for msg in server.iter() {
        let already_present = result.iter().any(|r| r.id == msg.id);
        if !already_present {
            result.push(msg.clone());
        }
    }

    result
}

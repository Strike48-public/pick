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
                        // Keep local user message at front if server hasn't caught up
                        let local_msgs: Vec<ChatMessage> = messages
                            .peek()
                            .iter()
                            .filter(|m| m.id.starts_with("local-"))
                            .cloned()
                            .collect();
                        let mut final_msgs = state.messages.clone();
                        for local_msg in &local_msgs {
                            let server_has_it = final_msgs
                                .iter()
                                .any(|s| s.sender_type == "USER" && s.text == local_msg.text);
                            if !server_has_it {
                                final_msgs.insert(0, local_msg.clone());
                            }
                        }
                        messages.set(final_msgs);
                    }

                    if done && has_agent_msg {
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
            Ok(state) => messages.set(state.messages),
            Err(e) => error_msg.set(Some(format!("Polling timed out: {}", e))),
        }
        agent_thinking.set(false);
        agent_status_text.set(String::new());
    }
}

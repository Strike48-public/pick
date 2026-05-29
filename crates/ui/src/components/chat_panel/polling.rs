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
/// Strategy: keep all current messages in their existing order (user message was
/// pushed first at the correct position), replace local placeholders with server
/// versions, then append any truly-new server messages not already present.
/// This prevents server misordering from placing the user's message after the
/// agent's response, while preserving all previously-fetched messages.
fn merge_messages(current: &[ChatMessage], server: &[ChatMessage]) -> Vec<ChatMessage> {
    // If current is empty, just use server (initial load)
    if current.is_empty() {
        return server.to_vec();
    }

    // If server response is empty, keep current state
    if server.is_empty() {
        return current.to_vec();
    }

    // Start with ALL current messages, replacing local placeholders with server versions
    let mut result: Vec<ChatMessage> = Vec::with_capacity(current.len().max(server.len()));

    for msg in current.iter() {
        if msg.id.starts_with("local-") {
            // Try to find the server version of this local message (matched by text)
            if let Some(server_msg) = server
                .iter()
                .find(|s| s.sender_type == "USER" && s.text == msg.text)
            {
                result.push(server_msg.clone());
            } else {
                // Server hasn't caught up yet, keep local version
                result.push(msg.clone());
            }
        } else {
            // Non-local message: check if server has an updated version
            if let Some(server_msg) = server.iter().find(|s| s.id == msg.id) {
                result.push(server_msg.clone());
            } else {
                // Server omitted it (pagination?), keep existing copy
                result.push(msg.clone());
            }
        }
    }

    // Append any truly-new server messages not already in result
    for msg in server.iter() {
        let already_present = result.iter().any(|r| r.id == msg.id);
        if !already_present {
            result.push(msg.clone());
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_msg(id: &str, text: &str) -> ChatMessage {
        ChatMessage {
            id: id.to_string(),
            sender_type: "USER".to_string(),
            sender_name: "You".to_string(),
            text: text.to_string(),
            parts: vec![],
        }
    }

    fn agent_msg(id: &str, text: &str) -> ChatMessage {
        ChatMessage {
            id: id.to_string(),
            sender_type: "AGENT".to_string(),
            sender_name: "agent".to_string(),
            text: text.to_string(),
            parts: vec![],
        }
    }

    #[test]
    fn merge_empty_current_returns_server() {
        let server = vec![user_msg("s1", "hello"), agent_msg("s2", "hi")];
        let result = merge_messages(&[], &server);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "s1");
        assert_eq!(result[1].id, "s2");
    }

    #[test]
    fn merge_empty_server_returns_current() {
        let current = vec![user_msg("local-0", "hello")];
        let result = merge_messages(&current, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "local-0");
    }

    #[test]
    fn merge_replaces_local_with_server_version() {
        let current = vec![user_msg("local-0", "hello")];
        let server = vec![user_msg("srv-1", "hello"), agent_msg("srv-2", "hi")];
        let result = merge_messages(&current, &server);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "srv-1"); // local replaced with server
        assert_eq!(result[1].id, "srv-2"); // agent appended
    }

    #[test]
    fn merge_preserves_user_before_agent_even_if_server_reverses() {
        // Server returns agent response before user message
        let current = vec![user_msg("local-0", "hello")];
        let server = vec![agent_msg("srv-2", "hi"), user_msg("srv-1", "hello")];
        let result = merge_messages(&current, &server);
        // User message stays first (from current order), agent appended after
        assert_eq!(result[0].id, "srv-1");
        assert_eq!(result[0].sender_type, "USER");
        assert_eq!(result[1].id, "srv-2");
        assert_eq!(result[1].sender_type, "AGENT");
    }

    #[test]
    fn merge_preserves_existing_non_local_messages() {
        // Current has server messages from a previous poll
        let current = vec![user_msg("srv-1", "hello"), agent_msg("srv-2", "hi")];
        // New poll returns same + new message
        let server = vec![
            user_msg("srv-1", "hello"),
            agent_msg("srv-2", "hi there"), // updated text
            agent_msg("srv-3", "anything else?"),
        ];
        let result = merge_messages(&current, &server);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].id, "srv-1");
        assert_eq!(result[1].text, "hi there"); // updated from server
        assert_eq!(result[2].id, "srv-3"); // new message appended
    }

    #[test]
    fn merge_keeps_message_if_server_omits_it() {
        let current = vec![user_msg("srv-1", "hello"), agent_msg("srv-2", "hi")];
        // Server only returns the user message (agent msg omitted)
        let server = vec![user_msg("srv-1", "hello")];
        let result = merge_messages(&current, &server);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "srv-1");
        assert_eq!(result[1].id, "srv-2"); // preserved from current
    }

    #[test]
    fn merge_local_not_yet_on_server() {
        let current = vec![user_msg("local-0", "new question")];
        // Server hasn't received it yet, only has old messages
        let server = vec![agent_msg("srv-old", "previous response")];
        let result = merge_messages(&current, &server);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "local-0"); // kept at position
        assert_eq!(result[1].id, "srv-old"); // appended
    }
}

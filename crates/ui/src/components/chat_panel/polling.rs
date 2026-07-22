//! Conversation polling helper with live status updates.

use dioxus::prelude::*;
use pentest_core::matrix::{AgentStatus, ChatClient, ChatMessage, MatrixChatClient};
use std::sync::Arc;

use super::constants::POLL_INTERVAL_MS;

// The chat-notice types and their builder now live in pentest-core so the crux
// shells share the exact same wording/behaviour. Re-exported here so existing
// `polling::ChatNotice` / `polling::ChatNoticeKind` references keep working.
pub use pentest_core::matrix::{build_error_notice, ChatNotice, ChatNoticeKind};

/// Poll a conversation until the agent finishes, updating signals along the way.
#[allow(clippy::too_many_arguments)]
pub async fn poll_and_update(
    client: Arc<MatrixChatClient>,
    conv_id: String,
    active_conversation_id: Signal<Option<String>>,
    mut messages: Signal<Vec<ChatMessage>>,
    mut agent_thinking: Signal<bool>,
    mut agent_status_text: Signal<String>,
    mut error_msg: Signal<Option<String>>,
    mut chat_notice: Signal<Option<ChatNotice>>,
) {
    /// Check if the UI is currently showing this conversation.
    fn is_active(active: &Signal<Option<String>>, conv_id: &str) -> bool {
        active
            .peek()
            .as_ref()
            .map(|c| c.as_str() == conv_id)
            .unwrap_or(false)
    }

    // Sticky flag: once we observe AgentStatus::Error, treat the conversation as
    // failed even if the backend transitions back to IDLE without producing an
    // agent message. The error reason itself only ships on the subscription
    // (`AgentStatusEvent.error`), which polling never sees — so we surface a
    // generic message that points the operator at the most likely causes.
    let mut saw_error = false;

    for _attempt in 0_u32.. {
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
                saw_error |= matches!(state.agent_status, AgentStatus::Error);
                if _attempt < 5 || _attempt % 10 == 0 {
                    tracing::info!(
                        "[ChatPoll] #{}: status={} msgs={} done={} has_agent_msg={} saw_error={}",
                        _attempt,
                        state.agent_status,
                        state.messages.len(),
                        done,
                        has_agent_msg,
                        saw_error,
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

                    // The agent backend hit an error. Cross-reference the
                    // tokenUsageStats query (same data Studio uses to render its
                    // sidebar usage widget) so we can tell "limit exceeded" from
                    // a generic upstream blip and surface a specific notice with
                    // a link the operator can click to verify in Studio.
                    if saw_error {
                        let notice = build_error_notice(&client).await;
                        chat_notice.set(Some(notice));
                        agent_thinking.set(false);
                        agent_status_text.set(String::new());
                        return;
                    }

                    if done && has_agent_msg {
                        agent_thinking.set(false);
                        agent_status_text.set(String::new());
                        return;
                    }
                } else if saw_error || (done && has_agent_msg) {
                    // Conversation finished (success or error) while user was viewing another one.
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

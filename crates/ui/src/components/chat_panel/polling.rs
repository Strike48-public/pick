//! Conversation polling helper with live status updates.

use dioxus::prelude::*;
use pentest_core::matrix::{
    AgentStatus, ChatClient, ChatMessage, MatrixChatClient, TokenUsageStatus,
};
use std::sync::Arc;

use super::constants::{MAX_POLL_ATTEMPTS, POLL_INTERVAL_MS};

/// Severity for an inline chat notice. Drives styling, not behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatNoticeKind {
    /// The server hit a hard limit (token/rate). User action required.
    TokenLimit,
    /// Some other upstream failure — usually transient.
    UpstreamError,
}

/// A small, less-shouty status message rendered inline near the chat input.
///
/// Polling produces these when it observes `AgentStatus::Error`. The actual
/// error reason ships on the `conversationEvents` GraphQL subscription
/// (`AgentStatusEvent.error`), which polling never sees — so we cross-reference
/// `tokenUsageStats` to tell "limit exceeded" from "generic upstream blip".
#[derive(Debug, Clone, PartialEq)]
pub struct ChatNotice {
    pub kind: ChatNoticeKind,
    pub title: String,
    pub detail: String,
    /// Optional URL to the Studio session (e.g. for checking token usage).
    pub studio_url: Option<String>,
}

/// Build a Studio web-app URL from the Matrix API base.
///
/// `MATRIX_API_URL` is the Matrix GraphQL host (e.g. `https://studio.example:443`);
/// the Studio SPA is served at `/studio/` on the same host. We:
///
/// * Strip the default port (`:443` for https, `:80` for http) — keeps the URL
///   shape identical to what a hand-typed Studio URL looks like, which avoids
///   bizarre browser security-context mismatches.
/// * Append `#/` so the hash-routed SPA bootstraps at the root route instead
///   of landing on a bare `/studio/` that some Vite builds will white-screen on.
fn studio_url_from_api(api_url: &str) -> Option<String> {
    let trimmed = api_url.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let normalized = strip_default_port(trimmed);
    Some(format!("{}/studio/#/", normalized))
}

/// Remove `:443` after an `https://` host, or `:80` after an `http://` host.
/// Leaves any other port (or absent port) untouched.
fn strip_default_port(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        if let Some(stripped_host) = strip_port_suffix(rest, ":443") {
            return format!("https://{}", stripped_host);
        }
    } else if let Some(rest) = url.strip_prefix("http://") {
        if let Some(stripped_host) = strip_port_suffix(rest, ":80") {
            return format!("http://{}", stripped_host);
        }
    }
    url.to_string()
}

/// Strip `port_suffix` from the host portion of `rest` (everything up to the
/// first `/`). Returns `None` if the port isn't present at that position.
fn strip_port_suffix(rest: &str, port_suffix: &str) -> Option<String> {
    let (host_part, path_part) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let stripped_host = host_part.strip_suffix(port_suffix)?;
    Some(format!("{}{}", stripped_host, path_part))
}

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

/// Build a `ChatNotice` describing why the conversation transitioned to
/// `AgentStatus::Error`. Queries `tokenUsageStats` to distinguish a real
/// limit-hit from a generic upstream blip; falls back to a generic notice
/// if that query fails or the server doesn't expose usage stats.
async fn build_error_notice(client: &MatrixChatClient) -> ChatNotice {
    let studio_url = studio_url_from_api(client.api_url());

    match client.get_token_usage_stats().await {
        Ok(Some(stats)) => match stats.first_exceeded() {
            Some((period, p)) => {
                let detail = match p.limit {
                    Some(limit) => format!(
                        "{} token limit reached ({} / {}). Wait for the window to reset, or \
                         contact your tenant admin to raise the limit.",
                        capitalize_period(period),
                        format_with_commas(p.usage),
                        format_with_commas(limit),
                    ),
                    None => format!(
                        "{} token limit reached ({} tokens used). Wait for the window to \
                         reset, or contact your tenant admin to raise the limit.",
                        capitalize_period(period),
                        format_with_commas(p.usage),
                    ),
                };
                ChatNotice {
                    kind: ChatNoticeKind::TokenLimit,
                    title: "Token limit reached".to_string(),
                    detail,
                    studio_url,
                }
            }
            None => generic_upstream_notice(studio_url, stats.daily.status),
        },
        Ok(None) => generic_upstream_notice(studio_url, TokenUsageStatus::Unknown),
        Err(e) => {
            tracing::warn!("[ChatPoll] tokenUsageStats query failed after ERROR: {}", e);
            generic_upstream_notice(studio_url, TokenUsageStatus::Unknown)
        }
    }
}

fn generic_upstream_notice(
    studio_url: Option<String>,
    daily_status: TokenUsageStatus,
) -> ChatNotice {
    // If the daily period is in WARNING, mention it — the operator may be
    // about to hit the limit and benefits from the heads-up.
    let detail = if matches!(daily_status, TokenUsageStatus::Warning) {
        "The agent backend returned an error and no reply was produced. You're close to your \
         daily token limit — check Studio for current usage."
            .to_string()
    } else {
        "The agent backend returned an error and no reply was produced. This is usually \
         transient — try again, or start a new chat."
            .to_string()
    };
    ChatNotice {
        kind: ChatNoticeKind::UpstreamError,
        title: "Agent error".to_string(),
        detail,
        studio_url,
    }
}

fn capitalize_period(p: &str) -> &'static str {
    match p {
        "daily" => "Daily",
        "weekly" => "Weekly",
        "monthly" => "Monthly",
        _ => "Period",
    }
}

fn format_with_commas(n: i64) -> String {
    let s = n.abs().to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    if n < 0 {
        format!("-{}", out)
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_with_commas_handles_small_and_large() {
        assert_eq!(format_with_commas(0), "0");
        assert_eq!(format_with_commas(42), "42");
        assert_eq!(format_with_commas(1_234), "1,234");
        assert_eq!(format_with_commas(1_080_000), "1,080,000");
        assert_eq!(format_with_commas(-1_234), "-1,234");
    }

    #[test]
    fn studio_url_strips_default_ports_and_appends_hash_route() {
        assert_eq!(
            studio_url_from_api("https://example.test:443/"),
            Some("https://example.test/studio/#/".to_string())
        );
        assert_eq!(
            studio_url_from_api("https://example.test:443"),
            Some("https://example.test/studio/#/".to_string())
        );
        assert_eq!(
            studio_url_from_api("http://example.test:80"),
            Some("http://example.test/studio/#/".to_string())
        );
        assert_eq!(studio_url_from_api(""), None);
    }

    #[test]
    fn studio_url_preserves_non_default_ports() {
        assert_eq!(
            studio_url_from_api("https://example.test:8443"),
            Some("https://example.test:8443/studio/#/".to_string())
        );
        assert_eq!(
            studio_url_from_api("http://localhost:4000"),
            Some("http://localhost:4000/studio/#/".to_string())
        );
    }

    #[test]
    fn strip_port_suffix_only_matches_at_host_boundary() {
        // ":443" appearing in a path must not be stripped
        assert_eq!(
            strip_default_port("https://example.test/foo:443/bar"),
            "https://example.test/foo:443/bar"
        );
    }
}

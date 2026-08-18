//! Inline chat-notice builder shared by the Dioxus app and the crux shells.
//!
//! When the agent backend transitions to `AgentStatus::Error`, the error reason
//! itself only ships on the `conversationEvents` GraphQL subscription
//! (`AgentStatusEvent.error`), which polling never sees. To surface a useful
//! message anyway we cross-reference `tokenUsageStats` (the same data Studio
//! renders in its sidebar usage widget) to tell a real "limit exceeded" from a
//! generic upstream blip, and produce a `ChatNotice` the UI can render.

use super::{ChatClient, MatrixChatClient, TokenUsageStatus};

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
pub fn studio_url_from_api(api_url: &str) -> Option<String> {
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

/// Build a `ChatNotice` describing why the conversation transitioned to
/// `AgentStatus::Error`. Queries `tokenUsageStats` to distinguish a real
/// limit-hit from a generic upstream blip; falls back to a generic notice
/// if that query fails or the server doesn't expose usage stats.
pub async fn build_error_notice(client: &MatrixChatClient) -> ChatNotice {
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
    // `unsigned_abs` (not `abs`) so i64::MIN — which has no positive i64 — does
    // not overflow-panic in debug builds on a hostile/pathological server value.
    let s = n.unsigned_abs().to_string();
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

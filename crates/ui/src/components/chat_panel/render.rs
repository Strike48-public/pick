//! Message rendering: rich parts, tool calls, markdown, and chart post-processing.

use dioxus::prelude::*;
use pentest_core::matrix::{ChatMessage, MessagePart, ToolCallInfo, ToolCallStatus};
use pulldown_cmark::{html, Options, Parser};

// ---------------------------------------------------------------------------
// Message rendering with rich parts
// ---------------------------------------------------------------------------

pub fn render_message(msg: &ChatMessage, expanded_tools: &mut Signal<Vec<String>>) -> Element {
    let is_user = msg.sender_type == "USER";
    let bubble_class = if is_user {
        "chat-bubble chat-bubble-user"
    } else {
        "chat-bubble chat-bubble-agent"
    };
    let sender = if is_user {
        "You".to_string()
    } else {
        msg.sender_name.clone()
    };
    let msg_id = msg.id.clone();

    if msg.parts.is_empty() {
        let html = render_markdown(&msg.text);
        return rsx! {
            div {
                key: "{msg_id}",
                class: "{bubble_class}",
                div { class: "chat-bubble-sender", "{sender}" }
                div {
                    class: "chat-bubble-text chat-markdown",
                    dangerous_inner_html: "{html}",
                    onmounted: move |_| {
                        spawn(async move {
                            if let Err(e) = document::eval("triggerChartPostProcess()").await {
                                tracing::warn!("JS eval failed (chart post-process): {e}");
                            }
                        });
                    },
                }
            }
        };
    }

    rsx! {
        div {
            key: "{msg_id}",
            class: "{bubble_class}",
            div { class: "chat-bubble-sender", "{sender}" }
            for part in msg.parts.iter() {
                {match part {
                    MessagePart::Text(text) => {
                        let html = render_markdown(text);
                        rsx! {
                            div {
                                class: "chat-bubble-text chat-markdown",
                                dangerous_inner_html: "{html}",
                                onmounted: move |_| {
                                    spawn(async move {
                                        if let Err(e) = document::eval("triggerChartPostProcess()").await {
                                            tracing::warn!("JS eval failed (chart post-process): {e}");
                                        }
                                    });
                                },
                            }
                        }
                    }
                    MessagePart::Thinking(text) => {
                        let text = text.clone();
                        rsx! {
                            div { class: "chat-thinking-block",
                                div { class: "chat-thinking-label", "Thinking" }
                                div { class: "chat-thinking-content", "{text}" }
                            }
                        }
                    }
                    MessagePart::ToolCall(tc) => {
                        render_tool_call(tc, expanded_tools)
                    }
                }}
            }
        }
    }
}

fn render_tool_call(tc: &ToolCallInfo, expanded_tools: &mut Signal<Vec<String>>) -> Element {
    let is_expanded = expanded_tools.read().contains(&tc.id);
    let tc_id_toggle = tc.id.clone();
    let name = tc.name.clone();
    let status = tc.status;
    let args = tc.arguments.clone();
    let result = tc.result.clone();
    let error = tc.error.clone();

    let status_class = match status {
        ToolCallStatus::Success => "tool-status-success",
        ToolCallStatus::Failed => "tool-status-error",
        _ => "tool-status-pending",
    };
    let status_display = status.to_string();

    rsx! {
        div { class: "chat-tool-call",
            div {
                class: "chat-tool-header",
                onclick: {
                    let mut expanded = *expanded_tools;
                    move |_| {
                        let mut list = expanded.write();
                        if let Some(pos) = list.iter().position(|id| id == &tc_id_toggle) {
                            list.remove(pos);
                        } else {
                            list.push(tc_id_toggle.clone());
                        }
                    }
                },
                span { class: "chat-tool-icon",
                    if is_expanded { "v " } else { "> " }
                }
                span { class: "chat-tool-name", "{name}" }
                span { class: "chat-tool-status {status_class}", "{status_display}" }
            }
            if is_expanded {
                div { class: "chat-tool-details",
                    if let Some(ref args_str) = args {
                        div { class: "chat-tool-section",
                            div { class: "chat-tool-section-label", "Arguments" }
                            pre { class: "chat-tool-code", "{args_str}" }
                        }
                    }
                    if let Some(ref result_str) = result {
                        div { class: "chat-tool-section",
                            div { class: "chat-tool-section-label", "Result" }
                            pre { class: "chat-tool-code", "{result_str}" }
                        }
                    }
                    if let Some(ref err_str) = error {
                        div { class: "chat-tool-section chat-tool-error",
                            div { class: "chat-tool-section-label", "Error" }
                            pre { class: "chat-tool-code", "{err_str}" }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Markdown rendering (pulldown-cmark)
// ---------------------------------------------------------------------------

/// Convert markdown text to HTML using pulldown-cmark.
pub fn render_markdown(input: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);

    let parser = Parser::new_ext(input, options);
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);
    html_output
}

/// JS snippet that loads mermaid + echarts CDN scripts and defines
/// `window.__processChatCharts()` to post-process code blocks.
pub const CHART_PROCESSOR_JS: &str = include_str!("../../assets/chart_processor.js");

/// Shared JS utility functions (scroll, form submit, etc.) injected once at mount.
pub const UTILS_JS: &str = include_str!("../../assets/utils.js");

/// Format an ISO 8601 timestamp as a relative time string (e.g. "2m ago").
pub fn format_relative_time(iso: &str) -> String {
    let parsed = chrono::DateTime::parse_from_rfc3339(iso)
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(&format!("{}Z", iso.trim())))
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let now = chrono::Utc::now();
    let ts = match parsed {
        Ok(dt) => dt,
        Err(_) => return "\u{2014}".to_string(),
    };

    let diff = (now - ts).num_seconds();
    if diff <= 0 {
        return "now".to_string();
    }
    let diff = diff as u64;
    if diff < 60 {
        return format!("{}s ago", diff);
    }
    let mins = diff / 60;
    if mins < 60 {
        return format!("{}m ago", mins);
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{}h ago", hours);
    }
    let days = hours / 24;
    format!("{}d ago", days)
}

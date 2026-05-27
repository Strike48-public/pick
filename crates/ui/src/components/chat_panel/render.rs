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
            // Show webwright screenshots ALWAYS (not just when expanded)
            if name == "webwright" {
                if let Some(ref result_str) = result {
                    {render_webwright_screenshots(result_str)}
                }
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

/// Render the live progress widget or fallback to the standard thinking dots.
/// When webwright is running via sidecar, shows a rich live feed of steps/screenshots.
pub fn render_live_progress(status_text: &str) -> Element {
    // Poll the watch channel into a Dioxus signal for reactivity
    let mut progress_signal = use_signal(|| pentest_tools::webwright::live_state::WebwrightProgress::default());

    use_future(move || async move {
        let mut rx = pentest_tools::webwright::live_state::subscribe();
        loop {
            // Wait for changes
            if rx.changed().await.is_err() {
                break;
            }
            progress_signal.set(rx.borrow().clone());
        }
    });

    let progress = progress_signal.read().clone();

    if progress.running {
        // Rich live webwright widget
        let step_text = format!("Step {} — {}", progress.step, progress.action);
        let finding_count = progress.findings.len();

        rsx! {
            div {
                style: "padding: 8px 0;",
                // Step indicator with pulsing dot
                div {
                    style: "display: flex; align-items: center; gap: 8px; margin-bottom: 6px;",
                    div {
                        style: "width: 8px; height: 8px; border-radius: 50%; background: #00ff88; animation: pulse 1.5s infinite; flex-shrink: 0;",
                    }
                    span {
                        style: "font-size: 13px; color: #00ff88; font-family: monospace;",
                        "{step_text}"
                    }
                }
                // Live screenshot (if available)
                if let Some(ref screenshot) = progress.screenshot {
                    div {
                        style: "margin: 6px 0; max-width: 280px; border: 1px solid #00ff8840; border-radius: 4px; overflow: hidden;",
                        img {
                            src: "data:image/png;base64,{screenshot}",
                            style: "width: 100%; height: auto; display: block; opacity: 0.9;",
                        }
                    }
                }
                // Findings ticker
                if finding_count > 0 {
                    div {
                        style: "margin-top: 6px; font-size: 11px;",
                        for finding in progress.findings.iter() {
                            div {
                                style: "display: flex; align-items: center; gap: 6px; margin: 2px 0;",
                                span {
                                    style: "padding: 1px 5px; border-radius: 3px; font-size: 10px; font-weight: 600; background: {severity_color(&finding.severity)}; color: #fff;",
                                    "{finding.severity}"
                                }
                                span {
                                    style: "color: #ccc;",
                                    "{finding.title}"
                                }
                            }
                        }
                    }
                }
            }
            // Pulse animation
            style { "@keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.3; }} }}" }
        }
    } else {
        // Standard thinking indicator
        rsx! {
            div { class: "chat-thinking-status",
                if !status_text.is_empty() {
                    span { class: "chat-status-label", "{status_text}" }
                }
                div { class: "chat-thinking-dots",
                    span { "." }
                    span { "." }
                    span { "." }
                }
            }
        }
    }
}

fn severity_color(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => "#dc2626",
        "high" => "#ea580c",
        "medium" => "#ca8a04",
        "low" => "#2563eb",
        _ => "#6b7280",
    }
}

/// Render webwright screenshots as inline thumbnails.
/// Reads files from disk at render time and base64-encodes them for display.
/// The LLM only sees file paths — the user sees actual images.
fn render_webwright_screenshots(result_json: &str) -> Element {
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(result_json);
    let val = match parsed {
        Ok(v) => v,
        Err(_) => return rsx! {},
    };

    // Get screenshot paths from the result
    let paths: Vec<String> = val["data"]["artifacts"]["screenshots"]
        .as_array()
        .or_else(|| val["artifacts"]["screenshots"].as_array())
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|p| p.as_str().map(|s| s.to_string()))
        .filter(|p| p.contains("final_"))
        .collect();

    if paths.is_empty() {
        return rsx! {};
    }

    // Resolve paths to actual files on disk and base64-encode for display.
    // Paths are workspace-relative like "webwright/<task-id>/final_runs/..."
    let workspace = crate::liveview_server::get_workspace_path();
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let rootfs_tmp = format!("{}/.local/share/pentest-sandbox/blackarch-rootfs/tmp", home);

    let screenshots: Vec<(String, String)> = paths
        .iter()
        .filter_map(|rel_path| {
            // Try connector workspace first, then rootfs /tmp
            let ws_full = std::path::Path::new(&workspace).join(rel_path);
            let rootfs_full = std::path::Path::new(&rootfs_tmp).join(rel_path);
            let file_path = if ws_full.exists() { ws_full } else { rootfs_full };

            std::fs::read(&file_path).ok().map(|bytes| {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                let filename = rel_path.rsplit('/').next().unwrap_or("screenshot").to_string();
                let data_uri = format!("data:image/png;base64,{}", b64);
                (filename, data_uri)
            })
        })
        .collect();

    if screenshots.is_empty() {
        return rsx! {};
    }

    rsx! {
        div {
            style: "margin-top: 8px; display: flex; flex-wrap: wrap; gap: 8px;",
            for (filename, data_uri) in screenshots.iter() {
                div {
                    class: "webwright-thumb",
                    style: "display: inline-block; max-width: 320px; border: 1px solid #333; border-radius: 6px; overflow: hidden; background: #1a1a2e; cursor: pointer;",
                    img {
                        class: "webwright-thumb-img",
                        src: "{data_uri}",
                        alt: "{filename}",
                        style: "width: 100%; height: auto; display: block;",
                    }
                    div {
                        style: "padding: 4px 8px; font-size: 11px; color: #888; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;",
                        "{filename}"
                    }
                }
            }
        }
        // Modal: clicking a thumbnail opens a fullscreen overlay (click overlay to close)
        {
            let modal_js = "(function(){document.querySelectorAll('.webwright-thumb').forEach(function(el){el.onclick=function(){var img=this.querySelector('.webwright-thumb-img');if(!img)return;var overlay=document.createElement('div');overlay.style.cssText='position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.92);z-index:9999;display:flex;align-items:center;justify-content:center;cursor:pointer;';var close=function(){document.body.removeChild(overlay);document.removeEventListener(\"keydown\",esc);};overlay.onclick=close;var esc=function(e){if(e.key===\"Escape\")close();};document.addEventListener(\"keydown\",esc);var big=document.createElement('img');big.src=img.src;big.style.cssText='max-width:95vw;max-height:95vh;object-fit:contain;border-radius:4px;';overlay.appendChild(big);document.body.appendChild(overlay);};});})()";
            rsx! { script { dangerous_inner_html: "{modal_js}" } }
        }
    }
}

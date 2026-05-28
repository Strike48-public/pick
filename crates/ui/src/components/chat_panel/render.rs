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
    let status_display = match status {
        ToolCallStatus::Success => "success".to_string(),
        ToolCallStatus::Failed => "failed".to_string(),
        _ => "running".to_string(),
    };

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
            // Webwright: show live progress while running, screenshots when done
            if name == "webwright" {
                if result.is_none() && error.is_none() {
                    // In-progress: show live widget
                    {render_live_progress("")}
                } else if let Some(ref result_str) = result {
                    // Complete: show screenshot thumbnails
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

/// Render the live progress widget for a webwright tool call.
/// Subscribes to the specific task's progress channel.
pub fn render_live_progress(status_text: &str) -> Element {
    // Find the most recent running task (or any task with progress)
    let mut progress_signal = use_signal(|| pentest_tools::webwright::live_state::WebwrightProgress::default());

    use_future(move || async move {
        loop {
            // Find active tasks and subscribe to one
            let tasks = pentest_tools::webwright::live_state::running_tasks();
            if let Some(task_id) = tasks.first() {
                let mut rx = pentest_tools::webwright::live_state::subscribe(task_id);
                loop {
                    if rx.changed().await.is_err() {
                        break;
                    }
                    let p = rx.borrow().clone();
                    let still_running = p.running;
                    progress_signal.set(p);
                    if !still_running {
                        break;
                    }
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    });

    let progress = progress_signal.read().clone();

    if progress.running {
        let step_text = format!("Step {} — {}", progress.step, progress.action);
        let has_screenshots = !progress.screenshots.is_empty() || progress.screenshot.is_some();

        rsx! {
            div {
                style: "padding: 8px; margin-top: 4px; background: #0d1117; border: 1px solid #21262d; border-radius: 6px; max-width: 700px;",
                // Header bar
                div {
                    style: "display: flex; align-items: center; gap: 8px; margin-bottom: 8px; padding-bottom: 6px; border-bottom: 1px solid #161b22;",
                    div {
                        style: "width: 6px; height: 6px; border-radius: 50%; background: #00ff88; animation: ww-pulse 1.2s ease-in-out infinite; flex-shrink: 0;",
                    }
                    span {
                        style: "font-size: 11px; color: #00ff88; font-family: 'JetBrains Mono', monospace; flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;",
                        "{step_text}"
                    }
                    span {
                        style: "font-size: 9px; color: #484f58; font-family: 'JetBrains Mono', monospace; flex-shrink: 0;",
                        "LIVE"
                    }
                }
                // Two-column layout: log left, screenshots right
                div {
                    style: "display: flex; gap: 8px; min-height: 100px;",
                    // Left: rolling log
                    div {
                        style: "flex: 1; min-width: 0;",
                        if !progress.log.is_empty() {
                            div {
                                style: "background: #010409; border: 1px solid #161b22; border-radius: 3px; padding: 5px 7px; font-family: 'JetBrains Mono', monospace; font-size: 10px; max-height: 160px; overflow-y: auto; line-height: 1.5;",
                                for entry in progress.log.iter().rev().take(10).collect::<Vec<_>>().into_iter().rev() {
                                    div {
                                        style: "color: #6e7681; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;",
                                        span {
                                            style: "color: #363b42; margin-right: 5px;",
                                            "{entry.step:>2}"
                                        }
                                        "{entry.action}"
                                    }
                                }
                            }
                        }
                        // Findings below log
                        if !progress.findings.is_empty() {
                            div {
                                style: "margin-top: 6px;",
                                for finding in progress.findings.iter() {
                                    div {
                                        style: "display: flex; align-items: center; gap: 5px; margin: 2px 0; font-size: 10px;",
                                        span {
                                            style: "padding: 0px 4px; border-radius: 2px; font-weight: 700; font-size: 9px; text-transform: uppercase; background: {severity_color(&finding.severity)}; color: #fff;",
                                            "{finding.severity}"
                                        }
                                        span { style: "color: #c9d1d9;", "{finding.title}" }
                                    }
                                }
                            }
                        }
                    }
                    // Right: primary screenshot large, thumbnails below
                    if has_screenshots {
                        div {
                            style: "width: 280px; flex-shrink: 0; display: flex; flex-direction: column; gap: 4px;",
                            // Primary (most recent) — large, max-height capped with scroll
                            if let Some(ref screenshot) = progress.screenshot {
                                div {
                                    class: "webwright-thumb",
                                    style: "border: 1px solid #00ff8840; border-radius: 4px; overflow-y: auto; max-height: 220px; cursor: pointer;",
                                    img {
                                        class: "webwright-thumb-img",
                                        src: "data:image/png;base64,{screenshot}",
                                        style: "width: 100%; height: auto; display: block;",
                                    }
                                }
                            }
                            // Older thumbnails — small horizontal strip
                            if progress.screenshots.len() > 1 {
                                div {
                                    style: "display: flex; gap: 3px; overflow-x: auto;",
                                    for shot in progress.screenshots.iter().rev().skip(1).take(6) {
                                        div {
                                            class: "webwright-thumb",
                                            style: "flex-shrink: 0; width: 56px; height: 38px; border: 1px solid #21262d; border-radius: 2px; overflow: hidden; cursor: pointer; opacity: 0.75;",
                                            img {
                                                class: "webwright-thumb-img",
                                                src: "data:image/png;base64,{shot}",
                                                style: "width: 100%; height: 100%; object-fit: cover;",
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            style { "@keyframes ww-pulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:0.2; }} }}" }
            // Modal for clicking screenshots (re-attaches on each render)
            {
                let modal_js = "(function(){document.querySelectorAll('.webwright-thumb').forEach(function(el){if(el._ww)return;el._ww=1;el.onclick=function(){var img=this.querySelector('.webwright-thumb-img');if(!img)return;var overlay=document.createElement('div');overlay.style.cssText='position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(2,4,8,0.95);z-index:9999;display:flex;align-items:center;justify-content:center;cursor:pointer;backdrop-filter:blur(4px);';var close=function(){document.body.removeChild(overlay);document.removeEventListener(\"keydown\",esc);};overlay.onclick=close;var esc=function(e){if(e.key===\"Escape\"||e.key===\"ArrowLeft\"||e.key===\"ArrowRight\")close();};document.addEventListener(\"keydown\",esc);var big=document.createElement('img');big.src=img.src;big.style.cssText='max-width:92vw;max-height:90vh;object-fit:contain;border-radius:6px;border:1px solid #21262d;';overlay.appendChild(big);document.body.appendChild(overlay);};});})()";
                rsx! { script { dangerous_inner_html: "{modal_js}" } }
            }
        }
    } else {
        rsx! {}
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
        .filter(|p| p.contains("final_") && (p.ends_with(".png") || p.ends_with(".jpg") || p.ends_with(".jpeg")))
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
                let mime = if rel_path.ends_with(".jpg") || rel_path.ends_with(".jpeg") {
                    "image/jpeg"
                } else {
                    "image/png"
                };
                let data_uri = format!("data:{};base64,{}", mime, b64);
                (filename, data_uri)
            })
        })
        .collect();

    if screenshots.is_empty() {
        return rsx! {};
    }

    let count = screenshots.len();

    rsx! {
        div {
            style: "margin-top: 6px; border-left: 2px solid #58a6ff44; padding-left: 10px;",
            // Summary line
            div {
                style: "font-size: 10px; color: #58a6ff; font-family: 'JetBrains Mono', monospace; margin-bottom: 6px; letter-spacing: 0.5px; text-transform: uppercase;",
                "{count} screenshots captured"
            }
            // Gallery grid: 3-4 columns of small thumbnails
            div {
                style: "display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 6px;",
                for (filename, data_uri) in screenshots.iter().rev() {
                    div {
                        class: "webwright-thumb",
                        style: "border: 1px solid #21262d; border-radius: 4px; overflow: hidden; cursor: pointer; transition: border-color 0.15s;",
                        img {
                            class: "webwright-thumb-img",
                            src: "{data_uri}",
                            alt: "{filename}",
                            style: "width: 100%; height: 90px; object-fit: cover; display: block;",
                        }
                        div {
                            style: "padding: 3px 6px; font-size: 9px; color: #6e7681; font-family: 'JetBrains Mono', monospace; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; background: #010409;",
                            "{filename}"
                        }
                    }
                }
            }
        }
        // Modal: click thumb → fullscreen overlay (Escape or click to close)
        {
            let modal_js = "(function(){document.querySelectorAll('.webwright-thumb').forEach(function(el){el.onclick=function(){var img=this.querySelector('.webwright-thumb-img');if(!img)return;var overlay=document.createElement('div');overlay.style.cssText='position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(2,4,8,0.95);z-index:9999;display:flex;align-items:center;justify-content:center;cursor:pointer;backdrop-filter:blur(4px);';var close=function(){document.body.removeChild(overlay);document.removeEventListener(\"keydown\",esc);};overlay.onclick=close;var esc=function(e){if(e.key===\"Escape\")close();};document.addEventListener(\"keydown\",esc);var big=document.createElement('img');big.src=img.src;big.style.cssText='max-width:92vw;max-height:90vh;object-fit:contain;border-radius:6px;border:1px solid #21262d;';overlay.appendChild(big);var hint=document.createElement('div');hint.textContent='ESC or click to close';hint.style.cssText='position:absolute;bottom:20px;color:#6e7681;font-size:12px;font-family:monospace;';overlay.appendChild(hint);document.body.appendChild(overlay);};});})()";
            rsx! { script { dangerous_inner_html: "{modal_js}" } }
        }
    }
}

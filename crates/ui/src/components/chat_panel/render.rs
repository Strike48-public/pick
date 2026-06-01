//! Message rendering: rich parts, tool calls, markdown, and chart post-processing.

use dioxus::prelude::*;
use pentest_core::matrix::{ChatMessage, MessagePart, ToolCallInfo, ToolCallStatus};
use pulldown_cmark::{html, Options, Parser};

// ---------------------------------------------------------------------------
// Message rendering with rich parts
// ---------------------------------------------------------------------------

pub fn render_message(
    msg: &ChatMessage,
    expanded_tools: &mut Signal<Vec<String>>,
    show_sender: bool,
) -> Element {
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
                if show_sender {
                    div { class: "chat-bubble-sender", "{sender}" }
                }
                div {
                    class: "chat-bubble-text chat-markdown",
                    dangerous_inner_html: "{html}",
                }
            }
        };
    }

    rsx! {
        div {
            key: "{msg_id}",
            class: "{bubble_class}",
            if show_sender {
                div { class: "chat-bubble-sender", "{sender}" }
            }
            for part in msg.parts.iter() {
                {match part {
                    MessagePart::Text(text) => {
                        let html = render_markdown(text);
                        rsx! {
                            div {
                                class: "chat-bubble-text chat-markdown",
                                dangerous_inner_html: "{html}",
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
                WebwrightGallery { result: result.clone(), error: error.clone() }
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

// ---------------------------------------------------------------------------
// Webwright gallery widget (Dioxus-native modal, no inline JS)
// ---------------------------------------------------------------------------

/// Webwright widget component — handles both live progress and completed gallery.
/// Uses Dioxus signals for the lightbox modal instead of fragile inline scripts.
#[component]
pub fn WebwrightGallery(result: Option<String>, error: Option<String>) -> Element {
    // Modal state: (all_images as data URIs, current index)
    let mut modal_open = use_signal(|| Option::<(Vec<String>, usize)>::None);
    let mut progress_signal =
        use_signal(pentest_tools::webwright::live_state::WebwrightProgress::default);

    let is_live = result.is_none() && error.is_none();

    // Subscribe to live progress updates
    use_future(move || async move {
        loop {
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

    // Build the completed screenshots list (only when result exists)
    let completed_shots: Vec<(String, String)> = if let Some(ref result_str) = result {
        load_screenshots_from_result(result_str)
    } else {
        Vec::new()
    };

    rsx! {
        // --- Live progress view ---
        if is_live {
            {render_live_widget(&progress_signal.read(), &mut modal_open)}
        }

        // --- Completed gallery view ---
        if !completed_shots.is_empty() {
            {render_completed_gallery(&completed_shots, &mut modal_open)}
        }

        // --- Lightbox modal (rendered at this level so it's always in the tree) ---
        {render_lightbox_modal(&mut modal_open)}

        // Keyframe animation for the pulse indicator
        style { "@keyframes ww-pulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:0.2; }} }}" }
    }
}

/// Render the live progress panel (log + screenshots).
fn render_live_widget(
    progress: &pentest_tools::webwright::live_state::WebwrightProgress,
    modal_open: &mut Signal<Option<(Vec<String>, usize)>>,
) -> Element {
    if !progress.running {
        return rsx! {};
    }

    let step_text = format!("Step {} \u{2014} {}", progress.step, progress.action);
    let has_screenshots = !progress.screenshots.is_empty() || progress.screenshot.is_some();

    // Collect all live screenshot URIs for the modal (newest first, matching grid display order)
    let all_uris: Vec<String> = progress
        .screenshots
        .iter()
        .rev()
        .map(|b64| format!("data:image/png;base64,{}", b64))
        .collect();

    rsx! {
        div {
            style: "padding: 10px; margin-top: 4px; background: #0d1117; border: 1px solid #21262d; border-radius: 6px; max-width: 720px;",
            // Header
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
                    style: "font-size: 9px; color: #484f58; font-family: 'JetBrains Mono', monospace; flex-shrink: 0; padding: 1px 5px; border: 1px solid #484f58; border-radius: 3px;",
                    "LIVE"
                }
            }
            // Two-column: log left, screenshots right
            div {
                style: "display: flex; gap: 10px; min-height: 80px;",
                // Log column
                div {
                    style: "flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 6px;",
                    if !progress.log.is_empty() {
                        div {
                            style: "background: #010409; border: 1px solid #161b22; border-radius: 4px; padding: 6px 8px; font-family: 'JetBrains Mono', monospace; font-size: 10px; max-height: 180px; overflow-y: auto; line-height: 1.6;",
                            for entry in progress.log.iter().rev().take(12).collect::<Vec<_>>().into_iter().rev() {
                                div {
                                    style: "color: #8b949e; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;",
                                    span {
                                        style: "color: #484f58; margin-right: 6px; user-select: none;",
                                        "{entry.step:>2}"
                                    }
                                    "{entry.action}"
                                }
                            }
                        }
                    }
                    // Findings
                    if !progress.findings.is_empty() {
                        div {
                            style: "margin-top: 2px;",
                            for finding in progress.findings.iter() {
                                div {
                                    style: "display: flex; align-items: center; gap: 6px; margin: 3px 0; font-size: 10px;",
                                    span {
                                        style: "padding: 1px 5px; border-radius: 2px; font-weight: 700; font-size: 9px; text-transform: uppercase; background: {severity_color(&finding.severity)}; color: #fff;",
                                        "{finding.severity}"
                                    }
                                    span { style: "color: #c9d1d9;", "{finding.title}" }
                                }
                            }
                        }
                    }
                }
                // Screenshot section: primary left, thumbnail grid right
                if has_screenshots {
                    div {
                        style: "flex-shrink: 0; display: flex; flex-direction: row; gap: 6px; max-width: 420px;",
                        // Primary (most recent) screenshot — left side, scrollable
                        if let Some(ref screenshot) = progress.screenshot {
                            {
                                let uri = format!("data:image/png;base64,{}", screenshot);
                                let all = all_uris.clone();
                                let idx = 0_usize; // newest is first in reversed list
                                let mut modal = *modal_open;
                                rsx! {
                                    div {
                                        key: "primary-{idx}",
                                        style: "flex-shrink: 0; width: 200px; max-height: 240px; border: 1px solid #00ff8833; border-radius: 4px; overflow-y: auto; overflow-x: hidden; cursor: pointer; background: #010409;",
                                        onclick: move |_| { modal.set(Some((all.clone(), idx))); },
                                        img {
                                            src: "{uri}",
                                            style: "width: 100%; height: auto; display: block;",
                                        }
                                    }
                                }
                            }
                        }
                        // Thumbnail grid — right of primary, wraps in 3 columns
                        if progress.screenshots.len() > 1 {
                            div {
                                style: "flex: 1; min-width: 0; display: grid; grid-template-columns: repeat(3, 1fr); gap: 3px; align-content: start; max-height: 240px; overflow-y: auto;",
                                for (i, shot) in progress.screenshots.iter().rev().skip(1).take(12).enumerate() {
                                    {
                                        let uri = format!("data:image/png;base64,{}", shot);
                                        let all = all_uris.clone();
                                        let idx = i + 1; // grid starts at index 1 (after primary)
                                        let mut modal = *modal_open;
                                        let key = format!("thumb-{}", idx);
                                        rsx! {
                                            div {
                                                key: "{key}",
                                                style: "border: 1px solid #21262d; border-radius: 3px; overflow: hidden; cursor: pointer; opacity: 0.8; transition: opacity 0.15s; aspect-ratio: 4/3;",
                                                onclick: move |_| { modal.set(Some((all.clone(), idx))); },
                                                img {
                                                    src: "{uri}",
                                                    style: "width: 100%; height: 100%; object-fit: cover; display: block;",
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Render the completed screenshot gallery grid.
fn render_completed_gallery(
    screenshots: &[(String, String)],
    modal_open: &mut Signal<Option<(Vec<String>, usize)>>,
) -> Element {
    let count = screenshots.len();
    let all_uris: Vec<String> = screenshots.iter().map(|(_, uri)| uri.clone()).collect();

    rsx! {
        div {
            style: "margin-top: 8px; padding: 10px; background: #0d1117; border: 1px solid #21262d; border-radius: 6px;",
            // Header
            div {
                style: "display: flex; align-items: center; gap: 8px; margin-bottom: 8px;",
                span {
                    style: "font-size: 10px; color: #58a6ff; font-family: 'JetBrains Mono', monospace; letter-spacing: 0.5px; text-transform: uppercase;",
                    "{count} screenshots captured"
                }
            }
            // Grid — force 4 columns regardless of container width
            div {
                style: "display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px;",
                for (i, (filename, data_uri)) in screenshots.iter().enumerate() {
                    {
                        let all = all_uris.clone();
                        let idx = i;
                        let mut modal = *modal_open;
                        let fname = filename.clone();
                        let duri = data_uri.clone();
                        rsx! {
                            div {
                                style: "border: 1px solid #21262d; border-radius: 4px; overflow: hidden; cursor: pointer; transition: border-color 0.2s, transform 0.15s; background: #010409;",
                                onclick: move |_| { modal.set(Some((all.clone(), idx))); },
                                img {
                                    src: "{duri}",
                                    alt: "{fname}",
                                    style: "width: 100%; height: 96px; object-fit: cover; display: block;",
                                }
                                div {
                                    style: "padding: 4px 6px; font-size: 9px; color: #8b949e; font-family: 'JetBrains Mono', monospace; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;",
                                    "{fname}"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Render the lightbox modal overlay. Uses native onkeydown for keyboard nav.
fn render_lightbox_modal(modal_open: &mut Signal<Option<(Vec<String>, usize)>>) -> Element {
    let state = modal_open.read().clone();
    let Some((ref images, current_idx)) = state else {
        return rsx! {};
    };

    if images.is_empty() {
        return rsx! {};
    }

    let idx = current_idx.min(images.len() - 1);
    let current_src = images[idx].clone();
    let total = images.len();
    let counter_text = format!("{} / {}", idx + 1, total);
    let has_prev = idx > 0;
    let has_next = idx < total - 1;

    let mut modal = *modal_open;
    let images_prev = images.clone();
    let images_next = images.clone();

    rsx! {
        div {
            // Focusable overlay for keyboard events
            tabindex: 0,
            style: "position: fixed; inset: 0; background: rgba(1,4,9,0.96); z-index: 9999; display: flex; align-items: center; justify-content: center; backdrop-filter: blur(6px); outline: none;",
            // Auto-focus on mount so keyboard events work immediately (retry for LiveView race)
            onmounted: move |_| {
                spawn(async move {
                    for _ in 0..5 {
                        let _ = document::eval(
                            "let el = document.querySelector('[data-lightbox-root]'); if(el) el.focus();"
                        ).await;
                        tokio::time::sleep(tokio::time::Duration::from_millis(80)).await;
                    }
                });
            },
            "data-lightbox-root": "true",
            // Keyboard navigation
            onkeydown: move |evt: Event<KeyboardData>| {
                let key = evt.key().to_string();
                match key.as_str() {
                    "Escape" => { modal.set(None); }
                    "ArrowLeft" => {
                        let st = modal.read().clone();
                        if let Some((imgs, i)) = st {
                            if i > 0 { modal.set(Some((imgs, i - 1))); }
                        }
                    }
                    "ArrowRight" => {
                        let st = modal.read().clone();
                        if let Some((imgs, i)) = st {
                            if i < imgs.len() - 1 { modal.set(Some((imgs, i + 1))); }
                        }
                    }
                    _ => {}
                }
            },
            // Click backdrop to close
            onclick: move |_| { modal.set(None); },

            // Image container (stop propagation so clicking image doesn't close)
            div {
                style: "position: relative; display: flex; align-items: center; justify-content: center; max-width: 94vw; max-height: 92vh;",
                onclick: move |e| { e.stop_propagation(); },

                // Prev button
                if has_prev {
                    {
                        let imgs = images_prev.clone();
                        let mut m = modal;
                        rsx! {
                            div {
                                style: "position: absolute; left: -48px; top: 50%; transform: translateY(-50%); width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; background: #21262d; border: 1px solid #30363d; border-radius: 50%; cursor: pointer; color: #c9d1d9; font-size: 18px; user-select: none; transition: background 0.15s;",
                                onclick: move |e| {
                                    e.stop_propagation();
                                    let st = m.read().clone();
                                    if let Some((_, i)) = st {
                                        if i > 0 { m.set(Some((imgs.clone(), i - 1))); }
                                    }
                                },
                                "\u{2039}"
                            }
                        }
                    }
                }

                // Main image
                img {
                    src: "{current_src}",
                    style: "max-width: 90vw; max-height: 88vh; object-fit: contain; border-radius: 4px; border: 1px solid #30363d;",
                }

                // Next button
                if has_next {
                    {
                        let imgs = images_next.clone();
                        let mut m = modal;
                        rsx! {
                            div {
                                style: "position: absolute; right: -48px; top: 50%; transform: translateY(-50%); width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; background: #21262d; border: 1px solid #30363d; border-radius: 50%; cursor: pointer; color: #c9d1d9; font-size: 18px; user-select: none; transition: background 0.15s;",
                                onclick: move |e| {
                                    e.stop_propagation();
                                    let st = m.read().clone();
                                    if let Some((_, i)) = st {
                                        if i < imgs.len() - 1 { m.set(Some((imgs.clone(), i + 1))); }
                                    }
                                },
                                "\u{203a}"
                            }
                        }
                    }
                }
            }

            // Counter + hint at bottom
            div {
                style: "position: absolute; bottom: 16px; left: 50%; transform: translateX(-50%); display: flex; align-items: center; gap: 12px;",
                onclick: move |e| { e.stop_propagation(); },
                span {
                    style: "font-size: 12px; color: #8b949e; font-family: 'JetBrains Mono', monospace;",
                    "{counter_text}"
                }
                span {
                    style: "font-size: 11px; color: #484f58; font-family: 'JetBrains Mono', monospace;",
                    "\u{2190}\u{2192} navigate \u{00b7} ESC close"
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn severity_color(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => "#dc2626",
        "high" => "#ea580c",
        "medium" => "#ca8a04",
        "low" => "#2563eb",
        _ => "#6b7280",
    }
}

/// Load screenshot files from a completed tool result JSON, returning (filename, data_uri) pairs.
fn load_screenshots_from_result(result_json: &str) -> Vec<(String, String)> {
    let val: serde_json::Value = match serde_json::from_str(result_json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let paths: Vec<String> = val["data"]["artifacts"]["screenshots"]
        .as_array()
        .or_else(|| val["artifacts"]["screenshots"].as_array())
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|p| p.as_str().map(|s| s.to_string()))
        .filter(|p| {
            p.contains("final_")
                && (p.ends_with(".png") || p.ends_with(".jpg") || p.ends_with(".jpeg"))
        })
        .collect();

    if paths.is_empty() {
        return Vec::new();
    }

    let workspace = crate::liveview_server::get_workspace_path();
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let rootfs_tmp = format!("{}/.local/share/pentest-sandbox/blackarch-rootfs/tmp", home);

    paths
        .iter()
        .filter_map(|rel_path| {
            let ws_full = std::path::Path::new(&workspace).join(rel_path);
            let rootfs_full = std::path::Path::new(&rootfs_tmp).join(rel_path);
            let file_path = if ws_full.exists() {
                ws_full
            } else {
                rootfs_full
            };

            std::fs::read(&file_path).ok().map(|bytes| {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                let filename = rel_path
                    .rsplit('/')
                    .next()
                    .unwrap_or("screenshot")
                    .to_string();
                let mime = if rel_path.ends_with(".jpg") || rel_path.ends_with(".jpeg") {
                    "image/jpeg"
                } else {
                    "image/png"
                };
                let data_uri = format!("data:{};base64,{}", mime, b64);
                (filename, data_uri)
            })
        })
        .collect()
}

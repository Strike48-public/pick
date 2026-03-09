//! Terminal output component

use dioxus::prelude::*;
use pentest_core::terminal::{LogLevel, TerminalLine};
use std::collections::HashSet;

const MAX_DISPLAYED_LOGS: usize = 100;

/// Terminal output component with filtering capabilities
#[component]
pub fn Terminal(lines: Vec<TerminalLine>) -> Element {
    let mut line_count = use_signal(|| 0usize);

    // Filter state - multi-select log levels (default: all except Debug)
    let mut visible_levels: Signal<HashSet<LogLevel>> = use_signal(|| {
        // Default: all except Debug
        [LogLevel::Info, LogLevel::Success, LogLevel::Warning, LogLevel::Error]
            .into_iter()
            .collect()
    });

    // Load from localStorage on mount
    use_effect(move || {
        spawn(async move {
            let eval_result = document::eval(
                r#"(() => {
                    try {
                        return localStorage.getItem('terminal-filters') || '["Info","Success","Warning","Error"]';
                    } catch(e) { return '["Info","Success","Warning","Error"]'; }
                })()"#
            );
            if let Ok(json_str) = eval_result.await {
                if let Ok(json_str) = serde_json::from_value::<String>(json_str) {
                    if let Ok(levels) = serde_json::from_str::<Vec<String>>(&json_str) {
                        let level_set: HashSet<LogLevel> = levels.iter().filter_map(|s| match s.as_str() {
                            "Debug" => Some(LogLevel::Debug),
                            "Info" => Some(LogLevel::Info),
                            "Success" => Some(LogLevel::Success),
                            "Warning" => Some(LogLevel::Warning),
                            "Error" => Some(LogLevel::Error),
                            _ => None,
                        }).collect();
                        visible_levels.set(level_set);
                    }
                }
            }
        });
    });

    // Search filter
    let mut search_query = use_signal(String::new);

    // Persist filter changes to localStorage
    let persist_filters = move || {
        let levels: Vec<String> = visible_levels.read()
            .iter()
            .map(|l| l.label().to_string())
            .collect();
        let json = serde_json::to_string(&levels).unwrap_or_default();
        let js = format!(r#"localStorage.setItem('terminal-filters', '{}')"#, json);
        spawn(async move {
            let _ = document::eval(&js).await;
        });
    };

    if lines.len() != *line_count.read() {
        line_count.set(lines.len());
    }

    use_effect(move || {
        let _count = *line_count.read();
        spawn(async move {
            if let Err(e) = document::eval("scrollToBottom('#terminal-output')").await {
                tracing::warn!("JS eval failed (terminal scroll): {e}");
            }
        });
    });

    // Filter and limit logs
    let filtered_lines: Vec<&TerminalLine> = lines.iter()
        .filter(|line| {
            // Level filter
            let level_match = visible_levels.read().contains(&line.level);
            // Search filter
            let search_match = if search_query.read().is_empty() {
                true
            } else {
                let query = search_query.read().to_lowercase();
                line.message.to_lowercase().contains(&query)
                    || line.source.as_ref().map(|s| s.to_lowercase().contains(&query)).unwrap_or(false)
            };
            level_match && search_match
        })
        .rev() // Most recent first
        .take(MAX_DISPLAYED_LOGS)
        .collect::<Vec<_>>()
        .into_iter()
        .rev() // Back to chronological order
        .collect();

    // Count logs by level (from all lines, not just filtered)
    let counts: Vec<(LogLevel, usize)> = [
        LogLevel::Error,
        LogLevel::Warning,
        LogLevel::Success,
        LogLevel::Info,
        LogLevel::Debug,
    ].iter().map(|level| {
        (*level, lines.iter().filter(|l| l.level == *level).count())
    }).collect();

    rsx! {
        style { {include_str!("css/terminal.css")} }

        div { class: "terminal-container",
            // Filter bar
            div { class: "terminal-filters",
                // Level filter buttons
                div { class: "filter-buttons",
                    // "All" button to select all levels
                    {
                        let all_levels: HashSet<LogLevel> = [
                            LogLevel::Error,
                            LogLevel::Warning,
                            LogLevel::Success,
                            LogLevel::Info,
                            LogLevel::Debug,
                        ].into_iter().collect();
                        let all_selected = visible_levels.read().len() == 5;
                        let btn_class = if all_selected {
                            "filter-btn filter-btn-all active"
                        } else {
                            "filter-btn filter-btn-all"
                        };
                        rsx! {
                            button {
                                class: "{btn_class}",
                                onclick: move |_| {
                                    visible_levels.set(all_levels.clone());
                                    persist_filters();
                                },
                                "All"
                            }
                        }
                    }

                    for (level, count) in counts {
                        {
                            let is_active = visible_levels.read().contains(&level);
                            let btn_class = if is_active {
                                format!("filter-btn filter-btn-{} active", level.css_class())
                            } else {
                                format!("filter-btn filter-btn-{}", level.css_class())
                            };
                            let label = format!("{} ({})", level.label(), count);
                            rsx! {
                                button {
                                    class: "{btn_class}",
                                    onclick: move |_| {
                                        let mut levels = visible_levels.write();
                                        if levels.contains(&level) {
                                            levels.remove(&level);
                                        } else {
                                            levels.insert(level);
                                        }
                                        drop(levels);
                                        persist_filters();
                                    },
                                    "{label}"
                                }
                            }
                        }
                    }
                }

                // Search and action buttons
                div { class: "filter-actions",
                    input {
                        class: "search-input",
                        r#type: "text",
                        placeholder: "Search logs...",
                        value: "{search_query}",
                        oninput: move |evt| search_query.set(evt.value().clone()),
                    }

                    button {
                        class: "action-btn",
                        onclick: move |_| {
                            search_query.set(String::new());
                        },
                        "Clear Search"
                    }

                    button {
                        class: "action-btn",
                        onclick: move |_| {
                            let export_data = lines.iter()
                                .map(|line| line.format_full())
                                .collect::<Vec<_>>()
                                .join("\n");
                            let js = format!(
                                r#"(() => {{
                                    const blob = new Blob([`{}`], {{ type: 'text/plain' }});
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a');
                                    a.href = url;
                                    a.download = 'logs-{}.txt';
                                    a.click();
                                    URL.revokeObjectURL(url);
                                }})()"#,
                                export_data.replace('`', r"\`").replace('\\', r"\\"),
                                chrono::Utc::now().format("%Y%m%d-%H%M%S")
                            );
                            spawn(async move {
                                let _ = document::eval(&js).await;
                            });
                        },
                        "Export"
                    }
                }
            }

            // Log display info
            div { class: "terminal-info",
                "Showing {filtered_lines.len()} of {lines.len()} logs (last {MAX_DISPLAYED_LOGS} max)"
            }

            // Terminal output
            div {
                class: "terminal",
                id: "terminal-output",
                for (i, line) in filtered_lines.iter().enumerate() {
                    TerminalLineComponent {
                        key: "{i}",
                        line: (*line).clone(),
                    }
                }
            }
        }
    }
}

/// Single terminal line component
#[component]
fn TerminalLineComponent(line: TerminalLine) -> Element {
    let has_details = line.details.is_some();
    let mut expanded = use_signal(|| false);

    let class = match line.level {
        LogLevel::Debug => "terminal-line debug",
        LogLevel::Info => "terminal-line info",
        LogLevel::Success => "terminal-line success",
        LogLevel::Warning => "terminal-line warning",
        LogLevel::Error => "terminal-line error",
    };

    let toggle_class = if has_details {
        "terminal-line-header expandable"
    } else {
        "terminal-line-header"
    };

    let arrow = if has_details {
        if *expanded.read() {
            "\u{25BE} "
        } else {
            "\u{25B8} "
        }
    } else {
        ""
    };

    rsx! {
        div { class: "{class}",
            div {
                class: "{toggle_class}",
                onclick: move |_| {
                    if has_details {
                        expanded.toggle();
                    }
                },
                "{arrow}{line.format()}"
            }
            if has_details && *expanded.read() {
                if let Some(details) = &line.details {
                    pre { class: "terminal-details",
                        "{details}"
                    }
                }
            }
        }
    }
}

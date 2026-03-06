//! Terminal output component

use dioxus::prelude::*;
use pentest_core::terminal::{LogLevel, TerminalLine};

/// Terminal output component
#[component]
pub fn Terminal(lines: Vec<TerminalLine>) -> Element {
    let mut line_count = use_signal(|| 0usize);

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

    rsx! {
        div { class: "terminal",
            id: "terminal-output",
            for (i, line) in lines.iter().enumerate() {
                TerminalLineComponent {
                    key: "{i}",
                    line: line.clone(),
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

//! Log filter bar component with level filters and counts

use dioxus::prelude::*;
use pentest_core::terminal::{LogLevel, TerminalLine};
use std::collections::HashSet;

/// Log filter bar with pill buttons for each log level
#[component]
pub fn LogFilterBar(
    lines: Signal<Vec<TerminalLine>>,
    filtered_lines: Signal<Vec<TerminalLine>>,
) -> Element {
    // Track which log levels are enabled (all enabled by default)
    let mut enabled_levels = use_signal(|| {
        let mut set = HashSet::new();
        set.insert(LogLevel::Debug);
        set.insert(LogLevel::Info);
        set.insert(LogLevel::Success);
        set.insert(LogLevel::Warning);
        set.insert(LogLevel::Error);
        set
    });

    // Persist filter state to localStorage
    let storage_key = "pick_log_filter_state";

    // Load from localStorage on mount
    use_effect(move || {
        spawn(async move {
            if let Ok(result) = document::eval(&format!(
                "localStorage.getItem('{}')",
                storage_key
            )).await {
                if let Some(stored) = result.as_str() {
                    if !stored.is_empty() && stored != "null" {
                        // Parse stored levels: "Debug,Info,Success,Warning,Error"
                        let mut set = HashSet::new();
                        for level_str in stored.split(',') {
                            match level_str {
                                "Debug" => { set.insert(LogLevel::Debug); }
                                "Info" => { set.insert(LogLevel::Info); }
                                "Success" => { set.insert(LogLevel::Success); }
                                "Warning" => { set.insert(LogLevel::Warning); }
                                "Error" => { set.insert(LogLevel::Error); }
                                _ => {}
                            }
                        }
                        if !set.is_empty() {
                            enabled_levels.set(set);
                        }
                    }
                }
            }
        });
    });

    // Count logs per level
    let counts = use_memo(move || {
        let mut counts = std::collections::HashMap::new();
        counts.insert(LogLevel::Debug, 0);
        counts.insert(LogLevel::Info, 0);
        counts.insert(LogLevel::Success, 0);
        counts.insert(LogLevel::Warning, 0);
        counts.insert(LogLevel::Error, 0);

        for line in lines.read().iter() {
            *counts.entry(line.level).or_insert(0) += 1;
        }
        counts
    });

    // Filter lines based on enabled levels
    use_effect(move || {
        let enabled = enabled_levels.read();
        let all_lines = lines.read();
        let filtered: Vec<TerminalLine> = all_lines
            .iter()
            .filter(|line| enabled.contains(&line.level))
            .cloned()
            .collect();
        filtered_lines.set(filtered);
    });

    // Save to localStorage when filter changes
    use_effect(move || {
        let enabled = enabled_levels.read();
        let level_names: Vec<&str> = enabled
            .iter()
            .map(|level| match level {
                LogLevel::Debug => "Debug",
                LogLevel::Info => "Info",
                LogLevel::Success => "Success",
                LogLevel::Warning => "Warning",
                LogLevel::Error => "Error",
            })
            .collect();
        let stored_value = level_names.join(",");

        spawn(async move {
            let _ = document::eval(&format!(
                "localStorage.setItem('{}', '{}')",
                storage_key, stored_value
            )).await;
        });
    });

    let mut toggle_level = move |level: LogLevel| {
        let mut levels = enabled_levels.write();
        if levels.contains(&level) {
            levels.remove(&level);
        } else {
            levels.insert(level);
        }
    };

    let toggle_all = move |_| {
        let mut levels = enabled_levels.write();
        if levels.len() == 5 {
            // All enabled, disable all
            levels.clear();
        } else {
            // Some disabled, enable all
            levels.clear();
            levels.insert(LogLevel::Debug);
            levels.insert(LogLevel::Info);
            levels.insert(LogLevel::Success);
            levels.insert(LogLevel::Warning);
            levels.insert(LogLevel::Error);
        }
    };

    let all_enabled = enabled_levels.read().len() == 5;
    let total_count = lines.read().len();

    let debug_count = counts.read().get(&LogLevel::Debug).copied().unwrap_or(0);
    let info_count = counts.read().get(&LogLevel::Info).copied().unwrap_or(0);
    let success_count = counts.read().get(&LogLevel::Success).copied().unwrap_or(0);
    let warning_count = counts.read().get(&LogLevel::Warning).copied().unwrap_or(0);
    let error_count = counts.read().get(&LogLevel::Error).copied().unwrap_or(0);

    let debug_enabled = enabled_levels.read().contains(&LogLevel::Debug);
    let info_enabled = enabled_levels.read().contains(&LogLevel::Info);
    let success_enabled = enabled_levels.read().contains(&LogLevel::Success);
    let warning_enabled = enabled_levels.read().contains(&LogLevel::Warning);
    let error_enabled = enabled_levels.read().contains(&LogLevel::Error);

    rsx! {
        style { {include_str!("css/log_filter_bar.css")} }

        div { class: "log-filter-bar",
            button {
                class: if all_enabled { "log-filter-btn all active" } else { "log-filter-btn all" },
                onclick: toggle_all,
                span { class: "log-filter-label", "All" }
                span { class: "log-filter-count", "({total_count})" }
            }

            button {
                class: if debug_enabled { "log-filter-btn debug active" } else { "log-filter-btn debug" },
                onclick: move |_| toggle_level(LogLevel::Debug),
                span { class: "log-filter-label", "Debug" }
                span { class: "log-filter-count", "({debug_count})" }
            }

            button {
                class: if info_enabled { "log-filter-btn info active" } else { "log-filter-btn info" },
                onclick: move |_| toggle_level(LogLevel::Info),
                span { class: "log-filter-label", "Info" }
                span { class: "log-filter-count", "({info_count})" }
            }

            button {
                class: if success_enabled { "log-filter-btn success active" } else { "log-filter-btn success" },
                onclick: move |_| toggle_level(LogLevel::Success),
                span { class: "log-filter-label", "Success" }
                span { class: "log-filter-count", "({success_count})" }
            }

            button {
                class: if warning_enabled { "log-filter-btn warning active" } else { "log-filter-btn warning" },
                onclick: move |_| toggle_level(LogLevel::Warning),
                span { class: "log-filter-label", "Warning" }
                span { class: "log-filter-count", "({warning_count})" }
            }

            button {
                class: if error_enabled { "log-filter-btn error active" } else { "log-filter-btn error" },
                onclick: move |_| toggle_level(LogLevel::Error),
                span { class: "log-filter-label", "Error" }
                span { class: "log-filter-count", "({error_count})" }
            }
        }
    }
}

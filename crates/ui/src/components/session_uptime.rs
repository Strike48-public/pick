//! Session uptime indicator component
//!
//! Shows how long the current session has been running with a live timer
//! that updates every second.

use dioxus::prelude::*;
use std::time::{Duration, SystemTime};

/// Format duration as human-readable uptime string
fn format_uptime(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

/// Session uptime indicator with live timer
#[component]
pub fn SessionUptime() -> Element {
    // Store the session start time
    let start_time = use_signal(SystemTime::now);

    // Current uptime display string (updated every second)
    let mut uptime_display = use_signal(|| String::from("0s"));

    // Update uptime every second
    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            if let Ok(elapsed) = start_time.read().elapsed() {
                uptime_display.set(format_uptime(elapsed));
            }
        }
    });

    rsx! {
        span {
            class: "session-uptime",
            title: "Session uptime - updates every second",
            "⏱ {uptime_display}"
        }
    }
}

//! Easy Mode — a simplified shell (network scan + chat) for non-expert users.

/// The canned chat message the Easy Mode "Scan" button sends. It instructs the
/// server-side agent to enumerate local interfaces, scan the local subnet, and
/// write a report document of the findings. Kept as one place so the wording is
/// consistent and testable.
pub fn easy_mode_scan_prompt() -> String {
    "Discover the devices on my local network: enumerate my network interfaces, \
     scan the local subnet for reachable hosts and their open services, then write \
     a clear report document summarizing what you found."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_prompt_mentions_network_and_report_document() {
        let p = easy_mode_scan_prompt().to_lowercase();
        assert!(p.contains("network"), "prompt should mention the network: {p}");
        assert!(
            p.contains("report document"),
            "prompt must ask the agent to write a report document: {p}"
        );
    }
}

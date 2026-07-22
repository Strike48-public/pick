//! ARP table tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, NetworkOps};
use serde_json::{json, Value};
use std::time::Duration;

/// Maximum number of concurrent DNS lookups for hostname resolution.
const MAX_DNS_LOOKUPS: usize = 20;

/// Timeout per DNS lookup in seconds.
const DNS_LOOKUP_TIMEOUT_SECS: u64 = 2;

/// ARP table tool
pub struct ArpTableTool;

#[async_trait]
impl PentestTool for ArpTableTool {
    fn name(&self) -> &str {
        "arp_table"
    }

    fn description(&self) -> &str {
        "Get the system ARP table showing IP to MAC address mappings"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description()).param(ToolParam::optional(
            "resolve_hostnames",
            ParamType::Boolean,
            format!(
                "Perform reverse DNS lookups on ARP entries (max {}, {}s timeout each)",
                MAX_DNS_LOOKUPS, DNS_LOOKUP_TIMEOUT_SECS
            ),
            json!(false),
        ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![
            Platform::Desktop,
            Platform::Web,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        let resolve_hostnames = params
            .get("resolve_hostnames")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        execute_timed(|| async move {
            let platform = get_platform();
            let mut entries = platform.get_arp_table().await?;

            if resolve_hostnames {
                resolve_arp_hostnames(&mut entries).await;
            }

            Ok(json!({
                "entries": entries.iter().map(|e| json!({
                    "ip": e.ip,
                    "mac": e.mac,
                    "interface": e.interface,
                    "hostname": e.hostname,
                })).collect::<Vec<_>>(),
                "count": entries.len(),
            }))
        })
        .await
    }
}

/// Resolve hostnames for ARP entries via reverse DNS lookup.
/// Limited to first [`MAX_DNS_LOOKUPS`] entries with a
/// [`DNS_LOOKUP_TIMEOUT_SECS`]-second timeout per lookup.
async fn resolve_arp_hostnames(entries: &mut [pentest_platform::ArpEntry]) {
    let lookup_timeout = Duration::from_secs(DNS_LOOKUP_TIMEOUT_SECS);

    let mut handles = Vec::new();

    for entry in entries.iter().take(MAX_DNS_LOOKUPS) {
        let ip = entry.ip.clone();
        let handle = tokio::spawn(async move {
            tokio::time::timeout(lookup_timeout, async {
                tokio::task::spawn_blocking(move || {
                    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                        if let Ok(hostname) = dns_lookup::lookup_addr(&addr) {
                            // Skip if resolver just returns the IP back
                            if hostname != ip {
                                return Some(hostname);
                            }
                        }
                    }
                    None
                })
                .await
                .unwrap_or(None)
            })
            .await
            .unwrap_or(None)
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        if let Ok(Some(hostname)) = handle.await {
            entries[i].hostname = Some(hostname);
        }
    }
}

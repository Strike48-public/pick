//! mDNS/DNS-SD network discovery tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolOutcome, ToolParam,
    ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, NetworkOps};
use serde_json::{json, Value};

use crate::util::{param_str, param_u64};

/// mDNS network discovery tool
pub struct NetworkDiscoverTool;

#[async_trait]
impl PentestTool for NetworkDiscoverTool {
    fn name(&self) -> &str {
        "network_discover"
    }

    fn description(&self) -> &str {
        "Discover services on the local network using mDNS/DNS-SD (Chromecast, printers, etc.)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::optional(
                "service_type",
                ParamType::String,
                "Service type to discover (e.g., '_http._tcp.local.', '_googlecast._tcp.local.')",
                json!("_services._dns-sd._udp.local."),
            ))
            .param(ToolParam::optional(
                "timeout_ms",
                ParamType::Integer,
                "Discovery timeout in milliseconds",
                json!(10000),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        // mDNS/DNS-SD discovery is pure outbound UDP multicast, permitted in
        // the iOS app sandbox with the local-network entitlement. Mirrors the
        // default set (Desktop/Android/Tui) plus iOS.
        vec![
            Platform::Desktop,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let raw = param_str(&params, "service_type");
            let service_type = if raw.is_empty() {
                "_services._dns-sd._udp.local."
            } else {
                &raw
            };

            let timeout_ms = param_u64(&params, "timeout_ms", 10000);

            let platform = get_platform();
            let (services, probe) = platform
                .mdns_discover_with_outcome(service_type, timeout_ms)
                .await?;

            Ok(json!({
                "services": services.iter().map(|s| json!({
                    "name": s.name,
                    "service_type": s.service_type,
                    "host": s.host,
                    "port": s.port,
                    "txt_records": s.txt_records,
                })).collect::<Vec<_>>(),
                "count": services.len(),
                "probe": probe,
            }))
        })
        .await
        .map(classify_probe_outcome)
    }
}

/// Reclassify a completed mDNS run from the platform probe outcome (#309).
///
/// The shared mDNS implementation degrades an unsendable probe (blocked
/// sandbox, no available socket) to an empty result rather than an error.
/// `data.probe` carries the [`ProbeOutcome`]; a `skipped` status downgrades the
/// result to [`ToolOutcome::Skipped`] — `with_outcome` also clears `success` —
/// so the model and the report gate read it as "the probe never ran", never as
/// evidence of a clean network. A `Ran` result (including a truthful
/// zero-finding sweep) passes through unchanged.
fn classify_probe_outcome(result: ToolResult) -> ToolResult {
    // Only a `Ran` result needs reclassification; anything the tool body
    // already marked Failed/Skipped passes through.
    if result.outcome != ToolOutcome::Ran {
        return result;
    }
    match probe_status(&result.data) {
        Some("skipped") => result.with_outcome(ToolOutcome::Skipped),
        _ => result,
    }
}

/// The `status` tag of the `probe` outcome recorded in a tool payload, if any.
fn probe_status(data: &Value) -> Option<&str> {
    data.get("probe")
        .and_then(|p| p.get("status"))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_probe_downgrades_outcome_and_success() {
        let result = ToolResult::success(json!({
            "services": [],
            "count": 0,
            "probe": {"status": "skipped", "reason": "send failed: network unreachable"},
        }));
        let classified = classify_probe_outcome(result);
        assert_eq!(classified.outcome, ToolOutcome::Skipped);
        assert!(!classified.success, "a skipped probe is not a success");
        assert_eq!(
            classified.data["probe"]["reason"].as_str(),
            Some("send failed: network unreachable")
        );
    }

    #[test]
    fn ran_zero_finding_sweep_stays_ran() {
        // "ran and found nothing" must remain a success — that is the whole
        // distinction #309 asks for.
        let result = ToolResult::success(json!({
            "services": [],
            "count": 0,
            "probe": {"status": "ran"},
        }));
        let classified = classify_probe_outcome(result);
        assert_eq!(classified.outcome, ToolOutcome::Ran);
        assert!(classified.success);
    }

    #[test]
    fn payload_without_probe_field_is_left_alone() {
        let result = ToolResult::success(json!({"services": [], "count": 0}));
        assert_eq!(classify_probe_outcome(result).outcome, ToolOutcome::Ran);
    }
}

//! SSDP/UPnP discovery tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolOutcome, ToolParam,
    ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, NetworkOps};
use serde_json::{json, Value};

use crate::util::param_u64;

/// SSDP discovery tool
pub struct SsdpDiscoverTool;

#[async_trait]
impl PentestTool for SsdpDiscoverTool {
    fn name(&self) -> &str {
        "ssdp_discover"
    }

    fn description(&self) -> &str {
        "Discover UPnP/SSDP devices on the local network (routers, smart TVs, IoT devices)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description()).param(ToolParam::optional(
            "timeout_ms",
            ParamType::Integer,
            "Discovery timeout in milliseconds",
            json!(5000),
        ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        // SSDP is pure outbound UDP multicast, which the iOS app sandbox
        // permits with the local-network entitlement. Mirrors the default
        // set (Desktop/Android/Tui) plus iOS.
        vec![
            Platform::Desktop,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        let timeout_ms = param_u64(&params, "timeout_ms", 5000);

        execute_timed(|| async move {
            let platform = get_platform();
            let (devices, probe) = platform.ssdp_discover_with_outcome(timeout_ms).await?;
            Ok(json!({
                "devices": devices.iter().map(|d| json!({
                    "location": d.location,
                    "server": d.server,
                    "usn": d.usn,
                    "st": d.st,
                    "friendly_name": d.friendly_name,
                    "manufacturer": d.manufacturer,
                    "model": d.model,
                })).collect::<Vec<_>>(),
                "count": devices.len(),
                "probe": probe,
            }))
        })
        .await
        .map(classify_probe_outcome)
    }
}

/// Reclassify a completed SSDP run from the platform probe outcome (#309).
///
/// The shared discovery implementation degrades an unsendable probe (blocked
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
            "devices": [],
            "count": 0,
            "probe": {"status": "skipped", "reason": "bind failed: permission denied"},
        }));
        let classified = classify_probe_outcome(result);
        assert_eq!(classified.outcome, ToolOutcome::Skipped);
        assert!(!classified.success, "a skipped probe is not a success");
        // The reason stays available for diagnostics.
        assert_eq!(
            classified.data["probe"]["reason"].as_str(),
            Some("bind failed: permission denied")
        );
    }

    #[test]
    fn ran_zero_finding_sweep_stays_ran() {
        // "ran and found nothing" must remain a success — that is the whole
        // distinction #309 asks for.
        let result = ToolResult::success(json!({
            "devices": [],
            "count": 0,
            "probe": {"status": "ran"},
        }));
        let classified = classify_probe_outcome(result);
        assert_eq!(classified.outcome, ToolOutcome::Ran);
        assert!(classified.success);
    }

    #[test]
    fn payload_without_probe_field_is_left_alone() {
        let result = ToolResult::success(json!({"devices": [], "count": 0}));
        assert_eq!(classify_probe_outcome(result).outcome, ToolOutcome::Ran);
    }
}

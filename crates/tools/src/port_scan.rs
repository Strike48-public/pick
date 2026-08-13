//! Port scanning tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_core::validation::{validate_port_spec, validate_target};
use pentest_platform::{get_platform, HostReachability, NetworkOps, ScanConfig};
use serde_json::{json, Value};

use crate::util::{param_str, param_u64};

/// Operator/agent-facing gloss for a host-level reachability verdict (#337).
///
/// The `no_response` note is deliberately non-committal: an all-timeout scan
/// cannot distinguish a down host from a live one behind a default-drop
/// firewall, so it must not read as "host is down".
fn host_state_note(reachability: HostReachability) -> &'static str {
    match reachability {
        HostReachability::Reachable => {
            "Host responded to at least one probe (open or refused), so it is up."
        }
        HostReachability::Unreachable => {
            "No probe reached the host (network/host unreachable, or blocked by the \
             sandbox/capabilities). This is a scan failure, not a finding about the host."
        }
        HostReachability::NoResponse => {
            "Every probe timed out with no response. Two causes are indistinguishable \
             from a TCP-connect scan: an offline host, or a live host silently dropping \
             all packets (default-drop firewall). Do NOT record this host as offline on \
             this evidence alone; if liveness matters, confirm with a separate probe."
        }
    }
}

/// Port scanning tool
pub struct PortScanTool;

#[async_trait]
impl PentestTool for PortScanTool {
    fn name(&self) -> &str {
        "port_scan"
    }

    fn description(&self) -> &str {
        "Scan TCP ports on a target host to identify open services"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "host",
                ParamType::String,
                "Target host IP or hostname",
            ))
            .param(ToolParam::optional(
                "ports",
                ParamType::String,
                "Port specification (e.g., '22,80,443' or '1-1024')",
                json!("22,80,443,8080"),
            ))
            .param(ToolParam::optional(
                "timeout_ms",
                ParamType::Integer,
                "Connection timeout per port in milliseconds",
                json!(2000),
            ))
            .param(ToolParam::optional(
                "concurrency",
                ParamType::Integer,
                "Number of concurrent connections",
                json!(50),
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
        execute_timed(|| async {
            // Parse and validate parameters
            let host = params.get("host").and_then(|v| v.as_str()).ok_or_else(|| {
                pentest_core::error::Error::InvalidParams("host parameter is required".into())
            })?;

            // Validate host (IP or hostname)
            let host = validate_target(host)?;

            let ports_str = {
                let s = param_str(&params, "ports");
                if s.is_empty() {
                    "22,80,443,8080".to_string()
                } else {
                    s
                }
            };

            // Validate port specification
            let ports_str = validate_port_spec(&ports_str)?;

            let timeout_ms = param_u64(&params, "timeout_ms", 2000);

            let concurrency = param_u64(&params, "concurrency", 50) as usize;

            // Parse port specification
            let ports = pentest_core::state::ScanConfig::parse_ports(&ports_str);
            if ports.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "No valid ports specified".into(),
                ));
            }

            let config = ScanConfig {
                host: host.clone(),
                ports,
                timeout_ms,
                concurrency,
            };

            // Execute scan
            let platform = get_platform();
            let result = platform.port_scan(config).await?;
            Ok(json!({
                "host": result.host,
                "ports": result.ports,
                "open_count": result.open_count,
                // Surface reachability failures so the agent can tell "we
                // checked and found nothing open" apart from "we could not
                // reach the target" (#306). A scan where unreachable_count
                // equals total_scanned means no packet reached the host.
                "unreachable_count": result.unreachable_count,
                "errors": result.errors,
                "total_scanned": result.ports.len(),
                "duration_ms": result.duration_ms,
                // Host-level reachability (#337): "reachable" (got a response),
                // "unreachable" (errno no-route), or "no_response" (every probe
                // timed out -> down OR silently firewalled). See host_state_note.
                "reachability": result.reachability,
                "host_state_note": host_state_note(result.reachability),
            }))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_response_note_never_asserts_host_is_down() {
        // #337 honesty guard: the all-timeout verdict must NOT tell the operator
        // the host is down (a live firewalled host is indistinguishable). It must
        // name both possibilities and point at a separate liveness check.
        let note = host_state_note(HostReachability::NoResponse);
        // Must not hand the caller a ready-made "host is down"/"offline" verdict.
        assert!(!note.to_lowercase().contains("host is down"));
        assert!(!note.to_lowercase().contains("host is offline"));
        // Must name the firewall alternative and flag the ambiguity + a caveat.
        assert!(note.contains("firewall"));
        assert!(note.contains("indistinguishable"));
        assert!(note.contains("Do NOT record"));
    }

    #[test]
    fn reachable_and_unreachable_notes_are_distinct_and_correct() {
        let reachable = host_state_note(HostReachability::Reachable);
        let unreachable = host_state_note(HostReachability::Unreachable);
        assert!(reachable.contains("up"));
        assert!(unreachable.contains("scan failure"));
        assert_ne!(reachable, unreachable);
        assert_ne!(reachable, host_state_note(HostReachability::NoResponse));
    }
}

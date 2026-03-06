//! Traffic capture tool
//!
//! This tool is stateless -- all capture session state (the active handle and
//! packet buffers) lives in the platform crate's `capture` module, which is
//! the single source of truth.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
#[cfg(feature = "desktop")]
use pentest_platform::{get_current_packets, start_current_capture, stop_current_capture};
use serde_json::{json, Value};
#[cfg(feature = "desktop")]
use std::time::Instant;

#[cfg(feature = "desktop")]
use crate::util::{param_str, param_u64};

/// Traffic capture tool
pub struct TrafficCaptureTool;

#[async_trait]
impl PentestTool for TrafficCaptureTool {
    fn name(&self) -> &str {
        "traffic_capture"
    }

    fn description(&self) -> &str {
        "Capture and analyze network traffic (requires elevated privileges)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "action",
                ParamType::String,
                "Action to perform: 'start', 'stop', or 'get_packets'",
            ))
            .param(ToolParam::optional(
                "limit",
                ParamType::Integer,
                "Number of packets to return (for get_packets)",
                json!(100),
            ))
            .param(ToolParam::optional(
                "filter",
                ParamType::String,
                "Protocol filter: 'tcp', 'udp', 'icmp', or 'all'",
                json!("all"),
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
        #[cfg(not(feature = "desktop"))]
        {
            let _ = &params;
            return Ok(ToolResult::error(
                "Traffic capture requires desktop platform",
            ));
        }

        #[cfg(feature = "desktop")]
        {
            let start = Instant::now();

            let action = match params.get("action").and_then(|v| v.as_str()) {
                Some(a) => a,
                None => return Ok(ToolResult::error("action parameter is required")),
            };

            match action {
                "start" => match start_current_capture().await {
                    Ok(()) => {
                        let duration_ms = start.elapsed().as_millis() as u64;
                        Ok(ToolResult::success_with_duration(
                            json!({
                                "status": "started",
                                "message": "Traffic capture started"
                            }),
                            duration_ms,
                        ))
                    }
                    Err(e) => Ok(ToolResult::error(e.to_string())),
                },

                "stop" => match stop_current_capture().await {
                    Ok(()) => {
                        let duration_ms = start.elapsed().as_millis() as u64;
                        Ok(ToolResult::success_with_duration(
                            json!({
                                "status": "stopped",
                                "message": "Traffic capture stopped"
                            }),
                            duration_ms,
                        ))
                    }
                    Err(e) => Ok(ToolResult::error(e.to_string())),
                },

                "get_packets" => {
                    let limit = param_u64(&params, "limit", 100) as usize;

                    let filter_raw = param_str(&params, "filter");
                    let filter = if filter_raw.is_empty() {
                        "all"
                    } else {
                        &filter_raw
                    };

                    match get_current_packets(limit).await {
                        Ok(packets) => {
                            // Apply protocol filter
                            let filtered: Vec<_> = if filter == "all" {
                                packets
                            } else {
                                packets
                                    .into_iter()
                                    .filter(|p| p.protocol.to_lowercase() == filter.to_lowercase())
                                    .collect()
                            };

                            let duration_ms = start.elapsed().as_millis() as u64;
                            Ok(ToolResult::success_with_duration(
                                json!({
                                    "packets": filtered.iter().map(|p| json!({
                                        "timestamp": p.timestamp,
                                        "protocol": p.protocol,
                                        "src_ip": p.src_ip,
                                        "dst_ip": p.dst_ip,
                                        "src_port": p.src_port,
                                        "dst_port": p.dst_port,
                                        "size": p.size,
                                        "tcp_flags": p.tcp_flags,
                                    })).collect::<Vec<_>>(),
                                    "count": filtered.len(),
                                }),
                                duration_ms,
                            ))
                        }
                        Err(e) => Ok(ToolResult::error(e.to_string())),
                    }
                }

                _ => Ok(ToolResult::error(format!("Unknown action: {}", action))),
            }
        }
    }
}

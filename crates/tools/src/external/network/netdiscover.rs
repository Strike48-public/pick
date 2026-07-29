//! Netdiscover - Active/passive network reconnaissance

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ExternalDependency, ParamType, PentestTool, Platform, ToolCategory, ToolContext,
    ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use crate::external::install::ensure_tool_installed;
use crate::external::runner::{param_str_opt, CommandBuilder};
use crate::util::param_bool;

pub struct NetdiscoverTool;

#[async_trait]
impl PentestTool for NetdiscoverTool {
    fn name(&self) -> &str {
        "netdiscover"
    }

    fn description(&self) -> &str {
        "Active/passive ARP reconnaissance tool"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(
                ExternalDependency::new("netdiscover", "netdiscover", "ARP scanner")
                    .category(ToolCategory::Network),
            )
            .param(ToolParam::optional(
                "range",
                ParamType::String,
                "IP range (e.g., 192.168.1.0/24), or a sentinel: 'current' (this \
                 host's primary subnet), 'auto'/'all' (every active local subnet, \
                 scanned one per invocation). Empty = netdiscover auto-scan. \
                 Prefer a sentinel over guessing a range.",
                json!(""),
            ))
            .param(ToolParam::optional(
                "interface",
                ParamType::String,
                "Network interface",
                json!(""),
            ))
            .param(ToolParam::optional(
                "passive",
                ParamType::Boolean,
                "Passive mode",
                json!(false),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Total timeout in seconds, split across subnets when 'auto'/'all' \
                 expands to several (each gets total/N, floored at 1s).",
                json!(60),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "netdiscover", "netdiscover").await?;

            let range = param_str_opt(&params, "range");
            let interface = param_str_opt(&params, "interface");
            let passive = param_bool(&params, "passive", false);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 60);

            // Resolve the range when one is given. netdiscover's `-r` takes a
            // SINGLE range (multiple require `-l file`), so an auto/current/all
            // sentinel that fans out to several subnets is run once per subnet
            // and the host lists are merged. An absent/empty range preserves
            // netdiscover's built-in auto-scan (no `-r`).
            let (ranges, out_of_subnet_warning): (Vec<Option<String>>, Option<String>) =
                match range.as_deref() {
                    Some(r) if !r.is_empty() => {
                        let prepared = crate::scan_target::prepare_scan_targets(r).await?;
                        (
                            prepared.targets.into_iter().map(Some).collect(),
                            prepared.warning,
                        )
                    }
                    // No range: single auto-scan invocation (range = None).
                    _ => (vec![None], None),
                };

            // Split the timeout budget across subnets so N subnets total ~=
            // `timeout_secs`, not N x timeout_secs. Floored at 1s per subnet.
            let per_range_timeout =
                Duration::from_secs((timeout_secs / ranges.len().max(1) as u64).max(1));

            let mut hosts = Vec::new();
            let mut failed_ranges: Vec<String> = Vec::new();
            for range_opt in &ranges {
                let mut builder = CommandBuilder::new();

                if let Some(r) = range_opt {
                    builder = builder.arg("-r", r);
                }

                if let Some(ref i) = interface {
                    if !i.is_empty() {
                        builder = builder.arg("-i", i);
                    }
                }

                if passive {
                    builder = builder.flag("-p");
                }

                let args = builder.build();
                let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                // Per-subnet failure is non-fatal: one unreachable subnet must
                // not discard the hosts already found on the others. Log and
                // continue, recording which range failed for the result.
                match platform
                    .execute_command("netdiscover", &args_refs, per_range_timeout)
                    .await
                {
                    Ok(result) => {
                        for line in result.stdout.lines() {
                            if line.contains('.') && !line.starts_with(' ') {
                                hosts.push(line.trim().to_string());
                            }
                        }
                    }
                    Err(e) => {
                        let label = range_opt.as_deref().unwrap_or("(auto-scan)");
                        tracing::warn!("netdiscover failed on range {}: {}", label, e);
                        failed_ranges.push(label.to_string());
                    }
                }
            }

            // If every range failed (and at least one was attempted), surface a
            // hard error - a wholesale failure is not a "0 hosts" success.
            if !failed_ranges.is_empty() && failed_ranges.len() == ranges.len() {
                return Err(pentest_core::error::Error::Network(format!(
                    "netdiscover failed on all {} range(s): {}",
                    ranges.len(),
                    failed_ranges.join(", ")
                )));
            }

            let resolved: Vec<&str> = ranges.iter().filter_map(|r| r.as_deref()).collect();
            Ok(json!({
                "resolved_ranges": resolved,
                "failed_ranges": failed_ranges,
                "out_of_subnet_warning": out_of_subnet_warning,
                "hosts": hosts,
                "count": hosts.len(),
            }))
        })
        .await
    }
}

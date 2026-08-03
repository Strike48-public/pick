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

/// Minimum wall-clock a single subnet's netdiscover run is granted, regardless
/// of how the total budget divides across subnets. Below this a per-subnet slice
/// is too short for the ARP sweep to surface anything, so many active subnets
/// (VPN + docker + wifi + wired) would otherwise all starve.
const MIN_PER_RANGE_TIMEOUT_SECS: u64 = 10;

/// Per-subnet timeout: split `total_secs` across `n_ranges`, but never below
/// [`MIN_PER_RANGE_TIMEOUT_SECS`]. When the floor binds, total time exceeds the
/// requested budget rather than running scans too short to complete. Pure so the
/// starvation boundary is unit-testable.
fn per_range_timeout_secs(total_secs: u64, n_ranges: usize) -> u64 {
    (total_secs / n_ranges.max(1) as u64).max(MIN_PER_RANGE_TIMEOUT_SECS)
}

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
                 expands to several (each gets total/N, with a per-subnet minimum \
                 so many subnets don't starve).",
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
            // `timeout_secs`, not N x timeout_secs. Floored at a per-subnet
            // MINIMUM so a many-subnet host (VPN + docker + wifi + wired) can't
            // starve every range: with a 60s budget and 61 subnets, integer
            // division would give 0 -> a useless 1s each and nothing completes.
            // Below the floor we let the total exceed `timeout_secs` (each subnet
            // still gets a workable slice) rather than run scans that can't finish.
            let per_range_timeout =
                Duration::from_secs(per_range_timeout_secs(timeout_secs, ranges.len()));

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_range_timeout_splits_budget_when_few_subnets() {
        // Normal case: 60s over 4 subnets -> 15s each (above the floor).
        assert_eq!(per_range_timeout_secs(60, 4), 15);
        // Single range (or none) gets the whole budget.
        assert_eq!(per_range_timeout_secs(60, 1), 60);
        assert_eq!(per_range_timeout_secs(60, 0), 60);
    }

    #[test]
    fn per_range_timeout_floors_so_many_subnets_dont_starve() {
        // The M2 bug: 60s / 61 subnets floors to 0 -> 1s each and nothing
        // completes. The floor must keep each subnet workable instead.
        assert_eq!(per_range_timeout_secs(60, 61), MIN_PER_RANGE_TIMEOUT_SECS);
        // Right at the boundary where the split would dip below the floor.
        assert_eq!(per_range_timeout_secs(60, 7), MIN_PER_RANGE_TIMEOUT_SECS); // 60/7=8 -> floored
        assert_eq!(per_range_timeout_secs(60, 6), 10); // 60/6=10 == floor, exact
                                                       // Never returns the useless sub-floor slice the bug produced.
        assert!(per_range_timeout_secs(60, 100) >= MIN_PER_RANGE_TIMEOUT_SECS);
    }
}

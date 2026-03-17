//! Bettercap - Swiss Army knife for network attacks and monitoring

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ExternalDependency, ParamType, PentestTool, Platform, ToolContext, ToolParam,
    ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use crate::external::install::ensure_tool_installed;
use crate::external::runner::{param_str_opt, CommandBuilder};
use crate::util::param_bool;

pub struct BettercapTool;

#[async_trait]
impl PentestTool for BettercapTool {
    fn name(&self) -> &str {
        "bettercap"
    }

    fn description(&self) -> &str {
        "Powerful framework for network attacks, reconnaissance, and monitoring"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "bettercap",
                "bettercap",
                "Network attack framework (Go-based)",
            ))
            .param(ToolParam::optional(
                "interface",
                ParamType::String,
                "Network interface to use (default: auto-detect)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "caplet",
                ParamType::String,
                "Caplet script to run (e.g., 'http-req-dump', 'mitm6')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "eval",
                ParamType::String,
                "Command to evaluate (e.g., 'net.probe on; net.show')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "gateway",
                ParamType::String,
                "Gateway IP address",
                json!(""),
            ))
            .param(ToolParam::optional(
                "target",
                ParamType::String,
                "Target IP or range",
                json!(""),
            ))
            .param(ToolParam::optional(
                "silent",
                ParamType::Boolean,
                "Suppress banner and events (default: true)",
                json!(true),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 300)",
                json!(300),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "bettercap", "bettercap").await?;

            let interface = param_str_opt(&params, "interface");
            let caplet = param_str_opt(&params, "caplet");
            let eval_cmd = param_str_opt(&params, "eval");
            let gateway = param_str_opt(&params, "gateway");
            let target = param_str_opt(&params, "target");
            let silent = param_bool(&params, "silent", true);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);

            let mut builder = CommandBuilder::new();

            if let Some(iface) = interface {
                if !iface.is_empty() {
                    builder = builder.arg("-iface", &iface);
                }
            }

            if let Some(cap) = caplet {
                if !cap.is_empty() {
                    builder = builder.arg("-caplet", &cap);
                }
            }

            if let Some(cmd) = eval_cmd {
                if !cmd.is_empty() {
                    builder = builder.arg("-eval", &cmd);
                }
            }

            if let Some(gw) = gateway {
                if !gw.is_empty() {
                    builder = builder.arg("--gateway", &gw);
                }
            }

            if let Some(tgt) = target {
                if !tgt.is_empty() {
                    builder = builder.arg("--target", &tgt);
                }
            }

            if silent {
                builder = builder.flag("--silent");
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("bettercap", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            Ok(json!({
                "success": result.exit_code == 0,
                "output": result.stdout,
                "error": if result.exit_code != 0 { result.stderr } else { String::new() },
            }))
        })
        .await
    }
}

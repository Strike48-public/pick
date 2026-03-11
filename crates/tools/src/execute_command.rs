//! Command execution tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use crate::util::param_u64;

/// Command execution tool
pub struct ExecuteCommandTool;

#[async_trait]
impl PentestTool for ExecuteCommandTool {
    fn name(&self) -> &str {
        "execute_command"
    }

    fn description(&self) -> &str {
        "Execute a shell command. Respects Settings > Shell Mode: Native (direct host execution) or Proot (sandboxed BlackArch environment with pacman)."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "command",
                ParamType::String,
                "The command to execute",
            ))
            .param(ToolParam::optional(
                "args",
                ParamType::Array,
                "Command arguments as an array",
                json!([]),
            ))
            .param(ToolParam::optional(
                "timeout_seconds",
                ParamType::Integer,
                "Command timeout in seconds",
                json!(120),
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

    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let workspace_path = ctx.workspace_path.clone();

        execute_timed(|| async move {
            let platform = get_platform();

            // Check if command execution is supported
            if !platform.is_command_exec_supported() {
                return Err(pentest_core::error::Error::PlatformNotSupported(
                    "Command execution not supported on this platform".into(),
                ));
            }

            let command = params
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    pentest_core::error::Error::InvalidParams("Command is required".into())
                })?;

            let args: Vec<String> = params
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let timeout_seconds = param_u64(&params, "timeout_seconds", 120);

            let timeout = Duration::from_secs(timeout_seconds);

            let result = if let Some(ref workspace) = workspace_path {
                platform
                    .execute_command_in_dir(command, &args_refs, timeout, Some(workspace.as_path()))
                    .await?
            } else {
                platform
                    .execute_command(command, &args_refs, timeout)
                    .await?
            };

            Ok(json!({
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "duration_ms": result.duration_ms,
            }))
        })
        .await
    }
}

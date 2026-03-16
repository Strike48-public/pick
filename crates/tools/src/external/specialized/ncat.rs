//! Ncat - Netcat reimplementation with SSL, proxy, and more

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
use crate::external::runner::{param_str_opt, param_str_or, CommandBuilder};
use crate::util::param_bool;

pub struct NcatTool;

#[async_trait]
impl PentestTool for NcatTool {
    fn name(&self) -> &str {
        "ncat"
    }

    fn description(&self) -> &str {
        "Feature-packed networking utility (Netcat reimplementation)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new("ncat", "nmap", "Networking utility (part of Nmap)"))
            .param(ToolParam::required("host", ParamType::String, "Target host"))
            .param(ToolParam::required("port", ParamType::Integer, "Target port"))
            .param(ToolParam::optional("listen", ParamType::Boolean, "Listen mode", json!(false)))
            .param(ToolParam::optional("command", ParamType::String, "Command to execute", json!("")))
            .param(ToolParam::optional("timeout", ParamType::Integer, "Timeout", json!(30)))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "ncat", "nmap").await?;

            let host = param_str_or(&params, "host", "");
            let port = crate::util::param_u64(&params, "port", 0);
            if host.is_empty() || port == 0 {
                return Err(pentest_core::error::Error::InvalidParams("host and port required".into()));
            }

            let listen = param_bool(&params, "listen", false);
            let command = param_str_opt(&params, "command");
            let timeout_secs = crate::util::param_u64(&params, "timeout", 30);

            let mut builder = CommandBuilder::new();
            if listen {
                builder = builder.flag("-l").arg("-p", &port.to_string());
            } else {
                builder = builder.positional(&host).positional(&port.to_string());
            }

            if let Some(cmd) = command {
                if !cmd.is_empty() {
                    builder = builder.arg("-e", &cmd);
                }
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform.execute_command("ncat", &args_refs, Duration::from_secs(timeout_secs)).await?;

            Ok(json!({"host": host, "port": port, "success": result.exit_code == 0, "output": result.stdout}))
        })
        .await
    }
}

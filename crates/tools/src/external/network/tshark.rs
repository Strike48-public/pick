//! TShark - Network protocol analyzer (CLI Wireshark)

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

pub struct TsharkTool;

#[async_trait]
impl PentestTool for TsharkTool {
    fn name(&self) -> &str {
        "tshark"
    }

    fn description(&self) -> &str {
        "Network protocol analyzer - CLI version of Wireshark"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new("tshark", "wireshark-cli", "Packet analyzer"))
            .param(ToolParam::optional("interface", ParamType::String, "Network interface", json!("")))
            .param(ToolParam::optional("capture_file", ParamType::String, "Read from capture file", json!("")))
            .param(ToolParam::optional("filter", ParamType::String, "Display filter", json!("")))
            .param(ToolParam::optional("count", ParamType::Integer, "Packet count", json!(100)))
            .param(ToolParam::optional("timeout", ParamType::Integer, "Timeout", json!(60)))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "tshark", "wireshark-cli").await?;

            let interface = param_str_opt(&params, "interface");
            let capture_file = param_str_opt(&params, "capture_file");
            let filter = param_str_opt(&params, "filter");
            let count = crate::util::param_u64(&params, "count", 100);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 60);

            let mut builder = CommandBuilder::new().arg("-c", &count.to_string());

            if let Some(iface) = interface {
                if !iface.is_empty() {
                    builder = builder.arg("-i", &iface);
                }
            }

            if let Some(file) = capture_file {
                if !file.is_empty() {
                    builder = builder.arg("-r", &file);
                }
            }

            if let Some(filt) = filter {
                if !filt.is_empty() {
                    builder = builder.arg("-Y", &filt);
                }
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform.execute_command("tshark", &args_refs, Duration::from_secs(timeout_secs)).await?;

            Ok(json!({"packets": result.stdout, "success": result.exit_code == 0}))
        })
        .await
    }
}

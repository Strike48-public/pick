//! Netdiscover - Active/passive network reconnaissance

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
            .external_dependency(ExternalDependency::new("netdiscover", "netdiscover", "ARP scanner"))
            .param(ToolParam::optional("range", ParamType::String, "IP range (e.g., 192.168.1.0/24)", json!("")))
            .param(ToolParam::optional("interface", ParamType::String, "Network interface", json!("")))
            .param(ToolParam::optional("passive", ParamType::Boolean, "Passive mode", json!(false)))
            .param(ToolParam::optional("timeout", ParamType::Integer, "Timeout", json!(60)))
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

            let mut builder = CommandBuilder::new();

            if let Some(r) = range {
                if !r.is_empty() {
                    builder = builder.arg("-r", &r);
                }
            }

            if let Some(i) = interface {
                if !i.is_empty() {
                    builder = builder.arg("-i", &i);
                }
            }

            if passive {
                builder = builder.flag("-p");
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform.execute_command("netdiscover", &args_refs, Duration::from_secs(timeout_secs)).await?;

            let mut hosts = Vec::new();
            for line in result.stdout.lines() {
                if line.contains('.') && !line.starts_with(' ') {
                    hosts.push(line.trim().to_string());
                }
            }

            Ok(json!({"hosts": hosts, "count": hosts.len()}))
        })
        .await
    }
}

//! snmpwalk - SNMP enumeration tool

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
use crate::external::runner::{param_str_or, CommandBuilder};

pub struct SnmpwalkTool;

#[async_trait]
impl PentestTool for SnmpwalkTool {
    fn name(&self) -> &str {
        "snmpwalk"
    }

    fn description(&self) -> &str {
        "Retrieve SNMP management information from network entities"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "snmpwalk",
                "net-snmp",
                "SNMP tools",
            ))
            .param(ToolParam::required(
                "host",
                ParamType::String,
                "Target host",
            ))
            .param(ToolParam::optional(
                "community",
                ParamType::String,
                "SNMP community string",
                json!("public"),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout",
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
            ensure_tool_installed(&platform, "snmpwalk", "net-snmp").await?;

            let host = param_str_or(&params, "host", "");
            if host.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "host required".into(),
                ));
            }

            let community = param_str_or(&params, "community", "public");
            let timeout_secs = crate::util::param_u64(&params, "timeout", 60);

            let builder = CommandBuilder::new()
                .arg("-v", "2c")
                .arg("-c", &community)
                .positional(&host);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("snmpwalk", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            Ok(json!({
                "host": host,
                "community": community,
                "output": result.stdout,
            }))
        })
        .await
    }
}

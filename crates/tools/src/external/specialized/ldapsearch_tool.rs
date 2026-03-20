//! ldapsearch - LDAP search utility

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

pub struct LdapsearchTool;

#[async_trait]
impl PentestTool for LdapsearchTool {
    fn name(&self) -> &str {
        "ldapsearch_tool"
    }

    fn description(&self) -> &str {
        "Query LDAP directory servers"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "ldapsearch",
                "openldap",
                "LDAP utilities",
            ))
            .param(ToolParam::required("host", ParamType::String, "LDAP host"))
            .param(ToolParam::optional(
                "base",
                ParamType::String,
                "Search base DN",
                json!(""),
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
            ensure_tool_installed(&platform, "ldapsearch", "openldap").await?;

            let host = param_str_or(&params, "host", "");
            if host.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "host required".into(),
                ));
            }

            let base = param_str_or(&params, "base", "");
            let timeout_secs = crate::util::param_u64(&params, "timeout", 60);

            let mut builder = CommandBuilder::new()
                .arg("-x", "")
                .arg("-H", &format!("ldap://{}", host));

            if !base.is_empty() {
                builder = builder.arg("-b", &base);
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("ldapsearch", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            Ok(json!({
                "host": host,
                "base": base,
                "output": result.stdout,
            }))
        })
        .await
    }
}

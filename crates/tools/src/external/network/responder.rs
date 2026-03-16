//! Responder - LLMNR, NBT-NS and MDNS poisoner

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
use crate::util::param_bool;

pub struct ResponderTool;

#[async_trait]
impl PentestTool for ResponderTool {
    fn name(&self) -> &str {
        "responder"
    }

    fn description(&self) -> &str {
        "LLMNR, NBT-NS and MDNS poisoner for credential capture"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "responder",
                "responder",
                "Network poisoning tool (Python-based)"
            ))
            .param(ToolParam::required(
                "interface",
                ParamType::String,
                "Network interface to use (e.g., 'eth0', 'wlan0')",
            ))
            .param(ToolParam::optional(
                "analyze",
                ParamType::Boolean,
                "Analyze mode only, don't poison (default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "wpad",
                ParamType::Boolean,
                "Start WPAD rogue proxy server (default: true)",
                json!(true),
            ))
            .param(ToolParam::optional(
                "force_wpad_auth",
                ParamType::Boolean,
                "Force WPAD authentication (default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "fingerprint",
                ParamType::Boolean,
                "Fingerprint hosts (default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 600)",
                json!(600),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "responder", "responder").await?;

            let interface = param_str_or(&params, "interface", "");
            if interface.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "interface parameter is required".into(),
                ));
            }

            let analyze = param_bool(&params, "analyze", false);
            let wpad = param_bool(&params, "wpad", true);
            let force_wpad_auth = param_bool(&params, "force_wpad_auth", false);
            let fingerprint = param_bool(&params, "fingerprint", false);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 600);

            let mut builder = CommandBuilder::new()
                .arg("-I", &interface);

            if analyze {
                builder = builder.flag("-A");
            }

            if wpad {
                builder = builder.flag("-w");
            }

            if force_wpad_auth {
                builder = builder.flag("-F");
            }

            if fingerprint {
                builder = builder.flag("-f");
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("responder", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            parse_responder_output(&result.stdout, &interface)
        })
        .await
    }
}

fn parse_responder_output(stdout: &str, interface: &str) -> Result<Value> {
    let mut captured_hashes = Vec::new();
    let mut captured_credentials = Vec::new();

    for line in stdout.lines() {
        if line.contains("NTLMv") || line.contains("::") {
            captured_hashes.push(line.trim().to_string());
        }

        if line.contains("Username:") || line.contains("Password:") {
            captured_credentials.push(line.trim().to_string());
        }
    }

    Ok(json!({
        "interface": interface,
        "captured_hashes": captured_hashes,
        "captured_credentials": captured_credentials,
        "hash_count": captured_hashes.len(),
        "summary": format!("Captured {} hashes, {} credentials", captured_hashes.len(), captured_credentials.len()),
    }))
}

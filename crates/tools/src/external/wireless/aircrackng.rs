//! Aircrack-ng - WiFi security auditing suite

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

pub struct AircrackngTool;

#[async_trait]
impl PentestTool for AircrackngTool {
    fn name(&self) -> &str {
        "aircrack-ng"
    }

    fn description(&self) -> &str {
        "WiFi WEP and WPA/WPA2-PSK key cracking tool"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "aircrack-ng",
                "aircrack-ng",
                "WiFi security auditing suite",
            ))
            .param(ToolParam::required(
                "capture_file",
                ParamType::String,
                "Capture file (.cap or .pcap) containing handshake",
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Wordlist file for WPA/WPA2 cracking",
                json!(""),
            ))
            .param(ToolParam::optional(
                "essid",
                ParamType::String,
                "Target ESSID (network name)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "bssid",
                ParamType::String,
                "Target BSSID (MAC address)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 3600)",
                json!(3600),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "aircrack-ng", "aircrack-ng").await?;

            let capture_file = param_str_or(&params, "capture_file", "");
            if capture_file.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "capture_file parameter is required".into(),
                ));
            }

            let wordlist = param_str_opt(&params, "wordlist");
            let essid = param_str_opt(&params, "essid");
            let bssid = param_str_opt(&params, "bssid");
            let timeout_secs = crate::util::param_u64(&params, "timeout", 3600);

            let mut builder = CommandBuilder::new();

            if let Some(wl) = wordlist {
                if !wl.is_empty() {
                    builder = builder.arg("-w", &wl);
                }
            }

            if let Some(e) = essid {
                if !e.is_empty() {
                    builder = builder.arg("-e", &e);
                }
            }

            if let Some(b) = bssid {
                if !b.is_empty() {
                    builder = builder.arg("-b", &b);
                }
            }

            builder = builder.positional(&capture_file);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("aircrack-ng", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            parse_aircrack_output(&result.stdout, &capture_file)
        })
        .await
    }
}

fn parse_aircrack_output(stdout: &str, capture_file: &str) -> Result<Value> {
    let mut key_found = false;
    let mut password = String::new();

    for line in stdout.lines() {
        if line.contains("KEY FOUND!") {
            key_found = true;
            if let Some(pwd) = line.split('[').nth(1) {
                password = pwd.trim_end_matches(']').trim().to_string();
            }
        }
    }

    Ok(json!({
        "capture_file": capture_file,
        "key_found": key_found,
        "password": password,
        "summary": if key_found {
            format!("Key found: {}", password)
        } else {
            "Key not found".to_string()
        },
    }))
}

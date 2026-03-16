//! THC Hydra - Login bruteforcer
//!
//! Hydra is a parallelized login cracker which supports numerous protocols
//! (SSH, FTP, HTTP, SMB, RDP, etc.) to attack and brute-force credentials.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult,
    ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use super::install::ensure_tool_installed;
use super::runner::{param_str_opt, param_str_or, CommandBuilder};
use crate::util::param_u64;

/// THC Hydra login bruteforcer
pub struct HydraTool;

#[async_trait]
impl PentestTool for HydraTool {
    fn name(&self) -> &str {
        "hydra"
    }

    fn description(&self) -> &str {
        "Parallelized login bruteforcer supporting 50+ protocols (SSH, FTP, HTTP, SMB, RDP, etc.)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target IP address or hostname",
            ))
            .param(ToolParam::required(
                "service",
                ParamType::String,
                "Service to attack (ssh, ftp, http-get, smb, rdp, mysql, postgres, etc.)",
            ))
            .param(ToolParam::optional(
                "username",
                ParamType::String,
                "Single username to test (use username_list for multiple)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "password",
                ParamType::String,
                "Single password to test (use password_list for multiple)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "username_list",
                ParamType::String,
                "Path to username wordlist",
                json!(""),
            ))
            .param(ToolParam::optional(
                "password_list",
                ParamType::String,
                "Path to password wordlist",
                json!(""),
            ))
            .param(ToolParam::optional(
                "port",
                ParamType::Integer,
                "Port number (default: service default)",
                json!(0),
            ))
            .param(ToolParam::optional(
                "threads",
                ParamType::Integer,
                "Number of parallel tasks (default: 16)",
                json!(16),
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

            // Ensure hydra is installed
            ensure_tool_installed(&platform, "hydra", "hydra").await?;

            // Extract parameters
            let target = param_str_or(&params, "target", "");
            let service = param_str_or(&params, "service", "");

            if target.is_empty() || service.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target and service parameters are required".into(),
                ));
            }

            let threads = param_u64(&params, "threads", 16);
            let port = param_u64(&params, "port", 0);
            let timeout = param_u64(&params, "timeout", 300);

            // Build hydra command
            let mut builder = CommandBuilder::new()
                .arg("-t", &threads.to_string())
                .arg("-o", "/tmp/hydra-output.txt")
                .flag("-f"); // Stop on first valid credential

            // Username specification
            if let Some(username) = param_str_opt(&params, "username") {
                if !username.is_empty() {
                    builder = builder.arg("-l", &username);
                }
            } else if let Some(user_list) = param_str_opt(&params, "username_list") {
                if !user_list.is_empty() {
                    builder = builder.arg("-L", &user_list);
                }
            } else {
                return Err(pentest_core::error::Error::InvalidParams(
                    "Either username or username_list must be provided".into(),
                ));
            }

            // Password specification
            if let Some(password) = param_str_opt(&params, "password") {
                if !password.is_empty() {
                    builder = builder.arg("-p", &password);
                }
            } else if let Some(pass_list) = param_str_opt(&params, "password_list") {
                if !pass_list.is_empty() {
                    builder = builder.arg("-P", &pass_list);
                }
            } else {
                return Err(pentest_core::error::Error::InvalidParams(
                    "Either password or password_list must be provided".into(),
                ));
            }

            // Port specification
            if port > 0 {
                builder = builder.arg("-s", &port.to_string());
            }

            // Target and service
            builder = builder.positional(&target).positional(&service);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute hydra
            let result = platform
                .execute_command("hydra", &args_refs, Duration::from_secs(timeout))
                .await?;

            // Read output file
            let output = super::runner::read_sandbox_file(&platform, "/tmp/hydra-output.txt")
                .await
                .unwrap_or_else(|_| result.stdout.clone());

            // Parse hydra output
            parse_hydra_output(&output, &target, &service)
        })
        .await
    }
}

/// Parse hydra output
fn parse_hydra_output(output: &str, target: &str, service: &str) -> Result<Value> {
    let mut credentials = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        // Hydra format: "[22][ssh] host: 10.0.0.1   login: admin   password: password123"
        if line.contains("login:") && line.contains("password:") {
            let username = if let Some(login_part) = line.split("login:").nth(1) {
                login_part.split_whitespace().next().unwrap_or("").to_string()
            } else {
                String::new()
            };

            let password = if let Some(pass_part) = line.split("password:").nth(1) {
                pass_part.trim().to_string()
            } else {
                String::new()
            };

            if !username.is_empty() && !password.is_empty() {
                credentials.push(json!({
                    "username": username,
                    "password": password,
                }));
            }
        }
    }

    let success = !credentials.is_empty();

    Ok(json!({
        "target": target,
        "service": service,
        "credentials": credentials,
        "count": credentials.len(),
        "success": success,
        "summary": if success {
            format!("Found {} valid credential(s)", credentials.len())
        } else {
            "No valid credentials found".to_string()
        },
    }))
}

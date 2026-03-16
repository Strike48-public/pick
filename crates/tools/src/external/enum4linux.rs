//! Enum4linux - SMB/Windows enumeration tool
//!
//! Enum4linux is a tool for enumerating information from Windows and Samba systems.
//! It's a wrapper around smbclient, rpcclient, net, and nmblookup.

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

/// Enum4linux SMB enumeration tool
pub struct Enum4linuxTool;

#[async_trait]
impl PentestTool for Enum4linuxTool {
    fn name(&self) -> &str {
        "enum4linux"
    }

    fn description(&self) -> &str {
        "Enumerate information from Windows and Samba systems (users, shares, groups, policies)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target IP address or hostname",
            ))
            .param(ToolParam::optional(
                "username",
                ParamType::String,
                "Username for authentication (optional)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "password",
                ParamType::String,
                "Password for authentication (optional)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "enumerate_all",
                ParamType::Boolean,
                "Enumerate all (users, shares, groups, policies, etc.)",
                json!(true),
            ))
            .param(ToolParam::optional(
                "verbose",
                ParamType::Boolean,
                "Verbose output",
                json!(false),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();

            // Ensure enum4linux is installed
            ensure_tool_installed(&platform, "enum4linux", "enum4linux").await?;

            // Extract parameters
            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target parameter is required".into(),
                ));
            }

            let enumerate_all = crate::util::param_bool(&params, "enumerate_all", true);
            let verbose = crate::util::param_bool(&params, "verbose", false);

            // Build enum4linux command
            let mut builder = CommandBuilder::new();

            // Enumerate all
            if enumerate_all {
                builder = builder.flag("-a");
            }

            // Verbose mode
            if verbose {
                builder = builder.flag("-v");
            }

            // Authentication
            if let Some(username) = param_str_opt(&params, "username") {
                if !username.is_empty() {
                    builder = builder.arg("-u", &username);

                    if let Some(password) = param_str_opt(&params, "password") {
                        if !password.is_empty() {
                            builder = builder.arg("-p", &password);
                        }
                    }
                }
            }

            // Add target
            builder = builder.positional(&target);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute enum4linux
            let result = platform
                .execute_command("enum4linux", &args_refs, Duration::from_secs(300))
                .await?;

            // enum4linux may return non-zero even on partial success
            if result.stdout.is_empty() && !result.stderr.is_empty() {
                return Err(pentest_core::error::Error::ToolExecution(format!(
                    "enum4linux failed: {}",
                    result.stderr
                )));
            }

            // Parse enum4linux output
            parse_enum4linux_output(&result.stdout, &target)
        })
        .await
    }
}

/// Parse enum4linux output
fn parse_enum4linux_output(stdout: &str, target: &str) -> Result<Value> {
    let mut users = Vec::new();
    let mut shares = Vec::new();
    let mut groups = Vec::new();
    let mut domain_info = serde_json::Map::new();

    let mut in_users_section = false;
    let mut in_shares_section = false;
    let mut in_groups_section = false;

    for line in stdout.lines() {
        let line = line.trim();

        // Detect sections
        if line.contains("Users on") {
            in_users_section = true;
            in_shares_section = false;
            in_groups_section = false;
            continue;
        } else if line.contains("Share Enumeration on") {
            in_users_section = false;
            in_shares_section = true;
            in_groups_section = false;
            continue;
        } else if line.contains("Groups on") {
            in_users_section = false;
            in_shares_section = false;
            in_groups_section = true;
            continue;
        }

        // Parse users
        if in_users_section && line.starts_with("user:") {
            if let Some(username) = line.strip_prefix("user:") {
                let username = username.trim().trim_start_matches('[').trim_end_matches(']');
                users.push(username.to_string());
            }
        }

        // Parse shares
        if in_shares_section && line.contains("Mapping:") {
            if let Some(share_name) = line.split_whitespace().next() {
                shares.push(share_name.to_string());
            }
        }

        // Parse groups
        if in_groups_section && line.starts_with("group:") {
            if let Some(groupname) = line.strip_prefix("group:") {
                let groupname = groupname.trim().trim_start_matches('[').trim_end_matches(']');
                groups.push(groupname.to_string());
            }
        }

        // Parse domain/workgroup info
        if line.contains("Domain Name:") {
            if let Some(domain) = line.split(':').nth(1) {
                domain_info.insert("domain_name".to_string(), json!(domain.trim()));
            }
        }
        if line.contains("Domain Sid:") {
            if let Some(sid) = line.split(':').nth(1) {
                domain_info.insert("domain_sid".to_string(), json!(sid.trim()));
            }
        }
    }

    Ok(json!({
        "target": target,
        "domain_info": domain_info,
        "users": users,
        "shares": shares,
        "groups": groups,
        "user_count": users.len(),
        "share_count": shares.len(),
        "group_count": groups.len(),
        "summary": format!("Found {} users, {} shares, {} groups", users.len(), shares.len(), groups.len()),
        "raw_output": stdout,
    }))
}

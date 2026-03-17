//! WPScan - WordPress security scanner
//!
//! WPScan is a free, non-commercial black box WordPress security scanner written in Ruby.

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

/// WPScan WordPress security scanner
pub struct WpscanTool;

#[async_trait]
impl PentestTool for WpscanTool {
    fn name(&self) -> &str {
        "wpscan"
    }

    fn description(&self) -> &str {
        "WordPress security scanner for vulnerabilities, themes, plugins, and user enumeration"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "wpscan",
                "wpscan",
                "WordPress vulnerability scanner (Ruby-based)"
            ))
            .param(ToolParam::required(
                "url",
                ParamType::String,
                "Target WordPress URL (e.g., 'https://example.com')",
            ))
            .param(ToolParam::optional(
                "enumerate",
                ParamType::String,
                "Enumerate: 'vp' (vulnerable plugins), 'vt' (themes), 'u' (users), 'ap' (all plugins), 'at' (all themes)",
                json!("vp,vt,u"),
            ))
            .param(ToolParam::optional(
                "api_token",
                ParamType::String,
                "WPScan API token for vulnerability data (optional)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "detection_mode",
                ParamType::String,
                "Detection mode: 'mixed', 'passive', 'aggressive' (default: mixed)",
                json!("mixed"),
            ))
            .param(ToolParam::optional(
                "plugins_detection",
                ParamType::String,
                "Plugin detection mode: 'mixed', 'passive', 'aggressive' (default: passive)",
                json!("passive"),
            ))
            .param(ToolParam::optional(
                "user_agent",
                ParamType::String,
                "Custom User-Agent string",
                json!(""),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 300)",
                json!(300),
            ))
            .param(ToolParam::optional(
                "random_user_agent",
                ParamType::Boolean,
                "Use random User-Agent (default: false)",
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

            // Ensure wpscan is installed
            ensure_tool_installed(&platform, "wpscan", "wpscan").await?;

            // Extract parameters
            let url = param_str_or(&params, "url", "");
            if url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "url parameter is required".into(),
                ));
            }

            let enumerate = param_str_or(&params, "enumerate", "vp,vt,u");
            let api_token = param_str_opt(&params, "api_token");
            let detection_mode = param_str_or(&params, "detection_mode", "mixed");
            let plugins_detection = param_str_or(&params, "plugins_detection", "passive");
            let user_agent = param_str_opt(&params, "user_agent");
            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);
            let random_ua = param_bool(&params, "random_user_agent", false);

            // Build wpscan command
            let mut builder = CommandBuilder::new()
                .arg("--url", &url)
                .arg("--enumerate", &enumerate)
                .arg("--detection-mode", &detection_mode)
                .arg("--plugins-detection", &plugins_detection)
                .flag("--format")
                .positional("json"); // JSON output

            if let Some(token) = api_token {
                if !token.is_empty() {
                    builder = builder.arg("--api-token", &token);
                }
            }

            if random_ua {
                builder = builder.flag("--random-user-agent");
            } else if let Some(ua) = user_agent {
                if !ua.is_empty() {
                    builder = builder.arg("--user-agent", &ua);
                }
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute wpscan
            let result = platform
                .execute_command("wpscan", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            // WPScan returns 0 on success, even with findings
            if result.exit_code != 0 && !result.stderr.is_empty() {
                return Ok(json!({
                    "url": url,
                    "vulnerabilities": [],
                    "plugins": [],
                    "themes": [],
                    "users": [],
                    "error": result.stderr,
                }));
            }

            // Parse JSON output
            parse_wpscan_output(&result.stdout, &url)
        })
        .await
    }
}

/// Parse wpscan JSON output
fn parse_wpscan_output(stdout: &str, url: &str) -> Result<Value> {
    // Try to parse as JSON
    if let Ok(scan_result) = serde_json::from_str::<Value>(stdout) {
        let mut vulnerabilities = Vec::new();
        let mut plugins = Vec::new();
        let mut themes = Vec::new();
        let mut users = Vec::new();

        // Extract plugins with vulnerabilities
        if let Some(plugins_obj) = scan_result.get("plugins").and_then(|v| v.as_object()) {
            for (plugin_name, plugin_data) in plugins_obj {
                let mut plugin_info = json!({
                    "name": plugin_name,
                    "version": plugin_data.get("version").and_then(|v| v.get("number")).and_then(|v| v.as_str()).unwrap_or("unknown"),
                });

                if let Some(vulns) = plugin_data
                    .get("vulnerabilities")
                    .and_then(|v| v.as_array())
                {
                    plugin_info["vulnerabilities"] = json!(vulns);
                    if !vulns.is_empty() {
                        vulnerabilities.extend_from_slice(vulns);
                    }
                }

                plugins.push(plugin_info);
            }
        }

        // Extract themes with vulnerabilities
        if let Some(themes_obj) = scan_result.get("themes").and_then(|v| v.as_object()) {
            for (theme_name, theme_data) in themes_obj {
                let mut theme_info = json!({
                    "name": theme_name,
                    "version": theme_data.get("version").and_then(|v| v.get("number")).and_then(|v| v.as_str()).unwrap_or("unknown"),
                });

                if let Some(vulns) = theme_data.get("vulnerabilities").and_then(|v| v.as_array()) {
                    theme_info["vulnerabilities"] = json!(vulns);
                    if !vulns.is_empty() {
                        vulnerabilities.extend_from_slice(vulns);
                    }
                }

                themes.push(theme_info);
            }
        }

        // Extract users
        if let Some(users_obj) = scan_result.get("users").and_then(|v| v.as_object()) {
            for (user_id, user_data) in users_obj {
                users.push(json!({
                    "id": user_id,
                    "username": user_data.get("username").and_then(|v| v.as_str()).unwrap_or(""),
                    "found_by": user_data.get("found_by").and_then(|v| v.as_str()).unwrap_or(""),
                }));
            }
        }

        let vuln_count = vulnerabilities.len();
        let summary = format!(
            "Found {} vulnerabilities, {} plugins, {} themes, {} users",
            vuln_count,
            plugins.len(),
            themes.len(),
            users.len()
        );

        return Ok(json!({
            "url": url,
            "vulnerabilities": vulnerabilities,
            "plugins": plugins,
            "themes": themes,
            "users": users,
            "wordpress_version": scan_result.get("version").and_then(|v| v.get("number")).and_then(|v| v.as_str()).unwrap_or("unknown"),
            "summary": summary,
        }));
    }

    // Fallback if JSON parsing fails
    Ok(json!({
        "url": url,
        "vulnerabilities": [],
        "plugins": [],
        "themes": [],
        "users": [],
        "error": "Failed to parse WPScan output",
        "raw_output": stdout,
    }))
}

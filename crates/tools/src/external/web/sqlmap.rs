//! SQLMap - Automatic SQL injection and database takeover tool
//!
//! SQLMap is an open source penetration testing tool that automates the process of
//! detecting and exploiting SQL injection flaws and taking over database servers.

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

/// SQLMap SQL injection tool
pub struct SqlmapTool;

#[async_trait]
impl PentestTool for SqlmapTool {
    fn name(&self) -> &str {
        "sqlmap"
    }

    fn description(&self) -> &str {
        "Automatic SQL injection detection and exploitation tool with database takeover capabilities"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "sqlmap",
                "sqlmap",
                "SQL injection automation tool (Python-based, ~30MB download)"
            ))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target URL (e.g., 'http://example.com/page.php?id=1')",
            ))
            .param(ToolParam::optional(
                "method",
                ParamType::String,
                "HTTP method: GET, POST, PUT, DELETE (default: GET)",
                json!("GET"),
            ))
            .param(ToolParam::optional(
                "data",
                ParamType::String,
                "POST data string (e.g., 'id=1&name=test')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "cookie",
                ParamType::String,
                "HTTP Cookie header value",
                json!(""),
            ))
            .param(ToolParam::optional(
                "level",
                ParamType::Integer,
                "Level of tests to perform (1-5, default: 1)",
                json!(1),
            ))
            .param(ToolParam::optional(
                "risk",
                ParamType::Integer,
                "Risk of tests to perform (1-3, default: 1)",
                json!(1),
            ))
            .param(ToolParam::optional(
                "dbms",
                ParamType::String,
                "Force DBMS (mysql, postgresql, mssql, oracle, sqlite, etc.)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "technique",
                ParamType::String,
                "SQL injection techniques: B(oolean), E(rror), U(nion), S(tacked), T(ime), Q(uery) (default: BEUSTQ)",
                json!("BEUSTQ"),
            ))
            .param(ToolParam::optional(
                "dump",
                ParamType::Boolean,
                "Dump database table entries (default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "dbs",
                ParamType::Boolean,
                "Enumerate databases (default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "tables",
                ParamType::Boolean,
                "Enumerate tables (default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "batch",
                ParamType::Boolean,
                "Never ask for user input, use default behavior (default: true)",
                json!(true),
            ))
            .param(ToolParam::optional(
                "threads",
                ParamType::Integer,
                "Maximum number of concurrent HTTP requests (default: 1)",
                json!(1),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Overall timeout in seconds (default: 600)",
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

            // Ensure sqlmap is installed
            ensure_tool_installed(&platform, "sqlmap", "sqlmap").await?;

            // Extract parameters
            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target parameter is required".into(),
                ));
            }

            let method = param_str_or(&params, "method", "GET");
            let data = param_str_opt(&params, "data");
            let cookie = param_str_opt(&params, "cookie");
            let level = crate::util::param_u64(&params, "level", 1);
            let risk = crate::util::param_u64(&params, "risk", 1);
            let dbms = param_str_opt(&params, "dbms");
            let technique = param_str_or(&params, "technique", "BEUSTQ");
            let dump = param_bool(&params, "dump", false);
            let dbs = param_bool(&params, "dbs", false);
            let tables = param_bool(&params, "tables", false);
            let batch = param_bool(&params, "batch", true);
            let threads = crate::util::param_u64(&params, "threads", 1);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 600);

            // Build sqlmap command
            let mut builder = CommandBuilder::new()
                .arg("-u", &target)
                .arg("--method", &method)
                .arg("--level", &level.to_string())
                .arg("--risk", &risk.to_string())
                .arg("--technique", &technique)
                .arg("--threads", &threads.to_string());

            if batch {
                builder = builder.flag("--batch");
            }

            if let Some(data_str) = data {
                if !data_str.is_empty() {
                    builder = builder.arg("--data", &data_str);
                }
            }

            if let Some(cookie_str) = cookie {
                if !cookie_str.is_empty() {
                    builder = builder.arg("--cookie", &cookie_str);
                }
            }

            if let Some(dbms_str) = dbms {
                if !dbms_str.is_empty() {
                    builder = builder.arg("--dbms", &dbms_str);
                }
            }

            // Action flags
            if dump {
                builder = builder.flag("--dump");
            }
            if dbs {
                builder = builder.flag("--dbs");
            }
            if tables {
                builder = builder.flag("--tables");
            }

            // Output format
            builder = builder.flag("--flush-session"); // Don't use cached sessions

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute sqlmap
            let result = platform
                .execute_command("sqlmap", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            if result.exit_code != 0 {
                return Ok(json!({
                    "success": false,
                    "target": target,
                    "vulnerable": false,
                    "error": format!("SQLMap failed: {}", result.stderr),
                    "stdout": result.stdout,
                }));
            }

            // Parse sqlmap output
            parse_sqlmap_output(&result.stdout, &target)
        })
        .await
    }
}

/// Parse sqlmap output
fn parse_sqlmap_output(stdout: &str, target: &str) -> Result<Value> {
    let mut vulnerable = false;
    let mut injectable_params = Vec::new();
    let mut dbms_detected = String::new();
    let mut databases = Vec::new();
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();

        // Check for vulnerability indicators
        if line.contains("is vulnerable") || line.contains("Parameter:") && line.contains("is vulnerable") {
            vulnerable = true;
            findings.push(line.to_string());
        }

        // Extract injectable parameters
        if line.starts_with("Parameter:") {
            if let Some(param) = line.split(':').nth(1) {
                injectable_params.push(param.trim().to_string());
            }
        }

        // Detect DBMS
        if line.contains("back-end DBMS:") {
            if let Some(dbms) = line.split("back-end DBMS:").nth(1) {
                dbms_detected = dbms.trim().to_string();
            }
        }

        // Extract databases
        if line.starts_with("[*]") && !line.contains("starting") && !line.contains("testing") {
            databases.push(line.trim_start_matches("[*]").trim().to_string());
        }
    }

    Ok(json!({
        "target": target,
        "vulnerable": vulnerable,
        "injectable_parameters": injectable_params,
        "dbms": dbms_detected,
        "databases": databases,
        "findings": findings,
        "summary": if vulnerable {
            format!("Target is vulnerable to SQL injection. DBMS: {}", dbms_detected)
        } else {
            "No SQL injection vulnerabilities found".to_string()
        },
        "raw_output": stdout,
    }))
}

//! John the Ripper - Password cracker
//!
//! John the Ripper is a fast password cracker that supports many hash formats
//! and attack modes (dictionary, incremental, external, etc.).

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use super::install::ensure_tool_installed;
use super::runner::{param_str_opt, param_str_or, CommandBuilder};

/// John the Ripper password cracker
pub struct JohnTool;

#[async_trait]
impl PentestTool for JohnTool {
    fn name(&self) -> &str {
        "john"
    }

    fn description(&self) -> &str {
        "Fast password cracker supporting many hash formats and attack modes (dictionary, incremental)"
    }

    fn schema(&self) -> ToolSchema {
        use pentest_core::tools::ExternalDependency;

        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "john",
                "john",
                "John the Ripper password cracker",
            ))
            .param(ToolParam::required(
                "hash_file",
                ParamType::String,
                "Path to file containing password hashes",
            ))
            .param(ToolParam::optional(
                "format",
                ParamType::String,
                "Hash format (e.g., 'md5', 'sha256', 'bcrypt', 'ntlm', 'raw-md5')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Wordlist path for dictionary attack",
                json!(""),
            ))
            .param(ToolParam::optional(
                "rules",
                ParamType::String,
                "Rules to apply (e.g., 'wordlist', 'single', 'incremental')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "incremental",
                ParamType::Boolean,
                "Use incremental mode (brute-force)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "show",
                ParamType::Boolean,
                "Show cracked passwords only",
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

            // Ensure john is installed
            ensure_tool_installed(&platform, "john", "john").await?;

            // Extract parameters
            let hash_file = param_str_or(&params, "hash_file", "");
            if hash_file.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "hash_file parameter is required".into(),
                ));
            }

            let show = crate::util::param_bool(&params, "show", false);

            // If show mode, just display cracked passwords
            if show {
                let result = platform
                    .execute_command("john", &["--show", &hash_file], Duration::from_secs(10))
                    .await?;

                return parse_john_show_output(&result.stdout, &hash_file);
            }

            // Build john cracking command
            let mut builder = CommandBuilder::new().positional(&hash_file);

            // Format specification
            if let Some(format) = param_str_opt(&params, "format") {
                if !format.is_empty() {
                    builder = builder.arg("--format", &format);
                }
            }

            // Attack mode
            let incremental = crate::util::param_bool(&params, "incremental", false);

            if incremental {
                // Incremental (brute-force) mode
                builder = builder.flag("--incremental");
            } else if let Some(wordlist) = param_str_opt(&params, "wordlist") {
                // Dictionary attack
                if !wordlist.is_empty() {
                    builder = builder.arg("--wordlist", &wordlist);

                    // Rules
                    if let Some(rules) = param_str_opt(&params, "rules") {
                        if !rules.is_empty() {
                            builder = builder.arg("--rules", &rules);
                        }
                    }
                }
            } else {
                // Default: single crack mode
                builder = builder.flag("--single");
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute john
            let _result = platform
                .execute_command("john", &args_refs, Duration::from_secs(600))
                .await?;

            // John may return non-zero even on partial success
            // Get cracked passwords
            let show_result = platform
                .execute_command("john", &["--show", &hash_file], Duration::from_secs(10))
                .await?;

            parse_john_show_output(&show_result.stdout, &hash_file)
        })
        .await
    }
}

/// Parse john --show output
fn parse_john_show_output(stdout: &str, hash_file: &str) -> Result<Value> {
    let mut cracked = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("0 password") {
            continue;
        }

        // John format: "username:password" or "username:password:hash"
        if let Some(colon_pos) = line.find(':') {
            let username = &line[..colon_pos];
            let rest = &line[colon_pos + 1..];

            if let Some(pass_end) = rest.find(':') {
                let password = &rest[..pass_end];
                cracked.push(json!({
                    "username": username,
                    "password": password,
                }));
            } else {
                // Simple format: username:password
                cracked.push(json!({
                    "username": username,
                    "password": rest,
                }));
            }
        }
    }

    Ok(json!({
        "hash_file": hash_file,
        "cracked": cracked,
        "count": cracked.len(),
        "summary": format!("Cracked {} password(s)", cracked.len()),
    }))
}

//! Hashcat - Advanced password recovery

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

pub struct HashcatTool;

#[async_trait]
impl PentestTool for HashcatTool {
    fn name(&self) -> &str {
        "hashcat"
    }

    fn description(&self) -> &str {
        "Advanced GPU-accelerated password recovery tool supporting 300+ hash types"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "hashcat",
                "hashcat",
                "GPU password cracker (requires GPU drivers for full performance)"
            ))
            .param(ToolParam::required(
                "hash_file",
                ParamType::String,
                "File containing hashes to crack",
            ))
            .param(ToolParam::optional(
                "hash_type",
                ParamType::Integer,
                "Hash type (0=MD5, 1000=NTLM, 1800=sha512crypt, etc.)",
                json!(0),
            ))
            .param(ToolParam::optional(
                "attack_mode",
                ParamType::Integer,
                "Attack mode: 0=straight, 1=combination, 3=brute-force, 6=hybrid (default: 0)",
                json!(0),
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Wordlist file path (for dictionary attacks)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "show",
                ParamType::Boolean,
                "Show cracked passwords only (default: false)",
                json!(false),
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
            ensure_tool_installed(&platform, "hashcat", "hashcat").await?;

            let hash_file = param_str_or(&params, "hash_file", "");
            if hash_file.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "hash_file parameter is required".into(),
                ));
            }

            let hash_type = crate::util::param_u64(&params, "hash_type", 0);
            let attack_mode = crate::util::param_u64(&params, "attack_mode", 0);
            let wordlist = param_str_opt(&params, "wordlist");
            let show = crate::util::param_bool(&params, "show", false);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 3600);

            let mut builder = CommandBuilder::new()
                .arg("-m", &hash_type.to_string())
                .arg("-a", &attack_mode.to_string());

            if show {
                builder = builder.flag("--show");
                builder = builder.positional(&hash_file);
            } else {
                builder = builder.positional(&hash_file);

                if let Some(wl) = wordlist {
                    if !wl.is_empty() {
                        builder = builder.positional(&wl);
                    }
                }
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("hashcat", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            parse_hashcat_output(&result.stdout, &hash_file)
        })
        .await
    }
}

fn parse_hashcat_output(stdout: &str, hash_file: &str) -> Result<Value> {
    let mut cracked = Vec::new();

    for line in stdout.lines() {
        if line.contains(':') && !line.starts_with('#') && !line.starts_with("Session") {
            cracked.push(line.trim().to_string());
        }
    }

    Ok(json!({
        "hash_file": hash_file,
        "cracked": cracked,
        "count": cracked.len(),
        "summary": format!("Cracked {} hashes", cracked.len()),
    }))
}

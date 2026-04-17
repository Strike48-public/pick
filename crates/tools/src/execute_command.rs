//! Command execution tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::provenance::{truncate_excerpt, ProbeCommand, Provenance};
use pentest_core::tools::{
    execute_timed_with_provenance, ParamType, PentestTool, Platform, ToolContext, ToolParam,
    ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::sync::OnceLock;
use std::time::Duration;

use crate::util::param_u64;

/// Command execution tool
pub struct ExecuteCommandTool;

#[async_trait]
impl PentestTool for ExecuteCommandTool {
    fn name(&self) -> &str {
        "execute_command"
    }

    fn description(&self) -> &str {
        "Execute a shell command. Respects Settings > Shell Mode: Native (direct host execution) or Proot (sandboxed BlackArch environment with pacman)."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "command",
                ParamType::String,
                "The command to execute",
            ))
            .param(ToolParam::optional(
                "args",
                ParamType::Array,
                "Command arguments as an array",
                json!([]),
            ))
            .param(ToolParam::optional(
                "timeout_seconds",
                ParamType::Integer,
                "Command timeout in seconds",
                json!(120),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![
            Platform::Desktop,
            Platform::Web,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let workspace_path = ctx.workspace_path.clone();

        execute_timed_with_provenance(|| async move {
            let platform = get_platform();

            // Check if command execution is supported
            if !platform.is_command_exec_supported() {
                return Err(pentest_core::error::Error::PlatformNotSupported(
                    "Command execution not supported on this platform".into(),
                ));
            }

            let command = params
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    pentest_core::error::Error::InvalidParams("Command is required".into())
                })?;

            let args: Vec<String> = params
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let timeout_seconds = param_u64(&params, "timeout_seconds", 120);

            let timeout = Duration::from_secs(timeout_seconds);

            let result = if let Some(ref workspace) = workspace_path {
                platform
                    .execute_command_in_dir(command, &args_refs, timeout, Some(workspace.as_path()))
                    .await?
            } else {
                platform
                    .execute_command(command, &args_refs, timeout)
                    .await?
            };

            let full_command = format_full_command(command, &args);
            let excerpt_source = if result.stdout.is_empty() {
                result.stderr.as_str()
            } else {
                result.stdout.as_str()
            };
            let provenance = Provenance::new(
                "shell",
                shell_version(),
                ProbeCommand::from_exact(full_command),
                truncate_excerpt(excerpt_source),
            );

            let data = json!({
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "duration_ms": result.duration_ms,
            });

            Ok((data, provenance))
        })
        .await
    }
}

/// Join `command` and its `args` into a single shell-like string suitable
/// for `ProbeCommand.command`. Arguments containing whitespace are quoted.
fn format_full_command(command: &str, args: &[String]) -> String {
    let mut out = String::with_capacity(command.len());
    out.push_str(command);
    for arg in args {
        out.push(' ');
        if arg.chars().any(char::is_whitespace) {
            out.push('"');
            out.push_str(&arg.replace('"', "\\\""));
            out.push('"');
        } else {
            out.push_str(arg);
        }
    }
    out
}

/// Detect the login shell version once per process. Falls back to
/// `"unknown"` if detection fails; we never block a scan on version probing.
fn shell_version() -> &'static str {
    static CACHED: OnceLock<String> = OnceLock::new();
    CACHED.get_or_init(detect_shell_version).as_str()
}

fn detect_shell_version() -> String {
    // `SHELL` tells us which interpreter the user runs. Default to bash.
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
    let bin = std::path::Path::new(&shell)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("bash");
    // Try "<shell> --version" synchronously; if it fails, return "unknown".
    match std::process::Command::new(&shell).arg("--version").output() {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let first_line = text.lines().next().unwrap_or("").trim();
            if first_line.is_empty() {
                bin.to_string()
            } else {
                first_line.to_string()
            }
        }
        _ => bin.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::tools::{PentestTool, ToolContext};

    #[test]
    fn format_full_command_joins_args() {
        let out = format_full_command("nmap", &["-sV".to_string(), "192.168.1.1".to_string()]);
        assert_eq!(out, "nmap -sV 192.168.1.1");
    }

    #[test]
    fn format_full_command_quotes_whitespace_args() {
        let out = format_full_command(
            "curl",
            &[
                "-H".to_string(),
                "User-Agent: test agent".to_string(),
                "https://example.com".to_string(),
            ],
        );
        assert_eq!(
            out,
            r#"curl -H "User-Agent: test agent" https://example.com"#
        );
    }

    #[test]
    fn shell_version_is_non_empty() {
        let v = shell_version();
        assert!(!v.is_empty());
    }

    #[tokio::test]
    async fn execute_emits_provenance_structure() {
        // Verifies the provenance contract: structure is always present when
        // the tool runs, regardless of whether the underlying sandbox lets
        // the command succeed. Output content is inherently environment-
        // dependent (sandbox may reject, binary may be absent, etc.), so we
        // assert on the reproducibility metadata itself, not the payload.
        let tool = ExecuteCommandTool;
        let ctx = ToolContext::default();
        let params = json!({ "command": "echo", "args": ["hello-provenance"] });

        let result = tool.execute(params, &ctx).await.expect("execute ok");
        let prov = result
            .provenance
            .expect("execute_command must emit provenance");
        assert_eq!(prov.underlying_tool, "shell");
        assert!(!prov.tool_version.is_empty());
        assert_eq!(prov.probe_commands.len(), 1);
        assert_eq!(prov.probe_commands[0].command, "echo hello-provenance");
        assert_eq!(
            prov.probe_commands[0].effective_command,
            "echo hello-provenance"
        );
    }

    #[tokio::test]
    async fn execute_redacts_secrets_in_effective_command() {
        let tool = ExecuteCommandTool;
        let ctx = ToolContext::default();
        let params = json!({
            "command": "echo",
            "args": ["-u", "admin:hunter2", "https://example.test"]
        });

        let result = tool.execute(params, &ctx).await.expect("execute ok");
        let prov = result.provenance.expect("provenance present");
        let eff = &prov.probe_commands[0].effective_command;
        assert!(!eff.contains("hunter2"), "secret must be redacted: {eff}");
        assert!(eff.contains("<REDACTED>"));
        // The exact command must retain the secret for internal traceability.
        assert!(prov.probe_commands[0].command.contains("hunter2"));
    }
}

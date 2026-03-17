//! Generic subprocess runner helpers for external tools
//!
//! Provides common utilities for building command arguments, handling timeouts,
//! and processing tool output.

use pentest_core::error::{Error, Result};
use pentest_platform::CommandExec;
use serde_json::Value;
use std::time::Duration;

/// Helper to extract string parameter with a default value
pub fn param_str_or(params: &Value, key: &str, default: &str) -> String {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

/// Helper to extract optional string parameter
pub fn param_str_opt(params: &Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Build command arguments with common options
pub struct CommandBuilder {
    args: Vec<String>,
}

impl CommandBuilder {
    /// Create a new command builder
    pub fn new() -> Self {
        Self { args: Vec::new() }
    }

    /// Add a flag (e.g., "-v" for verbose)
    pub fn flag(mut self, flag: &str) -> Self {
        self.args.push(flag.to_string());
        self
    }

    /// Add a flag with a value (e.g., "-o output.json")
    pub fn arg(mut self, flag: &str, value: &str) -> Self {
        self.args.push(flag.to_string());
        self.args.push(value.to_string());
        self
    }

    /// Add a positional argument
    pub fn positional(mut self, value: &str) -> Self {
        self.args.push(value.to_string());
        self
    }

    /// Add multiple arguments
    pub fn extend<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.args
            .extend(args.into_iter().map(|s| s.as_ref().to_string()));
        self
    }

    /// Add an optional flag with value (only if value is Some)
    pub fn arg_opt(mut self, flag: &str, value: Option<&str>) -> Self {
        if let Some(v) = value {
            self.args.push(flag.to_string());
            self.args.push(v.to_string());
        }
        self
    }

    /// Build the final arguments vector
    pub fn build(self) -> Vec<String> {
        self.args
    }

    /// Build as Vec<&str> for immediate execution
    pub fn build_refs(&self) -> Vec<&str> {
        self.args.iter().map(|s| s.as_str()).collect()
    }
}

impl Default for CommandBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Execute a command and return the result with error handling
pub async fn execute_tool(
    platform: &impl CommandExec,
    command: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<(String, String, i32)> {
    let result = platform.execute_command(command, args, timeout).await?;

    // Check for common error patterns
    if result.exit_code != 0 {
        // Some tools return non-zero even on success, check stderr
        if !result.stderr.is_empty() && result.stdout.is_empty() {
            return Err(Error::ToolExecution(format!(
                "{} failed (exit code {}): {}",
                command, result.exit_code, result.stderr
            )));
        }
    }

    Ok((result.stdout, result.stderr, result.exit_code))
}

/// Execute a command and parse JSON output
pub async fn execute_and_parse_json(
    platform: &impl CommandExec,
    command: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Value> {
    let (stdout, stderr, exit_code) = execute_tool(platform, command, args, timeout).await?;

    if exit_code != 0 && stdout.is_empty() {
        return Err(Error::ToolExecution(format!(
            "{} failed: {}",
            command, stderr
        )));
    }

    serde_json::from_str(&stdout).map_err(|e| {
        Error::ToolExecution(format!(
            "Failed to parse JSON output from {}: {} (output: {})",
            command, e, stdout
        ))
    })
}

/// Read file from sandbox and return contents
pub async fn read_sandbox_file(platform: &impl CommandExec, file_path: &str) -> Result<String> {
    let (stdout, stderr, exit_code) =
        execute_tool(platform, "cat", &[file_path], Duration::from_secs(10)).await?;

    if exit_code != 0 {
        return Err(Error::ToolExecution(format!(
            "Failed to read file '{}': {}",
            file_path, stderr
        )));
    }

    Ok(stdout)
}

/// Remove a file from sandbox (cleanup)
pub async fn remove_sandbox_file(platform: &impl CommandExec, file_path: &str) -> Result<()> {
    let _ = platform
        .execute_command("rm", &["-f", file_path], Duration::from_secs(5))
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_builder() {
        let args = CommandBuilder::new()
            .arg("-o", "output.json")
            .flag("-v")
            .positional("target.com")
            .arg_opt("-t", Some("10"))
            .arg_opt("-x", None)
            .build();

        assert_eq!(
            args,
            vec!["-o", "output.json", "-v", "target.com", "-t", "10"]
        );
    }

    #[test]
    fn test_param_str_or() {
        let params = serde_json::json!({"key": "value"});
        assert_eq!(param_str_or(&params, "key", "default"), "value");
        assert_eq!(param_str_or(&params, "missing", "default"), "default");
    }

    #[test]
    fn test_param_str_opt() {
        let params = serde_json::json!({"key": "value"});
        assert_eq!(param_str_opt(&params, "key"), Some("value".to_string()));
        assert_eq!(param_str_opt(&params, "missing"), None);
    }
}

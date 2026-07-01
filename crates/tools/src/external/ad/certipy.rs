//! Certipy - Active Directory Certificate Services (AD CS / ESC) attacks.
//!
//! Wraps Certipy in one-shot mode: a single subcommand (`find`, `auth`, `req`,
//! ...) runs against a domain controller and its output is captured. The
//! subcommand is allowlisted, the target is validated as an IP/hostname, and
//! optional `extra_args` are individually allowlisted before reaching the
//! process boundary. Everything is passed as an argv vector (never a shell
//! string).

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::provenance::Provenance;
use pentest_core::tools::{
    execute_timed_with_provenance, ExternalDependency, ParamType, PentestTool, Platform,
    ToolCategory, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_core::validation::validate_target;
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use super::super::runner::{param_str_opt, param_str_or};
use super::common::{is_allowed_flag_token, reject_metacharacters};
use crate::provenance_support::{format_full_command, tool_version};
use crate::util::param_u64;

/// Allowlisted Certipy subcommands.
const CERTIPY_COMMANDS: &[&str] = &[
    "find", "auth", "req", "account", "shadow", "relay", "ca", "template",
];

pub struct CertipyTool;

#[async_trait]
impl PentestTool for CertipyTool {
    fn name(&self) -> &str {
        "certipy"
    }

    fn description(&self) -> &str {
        "Certipy - Active Directory Certificate Services (AD CS / ESC) attack tool. \
         Runs a single allowlisted subcommand (find, auth, req, account, shadow, relay, \
         ca, template) against a domain controller. Reports stdout/stderr."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(
                ExternalDependency::new(
                    "certipy",
                    "certipy",
                    "Certipy - Active Directory Certificate Services (AD CS) attack tool",
                )
                .custom_installer("certipy")
                .category(ToolCategory::ActiveDirectory),
            )
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Domain controller IP address or hostname (passed as -dc-ip).",
            ))
            .param(ToolParam::required(
                "command",
                ParamType::String,
                "Certipy subcommand. One of: find, auth, req, account, shadow, relay, ca, template.",
            ))
            .param(ToolParam::optional(
                "username",
                ParamType::String,
                "Username (combined with domain as user@domain via -u).",
                json!(""),
            ))
            .param(ToolParam::optional(
                "password",
                ParamType::String,
                "Password (passed via -p). May contain symbols; shell metacharacters rejected.",
                json!(""),
            ))
            .param(ToolParam::optional(
                "domain",
                ParamType::String,
                "Domain name (combined with username as user@domain).",
                json!(""),
            ))
            .param(ToolParam::optional(
                "extra_args",
                ParamType::Array,
                "Extra Certipy flags/values. Each entry must match a conservative allowlist: \
                 alphanumeric plus '-', '_', '.', '/', '@', ':', '='.",
                json!([]),
            ))
            .param(ToolParam::required(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds. MUST be set explicitly. Use 120 for most subcommands.",
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed_with_provenance(|| async move {
            let platform = get_platform();
            let timeout_secs = param_u64(&params, "timeout", 120);

            let command = param_str_or(&params, "command", "");
            let target = param_str_or(&params, "target", "");
            let username = param_str_opt(&params, "username");
            let password = param_str_opt(&params, "password");
            let domain = param_str_opt(&params, "domain");
            let extra_args = parse_extra_args(&params)?;

            let args = build_certipy_args(
                &command,
                &target,
                username.as_deref(),
                password.as_deref(),
                domain.as_deref(),
                &extra_args,
            )?;
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("certipy", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let data = json!({
                "command": command,
                "target": target,
                "summary": format!("Certipy {command} against {target}"),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
            });

            let full_command = format_full_command("certipy", &args);
            let provenance = Provenance::new(
                "certipy",
                tool_version("certipy"),
                pentest_core::provenance::ProbeCommand::from_exact(full_command)
                    .with_description(format!("Certipy {command} subcommand")),
                pentest_core::provenance::truncate_excerpt(&result.stdout),
            );

            Ok((data, provenance))
        })
        .await
    }
}

/// Extract and validate the optional `extra_args` array.
///
/// Each entry must be a non-empty string, free of shell metacharacters, and
/// match the conservative flag/value allowlist so it cannot split into extra
/// arguments or smuggle injection characters.
fn parse_extra_args(params: &Value) -> Result<Vec<String>> {
    let raw = match params.get("extra_args") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => {
            return Err(pentest_core::error::Error::InvalidParams(
                "extra_args must be an array of strings".into(),
            ))
        }
    };

    let mut validated = Vec::with_capacity(raw.len());
    for entry in raw {
        let token = entry.as_str().ok_or_else(|| {
            pentest_core::error::Error::InvalidParams("extra_args entries must be strings".into())
        })?;
        let token = token.trim();
        reject_metacharacters(token, "extra_args")?;
        if !is_allowed_flag_token(token) {
            return Err(pentest_core::error::Error::InvalidParams(format!(
                "Invalid extra_args entry '{token}': only alphanumeric, '-', '_', '.', '/', '@', ':', '=' allowed"
            )));
        }
        validated.push(token.to_string());
    }
    Ok(validated)
}

/// Build the Certipy argv vector for a validated invocation.
///
/// Shape: `certipy <command> [-u <user>@<domain>] [-p <password>] -dc-ip <target> [extra_args...]`.
/// The leading `certipy` binary is supplied to `execute_command` separately, so
/// the returned vector starts at the subcommand.
fn build_certipy_args(
    command: &str,
    target: &str,
    username: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
    extra_args: &[String],
) -> Result<Vec<String>> {
    let command = command.trim();
    if !CERTIPY_COMMANDS.contains(&command) {
        return Err(pentest_core::error::Error::InvalidParams(format!(
            "Invalid command '{command}': expected one of {CERTIPY_COMMANDS:?}"
        )));
    }

    // -dc-ip target: an IP or hostname (also rejects metacharacters).
    let target = validate_target(target)?;

    let mut args = vec![command.to_string()];

    // -u user@domain: only added when a username is provided.
    if let Some(user) = username.map(str::trim).filter(|u| !u.is_empty()) {
        reject_metacharacters(user, "username")?;
        let principal = match domain.map(str::trim).filter(|d| !d.is_empty()) {
            Some(dom) => {
                // Domain participates in the AD principal, validate it as a host.
                let dom = validate_target(dom)?;
                format!("{user}@{dom}")
            }
            None => user.to_string(),
        };
        args.push("-u".to_string());
        args.push(principal);
    }

    // -p password: passwords may contain symbols, so only the shell-injection
    // metacharacter guard runs here (not validate_target). Only added when set.
    if let Some(pass) = password.filter(|p| !p.is_empty()) {
        reject_metacharacters(pass, "password")?;
        args.push("-p".to_string());
        args.push(pass.to_string());
    }

    args.push("-dc-ip".to_string());
    args.push(target);

    args.extend(extra_args.iter().cloned());

    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_accepts_allowlisted_commands() {
        for cmd in CERTIPY_COMMANDS {
            let args = build_certipy_args(cmd, "10.0.0.1", None, None, None, &[]).unwrap();
            assert_eq!(args[0], *cmd);
        }
    }

    #[test]
    fn build_args_rejects_unknown_command() {
        let err = build_certipy_args("exec", "10.0.0.1", None, None, None, &[]);
        assert!(err.is_err());
    }

    #[test]
    fn build_args_rejects_target_metacharacters() {
        let err = build_certipy_args("find", "10.0.0.1; rm -rf /", None, None, None, &[]);
        assert!(err.is_err());
    }

    #[test]
    fn build_args_constructs_full_invocation() {
        let args = build_certipy_args(
            "find",
            "10.0.0.1",
            Some("administrator"),
            Some("P@ssw0rd!"),
            Some("corp.local"),
            &[],
        )
        .unwrap();
        assert_eq!(
            args,
            vec![
                "find",
                "-u",
                "administrator@corp.local",
                "-p",
                "P@ssw0rd!",
                "-dc-ip",
                "10.0.0.1",
            ]
        );
    }

    #[test]
    fn build_args_omits_credentials_when_absent() {
        let args = build_certipy_args("find", "dc01.corp.local", None, None, None, &[]).unwrap();
        assert_eq!(args, vec!["find", "-dc-ip", "dc01.corp.local"]);
    }

    #[test]
    fn build_args_username_without_domain_has_no_at() {
        let args = build_certipy_args("auth", "10.0.0.1", Some("svc"), None, None, &[]).unwrap();
        assert_eq!(args, vec!["auth", "-u", "svc", "-dc-ip", "10.0.0.1"]);
    }

    #[test]
    fn build_args_rejects_password_with_shell_metacharacters() {
        let err = build_certipy_args(
            "find",
            "10.0.0.1",
            Some("admin"),
            Some("pass`whoami`"),
            None,
            &[],
        );
        assert!(err.is_err());
    }

    #[test]
    fn build_args_appends_validated_extra_args() {
        let extra = vec!["-scheme".to_string(), "ldap".to_string()];
        let args = build_certipy_args("find", "10.0.0.1", None, None, None, &extra).unwrap();
        assert_eq!(args, vec!["find", "-dc-ip", "10.0.0.1", "-scheme", "ldap"]);
    }

    #[test]
    fn parse_extra_args_rejects_unsafe_tokens() {
        assert!(parse_extra_args(&json!({"extra_args": ["; rm -rf /"]})).is_err());
        assert!(parse_extra_args(&json!({"extra_args": ["a b"]})).is_err());
        assert!(parse_extra_args(&json!({"extra_args": [123]})).is_err());
        assert!(parse_extra_args(&json!({"extra_args": "not array"})).is_err());
    }

    #[test]
    fn parse_extra_args_accepts_safe_tokens_and_absence() {
        assert_eq!(parse_extra_args(&json!({})).unwrap(), Vec::<String>::new());
        let parsed =
            parse_extra_args(&json!({"extra_args": ["-template", "User", "-ca", "corp-CA"]}))
                .unwrap();
        assert_eq!(parsed, vec!["-template", "User", "-ca", "corp-CA"]);
    }
}

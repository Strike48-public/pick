//! NetExec (`nxc`) - network service exploitation.
//!
//! Wraps NetExec in one-shot mode against a single target over an allowlisted
//! protocol (SMB/WinRM/LDAP/MSSQL/SSH/...). Optional credentials and a single
//! allowlisted enumeration action are appended. The protocol and action are
//! allowlisted, the target is validated as an IP/hostname, and everything is
//! passed as an argv vector (never a shell string).

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
use super::common::reject_metacharacters;
use crate::provenance_support::{format_full_command, tool_version};
use crate::util::param_u64;

/// Allowlisted NetExec protocols.
const NXC_PROTOCOLS: &[&str] = &[
    "smb", "winrm", "ldap", "mssql", "ssh", "ftp", "rdp", "vnc", "wmi",
];

pub struct NetExecTool;

#[async_trait]
impl PentestTool for NetExecTool {
    fn name(&self) -> &str {
        "netexec"
    }

    fn description(&self) -> &str {
        "NetExec (nxc) - network service exploitation across SMB/WinRM/LDAP/MSSQL/SSH. \
         Runs against a single target over an allowlisted protocol with optional \
         credentials and one allowlisted enumeration action (shares, users, groups, \
         loggedon, sessions, pass-pol). Reports stdout/stderr."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(
                ExternalDependency::new(
                    "nxc",
                    "netexec",
                    "NetExec (nxc) - network service exploitation across SMB/WinRM/LDAP/MSSQL/SSH",
                )
                .custom_installer("netexec")
                .category(ToolCategory::ActiveDirectory),
            )
            .param(ToolParam::required(
                "protocol",
                ParamType::String,
                "Protocol. One of: smb, winrm, ldap, mssql, ssh, ftp, rdp, vnc, wmi.",
            ))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target IP address or hostname.",
            ))
            .param(ToolParam::optional(
                "username",
                ParamType::String,
                "Username (passed via -u).",
                json!(""),
            ))
            .param(ToolParam::optional(
                "password",
                ParamType::String,
                "Password (passed via -p). May contain symbols; shell metacharacters rejected.",
                json!(""),
            ))
            .param(ToolParam::optional(
                "command_action",
                ParamType::String,
                "Optional enumeration action. One of: shares, users, groups, loggedon, \
                 sessions, pass-pol.",
                json!(""),
            ))
            .param(ToolParam::required(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds. MUST be set explicitly. Use 120 for most actions.",
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

            let protocol = param_str_or(&params, "protocol", "");
            let target = param_str_or(&params, "target", "");
            let username = param_str_opt(&params, "username");
            let password = param_str_opt(&params, "password");
            let command_action = param_str_opt(&params, "command_action");

            let args = build_netexec_args(
                &protocol,
                &target,
                username.as_deref(),
                password.as_deref(),
                command_action.as_deref(),
            )?;
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("nxc", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let data = json!({
                "protocol": protocol,
                "target": target,
                "summary": format!("NetExec {protocol} against {target}"),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
            });

            let full_command = format_full_command("nxc", &args);
            let provenance = Provenance::new(
                "netexec",
                tool_version("nxc"),
                pentest_core::provenance::ProbeCommand::from_exact(full_command)
                    .with_description(format!("NetExec {protocol} probe")),
                pentest_core::provenance::truncate_excerpt(&result.stdout),
            );

            Ok((data, provenance))
        })
        .await
    }
}

/// Map an allowlisted `command_action` to its NetExec flag.
fn action_flag(action: &str) -> Option<&'static str> {
    match action {
        "shares" => Some("--shares"),
        "users" => Some("--users"),
        "groups" => Some("--groups"),
        "loggedon" => Some("--loggedon-users"),
        "sessions" => Some("--sessions"),
        "pass-pol" => Some("--pass-pol"),
        _ => None,
    }
}

/// Build the NetExec argv vector for a validated invocation.
///
/// Shape: `nxc <protocol> <target> [-u <user>] [-p <password>] [<action flag>]`.
/// The leading `nxc` binary is supplied to `execute_command` separately, so the
/// returned vector starts at the protocol.
fn build_netexec_args(
    protocol: &str,
    target: &str,
    username: Option<&str>,
    password: Option<&str>,
    command_action: Option<&str>,
) -> Result<Vec<String>> {
    let protocol = protocol.trim();
    if !NXC_PROTOCOLS.contains(&protocol) {
        return Err(pentest_core::error::Error::InvalidParams(format!(
            "Invalid protocol '{protocol}': expected one of {NXC_PROTOCOLS:?}"
        )));
    }

    // target: an IP or hostname (also rejects metacharacters).
    let target = validate_target(target)?;

    let mut args = vec![protocol.to_string(), target];

    // -u username: only added when provided.
    if let Some(user) = username.map(str::trim).filter(|u| !u.is_empty()) {
        reject_metacharacters(user, "username")?;
        args.push("-u".to_string());
        args.push(user.to_string());
    }

    // -p password: passwords may contain symbols, so only the shell-injection
    // metacharacter guard runs here (not validate_target). Only added when set.
    if let Some(pass) = password.filter(|p| !p.is_empty()) {
        reject_metacharacters(pass, "password")?;
        args.push("-p".to_string());
        args.push(pass.to_string());
    }

    // Optional enumeration action, mapped to a single safe flag.
    if let Some(action) = command_action.map(str::trim).filter(|a| !a.is_empty()) {
        let flag = action_flag(action).ok_or_else(|| {
            pentest_core::error::Error::InvalidParams(format!(
                "Invalid command_action '{action}': expected one of shares, users, groups, \
                 loggedon, sessions, pass-pol"
            ))
        })?;
        args.push(flag.to_string());
    }

    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_accepts_allowlisted_protocols() {
        for proto in NXC_PROTOCOLS {
            let args = build_netexec_args(proto, "10.0.0.1", None, None, None).unwrap();
            assert_eq!(args[0], *proto);
        }
    }

    #[test]
    fn build_args_rejects_unknown_protocol() {
        let err = build_netexec_args("telnet", "10.0.0.1", None, None, None);
        assert!(err.is_err());
    }

    #[test]
    fn build_args_rejects_target_metacharacters() {
        let err = build_netexec_args("smb", "10.0.0.1 | id", None, None, None);
        assert!(err.is_err());
    }

    #[test]
    fn build_args_constructs_full_invocation() {
        let args = build_netexec_args(
            "smb",
            "10.0.0.1",
            Some("administrator"),
            Some("P@ssw0rd!"),
            Some("shares"),
        )
        .unwrap();
        assert_eq!(
            args,
            vec![
                "smb",
                "10.0.0.1",
                "-u",
                "administrator",
                "-p",
                "P@ssw0rd!",
                "--shares",
            ]
        );
    }

    #[test]
    fn build_args_omits_optional_fields() {
        let args = build_netexec_args("ldap", "dc01.corp.local", None, None, None).unwrap();
        assert_eq!(args, vec!["ldap", "dc01.corp.local"]);
    }

    #[test]
    fn build_args_rejects_unknown_action() {
        let err = build_netexec_args("smb", "10.0.0.1", None, None, Some("rce"));
        assert!(err.is_err());
    }

    #[test]
    fn build_args_rejects_password_with_shell_metacharacters() {
        let err = build_netexec_args("smb", "10.0.0.1", Some("admin"), Some("p$(id)"), None);
        assert!(err.is_err());
    }

    #[test]
    fn action_flag_maps_every_allowlisted_action() {
        assert_eq!(action_flag("shares"), Some("--shares"));
        assert_eq!(action_flag("users"), Some("--users"));
        assert_eq!(action_flag("groups"), Some("--groups"));
        assert_eq!(action_flag("loggedon"), Some("--loggedon-users"));
        assert_eq!(action_flag("sessions"), Some("--sessions"));
        assert_eq!(action_flag("pass-pol"), Some("--pass-pol"));
        assert_eq!(action_flag("nope"), None);
    }
}

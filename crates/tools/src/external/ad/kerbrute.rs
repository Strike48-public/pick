//! Kerbrute - Kerberos pre-auth username enumeration and password spraying.
//!
//! Wraps Kerbrute in one-shot mode. The mode (`userenum`, `passwordspray`,
//! `bruteuser`) maps to a Kerbrute subcommand; the domain and DC are validated
//! as IP/hostnames, the userlist is validated as a path-shaped value, and the
//! optional spray password runs through the shell-injection guard only.
//! Everything is passed as an argv vector (never a shell string).

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
use super::common::{is_allowed_path, reject_metacharacters};
use crate::provenance_support::{format_full_command, tool_version};
use crate::util::param_u64;

/// Allowlisted Kerbrute modes (each maps to the same-named subcommand).
const KERBRUTE_MODES: &[&str] = &["userenum", "passwordspray", "bruteuser"];

pub struct KerbruteTool;

#[async_trait]
impl PentestTool for KerbruteTool {
    fn name(&self) -> &str {
        "kerbrute"
    }

    fn description(&self) -> &str {
        "Kerbrute - Kerberos pre-auth username enumeration and password spraying. \
         mode='userenum' enumerates valid usernames from a userlist; \
         mode='passwordspray' sprays one password across a userlist; \
         mode='bruteuser' brute-forces one user from a wordlist. Reports stdout/stderr."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(
                ExternalDependency::new(
                    "kerbrute",
                    "kerbrute",
                    "Kerbrute - Kerberos pre-auth username enumeration and password spraying",
                )
                .custom_installer("kerbrute")
                .category(ToolCategory::ActiveDirectory),
            )
            .param(ToolParam::required(
                "mode",
                ParamType::String,
                "Mode. One of: userenum, passwordspray, bruteuser.",
            ))
            .param(ToolParam::required(
                "domain",
                ParamType::String,
                "Target domain (e.g. 'corp.local'), passed via -d.",
            ))
            .param(ToolParam::required(
                "dc",
                ParamType::String,
                "Domain controller IP address or hostname, passed via --dc.",
            ))
            .param(ToolParam::optional(
                "userlist",
                ParamType::String,
                "Path to a userlist/wordlist. Path-shaped values only \
                 (alphanumeric, '_', '-', '.', '/').",
                json!(""),
            ))
            .param(ToolParam::optional(
                "password",
                ParamType::String,
                "[passwordspray mode] Password to spray. May contain symbols; \
                 shell metacharacters rejected.",
                json!(""),
            ))
            .param(ToolParam::required(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds. MUST be set explicitly. Use 300 for enumeration/spraying.",
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed_with_provenance(|| async move {
            let platform = get_platform();
            let timeout_secs = param_u64(&params, "timeout", 300);

            let mode = param_str_or(&params, "mode", "");
            let domain = param_str_or(&params, "domain", "");
            let dc = param_str_or(&params, "dc", "");
            let userlist = param_str_opt(&params, "userlist");
            let password = param_str_opt(&params, "password");

            let args = build_kerbrute_args(
                &mode,
                &domain,
                &dc,
                userlist.as_deref(),
                password.as_deref(),
            )?;
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("kerbrute", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let data = json!({
                "mode": mode,
                "domain": domain,
                "dc": dc,
                "summary": format!("Kerbrute {mode} against {domain} via {dc}"),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
            });

            let full_command = format_full_command("kerbrute", &args);
            let provenance = Provenance::new(
                "kerbrute",
                tool_version("kerbrute"),
                pentest_core::provenance::ProbeCommand::from_exact(full_command)
                    .with_description(format!("Kerbrute {mode}")),
                pentest_core::provenance::truncate_excerpt(&result.stdout),
            );

            Ok((data, provenance))
        })
        .await
    }
}

/// Validate an optional userlist path and return it, or an error if missing
/// when required / malformed.
fn require_userlist(userlist: Option<&str>) -> Result<String> {
    let path = userlist
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            pentest_core::error::Error::InvalidParams("userlist is required for this mode".into())
        })?;
    reject_metacharacters(path, "userlist")?;
    if !is_allowed_path(path) {
        return Err(pentest_core::error::Error::InvalidParams(format!(
            "Invalid userlist '{path}': path-shaped values only \
             (alphanumeric, '_', '-', '.', '/')"
        )));
    }
    Ok(path.to_string())
}

/// Build the Kerbrute argv vector for a validated invocation.
///
/// Real Kerbrute CLI shape (subcommand first, then global flags, then
/// positionals):
///   * userenum:      `kerbrute userenum --dc <dc> -d <domain> <userlist>`
///   * passwordspray: `kerbrute passwordspray --dc <dc> -d <domain> <userlist> <password>`
///   * bruteuser:     `kerbrute bruteuser --dc <dc> -d <domain> <wordlist> <user>` —
///     here `<wordlist>` is the `userlist` path; brute target is supplied as the
///     userlist-driven positional per Kerbrute's password-file form.
///
/// The leading `kerbrute` binary is supplied to `execute_command` separately,
/// so the returned vector starts at the subcommand.
fn build_kerbrute_args(
    mode: &str,
    domain: &str,
    dc: &str,
    userlist: Option<&str>,
    password: Option<&str>,
) -> Result<Vec<String>> {
    let mode = mode.trim();
    if !KERBRUTE_MODES.contains(&mode) {
        return Err(pentest_core::error::Error::InvalidParams(format!(
            "Invalid mode '{mode}': expected one of {KERBRUTE_MODES:?}"
        )));
    }

    // domain and dc: hostname-ish / IP (also reject metacharacters).
    let domain = validate_target(domain)?;
    let dc = validate_target(dc)?;

    let mut args = vec![
        mode.to_string(),
        "--dc".to_string(),
        dc,
        "-d".to_string(),
        domain,
    ];

    match mode {
        "userenum" | "bruteuser" => {
            // Positional userlist/wordlist path.
            let list = require_userlist(userlist)?;
            args.push(list);
        }
        "passwordspray" => {
            // Positional userlist, then the spray password.
            let list = require_userlist(userlist)?;
            args.push(list);
            let pass = password
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .ok_or_else(|| {
                    pentest_core::error::Error::InvalidParams(
                        "password is required for mode='passwordspray'".into(),
                    )
                })?;
            // Spray password may contain symbols: shell-injection guard only.
            reject_metacharacters(pass, "password")?;
            args.push(pass.to_string());
        }
        // Unreachable given the allowlist check above, but return an error
        // rather than panic if the allowlist and this match ever drift apart.
        _ => {
            return Err(pentest_core::error::Error::InvalidParams(format!(
                "Unhandled kerbrute mode '{mode}'"
            )))
        }
    }

    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_accepts_allowlisted_modes() {
        for mode in KERBRUTE_MODES {
            let args = build_kerbrute_args(
                mode,
                "corp.local",
                "10.0.0.1",
                Some("users.txt"),
                Some("Spring2026"),
            )
            .unwrap();
            assert_eq!(args[0], *mode);
        }
    }

    #[test]
    fn build_args_rejects_unknown_mode() {
        let err = build_kerbrute_args("spray-all", "corp.local", "10.0.0.1", Some("u.txt"), None);
        assert!(err.is_err());
    }

    #[test]
    fn build_args_rejects_domain_metacharacters() {
        let err = build_kerbrute_args(
            "userenum",
            "corp.local; id",
            "10.0.0.1",
            Some("u.txt"),
            None,
        );
        assert!(err.is_err());
    }

    #[test]
    fn build_args_rejects_dc_metacharacters() {
        let err = build_kerbrute_args(
            "userenum",
            "corp.local",
            "10.0.0.1`id`",
            Some("u.txt"),
            None,
        );
        assert!(err.is_err());
    }

    #[test]
    fn build_args_userenum_constructs_expected_invocation() {
        let args = build_kerbrute_args(
            "userenum",
            "corp.local",
            "10.0.0.1",
            Some("/usr/share/wordlists/users.txt"),
            None,
        )
        .unwrap();
        assert_eq!(
            args,
            vec![
                "userenum",
                "--dc",
                "10.0.0.1",
                "-d",
                "corp.local",
                "/usr/share/wordlists/users.txt",
            ]
        );
    }

    #[test]
    fn build_args_passwordspray_appends_userlist_then_password() {
        let args = build_kerbrute_args(
            "passwordspray",
            "corp.local",
            "10.0.0.1",
            Some("users.txt"),
            Some("Spring2026!"),
        )
        .unwrap();
        assert_eq!(
            args,
            vec![
                "passwordspray",
                "--dc",
                "10.0.0.1",
                "-d",
                "corp.local",
                "users.txt",
                "Spring2026!",
            ]
        );
    }

    #[test]
    fn build_args_passwordspray_requires_password() {
        let err = build_kerbrute_args(
            "passwordspray",
            "corp.local",
            "10.0.0.1",
            Some("users.txt"),
            None,
        );
        assert!(err.is_err());
    }

    #[test]
    fn build_args_requires_userlist() {
        let err = build_kerbrute_args("userenum", "corp.local", "10.0.0.1", None, None);
        assert!(err.is_err());
    }

    #[test]
    fn build_args_rejects_userlist_metacharacters() {
        let err = build_kerbrute_args(
            "userenum",
            "corp.local",
            "10.0.0.1",
            Some("users.txt; rm -rf /"),
            None,
        );
        assert!(err.is_err());
    }

    #[test]
    fn build_args_rejects_password_with_shell_metacharacters() {
        let err = build_kerbrute_args(
            "passwordspray",
            "corp.local",
            "10.0.0.1",
            Some("users.txt"),
            Some("p`id`"),
        );
        assert!(err.is_err());
    }
}

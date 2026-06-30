//! BloodHound AD data collector (`bloodhound-python` ingestor).
//!
//! Wraps the `bloodhound-python` collector in one-shot mode: it authenticates
//! to a domain controller, runs a collection method, and writes a zipped JSON
//! dataset. Credentials are required; the domain and DC are validated as
//! IP/hostnames, the collection method is allowlisted, the password runs through
//! the shell-injection guard only, and everything is passed as an argv vector
//! (never a shell string).

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

use super::super::runner::param_str_or;
use super::common::reject_metacharacters;
use crate::provenance_support::{format_full_command, tool_version};
use crate::util::param_u64;

/// Allowlisted BloodHound collection methods.
const COLLECTION_METHODS: &[&str] = &[
    "Default",
    "All",
    "DCOnly",
    "Session",
    "Group",
    "LocalAdmin",
    "ACL",
    "Trusts",
];

/// Default collection method when the caller does not specify one.
const DEFAULT_COLLECTION_METHOD: &str = "Default";

pub struct BloodHoundTool;

#[async_trait]
impl PentestTool for BloodHoundTool {
    fn name(&self) -> &str {
        "bloodhound"
    }

    fn description(&self) -> &str {
        "BloodHound AD data collector (bloodhound-python ingestor). Authenticates to a \
         domain controller and collects an AD dataset using an allowlisted collection \
         method (Default, All, DCOnly, Session, Group, LocalAdmin, ACL, Trusts), writing \
         a zipped JSON dataset. Reports stdout/stderr."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(
                ExternalDependency::new(
                    "bloodhound-python",
                    "python-bloodhound",
                    "BloodHound AD data collector (bloodhound-python ingestor)",
                )
                .custom_installer("bloodhound")
                .category(ToolCategory::ActiveDirectory),
            )
            .param(ToolParam::required(
                "domain",
                ParamType::String,
                "Target domain (e.g. 'corp.local'), passed via -d.",
            ))
            .param(ToolParam::required(
                "username",
                ParamType::String,
                "Username (passed via -u).",
            ))
            .param(ToolParam::required(
                "password",
                ParamType::String,
                "Password (passed via -p). May contain symbols; shell metacharacters rejected.",
            ))
            .param(ToolParam::required(
                "dc",
                ParamType::String,
                "Domain controller IP address or hostname, passed via -dc.",
            ))
            .param(ToolParam::optional(
                "collection_method",
                ParamType::String,
                "Collection method. One of: Default, All, DCOnly, Session, Group, \
                 LocalAdmin, ACL, Trusts. Default 'Default'.",
                json!(DEFAULT_COLLECTION_METHOD),
            ))
            .param(ToolParam::required(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds. MUST be set explicitly. Use 600 for collection.",
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed_with_provenance(|| async move {
            let platform = get_platform();
            let timeout_secs = param_u64(&params, "timeout", 600);

            let domain = param_str_or(&params, "domain", "");
            let username = param_str_or(&params, "username", "");
            let password = param_str_or(&params, "password", "");
            let dc = param_str_or(&params, "dc", "");
            let collection_method =
                param_str_or(&params, "collection_method", DEFAULT_COLLECTION_METHOD);

            let args =
                build_bloodhound_args(&domain, &username, &password, &dc, &collection_method)?;
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command(
                    "bloodhound-python",
                    &args_refs,
                    Duration::from_secs(timeout_secs),
                )
                .await?;

            let data = json!({
                "domain": domain,
                "dc": dc,
                "collection_method": collection_method,
                "summary": format!(
                    "BloodHound {collection_method} collection of {domain} via {dc}"
                ),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
            });

            let full_command = format_full_command("bloodhound-python", &args);
            let provenance = Provenance::new(
                "bloodhound-python",
                tool_version("bloodhound-python"),
                pentest_core::provenance::ProbeCommand::from_exact(full_command)
                    .with_description(format!("BloodHound {collection_method} collection")),
                pentest_core::provenance::truncate_excerpt(&result.stdout),
            );

            Ok((data, provenance))
        })
        .await
    }
}

/// Build the `bloodhound-python` argv vector for a validated invocation.
///
/// Shape: `bloodhound-python -d <domain> -u <username> -p <password> -dc <dc> \
///   -c <collection_method> --zip`.
/// The leading `bloodhound-python` binary is supplied to `execute_command`
/// separately, so the returned vector starts at `-d`.
fn build_bloodhound_args(
    domain: &str,
    username: &str,
    password: &str,
    dc: &str,
    collection_method: &str,
) -> Result<Vec<String>> {
    // domain and dc: hostname-ish / IP (also reject metacharacters).
    let domain = validate_target(domain)?;
    let dc = validate_target(dc)?;

    let username = username.trim();
    if username.is_empty() {
        return Err(pentest_core::error::Error::InvalidParams(
            "username is required".into(),
        ));
    }
    reject_metacharacters(username, "username")?;

    // Password may contain symbols: shell-injection guard only (no validate_target).
    if password.is_empty() {
        return Err(pentest_core::error::Error::InvalidParams(
            "password is required".into(),
        ));
    }
    reject_metacharacters(password, "password")?;

    let collection_method = collection_method.trim();
    let collection_method = if collection_method.is_empty() {
        DEFAULT_COLLECTION_METHOD
    } else {
        collection_method
    };
    if !COLLECTION_METHODS.contains(&collection_method) {
        return Err(pentest_core::error::Error::InvalidParams(format!(
            "Invalid collection_method '{collection_method}': expected one of {COLLECTION_METHODS:?}"
        )));
    }

    Ok(vec![
        "-d".to_string(),
        domain,
        "-u".to_string(),
        username.to_string(),
        "-p".to_string(),
        password.to_string(),
        "-dc".to_string(),
        dc,
        "-c".to_string(),
        collection_method.to_string(),
        "--zip".to_string(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_accepts_all_collection_methods() {
        for method in COLLECTION_METHODS {
            let args =
                build_bloodhound_args("corp.local", "admin", "P@ss", "10.0.0.1", method).unwrap();
            // -c is the second-to-last flag, value immediately after.
            let idx = args.iter().position(|a| a == "-c").unwrap();
            assert_eq!(args[idx + 1], *method);
        }
    }

    #[test]
    fn build_args_defaults_empty_method_to_default() {
        let args = build_bloodhound_args("corp.local", "admin", "P@ss", "10.0.0.1", "").unwrap();
        let idx = args.iter().position(|a| a == "-c").unwrap();
        assert_eq!(args[idx + 1], "Default");
    }

    #[test]
    fn build_args_rejects_unknown_collection_method() {
        let err = build_bloodhound_args("corp.local", "admin", "P@ss", "10.0.0.1", "Everything");
        assert!(err.is_err());
    }

    #[test]
    fn build_args_constructs_full_invocation() {
        let args = build_bloodhound_args(
            "corp.local",
            "administrator",
            "P@ssw0rd!",
            "10.0.0.1",
            "All",
        )
        .unwrap();
        assert_eq!(
            args,
            vec![
                "-d",
                "corp.local",
                "-u",
                "administrator",
                "-p",
                "P@ssw0rd!",
                "-dc",
                "10.0.0.1",
                "-c",
                "All",
                "--zip",
            ]
        );
    }

    #[test]
    fn build_args_rejects_domain_metacharacters() {
        let err = build_bloodhound_args("corp.local; id", "admin", "P@ss", "10.0.0.1", "Default");
        assert!(err.is_err());
    }

    #[test]
    fn build_args_rejects_dc_metacharacters() {
        let err = build_bloodhound_args("corp.local", "admin", "P@ss", "10.0.0.1`id`", "Default");
        assert!(err.is_err());
    }

    #[test]
    fn build_args_requires_username_and_password() {
        assert!(build_bloodhound_args("corp.local", "", "P@ss", "10.0.0.1", "Default").is_err());
        assert!(build_bloodhound_args("corp.local", "admin", "", "10.0.0.1", "Default").is_err());
    }

    #[test]
    fn build_args_rejects_password_with_shell_metacharacters() {
        let err = build_bloodhound_args("corp.local", "admin", "p$(id)", "10.0.0.1", "Default");
        assert!(err.is_err());
    }
}

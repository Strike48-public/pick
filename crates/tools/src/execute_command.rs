//! Command execution tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::provenance::{truncate_excerpt, ProbeCommand, Provenance};
use pentest_core::tools::{
    execute_timed_with_provenance, ParamType, PentestTool, Platform, ToolContext, ToolOutcome,
    ToolParam, ToolResult, ToolSchema,
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
            .param(ToolParam::optional(
                "identity_ref",
                ParamType::String,
                "Label of an operator-provisioned test identity to run this \
                 command as (differential-authz testing). The connector injects \
                 the identity's auth header for the target binary locally - you \
                 never see or write the credential. Only these binaries support \
                 injection: curl, ffuf, wget, sqlmap. Fails if the label is \
                 unknown or the binary has no supported header flag.",
                json!(null),
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

        // Command execution unsupported here → the probe never ran. Return
        // Skipped directly (precondition unmet), before timing, so we never
        // have to string-match an error message to recover this case (#184).
        if !get_platform().is_command_exec_supported() {
            return Ok(ToolResult::skipped(
                "Command execution not supported on this platform",
            ));
        }

        // Parse command/args up front (not inside the timed closure) so that
        // identity injection can fail-closed BEFORE any subprocess spawns — an
        // unknown identity_ref or an unmappable binary must never run
        // unauthenticated and report success (pick#314 / #162 ethos).
        let command = match params.get("command").and_then(|v| v.as_str()) {
            Some(c) => c.to_string(),
            None => return Ok(ToolResult::error("Command is required")),
        };

        let mut args: Vec<String> = params
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // Identity injection (pick#314): if the caller referenced a test
        // identity, resolve it to its auth header and splice the correct
        // per-binary flag ahead of the user args. resolve_identity never
        // reveals the secret to the LLM; the connector injects it locally here.
        if let Some(label) = params.get("identity_ref").and_then(|v| v.as_str()) {
            match build_identity_injection(&command, label, ctx) {
                // Prepend so tool-specific positional args (e.g. a target URL)
                // stay last, matching how these binaries expect flags.
                Ok(mut injected) => {
                    injected.extend(std::mem::take(&mut args));
                    args = injected;
                }
                Err(e) => return Ok(ToolResult::error(e.to_string())),
            }
        }

        let timeout_seconds = param_u64(&params, "timeout_seconds", 120);

        // Build the run future via the provenance-timed helper so timing and
        // the error→Failed mapping stay consistent with every other tool. On
        // success we then reclassify the outcome from the process exit status
        // (see below) — a completed subprocess is not necessarily a completed
        // probe (#184).
        let run = execute_timed_with_provenance(|| async move {
            let platform = get_platform();

            let command = command.as_str();

            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

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
        .await?;

        Ok(classify_command_outcome(run))
    }
}

/// Reclassify a completed `execute_command` run's outcome from its process
/// exit status (#184).
///
/// A subprocess that *ran* is not necessarily a *completed probe*. Applied only
/// to a `Ran` result (an already-`Failed` result from the tool body — bad
/// params, spawn failure — passes through unchanged; the unsupported-platform
/// `Skipped` case is handled before this is reached). We downgrade to
/// [`ToolOutcome::Failed`] — `with_outcome` also clears `success` — when:
/// * the command timed out (never finished), or
/// * it exited nonzero **and produced no stdout** (errored with nothing to show), or
/// * the exit status is unreadable (fail closed — never assume success).
///
/// We deliberately do NOT fail a nonzero exit that still produced stdout: many
/// legitimate tools use nonzero exit codes as signal (`grep` with no match,
/// `diff`, `test`), and their stdout is real output the model may need. A zero
/// exit with empty stdout stays [`ToolOutcome::Ran`] — a truthful empty result.
///
/// The captured stdout/stderr/exit_code stay in `data` in every case, for the
/// model's diagnostic use.
fn classify_command_outcome(result: ToolResult) -> ToolResult {
    // Only a `Ran` result needs reclassification from exit status. Anything
    // already Failed/Skipped (the tool body returned Err, or the platform was
    // unsupported) is left as-is.
    if result.outcome != ToolOutcome::Ran {
        return result;
    }

    let timed_out = result.data.get("timed_out").and_then(Value::as_bool) == Some(true);
    let exit_code = result.data.get("exit_code").and_then(Value::as_i64);
    let stdout_empty = result
        .data
        .get("stdout")
        .and_then(Value::as_str)
        .map(str::is_empty)
        .unwrap_or(true);

    // Fail closed: a run whose exit status we cannot read is not a trustworthy
    // completed probe. The tool body always writes `exit_code`, so `None` here
    // means an unexpected data shape — treat it as Failed, never assume success.
    let failed =
        timed_out || exit_code.is_none() || (exit_code.is_some_and(|c| c != 0) && stdout_empty);

    if failed {
        result.with_outcome(ToolOutcome::Failed)
    } else {
        result
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

/// Reduce a `command` string to the bare executable name: strip any directory
/// path (`/usr/bin/curl` -> `curl`, `./sqlmap` -> `sqlmap`). The identity flag
/// map is keyed by executable name, not the invocation path.
fn binary_basename(command: &str) -> &str {
    std::path::Path::new(command)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(command)
}

/// Map a target binary to the argv fragment that passes a full HTTP header
/// line as a custom request header, for the given `header` value.
///
/// Session material (pick#162) is stored as a complete header line
/// (`"Authorization: Bearer ..."` or `"Cookie: sid=..."`), so a single
/// custom-header flag per binary handles both the auth and cookie cases - no
/// need to parse the material apart. Returns:
/// * `Some(vec![..])` - the argv fragment to splice in for a supported binary.
/// * `None` - the binary has no generic custom-header flag we trust. The caller
///   MUST fail loud rather than run without the identity: a curl-shaped `-H`
///   guessed onto a sibling tool is the exact silently-wrong bug pick#314
///   exists to avoid (PR-review Lens 7).
///
/// Binaries differ in flag *shape*, which is why this is a per-binary map and
/// not one splice rule:
/// * `curl` / `ffuf` take a separate `-H <value>` arg pair.
/// * `wget` / `sqlmap` take a single joined `--header=<value>` arg.
fn header_flags_for(binary: &str, header: &str) -> Option<Vec<String>> {
    match binary {
        "curl" | "ffuf" => Some(vec!["-H".to_string(), header.to_string()]),
        "wget" | "sqlmap" => Some(vec![format!("--header={header}")]),
        _ => None,
    }
}

/// Resolve an `identity_ref` label to the argv fragment that authenticates the
/// target `command` as that identity (pick#314).
///
/// Fails loud (returns `Err(message)`) - never silently runs unauthenticated,
/// which would misreport a differential-authz result (the pick#162 ethos) -
/// when:
/// * the label is unknown (not provisioned / typo), or
/// * the identity carries material but the binary has no supported header flag.
///
/// Returns `Ok(vec![])` (inject nothing) when the identity is anonymous (empty
/// material): running with no auth *is* that identity, so it is not a failure.
fn build_identity_injection(command: &str, label: &str, ctx: &ToolContext) -> Result<Vec<String>> {
    let material = ctx.resolve_identity(label).ok_or_else(|| {
        pentest_core::error::Error::InvalidParams(format!(
            "identity_ref '{label}' is not a provisioned test identity; \
             cannot authenticate as it (refusing to run unauthenticated)"
        ))
    })?;

    // Anonymous identity: no material to inject. Running as-is IS this identity.
    if material.is_empty() {
        return Ok(Vec::new());
    }

    let binary = binary_basename(command);
    header_flags_for(binary, material.expose()).ok_or_else(|| {
        pentest_core::error::Error::InvalidParams(format!(
            "identity_ref '{label}' cannot be injected into '{binary}': no \
             supported custom-header flag for this binary (supported: curl, \
             ffuf, wget, sqlmap). Refusing to run with the identity dropped."
        ))
    })
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
        // the tool runs. Output content is inherently environment-dependent
        // (binary may be absent, etc.), so we assert on the reproducibility
        // metadata itself, not the payload.
        //
        // Run host-direct (sandbox disabled). With the sandbox enabled and no
        // system proot, execute_command now DOWNLOADS the pinned proot binary
        // and sets up the BlackArch rootfs — on a CI runner that path hangs
        // (multi-GB rootfs / stalled fetch), timing the job out after hours.
        // Since #256 an enabled-but-unavailable sandbox also fails closed (Err,
        // no provenance). Disabling the sandbox takes the explicit host path,
        // matching the pentest-core integration tests (connector_execute.rs).
        pentest_platform::set_use_sandbox(false);
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
        // Host-direct: same rationale as execute_emits_provenance_structure —
        // with the sandbox enabled and no system proot, execute_command would
        // download proot + set up the rootfs and hang on a CI runner (and since
        // #256 an unavailable sandbox also fails closed with no provenance).
        pentest_platform::set_use_sandbox(false);
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

    // --- classify_command_outcome (pick#184 Lever 2) ----------------------
    //
    // A completed subprocess is not necessarily a completed probe. These pin
    // the exit-status → ToolOutcome mapping directly on the pure classifier so
    // they are deterministic (no live subprocess needed).

    /// Build a success-path ToolResult carrying the given process status, as
    /// the tool body produces before classification.
    fn ran(exit_code: i64, stdout: &str, timed_out: bool) -> ToolResult {
        ToolResult::success(json!({
            "stdout": stdout,
            "stderr": "",
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_ms": 1,
        }))
    }

    #[test]
    fn zero_exit_with_output_is_ran() {
        let r = classify_command_outcome(ran(0, "hello\n", false));
        assert_eq!(r.outcome, ToolOutcome::Ran);
        assert!(r.success);
    }

    #[test]
    fn zero_exit_empty_stdout_is_ran_truthful_empty() {
        // A command that ran cleanly and simply produced nothing is a truthful
        // empty result — must stay trustworthy, not be downgraded.
        let r = classify_command_outcome(ran(0, "", false));
        assert_eq!(r.outcome, ToolOutcome::Ran);
        assert!(r.success);
    }

    #[test]
    fn nonzero_exit_empty_stdout_is_failed() {
        // Errored and produced nothing — the fabrication substrate. Fail closed.
        let r = classify_command_outcome(ran(1, "", false));
        assert_eq!(r.outcome, ToolOutcome::Failed);
        assert!(!r.success);
    }

    #[test]
    fn nonzero_exit_with_stdout_stays_ran() {
        // Many legit tools exit nonzero yet produce real output (`grep` no
        // match, `diff`, `test`). Their stdout is real data — do NOT discard.
        let r = classify_command_outcome(ran(1, "line-of-real-output\n", false));
        assert_eq!(r.outcome, ToolOutcome::Ran);
        assert!(r.success);
    }

    #[test]
    fn timed_out_is_failed_even_with_partial_stdout() {
        // A timeout never finished, so even partial stdout is untrustworthy.
        let r = classify_command_outcome(ran(0, "partial output", true));
        assert_eq!(r.outcome, ToolOutcome::Failed);
        assert!(!r.success);
    }

    #[test]
    fn missing_exit_code_fails_closed() {
        // The tool body always writes exit_code; a missing one means an
        // unexpected data shape. Never assume success — fail closed (#184).
        let r = classify_command_outcome(ToolResult::success(json!({
            "stdout": "",
            "stderr": "something broke",
            "timed_out": false,
            // exit_code deliberately absent
        })));
        assert_eq!(r.outcome, ToolOutcome::Failed);
        assert!(!r.success);
    }

    #[test]
    fn already_failed_result_passes_through_unchanged() {
        // A tool body that returned Err (bad params, spawn failure) is already
        // Failed; classification must not touch it.
        let r = classify_command_outcome(ToolResult::error("bad params"));
        assert_eq!(r.outcome, ToolOutcome::Failed);
        assert!(!r.success);
    }

    #[test]
    fn skipped_result_passes_through_unchanged() {
        // The unsupported-platform Skipped case is produced upstream in
        // execute(); if one reaches the classifier it must survive.
        let r = classify_command_outcome(ToolResult::skipped("unsupported platform"));
        assert_eq!(r.outcome, ToolOutcome::Skipped);
    }

    // --- identity injection (pick#314) -------------------------------------
    //
    // A specialist ACTS as a differential-authz identity by referencing it by
    // `label` (never the secret, which the LLM never sees - pick#162). The
    // connector resolves the label to session material and splices the correct
    // "custom header" flag for the target binary. Session material is a full
    // HTTP header line (`"Authorization: Bearer ..."` / `"Cookie: sid=..."`),
    // so one flag handles both auth and cookie forms per binary.

    use pentest_core::identity::{IdentityStore, SessionMaterial};

    #[test]
    fn header_flags_curl_uses_separate_dash_h() {
        // curl takes the header as a separate `-H <value>` arg pair.
        assert_eq!(
            header_flags_for("curl", "Authorization: Bearer tok"),
            Some(vec![
                "-H".to_string(),
                "Authorization: Bearer tok".to_string()
            ])
        );
    }

    #[test]
    fn header_flags_ffuf_uses_separate_dash_h() {
        assert_eq!(
            header_flags_for("ffuf", "Cookie: sid=abc"),
            Some(vec!["-H".to_string(), "Cookie: sid=abc".to_string()])
        );
    }

    #[test]
    fn header_flags_wget_uses_joined_long_flag() {
        // wget takes `--header=<value>` as one joined arg.
        assert_eq!(
            header_flags_for("wget", "Authorization: Bearer tok"),
            Some(vec!["--header=Authorization: Bearer tok".to_string()])
        );
    }

    #[test]
    fn header_flags_sqlmap_uses_joined_long_flag() {
        assert_eq!(
            header_flags_for("sqlmap", "Cookie: sid=abc"),
            Some(vec!["--header=Cookie: sid=abc".to_string()])
        );
    }

    #[test]
    fn header_flags_unknown_binary_is_none() {
        // nmap/nikto/etc. have no generic custom-HTTP-header flag; return None
        // so the caller fails loud rather than guessing a curl-shaped `-H`.
        assert_eq!(header_flags_for("nmap", "Cookie: sid=abc"), None);
        assert_eq!(header_flags_for("echo", "Cookie: sid=abc"), None);
    }

    #[test]
    fn binary_basename_strips_path_and_args() {
        assert_eq!(binary_basename("/usr/bin/curl"), "curl");
        assert_eq!(binary_basename("curl"), "curl");
        assert_eq!(binary_basename("./sqlmap"), "sqlmap");
    }

    fn ctx_with(label: &str, material: &str) -> ToolContext {
        ToolContext::default().with_identities(IdentityStore::from_pairs([(
            label,
            SessionMaterial::new(material),
        )]))
    }

    #[test]
    fn build_injection_unknown_label_fails_loud() {
        // A label the connector never provisioned must NOT silently run
        // unauthenticated - that would misreport the authz result (#162 ethos).
        let ctx = ToolContext::default();
        let err = build_identity_injection("curl", "ghost", &ctx)
            .expect_err("unknown label must fail loud")
            .to_string();
        assert!(err.contains("ghost"), "message names the label: {err}");
    }

    #[test]
    fn build_injection_known_label_curl_injects_material() {
        let ctx = ctx_with("user_a", "Cookie: sid=secret-abc");
        let args = build_identity_injection("curl", "user_a", &ctx).expect("known label injects");
        assert_eq!(
            args,
            vec!["-H".to_string(), "Cookie: sid=secret-abc".to_string()]
        );
    }

    #[test]
    fn build_injection_unmapped_binary_fails_loud() {
        // Known identity, but the binary has no header flag: fail loud rather
        // than run the scan without the requested identity applied.
        let ctx = ctx_with("user_a", "Cookie: sid=abc");
        let err = build_identity_injection("nmap", "user_a", &ctx)
            .expect_err("unmapped binary must fail loud")
            .to_string();
        assert!(err.contains("nmap"), "message names the binary: {err}");
    }

    #[test]
    fn build_injection_empty_material_injects_nothing() {
        // An anonymous identity carries no material: inject nothing and succeed
        // (running with no auth IS that identity), never fail.
        let ctx = ctx_with("anon", "");
        let args =
            build_identity_injection("curl", "anon", &ctx).expect("anonymous injects nothing");
        assert!(args.is_empty());
    }

    #[test]
    fn injected_auth_header_redacts_in_effective_command() {
        // The injected secret must be scrubbed from effective_command (which
        // reaches evidence/report) but retained in the exact command.
        let full = format_full_command(
            "curl",
            &[
                "-H".to_string(),
                "Authorization: Bearer secrettoken123".to_string(),
                "https://x.test".to_string(),
            ],
        );
        let prov = Provenance::new("shell", "test", ProbeCommand::from_exact(full), "");
        let eff = &prov.probe_commands[0].effective_command;
        assert!(!eff.contains("secrettoken123"), "secret leaked: {eff}");
        assert!(eff.contains("<REDACTED>"));
        assert!(prov.probe_commands[0].command.contains("secrettoken123"));
    }

    #[tokio::test]
    async fn execute_unknown_identity_ref_fails_without_running() {
        // identity_ref pointing at no known identity fails closed BEFORE any
        // subprocess spawns - so no deterministic dependency on curl/etc.
        pentest_platform::set_use_sandbox(false);
        let tool = ExecuteCommandTool;
        let ctx = ToolContext::default();
        let params = json!({
            "command": "curl",
            "args": ["https://x.test"],
            "identity_ref": "ghost",
        });
        let result = tool.execute(params, &ctx).await.expect("execute ok");
        assert_eq!(result.outcome, ToolOutcome::Failed);
        assert!(!result.success);
        assert!(result.error.unwrap_or_default().contains("ghost"));
    }

    #[tokio::test]
    async fn execute_identity_ref_unmapped_binary_fails() {
        // Known identity, but nmap has no header flag: fail loud, do not run
        // the scan with the identity silently dropped.
        pentest_platform::set_use_sandbox(false);
        let tool = ExecuteCommandTool;
        let ctx = ToolContext::default().with_identities(IdentityStore::from_pairs([(
            "user_a",
            SessionMaterial::new("Cookie: sid=abc"),
        )]));
        let params = json!({
            "command": "nmap",
            "args": ["-sV", "10.0.0.1"],
            "identity_ref": "user_a",
        });
        let result = tool.execute(params, &ctx).await.expect("execute ok");
        assert_eq!(result.outcome, ToolOutcome::Failed);
        assert!(result.error.unwrap_or_default().contains("nmap"));
    }
}

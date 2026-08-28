//! Command execution tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::provenance::{redact_known_secret, truncate_excerpt, ProbeCommand, Provenance};
use pentest_core::specialist_spawner::IdentityRole;
use pentest_core::tools::{
    execute_timed_with_provenance, ParamType, PentestTool, Platform, ToolContext, ToolOutcome,
    ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec, CommandResult};
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
        //
        // `applied_identity` records what was injected so provenance can (a)
        // scrub the exact secret from `effective_command` by value, and (b)
        // attribute the response to the identity — a differential-authz finding
        // is only meaningful with the principal attached (#317 review #3/#6).
        let mut applied_identity: Option<AppliedIdentity> = None;
        // Distinguish "no identity requested" (absent / null - run as-is) from a
        // string label (resolve + inject) from any other JSON shape. An LLM
        // tool-call can violate the schema; a non-string identity_ref must fail
        // loud rather than be silently dropped and run unauthenticated while the
        // outcome is still attributed as a differential-authz probe (#317
        // review #2).
        match params.get("identity_ref") {
            None | Some(Value::Null) => {}
            Some(Value::String(label)) => {
                match build_identity_injection(&command, label, ctx) {
                    // Prepend so tool-specific positional args (e.g. a target
                    // URL) stay last, matching how these binaries expect flags.
                    Ok(injection) => {
                        applied_identity = Some(AppliedIdentity {
                            label: label.clone(),
                            secret: injection.injected_secret,
                        });

                        let mut injected = injection.args;
                        injected.extend(std::mem::take(&mut args));
                        args = injected;
                    }
                    Err(e) => return Ok(ToolResult::error(e.to_string())),
                }
            }
            Some(other) => {
                return Ok(ToolResult::error(format!(
                    "identity_ref must be a string label or omitted; got {} - \
                     refusing to run with the identity silently dropped",
                    json_type_name(other)
                )));
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
            let (data, provenance) = build_run_output(full_command, result, &applied_identity);

            // Promote the run into the evidence graph so findings the agent
            // builds on the output can be grounded (pick#52). One Info node per
            // run; raw stdout/stderr stay out of the node (see
            // evidence_from_execute_command).
            for node in
                crate::evidence_producer::evidence_from_execute_command(&data, provenance.clone())
            {
                let _ = crate::evidence_producer::push_evidence(node);
            }

            Ok((data, provenance))
        })
        .await?;

        Ok(classify_command_outcome(run))
    }
}

/// Build the `(data, provenance)` pair for a completed `execute_command` run.
///
/// Extracted from the run closure so the identity-secret scrub is testable
/// without a live subprocess. When an identity was injected (`applied` is
/// `Some` with a non-empty secret), the exact credential is scrubbed BY VALUE
/// from every agent-facing surface before it crosses the boundary:
/// * the published command (`effective_command`), and
/// * the captured output (`stdout`/`stderr`), which feeds both `data` and the
///   provenance excerpt — a target that reflects the injected header (verbose
///   echo, error page, `curl -v` on stderr) would otherwise put the raw
///   credential straight in front of the agent.
///
/// This closes the gap that the read-side sanitizer (`sanitize_agent_result`)
/// and `redact` cannot: they are regex-only and miss odd header shapes
/// (`X-Api-Id: ab12cd`). Because the injected secret is *known* here, scrubbing
/// by value removes it regardless of shape — security-by-construction over a
/// best-effort scrubber (#317 review, agent-output boundary). Anonymous
/// identities (empty secret) and non-identity runs pass output through
/// unchanged. The residual log/process-table surface is tracked in pick#335.
fn build_run_output(
    full_command: String,
    result: CommandResult,
    applied: &Option<AppliedIdentity>,
) -> (Value, Provenance) {
    let injected_secret = applied
        .as_ref()
        .map(|a| a.secret.as_str())
        .filter(|s| !s.is_empty());

    // Value-scrub the known secret out of the captured output. `redact_known_secret`
    // is a no-op when there is no secret, so non-identity runs are untouched.
    let (stdout, stderr) = match injected_secret {
        Some(secret) => (
            redact_known_secret(&result.stdout, secret),
            redact_known_secret(&result.stderr, secret),
        ),
        None => (result.stdout, result.stderr),
    };

    let excerpt_source = if stdout.is_empty() {
        stderr.as_str()
    } else {
        stdout.as_str()
    };

    // Scrub the injected secret from the published command by value and
    // attribute the probe to the identity label so a reviewer can tell which
    // principal produced the response (#317 review #3/#6).
    let probe_command = match applied {
        Some(AppliedIdentity { label, secret }) => {
            ProbeCommand::from_exact_redacting_secret(full_command, secret)
                .with_description(format!("authenticated as test identity: {label}"))
        }
        None => ProbeCommand::from_exact(full_command),
    };

    let provenance = Provenance::new(
        "shell",
        shell_version(),
        probe_command,
        truncate_excerpt(excerpt_source),
    );

    let data = json!({
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "duration_ms": result.duration_ms,
    });

    (data, provenance)
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

/// What `build_identity_injection` produced: the argv fragment to splice in,
/// plus the exact secret value it injected (empty for an anonymous identity) so
/// the caller can scrub it from published provenance by value (#317 review #3).
struct IdentityInjection {
    args: Vec<String>,
    injected_secret: String,
}

// Manual Debug: never print `injected_secret` (it is the raw auth header). The
// whole point of this type is to keep that value out of every sink; a derived
// Debug would defeat it in logs and test panic output.
impl std::fmt::Debug for IdentityInjection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityInjection")
            .field("args_len", &self.args.len())
            .field("has_secret", &!self.injected_secret.is_empty())
            .finish()
    }
}

/// A test identity that was actually applied to this command, captured for
/// provenance: `label` attributes the response to a principal (#317 review #6),
/// `secret` is the exact injected value scrubbed from `effective_command` (#3).
struct AppliedIdentity {
    label: String,
    secret: String,
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
fn build_identity_injection(
    command: &str,
    label: &str,
    ctx: &ToolContext,
) -> Result<IdentityInjection> {
    let identity = ctx.resolve_identity(label).ok_or_else(|| {
        pentest_core::error::Error::InvalidParams(format!(
            "identity_ref '{label}' is not a provisioned test identity; \
             cannot authenticate as it (refusing to run unauthenticated)"
        ))
    })?;
    let material = identity.material();

    // Empty material is only legitimate for an anonymous identity - running
    // with no auth *is* that identity, so inject nothing. For any other role,
    // empty material means the identity was mis-provisioned; running it would
    // report an unauthenticated request under a privileged label (a false
    // authz finding), so fail loud. This is defense-in-depth behind the loader
    // guard (`load_identities_from_file`), covering direct store population
    // paths that bypass the file loader (#317 review #1).
    if material.is_empty() {
        if identity.role() == IdentityRole::Anonymous {
            return Ok(IdentityInjection {
                args: Vec::new(),
                injected_secret: String::new(),
            });
        }
        return Err(pentest_core::error::Error::InvalidParams(format!(
            "identity_ref '{label}' (role {:?}) carries no session material; \
             refusing to run it unauthenticated under a non-anonymous label",
            identity.role()
        )));
    }

    let binary = binary_basename(command);
    let header = material.expose();
    let args = header_flags_for(binary, header).ok_or_else(|| {
        pentest_core::error::Error::InvalidParams(format!(
            "identity_ref '{label}' cannot be injected into '{binary}': no \
             supported custom-header flag for this binary (supported: curl, \
             ffuf, wget, sqlmap). Refusing to run with the identity dropped."
        ))
    })?;

    Ok(IdentityInjection {
        args,
        // The exact injected header value, kept so provenance can scrub it from
        // the published command by value rather than hoping a regex matches.
        injected_secret: header.to_string(),
    })
}

/// Human-readable JSON type name for a rejected `identity_ref` shape, so the
/// fail-loud message tells the caller *what* it sent (#317 review #2).
fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
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
    use pentest_core::specialist_spawner::IdentityRole;

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
        ctx_with_role(label, IdentityRole::User, material)
    }

    fn ctx_with_role(label: &str, role: IdentityRole, material: &str) -> ToolContext {
        ToolContext::default().with_identities(IdentityStore::from_pairs([(
            label,
            role,
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
        let injection =
            build_identity_injection("curl", "user_a", &ctx).expect("known label injects");
        assert_eq!(
            injection.args,
            vec!["-H".to_string(), "Cookie: sid=secret-abc".to_string()]
        );
        // The exact injected secret is captured so provenance can scrub it by value.
        assert_eq!(injection.injected_secret, "Cookie: sid=secret-abc");
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
        // An ANONYMOUS identity carries no material: inject nothing and succeed
        // (running with no auth IS that identity), never fail.
        let ctx = ctx_with_role("anon", IdentityRole::Anonymous, "");
        let injection =
            build_identity_injection("curl", "anon", &ctx).expect("anonymous injects nothing");
        assert!(injection.args.is_empty());
        assert!(injection.injected_secret.is_empty());
    }

    #[test]
    fn build_injection_nonanon_empty_material_fails_loud() {
        // #317 review #1 defense-in-depth: a non-anonymous identity that reached
        // the store with empty material (e.g. a direct-population path that
        // bypasses the file loader guard) must FAIL, not silently inject nothing
        // and run unauthenticated under a privileged label.
        let ctx = ctx_with_role("admin", IdentityRole::Privileged, "");
        let err = build_identity_injection("curl", "admin", &ctx)
            .expect_err("privileged identity with empty material must fail loud")
            .to_string();
        assert!(
            err.contains("admin") && err.contains("no session material"),
            "message must name the label and the cause: {err}"
        );
    }

    #[test]
    fn build_injection_anonymous_from_real_loader_injects_nothing() {
        // Regression for #317 H1: end-to-end through the PRODUCTION loader, not
        // a hand-built store. Earlier this passed only because `ctx_with` seeded
        // a placeholder the loader never created; the loader skipped empty-
        // session entries, so `identity_ref: "unauth"` (what both specialist
        // prompts tell the LLM to emit) resolved to None and hard-errored.
        let path = std::env::temp_dir().join("pick-exec-anon-e2e.json");
        std::fs::write(&path, r#"[{"label":"unauth","role":"anonymous"}]"#).unwrap();
        let loaded = pentest_core::identity::load_identities_from_file(&path).expect("loader ok");
        let ctx = ToolContext::default().with_identities(loaded.store);
        let injection = build_identity_injection("curl", "unauth", &ctx)
            .expect("anonymous from real loader injects nothing, does not error");
        assert!(injection.args.is_empty());
        std::fs::remove_file(&path).ok();
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

    #[test]
    fn exotic_shape_identity_header_is_scrubbed_by_value_not_pattern() {
        // #317 review #3: a short, non-hex, oddly-named header value slips past
        // every redact() regex (no `authorization:`/`cookie:`/keyword, < 32 hex,
        // < 40 base64). Because the injected secret is KNOWN, from_exact_redacting_secret
        // scrubs it by exact substring, so it never reaches effective_command
        // (which is published to reports) regardless of shape.
        let secret = "X-Api-Id: ab12cd";
        let full = format_full_command(
            "curl",
            &[
                "-H".to_string(),
                secret.to_string(),
                "https://x.test".to_string(),
            ],
        );

        // Baseline: pattern redaction alone does NOT catch this shape.
        assert!(
            pentest_core::provenance::redact(&full).contains("ab12cd"),
            "precondition: this shape is not caught by pattern redaction"
        );

        // Fix: value-scrub removes it from the published form.
        let pc = ProbeCommand::from_exact_redacting_secret(full, secret);
        assert!(
            !pc.effective_command.contains("ab12cd"),
            "exotic-shape secret leaked into effective_command: {}",
            pc.effective_command
        );
        assert!(pc.effective_command.contains("<REDACTED>"));
        // Exact form retained (but never serialized).
        assert!(pc.command.contains("ab12cd"));
    }

    #[test]
    fn run_output_scrubs_reflected_identity_secret_from_output() {
        // #317 agent-output boundary (ngdevo 2026-08-14 MEDIUM): a target that
        // reflects the injected auth header — verbose echo, error page, `curl -v`
        // on stderr — lands the raw credential in stdout/stderr → `data` → the
        // agent. The read-side sanitizer is regex-only, so an exotic shape slips
        // through. Because the injected secret is KNOWN, the tool scrubs it by
        // value before building `data`. Use `X-Api-Id: ab12cd` — a shape no
        // redact() regex catches — so a green result proves the value-scrub, not
        // an incidental pattern hit, is doing the work.
        let secret = "X-Api-Id: ab12cd";
        let applied = Some(AppliedIdentity {
            label: "user_a".to_string(),
            secret: secret.to_string(),
        });
        let result = CommandResult {
            stdout: format!("target reflected header: {secret}\n"),
            stderr: format!("verbose: > {secret}\n"),
            exit_code: 0,
            timed_out: false,
            duration_ms: 1,
        };
        let full = format_full_command(
            "curl",
            &[
                "-H".to_string(),
                secret.to_string(),
                "https://x.test".to_string(),
            ],
        );

        // Precondition (Lens 1): pattern redaction alone misses this shape, so
        // without the value-scrub the secret WOULD reach the agent.
        assert!(
            pentest_core::provenance::redact(&result.stdout).contains("ab12cd"),
            "precondition: this shape is not caught by pattern redaction"
        );

        let (data, prov) = build_run_output(full, result, &applied);

        let stdout = data.get("stdout").and_then(Value::as_str).unwrap();
        let stderr = data.get("stderr").and_then(Value::as_str).unwrap();
        assert!(
            !stdout.contains("ab12cd"),
            "reflected secret leaked into data.stdout: {stdout}"
        );
        assert!(
            !stderr.contains("ab12cd"),
            "reflected secret leaked into data.stderr: {stderr}"
        );
        assert!(
            !prov.raw_response_excerpt.contains("ab12cd"),
            "reflected secret leaked into provenance excerpt: {}",
            prov.raw_response_excerpt
        );
        // The label still rides on the wire so the principal is attributable.
        assert!(prov.probe_commands[0]
            .description
            .as_deref()
            .is_some_and(|d| d.contains("user_a")));
    }

    #[test]
    fn run_output_leaves_non_identity_output_untouched() {
        // No identity applied → output passes through verbatim. Guards against
        // the scrub over-reaching on ordinary runs (it must not blank output).
        let result = CommandResult {
            stdout: "clean tool output\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
            duration_ms: 1,
        };
        let (data, _) = build_run_output("echo hi".to_string(), result, &None);
        assert_eq!(
            data.get("stdout").and_then(Value::as_str),
            Some("clean tool output\n")
        );
    }

    #[test]
    fn run_output_anonymous_identity_does_not_scrub_output() {
        // An anonymous identity carries an empty secret: nothing to scrub, and a
        // naive `replace("", …)` would corrupt every character boundary. Output
        // must pass through unchanged.
        let applied = Some(AppliedIdentity {
            label: "unauth".to_string(),
            secret: String::new(),
        });
        let result = CommandResult {
            stdout: "unauthenticated response body\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
            duration_ms: 1,
        };
        let (data, _) = build_run_output("curl https://x.test".to_string(), result, &applied);
        assert_eq!(
            data.get("stdout").and_then(Value::as_str),
            Some("unauthenticated response body\n")
        );
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
    async fn execute_non_string_identity_ref_fails_without_running() {
        // #317 review #2: a non-string identity_ref (the LLM can violate the
        // schema) must fail loud, NOT be silently dropped via `.as_str() ->
        // None` and then run unauthenticated while still reported as a probe.
        pentest_platform::set_use_sandbox(false);
        let tool = ExecuteCommandTool;
        let ctx = ctx_with("user_a", "Cookie: sid=abc");
        let params = json!({
            "command": "curl",
            "args": ["https://x.test"],
            "identity_ref": 123,
        });
        let result = tool.execute(params, &ctx).await.expect("execute ok");
        assert_eq!(result.outcome, ToolOutcome::Failed);
        assert!(!result.success);
        let err = result.error.unwrap_or_default();
        assert!(
            err.contains("identity_ref must be a string") && err.contains("number"),
            "message must reject the shape and name it: {err}"
        );
    }

    #[tokio::test]
    async fn execute_null_identity_ref_runs_as_is() {
        // An explicit JSON null means "no identity" - same as omitted. It must
        // NOT be treated as a malformed ref (that would block legitimate
        // no-identity runs).
        pentest_platform::set_use_sandbox(false);
        let tool = ExecuteCommandTool;
        let ctx = ToolContext::default();
        let params = json!({
            "command": "curl",
            "args": ["--max-time", "1", "http://127.0.0.1:1/x"],
            "identity_ref": Value::Null,
        });
        // Runs (and fails on connection), but is NOT rejected as a malformed
        // identity_ref - the error, if any, is not the schema-rejection message.
        let result = tool.execute(params, &ctx).await.expect("execute ok");
        assert!(
            !result
                .error
                .unwrap_or_default()
                .contains("identity_ref must be a string"),
            "null identity_ref must be treated as no-identity, not malformed"
        );
    }

    #[tokio::test]
    async fn execute_with_identity_attributes_provenance_and_scrubs_secret() {
        // #317 review #6 (attribution) + #3 (value-scrub), end-to-end through
        // execute/1. curl against an unroutable host still RUNS (produces
        // provenance) but makes no real network call, so this is deterministic.
        // Guards the WIRING: the identity label must reach provenance.description
        // and the injected secret must never appear in effective_command.
        pentest_platform::set_use_sandbox(false);
        let tool = ExecuteCommandTool;
        let ctx = ToolContext::default().with_identities(IdentityStore::from_pairs([(
            "user_a",
            IdentityRole::User,
            SessionMaterial::new("X-Api-Id: ab12cd"),
        )]));
        let params = json!({
            "command": "curl",
            "args": ["--max-time", "1", "http://127.0.0.1:1/x"],
            "identity_ref": "user_a",
        });

        let result = tool.execute(params, &ctx).await.expect("execute ok");
        let prov = result.provenance.expect("command run produces provenance");
        let pc = &prov.probe_commands[0];

        // Attribution reached provenance (survives the wire; command does not).
        assert_eq!(
            pc.description.as_deref(),
            Some("authenticated as test identity: user_a")
        );
        // The exotic-shape secret is scrubbed from the published form by value.
        assert!(
            !pc.effective_command.contains("ab12cd"),
            "identity secret leaked into effective_command: {}",
            pc.effective_command
        );
    }

    #[tokio::test]
    async fn execute_identity_ref_unmapped_binary_fails() {
        // Known identity, but nmap has no header flag: fail loud, do not run
        // the scan with the identity silently dropped.
        pentest_platform::set_use_sandbox(false);
        let tool = ExecuteCommandTool;
        let ctx = ToolContext::default().with_identities(IdentityStore::from_pairs([(
            "user_a",
            IdentityRole::User,
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

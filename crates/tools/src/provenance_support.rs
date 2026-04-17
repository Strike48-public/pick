//! Shared provenance helpers for external-tool wrappers.
//!
//! Every external pentest tool (nmap, nuclei, whatweb, ...) needs to:
//!   1. Report its real binary name and runtime version.
//!   2. Record the exact command it just ran.
//!   3. Produce a `ProbeCommand` with a redacted `effective_command`.
//!
//! Tool authors cannot reliably write this by hand — version probes fork a
//! child process and secrets leak via flags. This module centralizes the
//! logic behind a single call site per tool.
//!
//! Versions are cached per-binary with a global `OnceLock<Mutex<HashMap>>`
//! so we probe each tool exactly once per process lifetime.

use pentest_core::provenance::{truncate_excerpt, ProbeCommand, Provenance};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Per-process cache of `{binary -> detected version string}`. Populated on
/// first access via `tool_version()`.
static VERSION_CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn version_cache() -> &'static Mutex<HashMap<String, String>> {
    VERSION_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Detect the runtime version of an external tool, caching the result per
/// binary for the life of the process.
///
/// Returns `"unknown"` if no `--version`/`-V`/`-v` invocation produces output,
/// but never blocks or errors — version detection is a nice-to-have, not a
/// hard requirement for scan correctness.
pub fn tool_version(binary: &str) -> String {
    {
        let guard = version_cache().lock().expect("version cache poisoned");
        if let Some(v) = guard.get(binary) {
            return v.clone();
        }
    }

    let detected = detect_version_once(binary);

    let mut guard = version_cache().lock().expect("version cache poisoned");
    guard.entry(binary.to_string()).or_insert(detected).clone()
}

fn detect_version_once(binary: &str) -> String {
    for flag in ["--version", "-V", "-v"] {
        let Ok(out) = std::process::Command::new(binary).arg(flag).output() else {
            continue;
        };
        if let Some(line) = first_nonempty_line(&out.stdout) {
            return line;
        }
        if let Some(line) = first_nonempty_line(&out.stderr) {
            return line;
        }
    }
    "unknown".to_string()
}

fn first_nonempty_line(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

/// Join `command` and its arguments into a single shell-like string. Args
/// containing whitespace are double-quoted; internal double quotes are
/// backslash-escaped.
pub fn format_full_command<S: AsRef<str>>(command: &str, args: &[S]) -> String {
    let mut out = String::with_capacity(command.len());
    out.push_str(command);
    for arg in args {
        out.push(' ');
        push_shell_arg(&mut out, arg.as_ref());
    }
    out
}

fn push_shell_arg(out: &mut String, arg: &str) {
    if arg.chars().any(char::is_whitespace) {
        out.push('"');
        out.push_str(&arg.replace('"', "\\\""));
        out.push('"');
    } else {
        out.push_str(arg);
    }
}

/// Convenience: build a single-step `Provenance` for a command the wrapper
/// just ran.  `description` is a one-line purpose (what the probe was
/// trying to learn) included on the `ProbeCommand`.
pub fn single_step_provenance<S: AsRef<str>>(
    binary: &str,
    command: &str,
    args: &[S],
    description: impl Into<String>,
    raw_response: &str,
) -> Provenance {
    let full = format_full_command(command, args);
    let probe = ProbeCommand::from_exact(full).with_description(description);
    Provenance::new(
        binary,
        tool_version(binary),
        probe,
        truncate_excerpt(raw_response),
    )
}

/// Convenience: build a `Provenance` directly from a pre-formatted command
/// string (useful when the tool does its own interpolation).
pub fn provenance_from_command(
    binary: &str,
    full_command: impl Into<String>,
    description: impl Into<String>,
    raw_response: &str,
) -> Provenance {
    let probe = ProbeCommand::from_exact(full_command).with_description(description);
    Provenance::new(
        binary,
        tool_version(binary),
        probe,
        truncate_excerpt(raw_response),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_full_command_quotes_whitespace_args_refs() {
        // &[&str] path — matches wrappers that pass args into execute_command.
        let args: &[&str] = &["-H", "User-Agent: x y", "https://example.test"];
        let out = format_full_command("curl", args);
        assert_eq!(out, r#"curl -H "User-Agent: x y" https://example.test"#);
    }

    #[test]
    fn format_full_command_handles_owned_strings() {
        // &[String] path — matches CommandBuilder output.
        let args: Vec<String> = vec!["-sV".into(), "192.168.1.1".into()];
        let out = format_full_command("nmap", &args);
        assert_eq!(out, "nmap -sV 192.168.1.1");
    }

    #[test]
    fn tool_version_caches_per_binary() {
        // First call may probe, second must hit the cache. We can't control
        // whether the binary exists on the test host, but both calls must
        // return the same value.
        let a = tool_version("uname");
        let b = tool_version("uname");
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn tool_version_falls_back_to_unknown_for_missing_binary() {
        let v = tool_version("definitely-not-a-real-binary-xyz-9999");
        assert_eq!(v, "unknown");
    }

    #[test]
    fn single_step_provenance_populates_fields() {
        let prov = single_step_provenance(
            "nmap",
            "nmap",
            &["-sV".to_string(), "192.168.1.1".to_string()],
            "service version probe",
            "Nmap scan report for 192.168.1.1",
        );
        assert_eq!(prov.underlying_tool, "nmap");
        assert_eq!(prov.probe_commands.len(), 1);
        assert_eq!(prov.probe_commands[0].command, "nmap -sV 192.168.1.1");
        assert_eq!(
            prov.probe_commands[0].description.as_deref(),
            Some("service version probe")
        );
        assert!(prov
            .raw_response_excerpt
            .contains("Nmap scan report for 192.168.1.1"));
    }

    #[test]
    fn single_step_provenance_redacts_secrets() {
        let prov = single_step_provenance(
            "curl",
            "curl",
            &[
                "-u".to_string(),
                "admin:hunter2".to_string(),
                "https://x.example".to_string(),
            ],
            "basic auth probe",
            "200 OK",
        );
        let eff = &prov.probe_commands[0].effective_command;
        assert!(!eff.contains("hunter2"), "secret leaked: {eff}");
        // The exact command is retained for internal traceability.
        assert!(prov.probe_commands[0].command.contains("hunter2"));
    }
}

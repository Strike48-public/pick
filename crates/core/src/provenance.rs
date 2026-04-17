//! Tool provenance for reproducible pentest findings.
//!
//! Every finding emitted to the Report Agent must carry `Provenance` so a
//! senior red teamer can reproduce it from the report alone. See GitHub
//! issue #52 for the contract this module fulfills.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Maximum bytes of `raw_response_excerpt` retained on a `Provenance`.
/// Oversized responses are truncated with a trailing marker.
pub const RAW_RESPONSE_MAX_BYTES: usize = 2048;

const TRUNCATION_MARKER: &str = "\n…[truncated]";

/// A single probe step with both an exact and a report-safe command form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeCommand {
    /// Exact command as executed. May contain secrets; internal use only.
    pub command: String,

    /// Redacted form safe to publish in reports.
    pub effective_command: String,

    /// Optional one-line purpose of this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ProbeCommand {
    /// Build a `ProbeCommand` from an exact command, deriving
    /// `effective_command` via [`redact`].
    pub fn from_exact(command: impl Into<String>) -> Self {
        let command = command.into();
        let effective_command = redact(&command);
        Self {
            command,
            effective_command,
            description: None,
        }
    }

    /// Attach a one-line purpose description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// Reproducibility metadata for a tool invocation that produces a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Real tool name — `nuclei`, `nmap`, `custom-s48-<detector>`.
    /// Never a wrapper agent name like `autopwn_webapp`.
    pub underlying_tool: String,

    /// Runtime-detected tool version.
    pub tool_version: String,

    /// Ordered probe steps that produced this result.
    pub probe_commands: Vec<ProbeCommand>,

    /// First `RAW_RESPONSE_MAX_BYTES` of target response, with truncation
    /// marker if it was cut.
    pub raw_response_excerpt: String,

    /// When the probe completed.
    pub timestamp: DateTime<Utc>,
}

impl Provenance {
    /// Build a `Provenance` with a single probe command and auto-truncated
    /// raw response.
    pub fn new(
        underlying_tool: impl Into<String>,
        tool_version: impl Into<String>,
        probe: ProbeCommand,
        raw_response: impl AsRef<str>,
    ) -> Self {
        Self {
            underlying_tool: underlying_tool.into(),
            tool_version: tool_version.into(),
            probe_commands: vec![probe],
            raw_response_excerpt: truncate_excerpt(raw_response.as_ref()),
            timestamp: Utc::now(),
        }
    }

    /// Build a `Provenance` with multiple probe steps.
    pub fn multi_step(
        underlying_tool: impl Into<String>,
        tool_version: impl Into<String>,
        probes: Vec<ProbeCommand>,
        raw_response: impl AsRef<str>,
    ) -> Self {
        Self {
            underlying_tool: underlying_tool.into(),
            tool_version: tool_version.into(),
            probe_commands: probes,
            raw_response_excerpt: truncate_excerpt(raw_response.as_ref()),
            timestamp: Utc::now(),
        }
    }
}

/// Truncate a raw response to `RAW_RESPONSE_MAX_BYTES`, appending a marker
/// if anything was cut. Preserves UTF-8 boundaries.
pub fn truncate_excerpt(raw: &str) -> String {
    if raw.len() <= RAW_RESPONSE_MAX_BYTES {
        return raw.to_string();
    }
    // Walk back from RAW_RESPONSE_MAX_BYTES to a valid char boundary.
    let mut end = RAW_RESPONSE_MAX_BYTES;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + TRUNCATION_MARKER.len());
    out.push_str(&raw[..end]);
    out.push_str(TRUNCATION_MARKER);
    out
}

// Secret-scrubbing regex set. Built once per process via `OnceLock`.
struct RedactRegexes {
    auth_header: Regex,
    bearer: Regex,
    basic_auth_flag: Regex,
    url_userinfo: Regex,
    password_flag: Regex,
    cookie_header: Regex,
    set_cookie: Regex,
    long_hex: Regex,
    long_b64: Regex,
    env_secret: Regex,
}

static REDACT_RE: OnceLock<RedactRegexes> = OnceLock::new();

fn redact_regexes() -> &'static RedactRegexes {
    REDACT_RE.get_or_init(|| RedactRegexes {
        auth_header: Regex::new(r"(?i)(authorization:\s*)(bearer|basic|token)\s+[^\s'\x22]+")
            .expect("valid auth header regex"),
        bearer: Regex::new(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+").expect("valid bearer regex"),
        basic_auth_flag: Regex::new(r"(-u\s+)[^\s]+:[^\s]+")
            .expect("valid basic auth flag regex"),
        url_userinfo: Regex::new(r"(https?://)([^/\s:@]+:[^/\s:@]+)@")
            .expect("valid url userinfo regex"),
        password_flag: Regex::new(
            r"(?i)(--password[=\s]+|--token[=\s]+|--api[_-]?key[=\s]+)[^\s]+",
        )
        .expect("valid password flag regex"),
        cookie_header: Regex::new(r"(?i)(cookie:\s*)[^\r\n]+").expect("valid cookie regex"),
        set_cookie: Regex::new(r"(?i)(set-cookie:\s*)[^\r\n]+").expect("valid set-cookie regex"),
        long_hex: Regex::new(r"\b[0-9a-fA-F]{32,}\b").expect("valid long hex regex"),
        long_b64: Regex::new(r"\b[A-Za-z0-9+/]{40,}={0,2}\b").expect("valid long base64 regex"),
        env_secret: Regex::new(
            r"(?i)((?:api[_-]?key|secret|token|password|passwd|pwd)\s*[=:]\s*)['\x22]?[^\s'\x22]+['\x22]?",
        )
        .expect("valid env secret regex"),
    })
}

const REDACTION: &str = "<REDACTED>";

/// Scrub likely secrets from an exact command so it is safe to publish.
///
/// This runs at emit time so tool authors can't forget. It errs on the side
/// of over-redaction — a redacted command may not be directly runnable, but
/// a senior reviewer can still tell what structure was executed.
pub fn redact(input: &str) -> String {
    let re = redact_regexes();
    let s = input.to_string();
    let s = re
        .auth_header
        .replace_all(&s, format!("${{1}}${{2}} {REDACTION}").as_str());
    let s = re
        .bearer
        .replace_all(&s, format!("Bearer {REDACTION}").as_str());
    let s = re
        .basic_auth_flag
        .replace_all(&s, format!("${{1}}{REDACTION}").as_str());
    let s = re
        .url_userinfo
        .replace_all(&s, format!("${{1}}{REDACTION}@").as_str());
    let s = re
        .password_flag
        .replace_all(&s, format!("${{1}}{REDACTION}").as_str());
    let s = re
        .cookie_header
        .replace_all(&s, format!("${{1}}{REDACTION}").as_str());
    let s = re
        .set_cookie
        .replace_all(&s, format!("${{1}}{REDACTION}").as_str());
    let s = re
        .env_secret
        .replace_all(&s, format!("${{1}}{REDACTION}").as_str());
    let s = re.long_hex.replace_all(&s, REDACTION);
    let s = re.long_b64.replace_all(&s, REDACTION);
    s.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_strips_authorization_bearer_header() {
        let cmd =
            r#"curl -H "Authorization: Bearer abc.def.ghi_SECRET_xyz" https://api.example.com"#;
        let out = redact(cmd);
        assert!(out.contains(REDACTION));
        assert!(!out.contains("SECRET_xyz"));
    }

    #[test]
    fn redact_strips_basic_auth_flag() {
        let cmd = "curl -u admin:hunter2 https://internal.example.com";
        let out = redact(cmd);
        assert!(!out.contains("hunter2"));
        assert!(out.contains(REDACTION));
    }

    #[test]
    fn redact_strips_url_userinfo() {
        let cmd = "git clone https://alice:s3cret@github.com/org/repo.git";
        let out = redact(cmd);
        assert!(!out.contains("s3cret"));
        assert!(!out.contains("alice:"));
    }

    #[test]
    fn redact_strips_long_hex_token() {
        let cmd = "curl -H 'X-API-Key: 0123456789abcdef0123456789abcdef0123456789abcdef' https://api.example.com";
        let out = redact(cmd);
        assert!(!out.contains("0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn redact_strips_password_flag() {
        let cmd = "nuclei --password supersecret123 -u https://target.example.com";
        let out = redact(cmd);
        assert!(!out.contains("supersecret123"));
    }

    #[test]
    fn redact_strips_cookie_header() {
        let cmd = r#"curl -H "Cookie: session=abc123; remember=deadbeef" https://app.example.com"#;
        let out = redact(cmd);
        assert!(!out.contains("abc123"));
        assert!(!out.contains("deadbeef"));
    }

    #[test]
    fn redact_strips_env_secret_assignment() {
        let cmd = "API_KEY=sk-live-xyz-1234567890 curl https://api.example.com";
        let out = redact(cmd);
        assert!(!out.contains("sk-live-xyz-1234567890"));
    }

    #[test]
    fn redact_preserves_non_secret_content() {
        let cmd = "nmap -sV -p 1-1024 192.168.1.1";
        let out = redact(cmd);
        assert_eq!(out, cmd);
    }

    #[test]
    fn truncate_excerpt_below_limit_is_identity() {
        let s = "hello world";
        assert_eq!(truncate_excerpt(s), s);
    }

    #[test]
    fn truncate_excerpt_over_limit_appends_marker() {
        let s = "a".repeat(RAW_RESPONSE_MAX_BYTES + 100);
        let out = truncate_excerpt(&s);
        assert!(out.ends_with(TRUNCATION_MARKER));
        assert!(out.len() < s.len() + TRUNCATION_MARKER.len() + 4);
    }

    #[test]
    fn truncate_excerpt_respects_utf8_boundaries() {
        // Construct a string whose nth byte lands mid-char.
        let prefix = "a".repeat(RAW_RESPONSE_MAX_BYTES - 1);
        let s = format!("{prefix}中文"); // multi-byte char crosses the limit
        let out = truncate_excerpt(&s);
        // Must not panic, must be valid UTF-8 (all Rust Strings are), and
        // must be truncated since input exceeded the limit.
        assert!(out.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn probe_command_from_exact_derives_effective_command() {
        let p = ProbeCommand::from_exact("curl -u admin:hunter2 https://x.example.com");
        assert_eq!(p.command, "curl -u admin:hunter2 https://x.example.com");
        assert!(!p.effective_command.contains("hunter2"));
    }

    #[test]
    fn provenance_new_roundtrips_through_serde() {
        let p = Provenance::new(
            "nmap",
            "7.95",
            ProbeCommand::from_exact("nmap -sV 192.168.1.1"),
            "Nmap scan report for 192.168.1.1",
        );
        let json = serde_json::to_string(&p).unwrap();
        let back: Provenance = serde_json::from_str(&json).unwrap();
        assert_eq!(back.underlying_tool, "nmap");
        assert_eq!(back.tool_version, "7.95");
        assert_eq!(back.probe_commands.len(), 1);
    }
}

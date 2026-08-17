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
    /// Exact command as executed. May contain secrets (e.g. an injected
    /// `Authorization: Bearer <token>` from a differential-authz identity run,
    /// or `curl -u user:pass`), so it is **never serialized** — `skip_serializing`
    /// keeps it off every wire/agent/report boundary by construction, not by
    /// best-effort scrubbing. `effective_command` is the redacted form that does
    /// cross the boundary. `default` lets a value deserialized from the wire
    /// (where the field is now absent) round-trip to an empty string rather than
    /// failing. Back-compat: evidence files persisted *before* this field became
    /// `skip_serializing` still carry a `command` key and deserialize cleanly
    /// (serde reads it, and only downstream `effective_command` is consumed), so
    /// no schema-version bump or migration is required. See pick#162 / #317 review.
    #[serde(skip_serializing, default)]
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

    /// Build a `ProbeCommand` when a specific secret value is *known* to be
    /// present in the command (e.g. an injected differential-authz identity
    /// header). The known secret is scrubbed by exact substring BEFORE the
    /// pattern-based [`redact`] runs, so `effective_command` is safe regardless
    /// of the secret's shape — closing the gap where a short, non-hex, oddly
    /// named header value (`-H "X-Api-Id: ab12cd"`) would slip past every regex
    /// and land verbatim in a customer-facing report (#317 review, Lens 10b:
    /// security-by-construction over best-effort scrubbing). `command` (the
    /// exact form) is retained in the struct but is never serialized.
    pub fn from_exact_redacting_secret(command: impl Into<String>, secret: &str) -> Self {
        let command = command.into();

        // Exact-substring scrub of the known secret first; then the regex pass
        // catches anything else (user-supplied creds in the same command line).
        let effective_command = redact(&redact_known_secret(&command, secret));

        // Canary: the by-value scrub silently no-ops if the secret does not
        // appear verbatim in `command` (e.g. the caller escaped an embedded `"`
        // while quoting the arg), leaving only the best-effort regex pass to
        // catch it. Trip loudly in debug/test builds so a future divergence
        // surfaces here instead of leaking to a report (#317 review, LOW).
        debug_assert!(
            secret.is_empty() || !effective_command.contains(secret),
            "known-secret value scrub degraded to pattern-only: the injected \
             secret survived verbatim into effective_command"
        );

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
/// if anything was cut. Preserves UTF-8 boundaries. Redacts secrets before
/// storing.
pub fn truncate_excerpt(raw: &str) -> String {
    // Redact secrets first
    let redacted = redact(raw);

    if redacted.len() <= RAW_RESPONSE_MAX_BYTES {
        return redacted;
    }
    // Walk back from RAW_RESPONSE_MAX_BYTES to a valid char boundary.
    let mut end = RAW_RESPONSE_MAX_BYTES;
    while end > 0 && !redacted.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + TRUNCATION_MARKER.len());
    out.push_str(&redacted[..end]);
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

/// Scrub a *known* secret value from `text` by exact substring, replacing it
/// with the same [`REDACTION`] marker [`redact`] uses. An empty `secret` is a
/// no-op.
///
/// This is the by-value counterpart to [`redact`]'s pattern matching: use it
/// wherever the exact injected credential is known — differential-authz
/// identity runs (#317) — so an odd-shaped header value that no regex catches
/// (`X-Api-Id: ab12cd`) is still removed before the text crosses a boundary.
/// Unlike a command line, raw process output (`stdout`/`stderr`) is unescaped,
/// so an exact match here is complete, not best-effort.
pub fn redact_known_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        text.to_string()
    } else {
        text.replace(secret, REDACTION)
    }
}

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
        // Use a string that won't match any redaction patterns
        let s = format!("HTTP Response: {}", "x ".repeat(RAW_RESPONSE_MAX_BYTES));
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
    fn truncate_excerpt_redacts_bearer_token() {
        let response = "HTTP/1.1 200 OK\nAuthorization: Bearer sk-abc123def456ghi789\nContent-Type: application/json";
        let out = truncate_excerpt(response);
        assert!(!out.contains("sk-abc123def456ghi789"));
        assert!(out.contains(REDACTION));
    }

    #[test]
    fn truncate_excerpt_redacts_basic_auth() {
        let response = "Request: curl -u admin:hunter2 https://api.example.com\nStatus: 200";
        let out = truncate_excerpt(response);
        assert!(!out.contains("hunter2"));
        assert!(out.contains(REDACTION));
    }

    #[test]
    fn truncate_excerpt_redacts_cookie_header() {
        let response =
            "GET /api HTTP/1.1\nCookie: session=abc123; remember=deadbeef\nHost: api.example.com";
        let out = truncate_excerpt(response);
        assert!(!out.contains("abc123"));
        assert!(!out.contains("deadbeef"));
        assert!(out.contains(REDACTION));
    }

    #[test]
    fn truncate_excerpt_redacts_long_hex_tokens() {
        let response = "API Key: 0123456789abcdef0123456789abcdef0123456789abcdef";
        let out = truncate_excerpt(response);
        assert!(!out.contains("0123456789abcdef0123456789abcdef"));
        assert!(out.contains(REDACTION));
    }

    #[test]
    fn truncate_excerpt_redacts_env_secrets() {
        let response = "Environment: API_KEY=sk-live-xyz-1234567890\nStatus: starting";
        let out = truncate_excerpt(response);
        assert!(!out.contains("sk-live-xyz-1234567890"));
        assert!(out.contains(REDACTION));
    }

    #[test]
    fn truncate_excerpt_preserves_non_secret_content() {
        let response = "Nmap scan report for 192.168.1.1\nPort 443/tcp open https";
        let out = truncate_excerpt(response);
        assert_eq!(out, response); // No secrets, should be unchanged
    }

    #[test]
    fn probe_command_from_exact_derives_effective_command() {
        let p = ProbeCommand::from_exact("curl -u admin:hunter2 https://x.example.com");
        assert_eq!(p.command, "curl -u admin:hunter2 https://x.example.com");
        assert!(!p.effective_command.contains("hunter2"));
    }

    #[test]
    fn probe_command_raw_command_never_serializes() {
        // #317 review CRITICAL: the raw `command` can carry an injected
        // credential (e.g. `-H "Authorization: Bearer <token>"` from a
        // differential-authz identity run). It must never cross the wire; only
        // the redacted `effective_command` may. Guards the leak by construction
        // — removing `#[serde(skip_serializing)]` on `command` turns this red.
        let secret = "Bearer sk-super-secret-token-abcdef1234567890";
        let raw = format!(r#"curl -H "Authorization: {secret}" https://target.example"#);
        let p = ProbeCommand::from_exact(&raw);

        // In memory the exact command is retained for local traceability.
        assert!(p.command.contains(secret), "in-memory command retained");

        // On the wire it must be gone: no `command` key, and the secret must not
        // appear anywhere in the serialized form (effective_command is redacted).
        let wire = serde_json::to_value(&p).expect("serialize");
        assert!(
            wire.get("command").is_none(),
            "raw command must not serialize: {wire}"
        );
        let wire_str = serde_json::to_string(&p).expect("serialize");
        assert!(
            !wire_str.contains("sk-super-secret-token-abcdef1234567890"),
            "secret leaked onto the wire: {wire_str}"
        );
    }

    #[test]
    fn probe_command_deserializes_legacy_wire_with_command_present() {
        // #317 H2 back-compat: `command` gained `#[serde(skip_serializing,
        // default)]`, so evidence files persisted BEFORE this change still carry
        // a `command` key. They must deserialize cleanly (serde consumes the key
        // via the field, applying `default` only when absent) — never error on a
        // replayed old-format file. The redacted `effective_command` is what
        // downstream reads, and it survives regardless.
        let legacy = r#"{
            "command": "curl -H \"Authorization: Bearer old-secret\" https://x.example",
            "effective_command": "curl -H \"Authorization: <REDACTED>\" https://x.example"
        }"#;
        let back: ProbeCommand = serde_json::from_str(legacy).expect("legacy wire deserializes");
        assert_eq!(
            back.effective_command,
            r#"curl -H "Authorization: <REDACTED>" https://x.example"#
        );
        // A new-format file (no `command` key) also deserializes, defaulting to "".
        let current = r#"{"effective_command":"nmap -sV 10.0.0.1"}"#;
        let back2: ProbeCommand = serde_json::from_str(current).expect("current wire deserializes");
        assert_eq!(back2.command, "");
        assert_eq!(back2.effective_command, "nmap -sV 10.0.0.1");
    }

    #[test]
    fn from_exact_redacting_secret_scrubs_arbitrary_shape_by_value() {
        // #317 review #3: a known secret is scrubbed by exact substring BEFORE
        // pattern redaction, so it never lands in effective_command even when its
        // shape defeats every regex (short, non-hex, non-keyword header value).
        let secret = "X-Api-Id: ab12cd";
        let cmd = format!(r#"curl -H "{secret}" https://x.test"#);

        // Precondition: pattern redaction alone does not catch this shape.
        assert!(redact(&cmd).contains("ab12cd"));

        let pc = ProbeCommand::from_exact_redacting_secret(cmd, secret);
        assert!(
            !pc.effective_command.contains("ab12cd"),
            "known secret leaked: {}",
            pc.effective_command
        );
        assert!(pc.effective_command.contains(REDACTION));
        assert!(
            pc.command.contains("ab12cd"),
            "exact form retained in-memory"
        );
    }

    #[test]
    fn from_exact_redacting_empty_secret_falls_back_to_pattern_only() {
        // An anonymous identity injects no secret; the empty-secret path must not
        // blank the whole command (empty substring replace) — it just pattern-redacts.
        let pc = ProbeCommand::from_exact_redacting_secret("curl https://x.test", "");
        assert_eq!(pc.effective_command, "curl https://x.test");
    }

    #[test]
    fn redact_known_secret_scrubs_exact_value_and_no_ops_on_empty() {
        // The shared by-value scrub (used for both effective_command and, at the
        // tool layer, stdout/stderr). Removes the exact value regardless of shape;
        // an empty secret is a no-op (never a corrupting empty-substring replace).
        let secret = "X-Api-Id: ab12cd";
        let scrubbed = redact_known_secret(&format!("reflected: {secret} end"), secret);
        assert!(
            !scrubbed.contains("ab12cd"),
            "value not scrubbed: {scrubbed}"
        );
        assert!(scrubbed.contains(REDACTION));

        assert_eq!(
            redact_known_secret("nothing to hide", ""),
            "nothing to hide",
            "empty secret must be a no-op"
        );
    }

    #[test]
    fn identity_attribution_description_survives_the_wire() {
        // #317 review #6: the identity label reaches serialized provenance via the
        // description, so a reviewer can attribute the response to a principal even
        // though the raw command (which carried the injected header) is not serialized.
        let pc = ProbeCommand::from_exact_redacting_secret(
            r#"curl -H "Cookie: sid=secret" https://x.test"#,
            "Cookie: sid=secret",
        )
        .with_description("authenticated as test identity: user_a");
        let p = Provenance::new("shell", "test", pc, "");

        let wire = serde_json::to_string(&p).expect("serialize");
        assert!(wire.contains("authenticated as test identity: user_a"));
        assert!(
            !wire.contains("sid=secret"),
            "secret leaked on the wire: {wire}"
        );
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

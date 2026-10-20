//! Diagnostics bundle for support (pick#476).
//!
//! One redacted report a support engineer can ask for instead of walking a
//! customer through logs, settings and environment by hand: version, OS,
//! sandbox state, an allowlisted view of the connector config, log-sink
//! health and the tail of the newest log file. `pentest-agent diagnose` and
//! the desktop Settings "Copy diagnostics" action both build it here.
//!
//! Nothing secret is serialized and then scrubbed. The config section is built
//! from an allowlist of fields, environment variables are reported as set or
//! unset only, and log lines pass through exact known-secret replacement and
//! then [`redact`]. Log lines still carry engagement data (targets, tool
//! output), which is the point of sending them.

use crate::config::{AppSettings, ConnectorConfig};
use crate::provenance::{redact, redact_known_secret};
use serde::Serialize;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Log lines included in the bundle by default.
pub const DEFAULT_TAIL_LINES: usize = 200;

/// How much of the end of the log file is read to find the tail. Bounds the
/// read on a large file; lines are JSON records well under this size.
const TAIL_READ_BYTES: u64 = 256 * 1024;

/// Longest log line kept, in bytes. A tool that logs a huge payload must not
/// turn the bundle into megabytes.
const MAX_LINE_BYTES: usize = 4096;

/// Known secrets shorter than this are not replaced by value, so a token of
/// `1` cannot blank every digit in the tail. Pattern redaction still runs.
const MIN_KNOWN_SECRET_LEN: usize = 8;

/// Environment variables whose presence matters to support. Reported as set
/// or unset, never with their values.
pub const REPORTED_ENV_VARS: &[&str] = &[
    "STRIKE48_HOST",
    "STRIKE48_URL",
    "STRIKE48_API_URL",
    "STRIKE48_TOKEN",
    "STRIKE48_REGISTRATION_TOKEN",
    "STRIKE48_TLS",
    "STRIKEHUB_SOCKET",
    "MATRIX_AUTH_TOKEN",
    "DISABLE_SANDBOX",
    "PENTEST_ALLOW_PRIVATE_IPS",
    "RUST_LOG",
];

/// Environment variables that hold secrets. Their live values are replaced
/// by exact match in the log tail before pattern redaction runs.
const SECRET_ENV_VARS: &[&str] = &[
    "STRIKE48_TOKEN",
    "STRIKE48_REGISTRATION_TOKEN",
    "MATRIX_AUTH_TOKEN",
    "AUTH_TOKEN",
    "KEYCLOAK_PASSWORD",
    "OPENAI_API_KEY",
];

/// Sandbox state, gathered by the platform crate (core cannot depend on it).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SandboxFacts {
    /// Whether commands run sandboxed (`is_sandbox_enabled`).
    pub enabled: bool,
    /// Whether `DISABLE_SANDBOX` forced the sandbox off for this process.
    pub disabled_by_env: bool,
    /// Active backend, or `None` when the sandbox has not initialized yet.
    pub backend: Option<String>,
    /// Contents of the rootfs `.rootfs_version` marker, if present.
    pub rootfs_version: Option<String>,
}

/// Host facts the platform crate supplies.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PlatformFacts {
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub sandbox: SandboxFacts,
}

/// The saved connector config, reduced to fields that are safe to share.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiagnosticConfig {
    /// Host with any URL userinfo redacted.
    pub host: String,
    pub tenant_id: String,
    pub instance_id: String,
    pub connector_name: String,
    pub use_tls: bool,
    pub reconnect_enabled: bool,
    pub aggression_level: String,
    /// Whether a token (JWT or OTT) is saved. The token itself never appears.
    pub auth_token_set: bool,
    /// Whether SDK credentials for this instance exist under `~/.strike48`.
    pub credentials_present: bool,
}

impl DiagnosticConfig {
    pub fn from_config(config: &ConnectorConfig) -> Self {
        Self {
            host: redact(&config.host),
            tenant_id: config.tenant_id.clone(),
            instance_id: config.instance_id.clone(),
            connector_name: config.connector_name.clone(),
            use_tls: config.use_tls,
            reconnect_enabled: config.reconnect_enabled,
            aggression_level: config.aggression_level.display_name().to_string(),
            auth_token_set: config.has_auth(),
            credentials_present: ConnectorConfig::credentials_present(&config.instance_id),
        }
    }
}

/// Non-secret app settings that change behavior.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SettingsFacts {
    pub shell_mode: String,
    pub auto_connect: bool,
    pub telemetry_enabled: bool,
    pub easy_mode: Option<bool>,
}

impl SettingsFacts {
    pub fn from_settings(settings: &AppSettings) -> Self {
        Self {
            shell_mode: format!("{:?}", settings.shell_mode),
            auto_connect: settings.auto_connect,
            telemetry_enabled: settings.telemetry_enabled,
            easy_mode: settings.easy_mode,
        }
    }
}

/// Log location, sink health and the redacted tail of the newest file.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LogFacts {
    pub dir: PathBuf,
    pub newest_file: Option<PathBuf>,
    pub file_sink_failed: bool,
    pub tail: Vec<String>,
}

/// The full report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiagnosticsBundle {
    pub generated_at: String,
    pub version: String,
    pub os: String,
    pub arch: String,
    pub platform: PlatformFacts,
    pub config: Option<DiagnosticConfig>,
    pub settings: Option<SettingsFacts>,
    /// `(name, set)` for each of [`REPORTED_ENV_VARS`].
    pub env: Vec<(String, bool)>,
    pub logs: LogFacts,
}

/// Everything [`collect`] needs that comes from outside core.
pub struct CollectInput {
    pub platform: PlatformFacts,
    pub settings: Option<AppSettings>,
    pub log_dir: PathBuf,
    pub tail_lines: usize,
}

/// Build the bundle from the current process environment.
pub fn collect(input: CollectInput) -> DiagnosticsBundle {
    let env = |name: &str| std::env::var(name).ok();
    let secrets = known_secrets(input.settings.as_ref(), env);
    let newest_file = crate::logging::newest_log_file(&input.log_dir);
    let tail = newest_file
        .as_deref()
        .map(|path| read_redacted_tail(path, input.tail_lines, &secrets))
        .unwrap_or_default();
    let config = input.settings.as_ref().and_then(|s| s.last_config.as_ref());
    DiagnosticsBundle {
        generated_at: chrono::Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        platform: input.platform,
        config: config.map(DiagnosticConfig::from_config),
        settings: input.settings.as_ref().map(SettingsFacts::from_settings),
        env: env_presence(env),
        logs: LogFacts {
            dir: input.log_dir,
            newest_file,
            file_sink_failed: crate::logging::file_sink_failed(),
            tail,
        },
    }
}

/// `(name, set)` for each reported environment variable. A variable set to an
/// empty string counts as unset.
pub fn env_presence(env: impl Fn(&str) -> Option<String>) -> Vec<(String, bool)> {
    REPORTED_ENV_VARS
        .iter()
        .map(|name| {
            let set = env(name).is_some_and(|v| !v.is_empty());
            ((*name).to_string(), set)
        })
        .collect()
}

/// Secret values to replace by exact match: the saved token plus the live
/// values of the secret environment variables.
pub fn known_secrets(
    settings: Option<&AppSettings>,
    env: impl Fn(&str) -> Option<String>,
) -> Vec<String> {
    let saved = settings
        .and_then(|s| s.last_config.as_ref())
        .map(|c| c.auth_token.clone());
    saved
        .into_iter()
        .chain(SECRET_ENV_VARS.iter().filter_map(|name| env(name)))
        .filter(|s| s.len() >= MIN_KNOWN_SECRET_LEN)
        .collect()
}

/// The last `max_lines` lines of `path`, each redacted and length-capped. An
/// unreadable file yields one line saying so, so the bundle still explains
/// why the tail is missing.
pub fn read_redacted_tail(path: &Path, max_lines: usize, secrets: &[String]) -> Vec<String> {
    match read_tail_lines(path, max_lines) {
        Ok(lines) => lines
            .iter()
            .map(|line| redact_line(line, secrets))
            .collect(),
        Err(e) => vec![format!("<could not read {}: {e}>", path.display())],
    }
}

fn read_tail_lines(path: &Path, max_lines: usize) -> std::io::Result<Vec<String>> {
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(TAIL_READ_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(TAIL_READ_BYTES).read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<&str> = text.lines().collect();
    // A read that starts mid-file starts mid-line; drop the fragment so a
    // secret cut in half there is not half-logged.
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    let skip = lines.len().saturating_sub(max_lines);
    Ok(lines[skip..].iter().map(|l| (*l).to_string()).collect())
}

fn redact_line(line: &str, secrets: &[String]) -> String {
    let by_value = secrets
        .iter()
        .fold(line.to_string(), |acc, s| redact_known_secret(&acc, s));
    cap_bytes(redact(&by_value), MAX_LINE_BYTES)
}

/// Cut `s` to at most `max` bytes on a char boundary, marking the cut.
fn cap_bytes(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} ...<truncated>", &s[..end])
}

/// Read `settings.json` without the rewrites `load_settings` performs.
pub fn read_settings_readonly() -> Option<AppSettings> {
    let contents = std::fs::read_to_string(crate::settings::settings_path()).ok()?;
    serde_json::from_str(&contents).ok()
}

impl DiagnosticsBundle {
    /// Pretty JSON, for tooling that parses the bundle.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|e| format!("{{\"error\":\"could not serialize diagnostics: {e}\"}}"))
    }

    /// Plain-text rendering for pasting into a ticket.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        self.write_header(&mut out);
        self.write_platform(&mut out);
        self.write_config(&mut out);
        self.write_env(&mut out);
        self.write_logs(&mut out);
        out
    }

    fn write_header(&self, out: &mut String) {
        out.push_str("== Pick diagnostics ==\n");
        push_kv(out, "generated", &self.generated_at);
        push_kv(out, "version", &self.version);
        push_kv(out, "os/arch", &format!("{}/{}", self.os, self.arch));
    }

    fn write_platform(&self, out: &mut String) {
        let p = &self.platform;
        push_kv(out, "os name", opt(&p.os_name));
        push_kv(out, "os version", opt(&p.os_version));
        push_kv(out, "kernel", opt(&p.kernel_version));
        out.push_str("\n== Sandbox ==\n");
        push_kv(out, "enabled", &p.sandbox.enabled.to_string());
        push_kv(
            out,
            "disabled by env",
            &p.sandbox.disabled_by_env.to_string(),
        );
        let backend = p.sandbox.backend.as_deref().unwrap_or("not initialized");
        push_kv(out, "backend", backend);
        push_kv(out, "rootfs version", opt(&p.sandbox.rootfs_version));
    }

    fn write_config(&self, out: &mut String) {
        out.push_str("\n== Connector config (saved) ==\n");
        match &self.config {
            Some(c) => {
                push_kv(out, "host", &c.host);
                push_kv(out, "tenant", &c.tenant_id);
                push_kv(out, "instance", &c.instance_id);
                push_kv(out, "connector name", &c.connector_name);
                push_kv(out, "tls", &c.use_tls.to_string());
                push_kv(out, "reconnect", &c.reconnect_enabled.to_string());
                push_kv(out, "aggression", &c.aggression_level);
                push_kv(out, "auth token set", &c.auth_token_set.to_string());
                push_kv(
                    out,
                    "credentials present",
                    &c.credentials_present.to_string(),
                );
            }
            None => out.push_str("none saved\n"),
        }
        if let Some(s) = &self.settings {
            push_kv(out, "shell mode", &s.shell_mode);
            push_kv(out, "auto connect", &s.auto_connect.to_string());
            push_kv(out, "telemetry", &s.telemetry_enabled.to_string());
            let easy = s.easy_mode.map_or("default".to_string(), |b| b.to_string());
            push_kv(out, "easy mode", &easy);
        }
    }

    fn write_env(&self, out: &mut String) {
        out.push_str("\n== Environment (set/unset only) ==\n");
        for (name, set) in &self.env {
            push_kv(out, name, if *set { "set" } else { "unset" });
        }
    }

    fn write_logs(&self, out: &mut String) {
        out.push_str("\n== Logs ==\n");
        push_kv(out, "dir", &self.logs.dir.display().to_string());
        let newest = self.logs.newest_file.as_ref();
        let newest = newest.map_or("none".to_string(), |p| p.display().to_string());
        push_kv(out, "newest file", &newest);
        push_kv(
            out,
            "file sink failed",
            &self.logs.file_sink_failed.to_string(),
        );
        out.push_str(&format!("tail ({} lines):\n", self.logs.tail.len()));
        for line in &self.logs.tail {
            out.push_str(line);
            out.push('\n');
        }
    }
}

fn push_kv(out: &mut String, key: &str, value: &str) {
    out.push_str(&format!("{key}: {value}\n"));
}

fn opt(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Write;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn settings_with_token(token: &str) -> AppSettings {
        let config = ConnectorConfig {
            host: "wss://alice:fake-pass-1@studio.example.com".to_string(),
            auth_token: token.to_string(),
            instance_id: "inst-diag-test".to_string(),
            ..ConnectorConfig::default()
        };
        AppSettings {
            last_config: Some(config),
            ..AppSettings::default()
        }
    }

    fn log_file_with(lines: &[String]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("connector.2026-10-20.log");
        let mut file = std::fs::File::create(&path).expect("create log");
        for line in lines {
            writeln!(file, "{line}").expect("write log");
        }
        (dir, path)
    }

    #[test]
    fn config_section_never_carries_the_token_or_userinfo() {
        let settings = settings_with_token("fake-saved-token-value");
        let config = DiagnosticConfig::from_config(settings.last_config.as_ref().unwrap());
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("fake-saved-token-value"), "{rendered}");
        assert!(!rendered.contains("fake-pass-1"), "{rendered}");
        assert!(config.auth_token_set);
        assert!(
            config.host.contains("studio.example.com"),
            "{}",
            config.host
        );
    }

    #[test]
    fn env_is_reported_as_presence_only() {
        let env = env_of(&[("STRIKE48_TOKEN", "fake-env-token-value"), ("RUST_LOG", "")]);
        let presence = env_presence(env);
        let get = |name: &str| presence.iter().find(|(n, _)| n == name).map(|(_, s)| *s);
        assert_eq!(get("STRIKE48_TOKEN"), Some(true));
        assert_eq!(get("RUST_LOG"), Some(false), "empty counts as unset");
        assert_eq!(get("DISABLE_SANDBOX"), Some(false));
        assert!(!format!("{presence:?}").contains("fake-env-token-value"));
    }

    #[test]
    fn known_secrets_include_saved_token_and_secret_env_but_not_short_values() {
        let settings = settings_with_token("fake-saved-token-value");
        let env = env_of(&[
            ("MATRIX_AUTH_TOKEN", "fake-matrix-token-value"),
            ("OPENAI_API_KEY", "short"),
            ("RUST_LOG", "debug-not-a-secret"),
        ]);
        let secrets = known_secrets(Some(&settings), env);
        assert!(secrets.contains(&"fake-saved-token-value".to_string()));
        assert!(secrets.contains(&"fake-matrix-token-value".to_string()));
        assert!(
            !secrets.contains(&"short".to_string()),
            "below the length floor"
        );
        assert!(!secrets.contains(&"debug-not-a-secret".to_string()));
    }

    #[test]
    fn tail_replaces_known_secrets_of_any_shape_and_pattern_redacts() {
        // `odd!shape` matches no pattern, so only by-value replacement can
        // remove it.
        let secrets = vec!["fake-odd!shape-secret".to_string()];
        let (_dir, path) = log_file_with(&[
            r#"{"message":"auth with fake-odd!shape-secret"}"#.to_string(),
            r#"{"message":"cfg {\"auth_token\":\"fake-escaped-token\"}"}"#.to_string(),
        ]);
        let tail = read_redacted_tail(&path, 10, &secrets).join("\n");
        assert!(!tail.contains("fake-odd!shape-secret"), "{tail}");
        assert!(!tail.contains("fake-escaped-token"), "{tail}");
        assert!(tail.contains("auth with"), "{tail}");
    }

    #[test]
    fn tail_keeps_only_the_last_lines() {
        let lines: Vec<String> = (0..50).map(|i| format!("line {i}")).collect();
        let (_dir, path) = log_file_with(&lines);
        let tail = read_redacted_tail(&path, 3, &[]);
        assert_eq!(tail, vec!["line 47", "line 48", "line 49"]);
    }

    #[test]
    fn tail_drops_the_partial_first_line_of_a_large_file() {
        // Size the file so the read window starts five bytes into the token:
        // the fragment is then `straddle-token` with no `Bearer` prefix, which
        // no pattern catches. Only dropping the fragment keeps it out.
        let prefix = "Authorization: Bearer ";
        let first = format!("{prefix}fake-straddle-token");
        let start = prefix.len() + 5;
        let second_len = TAIL_READ_BYTES as usize - 1 - (first.len() + 1 - start);
        let lines = vec![first, "z".repeat(second_len)];
        let (_dir, path) = log_file_with(&lines);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len() - TAIL_READ_BYTES,
            start as u64,
            "window must start inside the token"
        );
        let tail = read_redacted_tail(&path, 10, &[]).join("\n");
        let head: String = tail.chars().take(60).collect();
        assert!(!tail.contains("straddle-token"), "fragment kept: {head}");
    }

    #[test]
    fn tail_caps_long_lines() {
        let (_dir, path) = log_file_with(&["y ".repeat(MAX_LINE_BYTES)]);
        let tail = read_redacted_tail(&path, 1, &[]);
        assert!(tail[0].len() <= MAX_LINE_BYTES + 20, "{}", tail[0].len());
        assert!(tail[0].ends_with("...<truncated>"));
    }

    #[test]
    fn unreadable_log_yields_an_explanation_not_an_empty_tail() {
        let tail = read_redacted_tail(Path::new("/nonexistent/connector.log"), 10, &[]);
        assert_eq!(tail.len(), 1);
        assert!(tail[0].starts_with("<could not read"), "{}", tail[0]);
    }

    #[test]
    fn text_report_has_every_section_and_no_secrets() {
        let settings = settings_with_token("fake-saved-token-value");
        let (dir, _path) = log_file_with(&["{\"message\":\"hello\"}".to_string()]);
        let bundle = collect(CollectInput {
            platform: PlatformFacts::default(),
            settings: Some(settings),
            log_dir: dir.path().to_path_buf(),
            tail_lines: 10,
        });
        let text = bundle.to_text();
        for section in [
            "== Pick diagnostics ==",
            "== Sandbox ==",
            "== Connector config",
            "== Environment",
            "== Logs ==",
        ] {
            assert!(text.contains(section), "missing {section}:\n{text}");
        }
        assert!(text.contains("backend: not initialized"), "{text}");
        assert!(text.contains("hello"), "tail missing:\n{text}");
        assert!(!text.contains("fake-saved-token-value"), "{text}");
        assert!(!text.contains("fake-pass-1"), "{text}");
    }
}

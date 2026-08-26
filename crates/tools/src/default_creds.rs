//! Default credentials testing tool

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::provenance::{truncate_excerpt, ProbeCommand, Provenance};
use pentest_core::tools::{
    execute_timed_with_provenance, ParamType, PentestTool, Platform, ToolContext, ToolParam,
    ToolResult, ToolSchema,
};
use serde_json::{json, Value};
use tokio::time::Duration;

use crate::util::{param_str, param_u64};

/// Default credentials testing tool
pub struct DefaultCredsTool;

/// Copy the attempt log with every password masked.
///
/// The attempt log leaves this tool in two report-/wire-bound places: the
/// provenance `raw_response_excerpt`, and the returned `ToolResult.data`, which
/// the connector serializes whole onto the Matrix wire (`pick_connector.rs`
/// `ToolCompleted`). `truncate_excerpt`'s redaction pass does not catch
/// JSON-quoted `"password":"..."` pairs (its secret regex expects `password:`,
/// not `password":`), so a successful login would otherwise publish the
/// plaintext credential. Username and status are preserved so a reviewer still
/// sees the attempt structure (pick#52 / pick#317).
fn mask_attempts(attempts: &[Value]) -> Vec<Value> {
    attempts
        .iter()
        .map(|a| {
            let mut a = a.clone();
            if let Some(obj) = a.as_object_mut() {
                if obj.contains_key("password") {
                    obj.insert("password".to_string(), json!("<redacted>"));
                }
            }
            a
        })
        .collect()
}

/// Build one report-safe [`ProbeCommand`] per attempted credential.
///
/// The probe records the *structure* of each auth attempt so a reviewer can
/// reproduce it, but the password is scrubbed by exact value via
/// [`ProbeCommand::from_exact_redacting_secret`] before it can reach the
/// published `effective_command`. This matters most for the ssh
/// `sshpass -p '<pw>'` shape, which no `redact()` regex matches (only
/// `-u user:pass` / `--password` are caught) — see pick#52 / pick#317.
fn default_cred_probes(
    service: &str,
    credentials: &[(&str, &str)],
    host: &str,
    port: u16,
) -> Vec<ProbeCommand> {
    let template = match service.to_lowercase().as_str() {
        "ssh" => |u: &str, p: &str, h: &str, port: u16| {
            format!("sshpass -p '{p}' ssh -o StrictHostKeyChecking=no -p {port} {u}@{h} exit")
        },
        "ftp" => |u: &str, p: &str, h: &str, port: u16| {
            format!("curl --connect-timeout 5 -u {u}:{p} ftp://{h}:{port}/")
        },
        _ => |u: &str, p: &str, h: &str, port: u16| {
            format!("curl -s -o /dev/null -w '%{{http_code}}' -u {u}:{p} http://{h}:{port}/")
        },
    };

    credentials
        .iter()
        .map(|(u, p)| {
            let full = template(u, p, host, port);
            ProbeCommand::from_exact_redacting_secret(full, p)
                .with_description("default credential probe")
        })
        .collect()
}

impl DefaultCredsTool {
    /// Common default credentials database
    fn get_default_credentials(service: &str) -> Vec<(&'static str, &'static str)> {
        match service.to_lowercase().as_str() {
            "http" | "https" | "web" => vec![
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", ""),
                ("root", "root"),
                ("root", "password"),
                ("root", ""),
                ("administrator", "administrator"),
                ("administrator", "password"),
                ("user", "user"),
                ("guest", "guest"),
                ("admin", "1234"),
                ("admin", "12345"),
                ("admin", "123456"),
            ],
            "ssh" => vec![
                ("root", "root"),
                ("root", "password"),
                ("root", "toor"),
                ("admin", "admin"),
                ("admin", "password"),
                ("pi", "raspberry"), // Raspberry Pi default
                ("ubuntu", "ubuntu"),
                ("user", "user"),
            ],
            "ftp" => vec![
                ("anonymous", ""),
                ("anonymous", "anonymous"),
                ("ftp", "ftp"),
                ("admin", "admin"),
                ("root", "root"),
                ("user", "user"),
            ],
            "telnet" => vec![
                ("admin", "admin"),
                ("root", "root"),
                ("root", ""),
                ("admin", ""),
                ("user", "user"),
            ],
            "mysql" | "mariadb" => vec![
                ("root", ""),
                ("root", "root"),
                ("root", "password"),
                ("admin", "admin"),
                ("mysql", "mysql"),
            ],
            "postgresql" | "postgres" => vec![
                ("postgres", ""),
                ("postgres", "postgres"),
                ("postgres", "password"),
                ("admin", "admin"),
            ],
            "mongodb" | "mongo" => vec![
                ("admin", ""),
                ("admin", "admin"),
                ("root", ""),
                ("root", "root"),
            ],
            "smb" | "cifs" => vec![
                ("administrator", ""),
                ("administrator", "administrator"),
                ("admin", "admin"),
                ("guest", ""),
                ("guest", "guest"),
            ],
            _ => vec![
                ("admin", "admin"),
                ("root", "root"),
                ("user", "user"),
                ("guest", "guest"),
            ],
        }
    }

    /// Test HTTP Basic Authentication
    async fn test_http_auth(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        timeout_ms: u64,
    ) -> Result<bool> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .map_err(|e| Error::Network(format!("Failed to create HTTP client: {}", e)))?;

        let url = format!("http://{}:{}/", host, port);

        let response = client
            .get(&url)
            .basic_auth(username, Some(password))
            .send()
            .await
            .map_err(|e| Error::Network(format!("HTTP request failed: {}", e)))?;

        // Consider 200-299 as successful authentication
        Ok(response.status().is_success())
    }

    /// Test SSH authentication (requires execute_command)
    async fn test_ssh_auth(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        _timeout_ms: u64,
    ) -> Result<bool> {
        // Use sshpass if available
        let output = tokio::process::Command::new("sshpass")
            .args([
                "-p",
                password,
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=5",
                "-p",
                &port.to_string(),
                &format!("{}@{}", username, host),
                "exit",
            ])
            .output()
            .await;

        match output {
            Ok(result) => Ok(result.status.success()),
            Err(_) => {
                // sshpass not available or command failed
                Err(Error::ToolExecution(
                    "SSH testing requires 'sshpass' command".into(),
                ))
            }
        }
    }

    /// Test FTP authentication
    async fn test_ftp_auth(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        _timeout_ms: u64,
    ) -> Result<bool> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;

        let stream = TcpStream::connect(format!("{}:{}", host, port))
            .await
            .map_err(|e| Error::Network(format!("FTP connection failed: {}", e)))?;

        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        // Read welcome banner
        let mut line = String::new();
        let _ = reader.read_line(&mut line).await;

        // Send username
        write_half
            .write_all(format!("USER {}\r\n", username).as_bytes())
            .await
            .map_err(|e| Error::Network(format!("Failed to send USER: {}", e)))?;

        line.clear();
        let _ = reader.read_line(&mut line).await;

        // Send password
        write_half
            .write_all(format!("PASS {}\r\n", password).as_bytes())
            .await
            .map_err(|e| Error::Network(format!("Failed to send PASS: {}", e)))?;

        line.clear();
        let _ = reader.read_line(&mut line).await;

        // Check for success (230 = successful login)
        Ok(line.starts_with("230"))
    }
}

#[async_trait]
impl PentestTool for DefaultCredsTool {
    fn name(&self) -> &str {
        "default_creds_test"
    }

    fn description(&self) -> &str {
        "Test common default credentials against a service (HTTP, SSH, FTP, databases, etc.)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "host",
                ParamType::String,
                "Target host IP or hostname",
            ))
            .param(ToolParam::optional(
                "port",
                ParamType::Integer,
                "Target port number",
                json!(80),
            ))
            .param(ToolParam::optional(
                "service",
                ParamType::String,
                "Service type (http, ssh, ftp, mysql, postgresql, smb, etc.)",
                json!("http"),
            ))
            .param(ToolParam::optional(
                "timeout_ms",
                ParamType::Integer,
                "Connection timeout in milliseconds",
                json!(5000),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Android, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed_with_provenance(|| async {
            let host = param_str(&params, "host");
            if host.is_empty() {
                return Err(Error::InvalidParams("host parameter is required".into()));
            }

            let port = param_u64(&params, "port", 80) as u16;
            let service = param_str(&params, "service");
            let service = if service.is_empty() { "http" } else { &service };
            let timeout_ms = param_u64(&params, "timeout_ms", 5000);

            // Get default credentials for this service
            let credentials = Self::get_default_credentials(service);

            tracing::info!(
                "Testing {} default credentials against {}:{} ({})",
                credentials.len(),
                host,
                port,
                service
            );

            let mut attempts = Vec::new();
            let mut successful = 0;

            for (username, password) in &credentials {
                let success = match service.to_lowercase().as_str() {
                    "http" | "https" | "web" => {
                        Self::test_http_auth(&host, port, username, password, timeout_ms).await
                    }
                    "ssh" => Self::test_ssh_auth(&host, port, username, password, timeout_ms).await,
                    "ftp" => Self::test_ftp_auth(&host, port, username, password, timeout_ms).await,
                    _ => {
                        // For unsupported services, try HTTP auth as fallback
                        Self::test_http_auth(&host, port, username, password, timeout_ms).await
                    }
                };

                let status = match success {
                    Ok(true) => {
                        successful += 1;
                        "SUCCESS"
                    }
                    Ok(false) => "FAILED",
                    Err(_) => "ERROR",
                };

                attempts.push(json!({
                    "username": username,
                    "password": if password.is_empty() { "<empty>" } else { password },
                    "status": status,
                }));

                // Add small delay to avoid overwhelming the service
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            // One report-safe probe per attempted credential. The password is
            // scrubbed by exact value inside `default_cred_probes`, so it can't
            // reach the published `effective_command` (pick#52 / pick#317).
            let probes = default_cred_probes(service, &credentials, &host, port);

            // Mask passwords once, then reuse the masked log for BOTH sinks: the
            // provenance excerpt and the returned `data` (which the connector
            // serializes whole onto the Matrix wire). The plaintext `attempts`
            // never leaves this function (pick#52 / pick#317 — F4).
            let masked_attempts = mask_attempts(&attempts);
            let raw_excerpt = serde_json::to_string(&masked_attempts).unwrap_or_default();
            let provenance = Provenance::multi_step(
                match service.to_lowercase().as_str() {
                    "ssh" => "sshpass+openssh",
                    "ftp" => "ftp-socket",
                    _ => "curl",
                },
                env!("CARGO_PKG_VERSION"),
                probes,
                truncate_excerpt(&raw_excerpt),
            );

            let data = json!({
                "host": host,
                "port": port,
                "service": service,
                "attempts": masked_attempts,
                "successful": successful,
                "total_tested": credentials.len(),
            });
            // Promote each successful default-cred login into the evidence
            // graph (pick#52). Failed attempts produce no node, and the working
            // password is withheld from every node field.
            for node in
                crate::evidence_producer::evidence_from_default_creds(&data, provenance.clone())
            {
                let _ = crate::evidence_producer::push_evidence(node);
            }

            Ok((data, provenance))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_attempts_hides_passwords_keeps_username_status() {
        let attempts = vec![
            json!({"username": "admin", "password": "s3cr3t", "status": "SUCCESS"}),
            json!({"username": "root", "password": "hunter2", "status": "FAILED"}),
        ];

        // Serialize the masked log the same way both wire-bound sinks do (the
        // provenance excerpt and the returned `data`).
        let masked = serde_json::to_string(&mask_attempts(&attempts)).unwrap();

        assert!(
            !masked.contains("s3cr3t"),
            "plaintext password leaked after masking: {masked}"
        );
        assert!(
            !masked.contains("hunter2"),
            "plaintext password leaked after masking: {masked}"
        );
        assert!(masked.contains("admin"), "username should be preserved");
        assert!(masked.contains("SUCCESS"), "status should be preserved");
        assert!(masked.contains("<redacted>"), "password should be masked");
    }

    #[test]
    fn default_cred_probes_scrub_password_from_effective_command() {
        // Guards the production probe builder (F2). The ssh `sshpass -p '<pw>'`
        // shape is matched by NONE of redact()'s regexes, so the builder must
        // scrub the password by exact value; reverting it to `from_exact` turns
        // this red (pick#52 / pick#317).
        let ssh = default_cred_probes(
            "ssh",
            &[("pi", "raspberry"), ("root", "toor")],
            "10.0.0.5",
            22,
        );
        assert_eq!(ssh.len(), 2);
        for pc in &ssh {
            assert!(
                !pc.effective_command.contains("raspberry")
                    && !pc.effective_command.contains("toor"),
                "ssh default password leaked into effective_command: {}",
                pc.effective_command
            );
            assert!(
                pc.effective_command.contains("<REDACTED>"),
                "password position should be redacted: {}",
                pc.effective_command
            );
        }

        // The HTTP fallback (`-u user:pass`) must scrub too.
        let http = default_cred_probes("http", &[("admin", "s3cr3t")], "10.0.0.5", 80);
        assert!(
            !http[0].effective_command.contains("s3cr3t"),
            "http default password leaked: {}",
            http[0].effective_command
        );
    }
}

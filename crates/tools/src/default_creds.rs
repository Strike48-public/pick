//! Default credentials testing tool

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use serde_json::{json, Value};
use tokio::time::Duration;

use crate::util::{param_str, param_u64};

/// Default credentials testing tool
pub struct DefaultCredsTool;

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
        execute_timed(|| async {
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

            Ok(json!({
                "host": host,
                "port": port,
                "service": service,
                "attempts": attempts,
                "successful": successful,
                "total_tested": credentials.len(),
            }))
        })
        .await
    }
}

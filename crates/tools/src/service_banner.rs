//! Service banner grabbing tool

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::provenance::{truncate_excerpt, ProbeCommand, Provenance};
use pentest_core::tools::{
    execute_timed_with_provenance, ParamType, PentestTool, Platform, ToolContext, ToolParam,
    ToolResult, ToolSchema,
};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::util::{param_str, param_u64};

/// Service banner grabbing tool
pub struct ServiceBannerTool;

impl ServiceBannerTool {
    /// Common service probes mapped to port
    fn get_probe(port: u16) -> &'static str {
        match port {
            21 => "QUIT\r\n",                              // FTP
            22 => "",                                      // SSH - sends banner first
            23 => "",                                      // Telnet
            25 | 587 => "EHLO banner.local\r\n",           // SMTP
            80 | 8080 | 8000 => "HEAD / HTTP/1.0\r\n\r\n", // HTTP
            110 => "QUIT\r\n",                             // POP3
            143 => "A001 LOGOUT\r\n",                      // IMAP
            443 | 8443 => "GET / HTTP/1.0\r\n\r\n",        // HTTPS (won't work without TLS)
            3306 => "",                                    // MySQL
            5432 => "",                                    // PostgreSQL
            _ => "GET / HTTP/1.0\r\n\r\n",                 // Default HTTP probe
        }
    }

    /// Parse service type and version from banner
    fn parse_banner(banner: &str, port: u16) -> (Option<String>, Option<String>) {
        let banner_lower = banner.to_lowercase();

        // SSH
        if banner.starts_with("SSH-") {
            let parts: Vec<&str> = banner.split_whitespace().collect();
            if let Some(version_info) = parts.first() {
                return (Some("ssh".to_string()), Some(version_info.to_string()));
            }
        }

        // HTTP Server headers
        if let Some(server_line) = banner
            .lines()
            .find(|line| line.to_lowercase().starts_with("server:"))
        {
            let server_value = server_line
                .split(':')
                .nth(1)
                .unwrap_or("")
                .trim()
                .to_string();
            return (Some("http".to_string()), Some(server_value));
        }

        // FTP
        if banner_lower.starts_with("220") && (banner_lower.contains("ftp") || port == 21) {
            return (
                Some("ftp".to_string()),
                Some(banner.lines().next().unwrap_or("").to_string()),
            );
        }

        // SMTP
        if banner_lower.starts_with("220")
            && (banner_lower.contains("smtp") || port == 25 || port == 587)
        {
            return (
                Some("smtp".to_string()),
                Some(banner.lines().next().unwrap_or("").to_string()),
            );
        }

        // MySQL
        if port == 3306 && banner.contains("mysql") {
            return (
                Some("mysql".to_string()),
                Some(banner.lines().next().unwrap_or("").to_string()),
            );
        }

        // PostgreSQL
        if port == 5432 {
            return (Some("postgresql".to_string()), None);
        }

        // Telnet
        if port == 23 {
            return (Some("telnet".to_string()), Some(banner.to_string()));
        }

        // Default: unknown service
        (None, None)
    }
}

#[async_trait]
impl PentestTool for ServiceBannerTool {
    fn name(&self) -> &str {
        "service_banner"
    }

    fn description(&self) -> &str {
        "Grab service banners from open ports to identify service type and version"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "host",
                ParamType::String,
                "Target host IP or hostname",
            ))
            .param(ToolParam::required(
                "port",
                ParamType::Integer,
                "Target port number",
            ))
            .param(ToolParam::optional(
                "timeout_ms",
                ParamType::Integer,
                "Connection timeout in milliseconds",
                json!(5000),
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
        execute_timed_with_provenance(|| async {
            // Parse parameters
            let host = param_str(&params, "host");
            if host.is_empty() {
                return Err(Error::InvalidParams("host parameter is required".into()));
            }

            let port = params
                .get("port")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| Error::InvalidParams("port parameter is required".into()))?
                as u16;

            let timeout_ms = param_u64(&params, "timeout_ms", 5000);

            // Connect to target
            let addr = format!("{}:{}", host, port);
            let stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr))
                .await
                .map_err(|_| Error::Timeout(format!("Connection to {} timed out", addr)))?
                .map_err(|e| Error::Network(format!("Failed to connect to {}: {}", addr, e)))?;

            let (mut read_half, mut write_half) = stream.into_split();

            // Send probe if needed
            let probe = Self::get_probe(port);
            if !probe.is_empty() {
                write_half
                    .write_all(probe.as_bytes())
                    .await
                    .map_err(|e| Error::Network(format!("Failed to send probe: {}", e)))?;
            }

            // Read banner (max 4KB)
            let mut buffer = vec![0u8; 4096];
            let bytes_read = timeout(
                Duration::from_millis(timeout_ms),
                read_half.read(&mut buffer),
            )
            .await
            .map_err(|_| Error::Timeout("Banner read timed out".into()))?
            .map_err(|e| Error::Network(format!("Failed to read banner: {}", e)))?;

            let banner = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();

            // Parse banner
            let (service, version) = Self::parse_banner(&banner, port);

            // Provenance: the reproducible analogue of our raw TCP probe is
            // an ncat command piping the same bytes into the socket. This
            // lets a reviewer re-grab the banner with a standard tool.
            let reproducible = if probe.is_empty() {
                format!("ncat {host} {port}")
            } else {
                // Render escape sequences visibly (\r\n etc.) so the
                // published command is legible and executable as-is.
                let escaped = probe.replace('\r', "\\r").replace('\n', "\\n");
                format!("printf '{escaped}' | ncat {host} {port}")
            };
            let provenance = Provenance::new(
                "tcp-banner",
                env!("CARGO_PKG_VERSION"),
                ProbeCommand::from_exact(reproducible).with_description("raw TCP banner grab"),
                truncate_excerpt(&banner),
            );

            let data = json!({
                "host": host,
                "port": port,
                "banner": banner,
                "service": service,
                "version": version,
            });

            // Produce evidence nodes for the three-agent pipeline
            let evidence_nodes = crate::evidence_producer::evidence_from_service_banner(
                &data,
                &host,
                port,
                provenance.clone()
            );

            for node in evidence_nodes {
                crate::evidence_producer::push_evidence(node);
            }

            Ok((data, provenance))
        })
        .await
    }
}

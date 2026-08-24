//! URL Parser for Strike48 Connector SDK.
//!
//! Parses Strike48 endpoint URLs and auto-detects transport type from URL scheme.
//!
//! # Supported URL Schemes
//!
//! - `grpc://`  → gRPC transport, no TLS
//! - `grpcs://` → gRPC transport, with TLS
//! - `ws://`    → WebSocket transport, no TLS
//! - `wss://`   → WebSocket transport, with TLS
//! - `http://`  → WebSocket transport (via upgrade), no TLS
//! - `https://` → WebSocket transport (via upgrade), with TLS
//!
//! # Examples
//!
//! ```
//! use strike48_connector::url_parser::parse_url;
//! use strike48_connector::TransportType;
//!
//! // gRPC with TLS
//! let parsed = parse_url("grpcs://connectors.example.com:443").unwrap();
//! assert_eq!(parsed.host, "connectors.example.com");
//! assert_eq!(parsed.port, 443);
//! assert!(parsed.use_tls);
//!
//! // WebSocket with TLS
//! let parsed = parse_url("wss://connectors.example.com").unwrap();
//! assert_eq!(parsed.transport, TransportType::WebSocket);
//!
//! // Legacy format (defaults to gRPC)
//! let parsed = parse_url("localhost:50061").unwrap();
//! assert_eq!(parsed.transport, TransportType::Grpc);
//! ```

use crate::transport::TransportType;
use regex::Regex;
use std::sync::LazyLock;

/// Parsed Strike48 endpoint configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedEndpoint {
    /// Server hostname.
    pub host: String,
    /// Server port.
    pub port: u16,
    /// Auto-detected transport type.
    pub transport: TransportType,
    /// Whether to use TLS.
    pub use_tls: bool,
}

impl ParsedEndpoint {
    /// Full host:port string for gRPC client.
    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Scheme configuration.
struct SchemeConfig {
    transport: TransportType,
    use_tls: bool,
    default_port: u16,
}

/// Get configuration for a URL scheme.
fn get_scheme_config(scheme: &str) -> Option<SchemeConfig> {
    match scheme.to_lowercase().as_str() {
        "grpc" => Some(SchemeConfig {
            transport: TransportType::Grpc,
            use_tls: false,
            default_port: 50061,
        }),
        "grpcs" => Some(SchemeConfig {
            transport: TransportType::Grpc,
            use_tls: true,
            default_port: 443,
        }),
        "ws" => Some(SchemeConfig {
            transport: TransportType::WebSocket,
            use_tls: false,
            default_port: 80,
        }),
        "wss" => Some(SchemeConfig {
            transport: TransportType::WebSocket,
            use_tls: true,
            default_port: 443,
        }),
        "http" => Some(SchemeConfig {
            transport: TransportType::WebSocket,
            use_tls: false,
            default_port: 80,
        }),
        "https" => Some(SchemeConfig {
            transport: TransportType::WebSocket,
            use_tls: true,
            default_port: 443,
        }),
        _ => None,
    }
}

// Regex patterns
static URL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(grpcs?|wss?|https?)://([^:/\s]+)(?::(\d+))?(/.*)?$").unwrap()
});

static HOST_PORT_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([^:/\s]+)(?::(\d+))?$").unwrap());

/// Parse a Strike48 endpoint URL and extract configuration.
///
/// Supports both URL format (scheme://host:port) and legacy host:port format.
/// Transport type is auto-detected from the URL scheme.
///
/// # Arguments
///
/// * `url_or_host` - URL string (e.g., "grpcs://example.com:443") or host:port
///
/// # Returns
///
/// Parsed endpoint configuration with transport type
///
/// # Errors
///
/// Returns an error if the URL format is invalid
///
/// # Examples
///
/// ```
/// use strike48_connector::url_parser::parse_url;
///
/// // gRPC with TLS
/// let parsed = parse_url("grpcs://connectors.example.com:443").unwrap();
/// assert_eq!(parsed.host, "connectors.example.com");
///
/// // WebSocket with TLS
/// let parsed = parse_url("wss://connectors.example.com:443").unwrap();
///
/// // Legacy format (defaults to gRPC)
/// let parsed = parse_url("localhost:50061").unwrap();
/// ```
pub fn parse_url(url_or_host: &str) -> Result<ParsedEndpoint, String> {
    let input = url_or_host.trim();

    // Try to match URL with scheme
    if let Some(caps) = URL_PATTERN.captures(input) {
        let scheme = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let host = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let port_str = caps.get(3).map(|m| m.as_str());

        // Get config for this scheme
        let config = get_scheme_config(scheme).ok_or_else(|| {
            format!(
                "Unsupported URL scheme: {scheme}. Supported: grpc, grpcs, ws, wss, http, https"
            )
        })?;

        let port = match port_str {
            Some(p) => p.parse::<u16>().map_err(|_| format!("Invalid port: {p}"))?,
            None => config.default_port,
        };

        return Ok(ParsedEndpoint {
            host: host.to_string(),
            port,
            transport: config.transport,
            use_tls: config.use_tls,
        });
    }

    // Fallback: treat as host:port (legacy format, defaults to gRPC)
    if let Some(caps) = HOST_PORT_PATTERN.captures(input) {
        let host = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let port_str = caps.get(2).map(|m| m.as_str());

        let port = match port_str {
            Some(p) => p.parse::<u16>().map_err(|_| format!("Invalid port: {p}"))?,
            None => 50061,
        };

        // Infer TLS from port
        let use_tls = port == 443;

        return Ok(ParsedEndpoint {
            host: host.to_string(),
            port,
            transport: TransportType::Grpc, // Default to gRPC for legacy format
            use_tls,
        });
    }

    // Invalid format
    Err(format!(
        "Invalid URL format: {input}. Expected: grpcs://host:port, wss://host:port, or host:port"
    ))
}

/// Validate that a URL or host string is a valid Strike48 endpoint.
pub fn is_valid_url(url_or_host: &str) -> bool {
    parse_url(url_or_host).is_ok()
}

/// Get the transport type for a URL without full parsing.
pub fn get_transport_from_url(url_or_host: &str) -> Result<TransportType, String> {
    Ok(parse_url(url_or_host)?.transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpcs_url() {
        let parsed = parse_url("grpcs://connectors.example.com:443").unwrap();
        assert_eq!(parsed.host, "connectors.example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.transport, TransportType::Grpc);
        assert!(parsed.use_tls);
    }

    #[test]
    fn test_wss_url() {
        let parsed = parse_url("wss://connectors.example.com:443").unwrap();
        assert_eq!(parsed.host, "connectors.example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.transport, TransportType::WebSocket);
        assert!(parsed.use_tls);
    }

    #[test]
    fn test_legacy_host_port() {
        let parsed = parse_url("localhost:50061").unwrap();
        assert_eq!(parsed.host, "localhost");
        assert_eq!(parsed.port, 50061);
        assert_eq!(parsed.transport, TransportType::Grpc);
        assert!(!parsed.use_tls);
    }

    #[test]
    fn test_host_port_443() {
        let parsed = parse_url("connectors.example.com:443").unwrap();
        assert_eq!(parsed.port, 443);
        assert!(parsed.use_tls); // Inferred from port
    }

    #[test]
    fn test_default_ports() {
        assert_eq!(parse_url("grpc://host").unwrap().port, 50061);
        assert_eq!(parse_url("grpcs://host").unwrap().port, 443);
        assert_eq!(parse_url("ws://host").unwrap().port, 80);
        assert_eq!(parse_url("wss://host").unwrap().port, 443);
    }
}

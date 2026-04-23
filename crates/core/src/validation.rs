//! Input validation utilities for security-critical parameters
//!
//! This module provides validation functions for common input types used in
//! penetration testing tools: IP addresses, hostnames, ports, CIDR ranges, etc.
//!
//! All validation functions follow a consistent pattern:
//! - Accept a string slice as input
//! - Return `Result<T, Error>` where T is the validated type
//! - Reject inputs with shell metacharacters
//! - Provide clear error messages

use crate::error::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Validates IPv4 address format
///
/// # Examples
///
/// ```
/// use pentest_core::validation::validate_ipv4;
///
/// assert!(validate_ipv4("192.168.1.1").is_ok());
/// assert!(validate_ipv4("127.0.0.1").is_ok());
/// assert!(validate_ipv4("999.999.999.999").is_err());
/// ```
pub fn validate_ipv4(ip: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(ip.trim())
        .map_err(|_| Error::InvalidParams(format!("Invalid IPv4 address: {}", ip)))
}

/// Validates IPv6 address format
///
/// # Examples
///
/// ```
/// use pentest_core::validation::validate_ipv6;
///
/// assert!(validate_ipv6("::1").is_ok());
/// assert!(validate_ipv6("2001:db8::1").is_ok());
/// assert!(validate_ipv6("invalid").is_err());
/// ```
pub fn validate_ipv6(ip: &str) -> Result<Ipv6Addr> {
    Ipv6Addr::from_str(ip.trim())
        .map_err(|_| Error::InvalidParams(format!("Invalid IPv6 address: {}", ip)))
}

/// Validates IP address (v4 or v6)
///
/// # Examples
///
/// ```
/// use pentest_core::validation::validate_ip;
///
/// assert!(validate_ip("192.168.1.1").is_ok());
/// assert!(validate_ip("::1").is_ok());
/// assert!(validate_ip("not-an-ip").is_err());
/// ```
pub fn validate_ip(ip: &str) -> Result<IpAddr> {
    IpAddr::from_str(ip.trim())
        .map_err(|_| Error::InvalidParams(format!("Invalid IP address: {}", ip)))
}

/// Validates hostname (RFC 1123 compliant)
///
/// Rules:
/// - Alphanumeric characters and hyphens only
/// - Labels separated by dots
/// - Each label: 1-63 characters
/// - Total length: 1-253 characters
/// - No leading/trailing hyphens in labels
/// - No shell metacharacters
///
/// # Examples
///
/// ```
/// use pentest_core::validation::validate_hostname;
///
/// assert!(validate_hostname("example.com").is_ok());
/// assert!(validate_hostname("sub.example.com").is_ok());
/// assert!(validate_hostname("-invalid.com").is_err());
/// assert!(validate_hostname("; rm -rf /").is_err());
/// ```
pub fn validate_hostname(host: &str) -> Result<String> {
    let host = host.trim();

    if host.is_empty() || host.len() > 253 {
        return Err(Error::InvalidParams(format!(
            "Hostname length must be 1-253 characters: {}",
            host
        )));
    }

    // Check for shell metacharacters
    if has_shell_metacharacters(host) {
        return Err(Error::InvalidParams(format!(
            "Hostname contains shell metacharacters: {}",
            host
        )));
    }

    // Check each label
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::InvalidParams(format!(
                "Hostname label length must be 1-63 characters: {}",
                label
            )));
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::InvalidParams(format!(
                "Hostname label cannot start/end with hyphen: {}",
                label
            )));
        }

        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::InvalidParams(format!(
                "Hostname label contains invalid characters: {}",
                label
            )));
        }
    }

    Ok(host.to_string())
}

/// Check if a string contains shell metacharacters
fn has_shell_metacharacters(s: &str) -> bool {
    const SHELL_METACHARACTERS: &[char] = &[
        ';', '|', '&', '$', '`', '\n', '\r', '<', '>', '(', ')', '{', '}', '[', ']', '\\', '\'',
        '"', ' ', '\t',
    ];

    s.chars().any(|c| SHELL_METACHARACTERS.contains(&c))
}

/// Validates port number (1-65535)
///
/// # Examples
///
/// ```
/// use pentest_core::validation::validate_port;
///
/// assert!(validate_port(80).is_ok());
/// assert!(validate_port(443).is_ok());
/// assert!(validate_port(0).is_err());
/// ```
pub fn validate_port(port: u16) -> Result<u16> {
    if port == 0 {
        return Err(Error::InvalidParams(
            "Port must be between 1 and 65535".into(),
        ));
    }
    Ok(port)
}

/// Validates port specification string
///
/// Accepts formats:
/// - Single port: "80"
/// - Comma-separated: "80,443"
/// - Range: "1-1024"
/// - Mixed: "22,80-443,8080"
///
/// # Examples
///
/// ```
/// use pentest_core::validation::validate_port_spec;
///
/// assert!(validate_port_spec("80").is_ok());
/// assert!(validate_port_spec("80,443").is_ok());
/// assert!(validate_port_spec("1-1024").is_ok());
/// assert!(validate_port_spec("22,80-443,8080").is_ok());
/// assert!(validate_port_spec("0").is_err());
/// assert!(validate_port_spec("443-80").is_err());
/// ```
pub fn validate_port_spec(spec: &str) -> Result<String> {
    let spec = spec.trim();

    if spec.is_empty() {
        return Err(Error::InvalidParams(
            "Port specification cannot be empty".into(),
        ));
    }

    // Check for shell metacharacters
    if has_shell_metacharacters(spec) {
        return Err(Error::InvalidParams(format!(
            "Port specification contains shell metacharacters: {}",
            spec
        )));
    }

    // Split by comma
    for part in spec.split(',') {
        let part = part.trim();

        // Check for range (e.g., "80-443")
        if part.contains('-') {
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(Error::InvalidParams(format!(
                    "Invalid port range (expected format: START-END): {}",
                    part
                )));
            }

            let start = range_parts[0].trim().parse::<u16>().map_err(|_| {
                Error::InvalidParams(format!("Invalid port number: {}", range_parts[0]))
            })?;
            let end = range_parts[1].trim().parse::<u16>().map_err(|_| {
                Error::InvalidParams(format!("Invalid port number: {}", range_parts[1]))
            })?;

            validate_port(start)?;
            validate_port(end)?;

            if start >= end {
                return Err(Error::InvalidParams(format!(
                    "Invalid port range: start must be less than end ({})",
                    part
                )));
            }
        } else {
            // Single port
            let port = part
                .parse::<u16>()
                .map_err(|_| Error::InvalidParams(format!("Invalid port number: {}", part)))?;
            validate_port(port)?;
        }
    }

    Ok(spec.to_string())
}

/// Validates CIDR notation (e.g., "192.168.1.0/24")
///
/// # Examples
///
/// ```
/// use pentest_core::validation::validate_cidr;
///
/// assert!(validate_cidr("192.168.1.0/24").is_ok());
/// assert!(validate_cidr("10.0.0.0/8").is_ok());
/// assert!(validate_cidr("2001:db8::/32").is_ok());
/// assert!(validate_cidr("192.168.1.0/33").is_err());
/// ```
pub fn validate_cidr(cidr: &str) -> Result<String> {
    let cidr = cidr.trim();

    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidParams(format!(
            "Invalid CIDR notation (expected format: IP/PREFIX): {}",
            cidr
        )));
    }

    // Validate IP part
    let ip = validate_ip(parts[0])?;

    // Validate prefix length
    let prefix = parts[1]
        .parse::<u8>()
        .map_err(|_| Error::InvalidParams(format!("Invalid CIDR prefix: {}", parts[1])))?;

    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    if prefix > max_prefix {
        return Err(Error::InvalidParams(format!(
            "CIDR prefix must be 0-{} for {}: {}",
            max_prefix,
            if matches!(ip, IpAddr::V4(_)) {
                "IPv4"
            } else {
                "IPv6"
            },
            prefix
        )));
    }

    Ok(cidr.to_string())
}

/// Validates target specification (IP, hostname, or CIDR)
///
/// Accepts:
/// - IPv4: "192.168.1.1"
/// - IPv6: "2001:db8::1"
/// - Hostname: "example.com"
/// - CIDR: "192.168.1.0/24"
///
/// # Examples
///
/// ```
/// use pentest_core::validation::validate_target;
///
/// assert!(validate_target("192.168.1.1").is_ok());
/// assert!(validate_target("example.com").is_ok());
/// assert!(validate_target("192.168.1.0/24").is_ok());
/// assert!(validate_target("; rm -rf /").is_err());
/// ```
pub fn validate_target(target: &str) -> Result<String> {
    let target = target.trim();

    if target.is_empty() {
        return Err(Error::InvalidParams("Target cannot be empty".into()));
    }

    // Try CIDR first (contains '/')
    if target.contains('/') {
        return validate_cidr(target);
    }

    // Try IP address next
    if validate_ip(target).is_ok() {
        return Ok(target.to_string());
    }

    // Finally try hostname
    validate_hostname(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ipv4() {
        assert!(validate_ipv4("192.168.1.1").is_ok());
        assert!(validate_ipv4("127.0.0.1").is_ok());
        assert!(validate_ipv4("0.0.0.0").is_ok());
        assert!(validate_ipv4("255.255.255.255").is_ok());

        assert!(validate_ipv4("999.999.999.999").is_err());
        assert!(validate_ipv4("not-an-ip").is_err());
        assert!(validate_ipv4("").is_err());
    }

    #[test]
    fn test_validate_ipv6() {
        assert!(validate_ipv6("::1").is_ok());
        assert!(validate_ipv6("2001:db8::1").is_ok());
        assert!(validate_ipv6("fe80::1").is_ok());

        assert!(validate_ipv6("invalid").is_err());
        assert!(validate_ipv6("192.168.1.1").is_err());
    }

    #[test]
    fn test_validate_ip() {
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("::1").is_ok());
        assert!(validate_ip("2001:db8::1").is_ok());

        assert!(validate_ip("not-an-ip").is_err());
    }

    #[test]
    fn test_validate_hostname() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
        assert!(validate_hostname("my-host.local").is_ok());
        assert!(validate_hostname("a.b.c.d.e.f.g").is_ok());

        assert!(validate_hostname("-invalid.com").is_err());
        assert!(validate_hostname("invalid-.com").is_err());
        assert!(validate_hostname("invalid..com").is_err());
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname(&"a".repeat(254)).is_err()); // Too long
    }

    #[test]
    fn test_validate_port() {
        assert!(validate_port(1).is_ok());
        assert!(validate_port(80).is_ok());
        assert!(validate_port(443).is_ok());
        assert!(validate_port(65535).is_ok());

        assert!(validate_port(0).is_err());
    }

    #[test]
    fn test_validate_port_spec() {
        assert!(validate_port_spec("80").is_ok());
        assert!(validate_port_spec("80,443").is_ok());
        assert!(validate_port_spec("1-1024").is_ok());
        assert!(validate_port_spec("22,80-443,8080").is_ok());
        assert!(validate_port_spec("1-65535").is_ok());

        assert!(validate_port_spec("0").is_err());
        assert!(validate_port_spec("65536").is_err());
        assert!(validate_port_spec("443-80").is_err()); // Reversed range
        assert!(validate_port_spec("80-80").is_err()); // Start == end
        assert!(validate_port_spec("abc").is_err());
        assert!(validate_port_spec("").is_err());
        assert!(validate_port_spec("80-443-8080").is_err()); // Invalid range format
    }

    #[test]
    fn test_validate_cidr() {
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("172.16.0.0/12").is_ok());
        assert!(validate_cidr("0.0.0.0/0").is_ok());
        assert!(validate_cidr("2001:db8::/32").is_ok());

        assert!(validate_cidr("192.168.1.0/33").is_err()); // Invalid IPv4 prefix
        assert!(validate_cidr("2001:db8::/129").is_err()); // Invalid IPv6 prefix
        assert!(validate_cidr("192.168.1.0").is_err()); // Missing prefix
        assert!(validate_cidr("invalid/24").is_err()); // Invalid IP
    }

    #[test]
    fn test_validate_target() {
        assert!(validate_target("192.168.1.1").is_ok());
        assert!(validate_target("example.com").is_ok());
        assert!(validate_target("sub.example.com").is_ok());
        assert!(validate_target("192.168.1.0/24").is_ok());
        assert!(validate_target("::1").is_ok());
        assert!(validate_target("2001:db8::/32").is_ok());

        assert!(validate_target("").is_err());
        assert!(validate_target("-invalid.com").is_err());
    }

    #[test]
    fn test_command_injection_prevention() {
        // Semicolon (command chaining)
        assert!(validate_target("192.168.1.1; rm -rf /").is_err());
        assert!(validate_hostname("host; rm -rf /").is_err());

        // Pipe (command piping)
        assert!(validate_target("192.168.1.1 | cat /etc/passwd").is_err());
        assert!(validate_hostname("host | cat file").is_err());

        // Backticks (command substitution)
        assert!(validate_target("192.168.1.1 `whoami`").is_err());
        assert!(validate_hostname("host`whoami`").is_err());

        // Dollar parens (command substitution)
        assert!(validate_target("192.168.1.1 $(whoami)").is_err());
        assert!(validate_hostname("host$(whoami)").is_err());

        // Ampersand (background execution)
        assert!(validate_target("192.168.1.1 && echo pwned").is_err());
        assert!(validate_hostname("host && echo pwned").is_err());

        // Redirect
        assert!(validate_target("192.168.1.1 > /tmp/pwned").is_err());
        assert!(validate_hostname("host > file").is_err());

        // Newline
        assert!(validate_target("192.168.1.1\nrm -rf /").is_err());
        assert!(validate_hostname("host\nrm -rf /").is_err());

        // Quotes
        assert!(validate_hostname("host' OR '1'='1").is_err());
        assert!(validate_hostname("host\" OR \"1\"=\"1").is_err());

        // Port spec should also reject metacharacters
        assert!(validate_port_spec("80; rm -rf /").is_err());
        assert!(validate_port_spec("80 | cat file").is_err());
    }

    #[test]
    fn test_shell_metacharacters() {
        let dangerous = [
            ";", "|", "&", "$", "`", "\n", "\r", "<", ">", "(", ")", "{", "}", "[", "]", "\\",
            "'", "\"", " ", "\t",
        ];

        for meta in dangerous {
            assert!(
                has_shell_metacharacters(meta),
                "Should detect metacharacter: {}",
                meta.escape_default()
            );
        }

        // Safe characters
        assert!(!has_shell_metacharacters("example.com"));
        assert!(!has_shell_metacharacters("192.168.1.1"));
        assert!(!has_shell_metacharacters("my-host"));
        assert!(!has_shell_metacharacters("80,443"));
        assert!(!has_shell_metacharacters("1-1024"));
    }
}

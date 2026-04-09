//! JWT token validation utilities
//!
//! Provides functions to validate JWT tokens without requiring full verification,
//! specifically checking expiration timestamps.

use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum allowed size for JWT tokens (8KB)
/// Real JWTs are typically < 2KB, this provides safety margin while preventing abuse
const MAX_JWT_SIZE: usize = 8192;

#[derive(Debug, Deserialize)]
struct JwtClaims {
    exp: i64,
    #[allow(dead_code)]
    iat: Option<i64>,
}

/// Check if a JWT token is expired
///
/// SECURITY WARNING: This function only validates the expiration timestamp.
/// It does NOT verify the cryptographic signature. Use for client-side token
/// cleanup only, never for authentication/authorization decisions.
///
/// Returns:
/// - `Ok(true)` if token is expired
/// - `Ok(false)` if token is still valid
/// - `Err` if token cannot be parsed or exceeds size limit
pub fn is_jwt_expired(token: &str) -> Result<bool, String> {
    if token.is_empty() {
        return Ok(true); // Empty token is considered expired
    }

    // Validate token size before processing (prevent memory exhaustion DoS)
    if token.len() > MAX_JWT_SIZE {
        return Err(format!(
            "JWT token too large: {} bytes (max {})",
            token.len(),
            MAX_JWT_SIZE
        ));
    }

    // JWT format: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    // Decode payload (second part)
    let payload = parts[1];

    // Check base64 size before decode (additional safety)
    if payload.len() > MAX_JWT_SIZE / 2 {
        return Err("JWT payload too large".to_string());
    }

    use base64::Engine;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| format!("Failed to decode JWT payload: {}", e))?;

    let claims: JwtClaims = serde_json::from_slice(&decoded)
        .map_err(|e| format!("Failed to parse JWT claims: {}", e))?;

    // Get current timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System time error: {}", e))?
        .as_secs() as i64;

    // Check if expired (with 30 second buffer for clock skew)
    Ok(claims.exp < now + 30)
}

/// Validate and clear expired token from a string
///
/// Returns `None` if token is empty or expired, `Some(token)` if valid
pub fn validate_token(token: &str) -> Option<String> {
    if token.is_empty() {
        return None;
    }

    match is_jwt_expired(token) {
        Ok(true) => {
            tracing::debug!("JWT token is expired, clearing");
            None
        }
        Ok(false) => Some(token.to_string()),
        Err(e) => {
            tracing::warn!("Failed to validate JWT token: {}, clearing", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_token_is_expired() {
        assert!(is_jwt_expired("").unwrap());
    }

    #[test]
    fn test_invalid_format() {
        assert!(is_jwt_expired("not.a.valid.jwt").is_err());
        assert!(is_jwt_expired("invalid").is_err());
    }

    #[test]
    fn test_expired_token() {
        // Token with exp: 1 (Jan 1, 1970) - definitely expired
        // gitleaks:allow - This is a test JWT with fake signature, not a real secret
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEsImlhdCI6MH0.signature";
        assert!(is_jwt_expired(token).unwrap());
    }

    #[test]
    fn test_validate_token_empty() {
        assert_eq!(validate_token(""), None);
    }

    #[test]
    fn test_oversized_token_rejected() {
        // Create a token larger than MAX_JWT_SIZE (8KB)
        let large_token = "a".repeat(10000);
        let result = is_jwt_expired(&large_token);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too large"));
    }

    #[test]
    fn test_oversized_payload_rejected() {
        // Token with massive base64 payload (header.HUGE_PAYLOAD.signature)
        let huge_payload = "a".repeat(5000);
        let token = format!("header.{}.signature", huge_payload);
        let result = is_jwt_expired(&token);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too large"));
    }
}

//! JWT token validation utilities
//!
//! Provides functions to validate JWT tokens without requiring full verification,
//! specifically checking expiration timestamps.

use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct JwtClaims {
    exp: i64,
    #[allow(dead_code)]
    iat: Option<i64>,
}

/// Check if a JWT token is expired
///
/// Returns:
/// - `Ok(true)` if token is expired
/// - `Ok(false)` if token is still valid
/// - `Err` if token cannot be parsed
pub fn is_jwt_expired(token: &str) -> Result<bool, String> {
    if token.is_empty() {
        return Ok(true); // Empty token is considered expired
    }

    // JWT format: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    // Decode payload (second part)
    let payload = parts[1];
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
}

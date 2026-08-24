//! SDK Configuration Constants
//!
//! All timeout values and configuration constants used throughout the SDK.
//! Values can be overridden via environment variables for flexibility.

#![allow(dead_code)]

use std::env;

/// Get a numeric value from environment variable with fallback
#[allow(dead_code)]
pub fn get_env_number(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Registration timeout in milliseconds
/// Environment variable: STRIKE48_REGISTRATION_TIMEOUT_MS
/// Default: 10000 (10 seconds)
pub const REGISTRATION_TIMEOUT_MS: u64 = 10000;

/// Base reconnect delay in milliseconds (doubles each attempt up to MAX_BACKOFF_DELAY_MS).
/// Sequence: 500ms → 1s → 2s → 4s → 8s → 16s → 32s → 60s (cap).
/// Environment variable: STRIKE48_RECONNECT_DELAY_MS
/// Default: 500 (0.5 seconds)
pub const RECONNECT_DELAY_MS: u64 = 500;

/// Retry delay in milliseconds (for retry function)
/// Environment variable: STRIKE48_RETRY_DELAY_MS
/// Default: 1000 (1 second)
pub const RETRY_DELAY_MS: u64 = 1000;

/// Cleanup delay in milliseconds (time to wait for pending requests to complete)
/// Environment variable: STRIKE48_CLEANUP_DELAY_MS
/// Default: 100 (100 milliseconds)
pub const CLEANUP_DELAY_MS: u64 = 100;

/// Maximum backoff delay for reconnection in milliseconds.
/// Once reached, the SDK continues retrying indefinitely at this interval.
/// Environment variable: STRIKE48_MAX_BACKOFF_DELAY_MS
/// Default: 60000 (60 seconds)
pub const MAX_BACKOFF_DELAY_MS: u64 = 60000;

/// Jitter added to reconnection backoff to prevent thundering herd.
/// Environment variable: STRIKE48_RECONNECT_JITTER_MS
/// Default: 500 (500 milliseconds)
pub const RECONNECT_JITTER_MS: u64 = 500;

/// Maximum number of reconnect attempts before giving up.
/// Deprecated: The SDK now retries indefinitely with max backoff.
/// This function is kept for backward compatibility but is unused.
#[deprecated(note = "SDK now retries indefinitely with max backoff. Use MAX_BACKOFF_DELAY_MS.")]
pub fn max_reconnect_attempts() -> Option<usize> {
    env::var("STRIKE48_MAX_RECONNECT_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse().ok())
}

/// Maximum number of retry attempts (for retry function)
/// Environment variable: STRIKE48_MAX_RETRY_ATTEMPTS
/// Default: 3
pub const MAX_RETRY_ATTEMPTS: usize = 3;

/// Default timeout for connector operations in milliseconds
/// Environment variable: STRIKE48_DEFAULT_TIMEOUT_MS
/// Default: 30000 (30 seconds)
pub const DEFAULT_TIMEOUT_MS: u64 = 30000;

/// Timeout for credentials_issued message after PENDING status in milliseconds
/// Environment variable: STRIKE48_CREDENTIALS_TIMEOUT_MS
/// Default: 8000 (8 seconds)
pub const CREDENTIALS_TIMEOUT_MS: u64 = 8000;

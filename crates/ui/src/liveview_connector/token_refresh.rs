//! Server-side session token refresh loop.
//!
//! Matches kubestudio's `spawn_token_refresh` pattern: parse the sandbox
//! token's `exp` claim, schedule a refresh at 70 % of TTL, POST to
//! `/api/app/token/refresh`, and update the global session store.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Whether the token refresh loop has been spawned.
static REFRESH_SPAWNED: AtomicBool = AtomicBool::new(false);

/// Refresh constants matching Matrix Studio's injection scripts.
const MIN_REFRESH_DELAY_SECS: u64 = 30;
const REFRESH_TTL_FRACTION: f64 = 0.70;
const TOKEN_REFRESH_MAX_RETRIES: u32 = 3;
const TOKEN_REFRESH_RETRY_DELAY_SECS: u64 = 5;

/// Spawn a background token refresh loop (idempotent — only first call starts it).
pub(crate) fn spawn_token_refresh(api_base: String) {
    if REFRESH_SPAWNED.swap(true, Ordering::SeqCst) {
        return; // Already running
    }
    tokio::spawn(async move {
        tracing::info!("Session token refresh loop started");
        let client = build_http_client();
        loop {
            let token = crate::session::get_auth_token();
            if token.is_empty() {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }

            let remaining = match parse_token_remaining_secs(&token) {
                Some(r) if r > 0 => r as u64,
                _ => {
                    tokio::time::sleep(tokio::time::Duration::from_secs(MIN_REFRESH_DELAY_SECS))
                        .await;
                    continue;
                }
            };

            // Schedule at 70 % of remaining TTL, minimum 30 s
            let delay =
                ((remaining as f64 * REFRESH_TTL_FRACTION) as u64).max(MIN_REFRESH_DELAY_SECS);
            tracing::debug!(
                "Session token refresh scheduled in {}s (remaining {}s)",
                delay,
                remaining
            );
            tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;

            let current_token = crate::session::get_auth_token();
            if current_token.is_empty() {
                continue;
            }

            let mut success = false;
            for attempt in 0..TOKEN_REFRESH_MAX_RETRIES {
                match do_token_refresh(&client, &api_base, &current_token).await {
                    Ok(new_token) => {
                        crate::session::set_auth_token(&new_token);
                        tracing::info!("Session token refreshed successfully");
                        success = true;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Session token refresh attempt {}/{} failed: {}",
                            attempt + 1,
                            TOKEN_REFRESH_MAX_RETRIES,
                            e
                        );
                        if attempt + 1 < TOKEN_REFRESH_MAX_RETRIES {
                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                TOKEN_REFRESH_RETRY_DELAY_SECS,
                            ))
                            .await;
                        }
                    }
                }
            }
            if !success {
                tracing::error!(
                    "Session token refresh failed after {} attempts",
                    TOKEN_REFRESH_MAX_RETRIES
                );
            }
        }
    });
}

/// POST /api/app/token/refresh with Bearer auth, return new token string.
async fn do_token_refresh(
    client: &reqwest::Client,
    api_base: &str,
    token: &str,
) -> anyhow::Result<String> {
    let url = format!("{}/api/app/token/refresh", api_base.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("Refresh returned status {}", resp.status());
    }
    let body: serde_json::Value = resp.json().await?;
    body.get("token")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("No token in refresh response"))
}

/// Parse remaining seconds until expiry from a sandbox token.
///
/// Sandbox tokens are `base64url(payload).signature` (2-part format).
/// The payload contains an `exp` claim with a Unix timestamp.
fn parse_token_remaining_secs(token: &str) -> Option<i64> {
    let payload_b64 = token.split('.').next()?;
    // base64url → standard base64
    let standard = payload_b64.replace('-', "+").replace('_', "/");
    let padded = match standard.len() % 4 {
        2 => format!("{}==", standard),
        3 => format!("{}=", standard),
        _ => standard,
    };
    let bytes = BASE64.decode(&padded).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let exp = claims.get("exp")?.as_i64()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(exp - now)
}

/// Build a reqwest client that respects MATRIX_TLS_INSECURE.
fn build_http_client() -> reqwest::Client {
    let insecure = std::env::var("MATRIX_TLS_INSECURE")
        .or_else(|_| std::env::var("MATRIX_INSECURE"))
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

//! OAuth PKCE flow for desktop connectors.
//!
//! Provides interactive browser-based login using the authorization code flow
//! with PKCE (Proof Key for Code Exchange).

use base64::Engine;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// OAuth-related errors.
#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("OIDC config missing required field: {0}")]
    MissingConfig(&'static str),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Token exchange failed: {0}")]
    TokenExchange(String),

    #[error("Callback timeout (120s)")]
    CallbackTimeout,

    #[error("Invalid state parameter")]
    InvalidState,

    #[error("No authorization code in callback")]
    NoCode,

    #[error("No refresh token available")]
    NoRefreshToken,

    #[error("Failed to open browser: {0}")]
    BrowserOpen(String),
}

struct TokenSet {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Instant,
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: u64,
}

/// OAuth manager for PKCE flow in desktop connectors.
pub struct OAuthManager {
    oidc_config: strike48_proto::proto::OidcConfig,
    tokens: RwLock<Option<TokenSet>>,
    #[allow(dead_code)] // Reserved for background token refresh
    refresh_handle: Mutex<Option<JoinHandle<()>>>,
}

impl OAuthManager {
    /// Create a new OAuth manager with the given OIDC configuration.
    pub fn new(oidc_config: strike48_proto::proto::OidcConfig) -> Self {
        Self {
            oidc_config,
            tokens: RwLock::new(None),
            refresh_handle: Mutex::new(None),
        }
    }

    /// Perform interactive login: open browser, bind localhost callback, exchange code for tokens.
    pub async fn login_interactive(&self) -> Result<String, OAuthError> {
        let auth_endpoint = Some(self.oidc_config.authorization_endpoint.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(OAuthError::MissingConfig("authorization_endpoint"))?;
        let token_endpoint = Some(self.oidc_config.token_endpoint.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(OAuthError::MissingConfig("token_endpoint"))?;
        let client_id = Some(self.oidc_config.client_id.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(OAuthError::MissingConfig("client_id"))?;

        // Generate PKCE code_verifier (43-128 random bytes, base64url-encoded)
        let code_verifier = Self::generate_code_verifier();
        let code_challenge = Self::compute_code_challenge(&code_verifier);
        let state: String = (0..32)
            .map(|_| rand::random::<u8>())
            .map(|b| format!("{b:02x}"))
            .collect();

        // Bind callback server on random port
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| OAuthError::TokenExchange(format!("Failed to bind callback: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| OAuthError::TokenExchange(format!("Failed to get local addr: {e}")))?
            .port();
        let redirect_uri = format!("http://127.0.0.1:{port}/callback");

        // Build authorization URL
        let mut auth_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}",
            auth_endpoint.trim_end_matches('?'),
            urlencoding::encode(client_id),
            urlencoding::encode(&redirect_uri),
            urlencoding::encode(&code_challenge),
            urlencoding::encode(&state),
        );
        let scope_str: String = self
            .oidc_config
            .scopes
            .iter()
            .filter(|s| !s.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        if !scope_str.is_empty() {
            auth_url.push_str("&scope=");
            auth_url.push_str(&urlencoding::encode(&scope_str));
        }

        // Open browser
        open::that(&auth_url).map_err(|e| OAuthError::BrowserOpen(e.to_string()))?;

        // Wait for callback with 120s timeout
        let (code, callback_state) = Self::wait_for_callback(&listener).await?;

        if callback_state != state {
            return Err(OAuthError::InvalidState);
        }

        let token_set = self
            .exchange_code(
                &code,
                &redirect_uri,
                &code_verifier,
                token_endpoint,
                client_id,
            )
            .await?;

        let access_token = token_set.access_token.clone();
        *self.tokens.write().await = Some(token_set);
        Ok(access_token)
    }

    /// Get current valid access token. Refreshes if expired and refresh_token is available.
    pub async fn get_token(&self) -> Result<String, OAuthError> {
        let tokens = self.tokens.write().await;
        if let Some(ref ts) = *tokens {
            // Consider expired 30s before actual expiry
            if ts
                .expires_at
                .saturating_duration_since(Instant::now())
                .as_secs()
                > 30
            {
                return Ok(ts.access_token.clone());
            }
            if ts.refresh_token.is_some() {
                drop(tokens);
                return self.refresh().await;
            }
        }
        Err(OAuthError::NoRefreshToken)
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
        token_endpoint: &str,
        client_id: &str,
    ) -> Result<TokenSet, OAuthError> {
        let client = crate::transport::proxy::build_http_client(token_endpoint);
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", code_verifier),
        ];

        let resp = client.post(token_endpoint).form(&params).send().await?;

        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            return Err(OAuthError::TokenExchange(format!(
                "Token exchange failed ({}): {}",
                status, body
            )));
        }

        let token_resp: TokenResponse = serde_json::from_str(&body)
            .map_err(|e| OAuthError::TokenExchange(format!("Invalid token response: {e}")))?;

        let expires_at =
            Instant::now() + Duration::from_secs(token_resp.expires_in.saturating_sub(30).max(60));

        Ok(TokenSet {
            access_token: token_resp.access_token,
            refresh_token: token_resp.refresh_token,
            expires_at,
        })
    }

    /// Refresh the access token using the refresh_token grant.
    pub async fn refresh(&self) -> Result<String, OAuthError> {
        let token_endpoint = Some(self.oidc_config.token_endpoint.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(OAuthError::MissingConfig("token_endpoint"))?;
        let client_id = Some(self.oidc_config.client_id.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(OAuthError::MissingConfig("client_id"))?;

        let refresh_token = {
            let tokens = self.tokens.read().await;
            tokens
                .as_ref()
                .and_then(|t| t.refresh_token.clone())
                .ok_or(OAuthError::NoRefreshToken)?
        };

        let client = crate::transport::proxy::build_http_client(token_endpoint);
        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", client_id),
        ];

        let resp = client.post(token_endpoint).form(&params).send().await?;

        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            return Err(OAuthError::TokenExchange(format!(
                "Refresh failed ({}): {}",
                status, body
            )));
        }

        let token_resp: TokenResponse = serde_json::from_str(&body)
            .map_err(|e| OAuthError::TokenExchange(format!("Invalid refresh response: {e}")))?;

        let expires_at =
            Instant::now() + Duration::from_secs(token_resp.expires_in.saturating_sub(30).max(60));

        let new_tokens = TokenSet {
            access_token: token_resp.access_token.clone(),
            refresh_token: token_resp.refresh_token.or(Some(refresh_token)),
            expires_at,
        };

        *self.tokens.write().await = Some(new_tokens);
        Ok(token_resp.access_token)
    }

    fn generate_code_verifier() -> String {
        let bytes: Vec<u8> = (0..64).map(|_| rand::random()).collect();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
    }

    fn compute_code_challenge(verifier: &str) -> String {
        let hash = Sha256::digest(verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
    }

    async fn wait_for_callback(listener: &TcpListener) -> Result<(String, String), OAuthError> {
        let (stream, _) = timeout(Duration::from_secs(120), listener.accept())
            .await
            .map_err(|_| OAuthError::CallbackTimeout)?
            .map_err(|e| OAuthError::TokenExchange(format!("Accept failed: {e}")))?;

        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .await
            .map_err(|e| OAuthError::TokenExchange(format!("Read failed: {e}")))?;

        let mut code = None;
        let mut state = None;
        if let Some(path_query) = request_line.split_whitespace().nth(1) {
            let (path, query) = path_query.split_once('?').unwrap_or((path_query, ""));
            if path == "/callback" || path.starts_with("/callback") {
                for pair in query.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        let v = urlencoding::decode(v).unwrap_or_default();
                        match k {
                            "code" => code = Some(v.into_owned()),
                            "state" => state = Some(v.into_owned()),
                            _ => {}
                        }
                    }
                }
            }
        }

        let code = code.ok_or(OAuthError::NoCode)?;
        let state = state.unwrap_or_default();

        let success = !request_line.contains("error=");
        let (status, body) = if success {
            (
                "200 OK",
                r#"<!DOCTYPE html><html><head><title>Success</title></head><body><h1>Login successful</h1><p>You can close this window.</p></body></html>"#,
            )
        } else {
            (
                "400 Bad Request",
                r#"<!DOCTYPE html><html><head><title>Error</title></head><body><h1>Login failed</h1><p>Please try again.</p></body></html>"#,
            )
        };

        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );

        let mut stream = reader.into_inner();
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(|e| OAuthError::TokenExchange(format!("Write response failed: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| OAuthError::TokenExchange(format!("Flush failed: {e}")))?;

        Ok((code, state))
    }
}

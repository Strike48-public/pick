//! OAuth authentication flows for the Matrix API.
//!
//! Two paths: programmatic (env-var credentials) and browser-based (PKCE).

/// Fetch an access token from the Matrix API via its OAuth login flow.
///
/// Performs the full programmatic OAuth dance:
/// 1. `GET {matrix_url}/auth/login` -> 302 to Keycloak + `_matrix_studio_key` cookie
/// 2. `GET` Keycloak login form, extract action URL
/// 3. `POST` credentials -> 302 to Matrix `/auth/callback`
/// 4. `GET` callback with matrix cookie -> `_matrix_sid` cookie
/// 5. `POST /auth/refresh` with `_matrix_sid` -> access token
///
/// Env vars: `MATRIX_API_URL`/`MATRIX_URL`, `KEYCLOAK_USERNAME`, `KEYCLOAK_PASSWORD`.
///
/// Returns `None` if no Matrix URL is configured.
pub async fn fetch_matrix_token() -> crate::error::Result<Option<String>> {
    let matrix_url = std::env::var("MATRIX_API_URL")
        .or_else(|_| std::env::var("MATRIX_URL"))
        .unwrap_or_default();
    if matrix_url.is_empty() {
        return Ok(None);
    }
    fetch_matrix_token_from(&matrix_url).await.map(Some)
}

/// Fetch an access token from a specific Matrix API URL.
///
/// Uses a single no-redirect cookie-store client for the entire flow so
/// the one-time Keycloak PAR `request_uri` is only consumed once and all
/// cookies (Matrix + Keycloak) are tracked automatically.
pub async fn fetch_matrix_token_from(matrix_url: &str) -> crate::error::Result<String> {
    let username = std::env::var("KEYCLOAK_USERNAME").map_err(|_| {
        crate::error::Error::Matrix(
            "KEYCLOAK_USERNAME env var is required for programmatic auth".into(),
        )
    })?;
    let password = std::env::var("KEYCLOAK_PASSWORD").map_err(|_| {
        crate::error::Error::Matrix(
            "KEYCLOAK_PASSWORD env var is required for programmatic auth".into(),
        )
    })?;
    let base = super::normalize_url(matrix_url);

    let client = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(
            std::env::var("MATRIX_INSECURE")
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false),
        )
        .build()
        .map_err(|e| crate::error::Error::Matrix(e.to_string()))?;

    tracing::info!("Matrix auth: starting login flow");

    let kc_url = init_sso_login(&client, base).await?;
    let action_url = get_login_form(&client, &kc_url).await?;
    let callback_resp = submit_credentials(&client, &action_url, &username, &password).await?;
    let matrix_sid = extract_matrix_sid(callback_resp)?;
    let token = complete_login(&client, base, &matrix_sid).await?;

    tracing::info!("Matrix auth: token obtained successfully");
    Ok(token)
}

// ---------------------------------------------------------------------------
// Programmatic OAuth flow helpers
// ---------------------------------------------------------------------------

/// Step 1: Hit the Matrix SSO login endpoint and return the Keycloak redirect URL.
async fn init_sso_login(client: &reqwest::Client, base: &str) -> crate::error::Result<String> {
    let login_url = format!(
        "{}/auth/login?redirect=http://localhost:19999/callback",
        base
    );
    let resp = client
        .get(&login_url)
        .send()
        .await
        .map_err(|e| crate::error::Error::Matrix(e.to_string()))?;
    if !resp.status().is_redirection() {
        return Err(crate::error::Error::Matrix(format!(
            "Expected redirect from /auth/login, got {}",
            resp.status()
        )));
    }
    location(&resp)
}

/// Step 2: Fetch the Keycloak login form and extract its POST action URL.
///
/// The initial Keycloak URL may respond with a 200 (form directly) or a 302
/// (redirect to the actual login page). Both cases are handled.
async fn get_login_form(client: &reqwest::Client, kc_url: &str) -> crate::error::Result<String> {
    let resp = client
        .get(kc_url)
        .send()
        .await
        .map_err(|e| crate::error::Error::Matrix(e.to_string()))?;
    let form_html = if resp.status().is_redirection() {
        let redir = location(&resp)?;
        let redir_resp = client
            .get(&redir)
            .send()
            .await
            .map_err(|e| crate::error::Error::Matrix(e.to_string()))?;
        redir_resp
            .text()
            .await
            .map_err(|e| crate::error::Error::Matrix(e.to_string()))?
    } else {
        resp.text()
            .await
            .map_err(|e| crate::error::Error::Matrix(e.to_string()))?
    };
    extract_form_action(&form_html)
        .ok_or_else(|| crate::error::Error::Matrix("No login form action in Keycloak page".into()))
}

/// Step 3: POST credentials to the Keycloak form and follow the redirect to the
/// Matrix `/auth/callback` endpoint. Returns the callback response (not yet
/// consumed) so the caller can extract cookies from it.
async fn submit_credentials(
    client: &reqwest::Client,
    action_url: &str,
    username: &str,
    password: &str,
) -> crate::error::Result<reqwest::Response> {
    let resp = client
        .post(action_url)
        .form(&[("username", username), ("password", password)])
        .send()
        .await
        .map_err(|e| crate::error::Error::Matrix(e.to_string()))?;
    if !resp.status().is_redirection() {
        return Err(crate::error::Error::Matrix(format!(
            "Expected redirect after login, got {} (wrong credentials?)",
            resp.status()
        )));
    }
    let callback_url = location(&resp)?;
    if !callback_url.contains("/auth/callback") {
        return Err(crate::error::Error::Matrix(format!(
            "Unexpected redirect target: {}",
            callback_url
        )));
    }
    client
        .get(&callback_url)
        .send()
        .await
        .map_err(|e| crate::error::Error::Matrix(e.to_string()))
}

/// Step 4: Extract the `_matrix_sid` cookie value from the callback response.
fn extract_matrix_sid(resp: reqwest::Response) -> crate::error::Result<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|s| s.starts_with("_matrix_sid="))
        .and_then(|s| s.strip_prefix("_matrix_sid="))
        .map(|s| s.split(';').next().unwrap_or_default().to_string())
        .ok_or_else(|| crate::error::Error::Matrix("No _matrix_sid in callback response".into()))
}

/// Step 5: POST to `/auth/refresh` with the session cookie and return the
/// access token from the JSON response.
async fn complete_login(
    client: &reqwest::Client,
    base: &str,
    matrix_sid: &str,
) -> crate::error::Result<String> {
    let resp = client
        .post(format!("{}/auth/refresh", base))
        .header("Cookie", format!("_matrix_sid={}", matrix_sid))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| crate::error::Error::Matrix(e.to_string()))?;
    if !resp.status().is_success() {
        let st = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(crate::error::Error::Matrix(format!(
            "Token refresh failed: {} - {}",
            st, body
        )));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| crate::error::Error::Matrix(e.to_string()))?;
    body.get("access_token")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| crate::error::Error::Matrix("No access_token in refresh response".into()))
}

// ---------------------------------------------------------------------------
// Browser-based OAuth
// ---------------------------------------------------------------------------

#[cfg(feature = "browser-auth")]
static BROWSER_TOKEN_CACHE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

#[cfg(feature = "browser-auth")]
type BrowserOpenerFn = Option<Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>>;

#[cfg(feature = "browser-auth")]
static BROWSER_OPENER: std::sync::Mutex<BrowserOpenerFn> = std::sync::Mutex::new(None);

/// Callback to set the OAuth callback port on the native side (Android).
/// On Android, the OAuthCallbackActivity needs to know which port the local
/// Axum server is listening on so it can forward the token from the custom
/// URI scheme intent.
#[cfg(feature = "browser-auth")]
type OAuthPortSetterFn = Option<Box<dyn Fn(u16) + Send + Sync>>;

#[cfg(feature = "browser-auth")]
static OAUTH_PORT_SETTER: std::sync::Mutex<OAuthPortSetterFn> = std::sync::Mutex::new(None);

/// Custom URI scheme for native app OAuth callbacks (Android).
#[cfg(feature = "browser-auth")]
const NATIVE_OAUTH_REDIRECT: &str = "com.strike48.pentest://oauth/callback";

/// Return the cached browser-obtained token, if any.
#[cfg(feature = "browser-auth")]
pub fn cached_browser_token() -> Option<String> {
    BROWSER_TOKEN_CACHE.lock().ok()?.clone()
}

/// Clear the cached browser token (e.g. when it's known to be stale).
#[cfg(feature = "browser-auth")]
pub fn clear_browser_token_cache() {
    if let Ok(mut cache) = BROWSER_TOKEN_CACHE.lock() {
        *cache = None;
    }
}

/// Set a custom browser opener function (e.g., for Android Intent-based opening).
/// This function will be called instead of open::that() when opening the browser.
#[cfg(feature = "browser-auth")]
pub fn set_browser_opener<F>(opener: F)
where
    F: Fn(&str) -> Result<(), String> + Send + Sync + 'static,
{
    if let Ok(mut opener_lock) = BROWSER_OPENER.lock() {
        *opener_lock = Some(Box::new(opener));
    }
}

/// Register a callback to set the OAuth callback port on the native side.
///
/// On Android, this should call `ConnectorBridge.setOAuthCallbackPort(port)` via JNI
/// so that `OAuthCallbackActivity` knows where to forward the token.
#[cfg(feature = "browser-auth")]
pub fn set_oauth_port_setter<F>(setter: F)
where
    F: Fn(u16) + Send + Sync + 'static,
{
    if let Ok(mut s) = OAUTH_PORT_SETTER.lock() {
        *s = Some(Box::new(setter));
    }
}

/// Tell the native side (Android) which port the callback server is on.
#[cfg(feature = "browser-auth")]
fn notify_oauth_port(port: u16) {
    if let Ok(s) = OAUTH_PORT_SETTER.lock() {
        if let Some(ref setter) = *s {
            setter(port);
        }
    }
}

#[cfg(not(feature = "browser-auth"))]
pub fn cached_browser_token() -> Option<String> {
    None
}

#[cfg(not(feature = "browser-auth"))]
pub fn clear_browser_token_cache() {}

/// Fetch an access token by opening the system browser for login.
///
/// Flow:
/// 1. Start a local callback server on an OS-assigned port
/// 2. Open browser to `{api_url}/auth/login?redirect=http://localhost:{port}/callback`
/// 3. Matrix API handles the full Keycloak OAuth dance in the browser
/// 4. After login, Matrix redirects browser to our local callback with access_token
/// 5. Return the access_token
///
/// The token is cached in a process-global static so it survives Dioxus component
/// remounts.
#[cfg(feature = "browser-auth")]
pub async fn fetch_matrix_token_browser(matrix_url: &str) -> crate::error::Result<String> {
    if let Some(cached) = cached_browser_token() {
        tracing::info!("Browser login: using cached token (len={})", cached.len());
        return Ok(cached);
    }

    let base = super::normalize_url(matrix_url).to_string();

    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

    // -----------------------------------------------------------------------
    // Bind the callback server FIRST so we know the local port before
    // generating the callback HTML (which embeds it for the redirect fallback).
    // -----------------------------------------------------------------------
    // Preferred ports: 4000, 5173 (in the Matrix server's CORS whitelist).
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:4000").await {
        Ok(l) => {
            tracing::info!("[BROWSER_AUTH] Bound to port 4000");
            l
        }
        Err(_) => {
            match tokio::net::TcpListener::bind("127.0.0.1:5173").await {
                Ok(l) => {
                    tracing::info!("[BROWSER_AUTH] Bound to port 5173 (4000 was busy)");
                    l
                }
                Err(_) => {
                    tracing::warn!("[BROWSER_AUTH] Ports 4000 and 5173 busy, using random port (CORS may fail)");
                    tokio::net::TcpListener::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| {
                            crate::error::Error::Matrix(format!(
                                "Failed to bind callback server: {}",
                                e
                            ))
                        })?
                }
            }
        }
    };
    let local_port = listener
        .local_addr()
        .map_err(|e| crate::error::Error::Matrix(e.to_string()))?
        .port();

    tracing::info!(
        "[BROWSER_AUTH] Callback server listening on port {}",
        local_port
    );

    // -----------------------------------------------------------------------
    // Callback HTML — tries multiple strategies to obtain the access token:
    //
    // 1. Token in URL query params (server passed it via redirect relay)
    // 2. Cross-origin POST /auth/refresh (works on desktop, fails on Android
    //    due to SameSite=Lax blocking cookies on cross-origin fetch)
    // 3. Redirect to Matrix origin for same-site exchange — top-level GET
    //    navigations DO send SameSite=Lax cookies. Server's /auth/refresh
    //    with ?redirect=<url> does the refresh and redirects back with token.
    // -----------------------------------------------------------------------
    let callback_html = format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Logging in…</title></head>
<body style="font-family:system-ui;text-align:center;margin-top:60px;background:#1e1e2e;color:#cdd6f4">
<h2 id="status">Completing login…</h2>
<p id="detail">Fetching access token from server.</p>
<pre id="debug" style="text-align:left;background:#2e2e3e;padding:10px;margin:20px;font-size:10px;max-height:300px;overflow:auto;"></pre>
<script>
(async function() {{
  var s = document.getElementById('status');
  var d = document.getElementById('detail');
  var dbg = document.getElementById('debug');
  function log(msg) {{
    console.log(msg);
    dbg.textContent += msg + '\n';
  }}

  var LOCAL_PORT = {local_port};
  var MATRIX_URL = '{matrix_url}';

  try {{
    log('[CALLBACK] Page loaded, starting token fetch...');
    log('[CALLBACK] Matrix URL: ' + MATRIX_URL);

    // Strategy 1: Token passed directly in the URL query params
    // (server supports redirect-based token relay)
    var params = new URLSearchParams(window.location.search);
    var urlToken = params.get('access_token');
    if (urlToken) {{
      log('[CALLBACK] Got token from URL param (len=' + urlToken.length + ')');
      var localResp = await fetch('/token?access_token=' + encodeURIComponent(urlToken));
      log('[CALLBACK] Local /token response: ' + localResp.status);
      s.textContent = 'Login successful!';
      d.textContent = 'You can close this tab and return to the app.';
      return;
    }}

    // Strategy 2: Cross-origin POST to /auth/refresh
    // Works on desktop browsers. Fails on mobile due to SameSite=Lax cookie
    // policy blocking cookies on cross-origin subresource requests.
    log('[CALLBACK] Trying cross-origin fetch to ' + MATRIX_URL + '/auth/refresh');
    var resp = await fetch(MATRIX_URL + '/auth/refresh', {{
      method: 'POST',
      credentials: 'include',
      headers: {{ 'Accept': 'application/json' }}
    }});

    log('[CALLBACK] Fetch response status: ' + resp.status);

    if (resp.ok) {{
      var data = await resp.json();
      log('[CALLBACK] Response JSON keys: ' + Object.keys(data).join(', '));
      var token = data.access_token || '';
      if (token) {{
        log('[CALLBACK] Token present (len=' + token.length + '), sending to /token');
        var localResp = await fetch('/token?access_token=' + encodeURIComponent(token));
        log('[CALLBACK] Local /token response: ' + localResp.status);
        s.textContent = 'Login successful!';
        d.textContent = 'You can close this tab and return to the app.';
        log('[CALLBACK] SUCCESS via cross-origin fetch');
        return;
      }}
    }}

    // Strategy 2 failed (no cookie sent) — fall through to redirect
    log('[CALLBACK] Cross-origin fetch failed (status=' + resp.status + '), trying redirect');
    throw new Error('cross-origin fetch returned ' + resp.status);

  }} catch(e) {{
    log('[CALLBACK] Fetch error: ' + e.message);

    // Strategy 3: Redirect to Matrix origin for same-site token exchange.
    // Top-level GET navigations send SameSite=Lax cookies. The server's
    // /auth/refresh?redirect=<url> does the refresh and 302s back to our
    // /token endpoint with ?access_token=xxx appended.
    var tokenUrl = 'http://localhost:' + LOCAL_PORT + '/token';
    var refreshUrl = MATRIX_URL + '/auth/refresh?redirect=' + encodeURIComponent(tokenUrl);
    log('[CALLBACK] Redirecting to Matrix origin: ' + refreshUrl);
    s.textContent = 'Completing login…';
    d.textContent = 'Redirecting for token exchange…';
    window.location.href = refreshUrl;
  }}
}})();
</script>
</body></html>"#,
        matrix_url = base,
        local_port = local_port,
    );

    // -----------------------------------------------------------------------
    // Routes
    // -----------------------------------------------------------------------
    let app = axum::Router::new()
        .route(
            "/callback",
            axum::routing::get({
                let callback_html = callback_html.clone();
                let tx_cb = tx.clone();
                move |query: axum::extract::Query<std::collections::HashMap<String, String>>| {
                    let html = callback_html.clone();
                    let tx = tx_cb.clone();
                    async move {
                        // If the server already passed the token in the redirect URL,
                        // capture it directly — no HTML page / JS needed.
                        if let Some(token) = query.get("access_token") {
                            if !token.is_empty() {
                                tracing::info!(
                                    "[BROWSER_AUTH] /callback got access_token in URL (len={})",
                                    token.len()
                                );
                                if let Some(sender) = tx.lock().await.take() {
                                    let _ = sender.send(token.clone());
                                }
                                return axum::response::Html(
                                    "<html><body style='background:#1e1e2e;color:#cdd6f4;\
                                     text-align:center;margin-top:60px;font-family:system-ui'>\
                                     <h2>Login successful!</h2>\
                                     <p>You can close this tab and return to the app.</p>\
                                     </body></html>"
                                        .to_string(),
                                );
                            }
                        }
                        tracing::info!(
                            "[BROWSER_AUTH] /callback hit, serving token-fetch page (HTML len={})",
                            html.len()
                        );
                        axum::response::Html(html)
                    }
                }
            }),
        )
        .route(
            "/token",
            axum::routing::get({
                let tx = tx.clone();
                move |query: axum::extract::Query<std::collections::HashMap<String, String>>| {
                    let tx = tx.clone();
                    async move {
                        tracing::info!(
                            "[BROWSER_AUTH] /token called with query params: {:?}",
                            query.0.keys().collect::<Vec<_>>()
                        );
                        if let Some(token) = query.get("access_token") {
                            tracing::info!(
                                "[BROWSER_AUTH] access_token present, len={}, sending to channel",
                                token.len()
                            );
                            if !token.is_empty() {
                                if let Some(sender) = tx.lock().await.take() {
                                    tracing::info!("[BROWSER_AUTH] Sending token to channel");
                                    let _ = sender.send(token.clone());
                                } else {
                                    tracing::warn!(
                                        "[BROWSER_AUTH] Channel sender already consumed!"
                                    );
                                }
                                return axum::response::Html(
                                    "<html><body style='background:#1e1e2e;color:#cdd6f4;\
                                     text-align:center;margin-top:60px;font-family:system-ui'>\
                                     <h2>Login successful!</h2>\
                                     <p>You can close this tab and return to the app.</p>\
                                     </body></html>"
                                        .to_string(),
                                );
                            } else {
                                tracing::warn!("[BROWSER_AUTH] access_token is empty");
                            }
                        } else {
                            tracing::warn!("[BROWSER_AUTH] No access_token in query params");
                        }
                        axum::response::Html("missing token".to_string())
                    }
                }
            }),
        );

    let server_handle = tokio::spawn(async move {
        tracing::info!("[BROWSER_AUTH] Server task started, serving app");
        match axum::serve(listener, app).await {
            Ok(_) => tracing::info!("[BROWSER_AUTH] Server exited normally"),
            Err(e) => tracing::error!("[BROWSER_AUTH] Server error: {}", e),
        }
    });

    // On Android, use a custom URI scheme so the OS routes the OAuth redirect
    // back to OAuthCallbackActivity (intent filter) instead of requiring the
    // browser to reach localhost.  The Activity forwards the token to the local
    // Axum server via HTTP, so we still need the server running.
    let redirect_url = if cfg!(target_os = "android") {
        notify_oauth_port(local_port);
        tracing::info!(
            "[BROWSER_AUTH] Android: using native redirect scheme, port={}",
            local_port
        );
        NATIVE_OAUTH_REDIRECT.to_string()
    } else {
        format!("http://localhost:{}/callback", local_port)
    };

    // Percent-encode the redirect URL for the query parameter.
    // We only need to handle the chars present in our redirect URLs.
    let encoded_redirect: String = redirect_url
        .chars()
        .flat_map(|c| match c {
            ':' => vec!['%', '3', 'A'],
            '/' => vec!['%', '2', 'F'],
            '?' => vec!['%', '3', 'F'],
            '&' => vec!['%', '2', '6'],
            '=' => vec!['%', '3', 'D'],
            _ => vec![c],
        })
        .collect();
    let login_url = format!("{}/auth/login?redirect={}", base, encoded_redirect);
    tracing::info!("[BROWSER_AUTH] Opening browser to: {}", login_url);

    // Try custom browser opener first (for Android Intent support)
    let custom_opener_result = if let Ok(opener_lock) = BROWSER_OPENER.lock() {
        if let Some(ref opener) = *opener_lock {
            tracing::info!("[BROWSER_AUTH] Using custom browser opener");
            match opener(&login_url) {
                Ok(_) => {
                    tracing::info!("[BROWSER_AUTH] Browser opened via custom opener");
                    Some(Ok(()))
                }
                Err(e) => {
                    tracing::warn!("[BROWSER_AUTH] Custom browser opener failed: {}", e);
                    Some(Err(e))
                }
            }
        } else {
            tracing::info!("[BROWSER_AUTH] No custom browser opener registered");
            None
        }
    } else {
        tracing::warn!("[BROWSER_AUTH] Failed to acquire browser opener lock");
        None
    };

    // Fall back to standard open::that() if no custom opener or it failed
    if custom_opener_result.is_none() {
        tracing::info!("[BROWSER_AUTH] Falling back to open::that()");
        if let Err(e) = open::that(&login_url) {
            tracing::error!(
                "[BROWSER_AUTH] Failed to open browser: {}. Please open this URL manually:\n{}",
                e,
                login_url
            );
        } else {
            tracing::info!("[BROWSER_AUTH] Browser opened via open::that()");
        }
    }

    tracing::info!("[BROWSER_AUTH] Waiting for token (120s timeout)...");
    let token = tokio::time::timeout(std::time::Duration::from_secs(120), rx)
        .await
        .map_err(|_| {
            tracing::error!("[BROWSER_AUTH] Timeout waiting for token");
            crate::error::Error::Matrix(
                "Login timed out — no token received within 120 seconds".into(),
            )
        })?
        .map_err(|_| {
            tracing::error!("[BROWSER_AUTH] Token channel closed unexpectedly");
            crate::error::Error::Matrix("Token channel closed unexpectedly".into())
        })?;

    tracing::info!("[BROWSER_AUTH] Token received from channel, stopping server");
    server_handle.abort();

    if token.is_empty() {
        tracing::error!("[BROWSER_AUTH] Received empty token");
        return Err(crate::error::Error::Matrix(
            "Empty access token received".into(),
        ));
    }

    tracing::info!(
        "[BROWSER_AUTH] Successfully obtained access token (len={})",
        token.len()
    );

    if let Ok(mut cache) = BROWSER_TOKEN_CACHE.lock() {
        *cache = Some(token.clone());
    }

    Ok(token)
}

#[cfg(not(feature = "browser-auth"))]
pub async fn fetch_matrix_token_browser(_matrix_url: &str) -> crate::error::Result<String> {
    Err(crate::error::Error::Matrix(
        "Browser authentication not available on this platform".into(),
    ))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn location(resp: &reqwest::Response) -> crate::error::Result<String> {
    resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            crate::error::Error::Matrix(format!("No Location header in {} response", resp.status()))
        })
}

fn extract_form_action(html: &str) -> Option<String> {
    let idx = html.find("action=\"")?;
    let rest = &html[idx + 8..];
    let end = rest.find('"')?;
    Some(rest[..end].replace("&amp;", "&"))
}

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

/// Open `url` in the host's system browser.
///
/// Reuses the same opener chain as the OAuth login flow (custom opener for
/// Android Intent → `open::that()` fallback), so the URL launches in the user's
/// real default browser rather than in a wry sub-WebView. The wry path is what
/// makes Vite-style SPAs render blank with "origin: null" CORS failures, so any
/// UI link that should land in the system browser must route through here.
///
/// Returns the underlying error as a String if every opener path fails.
#[cfg(feature = "browser-auth")]
pub fn open_url_in_browser(url: &str) -> Result<(), String> {
    tracing::info!("[BROWSER_OPEN] Opening URL via system browser: {}", url);

    if let Ok(opener_lock) = BROWSER_OPENER.lock() {
        if let Some(ref opener) = *opener_lock {
            match opener(url) {
                Ok(()) => {
                    tracing::info!("[BROWSER_OPEN] Opened via custom opener");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        "[BROWSER_OPEN] Custom opener failed: {} (falling back to open::that)",
                        e
                    );
                }
            }
        }
    }

    match open::that(url) {
        Ok(()) => {
            tracing::info!("[BROWSER_OPEN] Opened via open::that()");
            Ok(())
        }
        Err(e) => {
            tracing::error!("[BROWSER_OPEN] open::that() failed: {}", e);
            Err(e.to_string())
        }
    }
}

#[cfg(not(feature = "browser-auth"))]
pub fn open_url_in_browser(_url: &str) -> Result<(), String> {
    Err("browser-auth feature not enabled".to_string())
}

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

    // Diagnostic channel: the callback page pings `/diag` immediately before it
    // falls back to the Strategy 3 top-level redirect. That redirect only
    // completes if the server 302s `/auth/refresh?redirect=<loopback>/token`
    // back to us; several server builds instead return the token as JSON and
    // never redirect (see issue #194), which strands the flow. This ping lets
    // us fail fast with an actionable message instead of blocking the full 120s.
    let (diag_tx, diag_rx) = tokio::sync::oneshot::channel::<String>();
    let diag_tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(diag_tx)));

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
                    // Ports 4000 and 5173 are required for CORS (Matrix server whitelist).
                    // Using a random port would cause the callback to timeout due to CORS rejection.
                    tracing::error!(
                        "[BROWSER_AUTH] Ports 4000 and 5173 are busy. Browser OAuth requires one of these ports. \
                         Stop the process using these ports (likely dev servers: `lsof -i :4000` and `lsof -i :5173`)."
                    );
                    return Err(crate::error::Error::Matrix(
                        "matrix: Browser OAuth requires ports 4000 or 5173 to be available. \
                         Both ports are currently in use. Stop any dev servers (Vite, Vue CLI, etc.) \
                         or other processes using these ports and try again. \
                         To check: `lsof -i :4000` and `lsof -i :5173`".to_string()
                    ));
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

    // CSRF `state`: an unguessable, single-use token that binds the browser
    // callback to the flow this connector initiated. `/callback` and `/token`
    // only accept an `access_token` accompanied by a matching `state`, so a
    // cross-site page or a local process cannot fixate an attacker-chosen
    // token into the session while the loopback server is up (issue #375).
    let oauth_state = generate_oauth_state();

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
    let callback_html = build_callback_html(&base, local_port, &oauth_state);

    // -----------------------------------------------------------------------
    // Routes
    // -----------------------------------------------------------------------
    let app = axum::Router::new()
        .route(
            "/callback",
            axum::routing::get({
                let callback_html = callback_html.clone();
                let tx_cb = tx.clone();
                let expected_state = oauth_state.clone();
                move |query: axum::extract::Query<std::collections::HashMap<String, String>>| {
                    let html = callback_html.clone();
                    let tx = tx_cb.clone();
                    let expected_state = expected_state.clone();
                    async move {
                        // If the server already passed the token in the redirect URL,
                        // capture it directly — no HTML page / JS needed. It is only
                        // honored when accompanied by the matching CSRF `state`
                        // (issue #375); otherwise the request is rejected without
                        // touching the token channel.
                        let raw_token = query.get("access_token").map(String::as_str).unwrap_or("");
                        if !raw_token.is_empty() {
                            match accept_callback_token(
                                &expected_state,
                                Some(raw_token),
                                query.get("state").map(String::as_str),
                            ) {
                                Some(token) => {
                                    tracing::info!(
                                        "[BROWSER_AUTH] /callback got valid access_token in URL (len={})",
                                        token.len()
                                    );
                                    if let Some(sender) = tx.lock().await.take() {
                                        let _ = sender.send(token.to_string());
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
                                None => {
                                    tracing::warn!(
                                        "[BROWSER_AUTH] /callback rejected access_token: missing/mismatched CSRF state (possible token fixation)"
                                    );
                                    return axum::response::Html(REJECTED_CALLBACK_HTML.to_string());
                                }
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
                let expected_state = oauth_state.clone();
                move |query: axum::extract::Query<std::collections::HashMap<String, String>>| {
                    let tx = tx.clone();
                    let expected_state = expected_state.clone();
                    async move {
                        tracing::info!(
                            "[BROWSER_AUTH] /token called with query params: {:?}",
                            query.0.keys().collect::<Vec<_>>()
                        );
                        // Accept only a non-empty access_token that carries the
                        // matching CSRF `state`. A cross-site page or local
                        // process that hits /token without the state cannot
                        // fixate a token into the session (issue #375).
                        match accept_callback_token(
                            &expected_state,
                            query.get("access_token").map(String::as_str),
                            query.get("state").map(String::as_str),
                        ) {
                            Some(token) => {
                                tracing::info!(
                                    "[BROWSER_AUTH] access_token accepted (len={}), sending to channel",
                                    token.len()
                                );
                                if let Some(sender) = tx.lock().await.take() {
                                    tracing::info!("[BROWSER_AUTH] Sending token to channel");
                                    let _ = sender.send(token.to_string());
                                } else {
                                    tracing::warn!("[BROWSER_AUTH] Channel sender already consumed!");
                                }
                                axum::response::Html(
                                    "<html><body style='background:#1e1e2e;color:#cdd6f4;\
                                     text-align:center;margin-top:60px;font-family:system-ui'>\
                                     <h2>Login successful!</h2>\
                                     <p>You can close this tab and return to the app.</p>\
                                     </body></html>"
                                        .to_string(),
                                )
                            }
                            None => {
                                let had_token = query
                                    .get("access_token")
                                    .map(|t| !t.is_empty())
                                    .unwrap_or(false);
                                if had_token {
                                    tracing::warn!(
                                        "[BROWSER_AUTH] /token rejected access_token: missing/mismatched CSRF state"
                                    );
                                } else {
                                    tracing::warn!("[BROWSER_AUTH] No access_token in query params");
                                }
                                axum::response::Html("missing token".to_string())
                            }
                        }
                    }
                }
            }),
        )
        .route(
            "/diag",
            axum::routing::get({
                let diag_tx = diag_tx.clone();
                move |query: axum::extract::Query<std::collections::HashMap<String, String>>| {
                    let diag_tx = diag_tx.clone();
                    async move {
                        let stage = query
                            .get("stage")
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string());
                        let reason = query
                            .get("reason")
                            .cloned()
                            .unwrap_or_else(|| "unspecified".to_string());
                        tracing::warn!(
                            "[BROWSER_AUTH] /diag hit before redirect fallback (stage={}, reason={})",
                            stage,
                            reason
                        );
                        if let Some(sender) = diag_tx.lock().await.take() {
                            let _ = sender.send(reason);
                        }
                        axum::response::Html("ok".to_string())
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
        // Carry the CSRF `state` on the loopback redirect so a token the server
        // hands back directly on `/callback?access_token=…` arrives with it
        // (issue #375). The custom percent-encoder below encodes `?`/`=`.
        format!(
            "http://localhost:{}/callback?state={}",
            local_port, oauth_state
        )
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

    // Grace window after the callback page signals it is about to attempt the
    // Strategy 3 redirect. If the server honors `?redirect=`, the token lands
    // on `/token` within this window; if it returns JSON instead (issue #194),
    // nothing more will arrive and we fail fast with a precise diagnostic
    // rather than blocking out the full 120s.
    const REDIRECT_GRACE: std::time::Duration = std::time::Duration::from_secs(15);
    const OVERALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    let token_result = await_browser_token(rx, diag_rx, REDIRECT_GRACE, OVERALL_TIMEOUT).await;

    // Stop the callback server on every exit path so the scarce CORS-whitelisted
    // port (4000/5173) is released even when auth fails.
    let token = match token_result {
        Ok(token) => token,
        Err(e) => {
            server_handle.abort();
            return Err(e);
        }
    };

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

/// Race the token hand-off against the Strategy 3 diagnostic beacon.
///
/// Outcomes, in priority order:
/// * a token arrives on `token_rx` (any strategy succeeded) -> `Ok(token)`;
/// * the callback page pings `/diag` (`diag_rx`) just before the one-way
///   Strategy 3 redirect -> wait `redirect_grace` for a token, then fail fast
///   with the issue #194 contract-gap message if none lands;
/// * neither happens within `overall_timeout` -> the legacy blanket timeout.
///
/// Extracted from [`fetch_matrix_token_browser`] so the wait logic is unit
/// testable without spawning a browser or binding a socket.
#[cfg(feature = "browser-auth")]
async fn await_browser_token(
    mut token_rx: tokio::sync::oneshot::Receiver<String>,
    mut diag_rx: tokio::sync::oneshot::Receiver<String>,
    redirect_grace: std::time::Duration,
    overall_timeout: std::time::Duration,
) -> crate::error::Result<String> {
    let channel_closed = || {
        tracing::error!("[BROWSER_AUTH] Token channel closed unexpectedly");
        crate::error::Error::Matrix("Token channel closed unexpectedly".into())
    };

    let overall = tokio::time::sleep(overall_timeout);
    tokio::pin!(overall);

    // Exhaustive select: exactly one arm resolves, so no surrounding loop is
    // needed. `biased` gives the token precedence over the diagnostic beacon
    // when both are ready in the same poll.
    tokio::select! {
        biased;

        // Token arrived (any strategy succeeded).
        res = &mut token_rx => res.map_err(|_| channel_closed()),

        // Callback page is about to attempt the one-way Strategy 3 redirect.
        // Give the token a short grace window, then fail fast if it never
        // lands: the redirect contract is broken server-side (issue #194).
        diag = &mut diag_rx => {
            let reason = diag.unwrap_or_else(|_| "unspecified".to_string());
            tracing::warn!(
                "[BROWSER_AUTH] Redirect fallback armed (reason={}); waiting {}s for /token",
                reason,
                redirect_grace.as_secs()
            );
            match tokio::time::timeout(redirect_grace, &mut token_rx).await {
                Ok(res) => res.map_err(|_| channel_closed()),
                Err(_) => {
                    tracing::error!(
                        "[BROWSER_AUTH] Token not delivered after redirect fallback (reason={})",
                        reason
                    );
                    Err(crate::error::Error::Matrix(
                        "Browser login could not retrieve the access token. The server \
                         returned the token as JSON instead of redirecting it back to the \
                         connector (GET /auth/refresh?redirect=<loopback>/token did not \
                         302 to the loopback). This is a server-side token-relay contract \
                         gap (issue #194), not a connectivity problem. Update the Strike48 \
                         server to honor the ?redirect= parameter, or supply a token via \
                         MATRIX_AUTH_TOKEN / KEYCLOAK_USERNAME+PASSWORD to bypass browser \
                         OAuth."
                            .into(),
                    ))
                }
            }
        }

        // Hard ceiling: neither a token nor a diagnostic beacon arrived.
        _ = &mut overall => {
            tracing::error!("[BROWSER_AUTH] Timeout waiting for token");
            Err(crate::error::Error::Matrix(
                "Login timed out — no token received within 120 seconds".into(),
            ))
        }
    }
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

// ---------------------------------------------------------------------------
// Browser-OAuth hardening helpers (issue #375)
// ---------------------------------------------------------------------------

/// Encode `value` as a JavaScript string literal safe to embed inside an inline
/// `<script>` element.
///
/// `serde_json` emits a correctly quoted-and-escaped string literal (handling
/// `'`, `"`, `\`, and the C0 control characters). We additionally escape:
/// - `<`/`>` as `\uXXXX` so a value containing `</script>` cannot terminate the
///   surrounding `<script>` block;
/// - U+2028/U+2029, which are valid in JSON but are JavaScript line terminators
///   that would otherwise break out of the string literal.
///
/// Without this a maliciously-configured server URL could break out of the JS
/// string and inject script into the page that handles the access token, which
/// equals token theft.
#[cfg_attr(not(feature = "browser-auth"), allow(dead_code))]
fn js_string_literal(value: &str) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "\"\"".to_string())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Generate an unguessable, single-use CSRF `state` token for the loopback
/// OAuth flow. 122 bits of CSPRNG entropy (UUIDv4), matching the token style
/// already used for connector identifiers elsewhere in the crate.
#[cfg_attr(not(feature = "browser-auth"), allow(dead_code))]
fn generate_oauth_state() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Constant-time equality for the OAuth `state` token.
///
/// The token is single-use per login, so a plain compare would already be
/// safe; constant-time is defense-in-depth against a timing oracle. A missing
/// or differently-sized value never matches.
#[cfg_attr(not(feature = "browser-auth"), allow(dead_code))]
fn state_matches(expected: &str, provided: Option<&str>) -> bool {
    let provided = match provided {
        Some(p) => p.as_bytes(),
        None => return false,
    };
    let expected = expected.as_bytes();
    if expected.len() != provided.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(provided.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Single choke point deciding whether a loopback callback/token request may
/// hand a token to the connector.
///
/// Both `/callback` and `/token` route through this, so the CSRF check cannot
/// be bypassed by hitting one endpoint rather than the other. A token is
/// accepted only when it is non-empty AND accompanied by the matching CSRF
/// `state`. Returns the token to forward, or `None` to reject.
#[cfg_attr(not(feature = "browser-auth"), allow(dead_code))]
fn accept_callback_token<'a>(
    expected_state: &str,
    access_token: Option<&'a str>,
    provided_state: Option<&str>,
) -> Option<&'a str> {
    let token = access_token.filter(|t| !t.is_empty())?;
    if state_matches(expected_state, provided_state) {
        Some(token)
    } else {
        None
    }
}

/// Page shown when a `/callback` token arrives without the matching CSRF state.
#[cfg(feature = "browser-auth")]
const REJECTED_CALLBACK_HTML: &str = "<html><body style='background:#1e1e2e;color:#cdd6f4;\
     text-align:center;margin-top:60px;font-family:system-ui'>\
     <h2>Login could not be verified</h2>\
     <p>This callback did not match the pending login (state mismatch). \
     Please close this tab and start the login again from the app.</p>\
     </body></html>";

/// Build the loopback callback page served on `/callback`.
///
/// `matrix_url` and `oauth_state` are interpolated through [`js_string_literal`]
/// so a hostile configured server URL cannot break out of the inline script
/// (issue #375). The state is embedded so every client-side path that posts to
/// `/token` (Strategies 1 and 2 fetches, and the Strategy 3 redirect target)
/// carries it — otherwise the server-side `/token` state check would reject the
/// legitimate flow.
#[cfg(feature = "browser-auth")]
fn build_callback_html(matrix_url: &str, local_port: u16, oauth_state: &str) -> String {
    format!(
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
  var MATRIX_URL = {matrix_url};
  var OAUTH_STATE = {oauth_state};

  try {{
    log('[CALLBACK] Page loaded, starting token fetch...');
    log('[CALLBACK] Matrix URL: ' + MATRIX_URL);

    // Strategy 1: Token passed directly in the URL query params
    // (server supports redirect-based token relay)
    var params = new URLSearchParams(window.location.search);
    var urlToken = params.get('access_token');
    if (urlToken) {{
      log('[CALLBACK] Got token from URL param (len=' + urlToken.length + ')');
      var localResp = await fetch('/token?access_token=' + encodeURIComponent(urlToken) + '&state=' + encodeURIComponent(OAUTH_STATE));
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
        var localResp = await fetch('/token?access_token=' + encodeURIComponent(token) + '&state=' + encodeURIComponent(OAUTH_STATE));
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
    // /auth/refresh?redirect=<url> is *expected* to do the refresh and 302
    // back to our /token endpoint with ?access_token=xxx appended.
    //
    // Known failure (issue #194): some server builds return the token as a
    // JSON body instead of honoring ?redirect=, so the browser lands on raw
    // JSON on the Matrix origin, this page's JS is gone, and /token is never
    // hit. Because that navigation is one-way, we ping our own same-origin
    // /diag endpoint FIRST so the connector can fail fast with a precise
    // message instead of blocking for the full 120s timeout.
    var tokenUrl = 'http://localhost:' + LOCAL_PORT + '/token?state=' + encodeURIComponent(OAUTH_STATE);
    var refreshUrl = MATRIX_URL + '/auth/refresh?redirect=' + encodeURIComponent(tokenUrl);
    log('[CALLBACK] Strategies 1+2 failed; arming diagnostic before redirect');
    try {{
      await fetch('/diag?stage=strategy3_redirect&reason=' +
        encodeURIComponent(e && e.message ? e.message : 'strategy2_failed'));
    }} catch (diagErr) {{
      log('[CALLBACK] /diag ping failed: ' + diagErr.message);
    }}
    log('[CALLBACK] Redirecting to Matrix origin: ' + refreshUrl);
    s.textContent = 'Completing login…';
    d.textContent = 'Redirecting for token exchange…';
    window.location.href = refreshUrl;
  }}
}})();
</script>
</body></html>"#,
        matrix_url = js_string_literal(matrix_url),
        local_port = local_port,
        oauth_state = js_string_literal(oauth_state),
    )
}

#[cfg(test)]
mod oauth_hardening_tests {
    use super::{accept_callback_token, generate_oauth_state, js_string_literal, state_matches};

    #[test]
    fn js_string_literal_wraps_plain_url_in_double_quotes() {
        assert_eq!(
            js_string_literal("https://host.example:443"),
            "\"https://host.example:443\""
        );
    }

    #[test]
    fn js_string_literal_defuses_single_quote_breakout() {
        // #375 vector: a `'` in the configured URL must stay inside the literal.
        // serde_json double-quotes the value, so a bare `'` cannot close the
        // (now double-quoted) literal. Exactly the two wrapping quotes appear.
        let encoded = js_string_literal("https://evil'-alert(1)-'");
        assert!(encoded.starts_with('"') && encoded.ends_with('"'));
        assert_eq!(
            encoded.matches('"').count(),
            2,
            "unexpected quote: {encoded}"
        );
    }

    #[test]
    fn js_string_literal_neutralizes_script_close() {
        // A value carrying </script> must not terminate the inline <script>.
        let encoded = js_string_literal("x</script><script>alert(1)</script>");
        assert!(!encoded.contains('<'), "'<' must be escaped, got {encoded}");
        assert!(!encoded.contains('>'), "'>' must be escaped, got {encoded}");
        assert!(!encoded.contains("</script>"));
        assert!(encoded.contains("\\u003c") && encoded.contains("\\u003e"));
    }

    #[test]
    fn js_string_literal_escapes_js_line_terminators() {
        // U+2028/U+2029 are valid JSON but are JS line terminators that would
        // otherwise break out of the string literal inside a <script> block.
        let encoded = js_string_literal("https://evil\u{2028}alert(1)//\u{2029}x");
        assert!(
            !encoded.contains('\u{2028}'),
            "U+2028 must be escaped: {encoded}"
        );
        assert!(
            !encoded.contains('\u{2029}'),
            "U+2029 must be escaped: {encoded}"
        );
        assert!(encoded.contains("\\u2028") && encoded.contains("\\u2029"));
    }

    #[test]
    fn generate_oauth_state_is_unique_and_unguessable() {
        let a = generate_oauth_state();
        let b = generate_oauth_state();
        assert_ne!(a, b, "state must not repeat between logins");
        assert!(!a.is_empty());
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    }

    #[test]
    fn state_matches_only_on_exact_value() {
        let s = generate_oauth_state();
        assert!(state_matches(&s, Some(&s)));
        assert!(!state_matches(&s, Some("nope")));
        assert!(
            !state_matches(&s, Some(&format!("{s}x"))),
            "length mismatch"
        );
        assert!(!state_matches(&s, None), "missing state must not match");
    }

    #[test]
    fn accept_callback_token_requires_matching_state() {
        let st = "s3cr3t-state";
        // Happy path: non-empty token WITH the matching state.
        assert_eq!(
            accept_callback_token(st, Some("jwt"), Some("s3cr3t-state")),
            Some("jwt")
        );
        // CSRF: correct token shape, wrong or absent state -> rejected. These
        // go red if the state gate is removed from the choke point.
        assert_eq!(accept_callback_token(st, Some("jwt"), Some("wrong")), None);
        assert_eq!(accept_callback_token(st, Some("jwt"), None), None);
        // Degenerate tokens -> rejected regardless of state.
        assert_eq!(
            accept_callback_token(st, Some(""), Some("s3cr3t-state")),
            None
        );
        assert_eq!(accept_callback_token(st, None, Some("s3cr3t-state")), None);
    }
}

#[cfg(all(test, feature = "browser-auth"))]
mod callback_html_tests {
    use super::build_callback_html;

    #[test]
    fn malicious_matrix_url_cannot_break_out_of_script() {
        // A configured server URL laced with a script-close plus a quote
        // breakout must escape neither the inline <script> nor the JS literal.
        // Reverting the js_string_literal wiring turns this red.
        let html =
            build_callback_html("https://evil'</script><script>steal()//", 4000, "abc-state");
        // Our page carries exactly one <script>...</script>; no injected pair.
        assert_eq!(html.matches("<script>").count(), 1, "injected <script>");
        assert_eq!(html.matches("</script>").count(), 1, "injected </script>");
        // matrix_url is embedded as a double-quoted literal, so the `'` is inert
        // data, and the </script> from the payload is unicode-escaped.
        assert!(html.contains("var MATRIX_URL = \"https://evil'"));
        assert!(html.contains("\\u003c/script\\u003e"));
    }

    #[test]
    fn callback_html_wires_state_into_every_token_path() {
        // The CSRF state must reach every path that posts to /token, or the
        // /token state check would reject the legitimate flow.
        let html = build_callback_html("https://host", 4000, "the-state-token");
        assert!(html.contains("var OAUTH_STATE = \"the-state-token\";"));
        // Strategy 1 + Strategy 2 same-origin fetches carry the state.
        assert_eq!(
            html.matches("'&state=' + encodeURIComponent(OAUTH_STATE)")
                .count(),
            2,
            "both /token fetches must append the state"
        );
        // Strategy 3 redirect target carries the state.
        assert!(html.contains("'/token?state=' + encodeURIComponent(OAUTH_STATE)"));
    }
}

#[cfg(all(test, feature = "browser-auth"))]
mod browser_token_tests {
    use super::await_browser_token;
    use std::time::Duration;
    use tokio::sync::oneshot;

    // Generous durations relative to the sub-millisecond channel sends below,
    // so the test asserts *which* branch wins, not wall-clock timing.
    const GRACE: Duration = Duration::from_millis(200);
    const OVERALL: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn returns_token_when_delivered() {
        let (tx, rx) = oneshot::channel();
        let (_diag_tx, diag_rx) = oneshot::channel();
        tx.send("jwt-abc".to_string()).unwrap();

        let result = await_browser_token(rx, diag_rx, GRACE, OVERALL).await;
        assert_eq!(result.unwrap(), "jwt-abc");
    }

    #[tokio::test]
    async fn token_wins_over_diagnostic_when_both_present() {
        // Both ready in the same poll: the `biased` outer select resolves via
        // the token arm before the diag arm runs. Token must win.
        let (tx, rx) = oneshot::channel();
        let (diag_tx, diag_rx) = oneshot::channel();
        diag_tx.send("strategy2_failed".to_string()).unwrap();
        tx.send("jwt-relayed".to_string()).unwrap();

        let result = await_browser_token(rx, diag_rx, GRACE, OVERALL).await;
        assert_eq!(result.unwrap(), "jwt-relayed");
    }

    #[tokio::test(start_paused = true)]
    async fn token_arrives_within_grace_after_diag_fires() {
        // Strategy 3 legitimately worked but slowly: the diag beacon fired
        // first (strategies 1-2 failed), then the redirect round-trip delivered
        // the token partway through the grace window. This exercises the
        // `Ok(res)` arm of the nested grace-window timeout - the branch a
        // too-short grace would regress into a spurious login failure.
        let (tx, rx) = oneshot::channel();
        let (diag_tx, diag_rx) = oneshot::channel();
        diag_tx.send("strategy2_failed".to_string()).unwrap();

        // Deliver the token after the diag arm has entered its grace wait, but
        // well within GRACE. `start_paused` makes the sleep advance virtual
        // time deterministically.
        tokio::spawn(async move {
            tokio::time::sleep(GRACE / 3).await;
            tx.send("jwt-delayed-relay".to_string()).unwrap();
        });

        let result = await_browser_token(rx, diag_rx, GRACE, OVERALL).await;
        assert_eq!(result.unwrap(), "jwt-delayed-relay");
    }

    #[tokio::test(start_paused = true)]
    async fn fails_fast_with_contract_message_when_redirect_lands_on_json() {
        // The #194 case: /diag fires, no token ever arrives. We must fail with
        // the server-contract diagnostic bounded by the grace window, not the
        // 120s ceiling. `start_paused` makes the timing deterministic (no
        // wall-clock dependence, so no CI flakiness).
        let (_tx, rx) = oneshot::channel();
        let (diag_tx, diag_rx) = oneshot::channel();
        diag_tx
            .send("cross-origin fetch returned 401".to_string())
            .unwrap();

        let start = tokio::time::Instant::now();
        let result = await_browser_token(rx, diag_rx, GRACE, OVERALL).await;
        let elapsed = start.elapsed();

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("issue #194") && err.contains("redirect"),
            "expected contract-gap diagnostic, got: {err}"
        );
        // Fast-fail: bounded by the grace window, nowhere near the 120s ceiling.
        assert!(
            elapsed >= GRACE && elapsed < OVERALL,
            "should fail via the {GRACE:?} grace window, took {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn overall_timeout_when_nothing_arrives() {
        // Neither a token nor a diagnostic beacon: fall through to the ceiling.
        let (_tx, rx) = oneshot::channel();
        let (_diag_tx, diag_rx) = oneshot::channel();

        let result = await_browser_token(rx, diag_rx, GRACE, OVERALL).await;
        let err = result.unwrap_err().to_string();
        assert!(err.contains("timed out"), "expected timeout, got: {err}");
    }

    #[tokio::test(start_paused = true)]
    async fn errors_when_token_sender_dropped_before_diag() {
        // The token sender is dropped without sending and no diag fires: the
        // outer token arm sees the channel close and maps to channel-closed.
        let (tx, rx) = oneshot::channel::<String>();
        let (_diag_tx, diag_rx) = oneshot::channel();
        drop(tx);

        let result = await_browser_token(rx, diag_rx, GRACE, OVERALL).await;
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("channel closed"),
            "expected channel-closed error, got: {err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn errors_when_token_sender_dropped_during_grace() {
        // Diag fires, then the token sender is dropped during the grace window:
        // the nested grace wait sees the channel close and maps to
        // channel-closed (line 803), not the #194 contract-gap message.
        let (tx, rx) = oneshot::channel::<String>();
        let (diag_tx, diag_rx) = oneshot::channel();
        diag_tx.send("strategy2_failed".to_string()).unwrap();

        tokio::spawn(async move {
            tokio::time::sleep(GRACE / 3).await;
            drop(tx);
        });

        let result = await_browser_token(rx, diag_rx, GRACE, OVERALL).await;
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("channel closed"),
            "expected channel-closed error, got: {err}"
        );
    }
}

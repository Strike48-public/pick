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
        .danger_accept_invalid_certs(super::insecure_tls())
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

/// Oneshot sender for the Android native-OAuth login currently in flight, if
/// any. `OAuthCallbackActivity` completes it via [`deliver_native_oauth_callback`]
/// (JNI) rather than the loopback server, which can't survive the app being
/// backgrounded while the system browser is open.
#[cfg(feature = "browser-auth")]
static NATIVE_OAUTH_TX: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<String>>> =
    std::sync::Mutex::new(None);

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

/// Native web-auth-session hook (iOS `ASWebAuthenticationSession`).
///
/// Given the login URL and the callback URL scheme (e.g. `com.strike48.pentest`),
/// present the platform's in-app auth browser and return the full callback URL
/// (`com.strike48.pentest://oauth/callback?...`) it redirects to. Blocking; the
/// caller runs it on a blocking thread. When registered, iOS uses this instead
/// of the loopback callback server (which can't work: launching a browser
/// backgrounds the app and suspends the server).
#[cfg(feature = "browser-auth")]
type WebAuthSessionFn = Option<Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>>;

#[cfg(feature = "browser-auth")]
static WEB_AUTH_SESSION: std::sync::Mutex<WebAuthSessionFn> = std::sync::Mutex::new(None);

/// Register a native web-auth-session provider (iOS `ASWebAuthenticationSession`).
#[cfg(feature = "browser-auth")]
pub fn set_web_auth_session<F>(session: F)
where
    F: Fn(&str, &str) -> Result<String, String> + Send + Sync + 'static,
{
    if let Ok(mut lock) = WEB_AUTH_SESSION.lock() {
        *lock = Some(Box::new(session));
    }
}

/// Custom URL scheme (no path) for the native OAuth callback, used as the
/// `ASWebAuthenticationSession` callback scheme on iOS.
#[cfg(feature = "browser-auth")]
const NATIVE_OAUTH_SCHEME: &str = "com.strike48.pentest";

/// Deliver an Android native-OAuth callback URL into the in-flight login.
///
/// `OAuthCallbackActivity` calls this (via its JNI export in the app's native
/// lib) with the full custom-scheme callback URL — e.g.
/// `com.strike48.pentest://oauth/callback?access_token=...` — after the OS
/// routes the browser redirect back to the app. We parse the token and complete
/// the oneshot that [`fetch_matrix_token_browser`] is awaiting. This replaces
/// the loopback HTTP hand-off, which fails on Android because launching the
/// browser backgrounds the app and the OS suspends the callback server.
///
/// Returns `true` when a login was waiting and a token was delivered.
///
/// The token is ALSO cached in [`BROWSER_TOKEN_CACHE`] unconditionally, so a
/// callback that arrives after the awaiting login timed out (a slow interactive
/// browser sign-in can exceed the wait) is not lost: the next
/// [`fetch_matrix_token_browser`] serves it from cache with no second browser
/// round-trip.
#[cfg(feature = "browser-auth")]
pub fn deliver_native_oauth_callback(callback_url: &str) -> bool {
    let Some(token) = token_from_callback_url(callback_url) else {
        tracing::warn!("[BROWSER_AUTH] native OAuth callback URL contained no access_token");
        return false;
    };
    // Cache first so a late callback (past the await timeout) still lands.
    if let Ok(mut cache) = BROWSER_TOKEN_CACHE.lock() {
        *cache = Some(token.clone());
    }
    let sender = match NATIVE_OAUTH_TX.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => {
            tracing::error!("[BROWSER_AUTH] native OAuth sender lock poisoned");
            return false;
        }
    };
    match sender {
        Some(tx) => tx.send(token).is_ok(),
        None => {
            // No login awaiting (it timed out, or the app relaunched). The token
            // is cached above, so a subsequent sign-in reuses it immediately.
            tracing::info!(
                "[BROWSER_AUTH] native OAuth callback cached; no login in flight (will reuse)"
            );
            true
        }
    }
}

/// If a native web-auth-session is registered (iOS), run the OIDC flow through
/// it and return the token. Returns `Ok(None)` when no session is registered so
/// the caller falls through to the loopback-server flow (desktop/Android).
///
/// The provider presents `ASWebAuthenticationSession` for
/// `{base}/auth/login?redirect=com.strike48.pentest://oauth/callback` and
/// returns the callback URL; we pull `access_token` from its query.
#[cfg(feature = "browser-auth")]
async fn try_native_web_auth_session(base: &str) -> crate::error::Result<Option<String>> {
    let has_session = WEB_AUTH_SESSION
        .lock()
        .map(|l| l.is_some())
        .unwrap_or(false);
    if !has_session {
        return Ok(None);
    }

    // Build the login URL with the native-scheme redirect using the url crate
    // (reqwest re-exports it) so query encoding is correct, not hand-rolled.
    let redirect = format!("{NATIVE_OAUTH_SCHEME}://oauth/callback");
    let mut login_url = reqwest::Url::parse(base)
        .map_err(|e| crate::error::Error::Matrix(format!("invalid Matrix base URL: {e}")))?;
    login_url.set_path("/auth/login");
    login_url
        .query_pairs_mut()
        .append_pair("redirect", &redirect);
    let login_url = login_url.to_string();
    tracing::info!("[BROWSER_AUTH] iOS: presenting web auth session -> {login_url}");

    // The session is blocking (waits for the user + callback), so run it off the
    // async executor.
    let scheme = NATIVE_OAUTH_SCHEME.to_string();
    let callback_url = tokio::task::spawn_blocking(move || {
        let lock = WEB_AUTH_SESSION
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?;
        let session = lock
            .as_ref()
            .ok_or_else(|| "no web auth session".to_string())?;
        session(&login_url, &scheme)
    })
    .await
    .map_err(|e| crate::error::Error::Matrix(format!("web auth task join error: {e}")))?
    .map_err(crate::error::Error::Matrix)?;

    tracing::info!("[BROWSER_AUTH] iOS: web auth session returned a callback URL");
    let token = token_from_callback_url(&callback_url).ok_or_else(|| {
        crate::error::Error::Matrix(
            "iOS web auth callback URL contained no access_token".to_string(),
        )
    })?;

    // Cache like the loopback flow does, so a later chat visit reuses it.
    if let Ok(mut cache) = BROWSER_TOKEN_CACHE.lock() {
        *cache = Some(token.clone());
    }
    Ok(Some(token))
}

/// Extract the `access_token` query parameter from a callback URL, using the
/// url crate's parser (handles percent-decoding). The callback carries the
/// token in either the query string or the fragment, so try both.
#[cfg(feature = "browser-auth")]
fn token_from_callback_url(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if let Some((_, v)) = parsed.query_pairs().find(|(k, _)| k == "access_token") {
        if !v.is_empty() {
            return Some(v.into_owned());
        }
    }
    // Fragment form: ...#access_token=...&token_type=...
    if let Some(frag) = parsed.fragment() {
        for (k, v) in reqwest::Url::parse(&format!("{NATIVE_OAUTH_SCHEME}://x/?{frag}"))
            .ok()?
            .query_pairs()
        {
            if k == "access_token" && !v.is_empty() {
                return Some(v.into_owned());
            }
        }
    }
    None
}

/// Android native OAuth: open the system browser and await the token that
/// `OAuthCallbackActivity` delivers via [`deliver_native_oauth_callback`].
///
/// This is the Android analog of [`try_native_web_auth_session`] (iOS). Both
/// avoid the loopback callback server, which can't work on mobile: launching
/// the browser backgrounds the app, so the in-process HTTP listener is
/// suspended and the custom-scheme redirect has nothing to reach. Instead the
/// OS routes `com.strike48.pentest://oauth/callback?access_token=...` to our
/// exported Activity, which hands the URL straight into the core over JNI.
///
/// Returns `Ok(None)` on non-Android targets so desktop falls through to the
/// loopback-server flow.
#[cfg(feature = "browser-auth")]
async fn try_native_android_oauth(base: &str) -> crate::error::Result<Option<String>> {
    if !cfg!(target_os = "android") {
        return Ok(None);
    }

    // Build `{base}/auth/login?redirect=com.strike48.pentest://oauth/callback`
    // with the url crate so query encoding is correct (not hand-rolled).
    let redirect = format!("{NATIVE_OAUTH_SCHEME}://oauth/callback");
    let mut login_url = reqwest::Url::parse(base)
        .map_err(|e| crate::error::Error::Matrix(format!("invalid Matrix base URL: {e}")))?;
    login_url.set_path("/auth/login");
    login_url
        .query_pairs_mut()
        .append_pair("redirect", &redirect);
    let login_url = login_url.to_string();

    // Register the oneshot BEFORE opening the browser so a fast callback can't
    // race us. Replacing any stale sender abandons a prior abandoned attempt.
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    match NATIVE_OAUTH_TX.lock() {
        Ok(mut guard) => *guard = Some(tx),
        Err(_) => {
            return Err(crate::error::Error::Matrix(
                "native OAuth sender lock poisoned".to_string(),
            ))
        }
    }

    tracing::info!("[BROWSER_AUTH] Android: opening browser for native OAuth -> {login_url}");
    open_url_via_opener(&login_url);

    // Wait for the Activity to deliver the token (or time out). A first-time
    // interactive browser sign-in (Keycloak form + consent, on a cold browser)
    // can take well over two minutes, so give it a generous 5-minute window;
    // observed real logins landed at ~2m20s and were lost under the old 120s cap.
    // A late callback past even this is still recovered from BROWSER_TOKEN_CACHE
    // (see `deliver_native_oauth_callback`).
    const OAUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
    let token = match tokio::time::timeout(OAUTH_TIMEOUT, rx).await {
        Ok(Ok(token)) => token,
        Ok(Err(_)) => {
            // Sender dropped without sending (e.g. a later attempt replaced it).
            let _ = NATIVE_OAUTH_TX.lock().map(|mut g| g.take());
            return Err(crate::error::Error::Matrix(
                "native OAuth callback channel closed".to_string(),
            ));
        }
        Err(_) => {
            let _ = NATIVE_OAUTH_TX.lock().map(|mut g| g.take());
            return Err(crate::error::Error::Matrix(
                "native OAuth timed out waiting for callback".to_string(),
            ));
        }
    };

    if token.is_empty() {
        return Err(crate::error::Error::Matrix(
            "native OAuth delivered an empty token".to_string(),
        ));
    }

    // Cache like the loopback flow does, so a later chat visit reuses it.
    if let Ok(mut cache) = BROWSER_TOKEN_CACHE.lock() {
        *cache = Some(token.clone());
    }
    Ok(Some(token))
}

/// Open a URL using the registered platform browser opener, falling back to
/// `open::that`. Shared by the Android native-OAuth and loopback flows.
#[cfg(feature = "browser-auth")]
fn open_url_via_opener(url: &str) {
    if let Ok(opener_lock) = BROWSER_OPENER.lock() {
        if let Some(ref opener) = *opener_lock {
            match opener(url) {
                Ok(_) => {
                    tracing::info!("[BROWSER_AUTH] Browser opened via custom opener");
                    return;
                }
                Err(e) => tracing::warn!("[BROWSER_AUTH] Custom browser opener failed: {e}"),
            }
        }
    }
    if let Err(e) = open::that(url) {
        tracing::error!(
            "[BROWSER_AUTH] Failed to open browser: {e}. Please open this URL manually:\n{url}"
        );
    } else {
        tracing::info!("[BROWSER_AUTH] Browser opened via open::that()");
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

    // iOS: use the native ASWebAuthenticationSession when registered. It keeps
    // the app foregrounded and delivers the custom-scheme callback URL directly,
    // so we skip the loopback callback server entirely (that server can't work
    // on iOS — launching a browser suspends the app process).
    if let Some(token) = try_native_web_auth_session(&base).await? {
        return Ok(token);
    }

    // Android: route the custom-scheme redirect to OAuthCallbackActivity, which
    // delivers the token over JNI. Like iOS, this skips the loopback server (it
    // can't survive the app being backgrounded while the browser is open).
    if let Some(token) = try_native_android_oauth(&base).await? {
        return Ok(token);
    }

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
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Signing in to Pick</title>
<style>
  :root {{ --sage:#9cbfae; --ink:#17201b; --bg:#1b211e; --surface:#242b27; --text:#e9eeeb; --muted:rgba(233,238,235,0.62); }}
  * {{ box-sizing:border-box; }}
  body {{ font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; margin:0; min-height:100vh;
         display:flex; align-items:center; justify-content:center; background:var(--bg); color:var(--text); }}
  .card {{ text-align:center; padding:40px 28px; max-width:420px; }}
  .badge {{ width:56px; height:56px; border-radius:16px; background:var(--sage); color:var(--ink);
            display:flex; align-items:center; justify-content:center; margin:0 auto 20px;
            font-size:30px; font-weight:700; }}
  #status {{ font-size:1.35rem; font-weight:600; margin:0 0 8px; }}
  #detail {{ font-size:0.95rem; color:var(--muted); line-height:1.5; margin:0; }}
  .spinner {{ width:28px; height:28px; margin:22px auto 0; border:3px solid var(--surface);
              border-top-color:var(--sage); border-radius:50%; animation:spin 0.8s linear infinite; }}
  @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
  .done .spinner {{ display:none; }}
  #debug {{ display:none; }}
</style></head>
<body>
<div class="card" id="card">
  <div class="badge">S</div>
  <h1 id="status">Completing sign-in…</h1>
  <p id="detail">Fetching your access token from Strike48.</p>
  <div class="spinner"></div>
</div>
<pre id="debug"></pre>
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
      s.textContent = 'You are signed in';
      d.textContent = 'You can close this tab and return to Pick to start scanning.';
      document.getElementById('card').classList.add('done');
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
    // /auth/refresh?redirect=<url> is *expected* to do the refresh and 302
    // back to our /token endpoint with ?access_token=xxx appended.
    //
    // Known failure (issue #194): some server builds return the token as a
    // JSON body instead of honoring ?redirect=, so the browser lands on raw
    // JSON on the Matrix origin, this page's JS is gone, and /token is never
    // hit. Because that navigation is one-way, we ping our own same-origin
    // /diag endpoint FIRST so the connector can fail fast with a precise
    // message instead of blocking for the full 120s timeout.
    var tokenUrl = 'http://localhost:' + LOCAL_PORT + '/token';
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

    // This loopback flow is desktop-only: Android and iOS return their token
    // from the native paths above before reaching here. The browser reaches the
    // callback server directly over localhost.
    let redirect_url = format!("http://localhost:{}/callback", local_port);

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

    open_url_via_opener(&login_url);

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

#[cfg(all(test, feature = "browser-auth"))]
mod native_oauth_tests {
    use super::{
        cached_browser_token, clear_browser_token_cache, deliver_native_oauth_callback,
        NATIVE_OAUTH_TX,
    };

    // All cases live in one test: they share the NATIVE_OAUTH_TX process-global,
    // so running them as separate #[test]s would race under the default
    // multi-threaded runner. Each case resets the global before it runs.
    #[test]
    fn native_oauth_delivery() {
        // A callback URL completes the in-flight oneshot with the parsed token.
        {
            let (tx, rx) = tokio::sync::oneshot::channel::<String>();
            *NATIVE_OAUTH_TX.lock().unwrap() = Some(tx);
            let delivered = deliver_native_oauth_callback(
                "com.strike48.pentest://oauth/callback?access_token=jwt-native",
            );
            assert!(delivered, "delivery should succeed when a login is waiting");
            assert_eq!(rx.blocking_recv().unwrap(), "jwt-native");
            // The sender is taken on delivery, so the slot is cleared.
            assert!(NATIVE_OAUTH_TX.lock().unwrap().is_none());
        }

        // A callback with no access_token neither delivers nor consumes the
        // waiting sender (so a later valid callback can still arrive).
        {
            let (tx, _rx) = tokio::sync::oneshot::channel::<String>();
            *NATIVE_OAUTH_TX.lock().unwrap() = Some(tx);
            let delivered =
                deliver_native_oauth_callback("com.strike48.pentest://oauth/callback?error=denied");
            assert!(!delivered, "no token in URL should not report success");
            assert!(
                NATIVE_OAUTH_TX.lock().unwrap().is_some(),
                "waiting sender must survive a tokenless callback"
            );
            NATIVE_OAUTH_TX.lock().unwrap().take();
        }

        // A callback with no login in flight still succeeds by caching the token
        // (recovers a late/post-timeout callback for the next sign-in).
        {
            NATIVE_OAUTH_TX.lock().unwrap().take();
            clear_browser_token_cache();
            let delivered = deliver_native_oauth_callback(
                "com.strike48.pentest://oauth/callback?access_token=orphan",
            );
            assert!(
                delivered,
                "delivery with no login in flight should still cache + report success"
            );
            assert_eq!(
                cached_browser_token().as_deref(),
                Some("orphan"),
                "token must be cached for the next sign-in to reuse"
            );
            clear_browser_token_cache();
        }
    }
}

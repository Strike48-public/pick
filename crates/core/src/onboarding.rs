//! One-command onboarding: connect Pick to any Prospector Studio from a URL.
//!
//! `pick connect <url>` should be all a first-time operator needs. This module
//! turns a single Studio URL into a registered connector:
//!
//! 1. Validate + normalize the URL into an HTTP API base and a WebSocket host.
//! 2. Obtain a Keycloak bearer token via the browser ([`crate::matrix::fetch_matrix_token_browser`]).
//!    That reuses the proven `{api}/auth/login` mediation — Matrix runs the full
//!    OIDC/PKCE dance server-side, so we never touch Keycloak endpoints, realms,
//!    or client-redirect whitelists directly.
//! 3. Resolve the tenant from the authenticated session ([`fetch_tenant_id`]).
//! 4. Mint a pre-approved OTT ([`create_pre_approved_token`]) so registration is
//!    auto-approved. If the Studio has that endpoint disabled, degrade to the
//!    post-approval flow (register pending, approve once in Studio).
//! 5. Persist a [`ConnectorConfig`] (with a URL-scoped instance id, so a new
//!    Studio never replays another tenant's saved credential).
//!
//! The browser step requires the `browser-auth` feature and a local browser;
//! remote/headless hosts use the post-approval flow or `scripts/connect.sh`.

use crate::config::ConnectorConfig;

/// SDK connector type for Pick (matches the credential-file / gateway naming).
#[cfg(feature = "browser-auth")]
const CONNECTOR_TYPE: &str = "pentest-connector";

/// How the connector will authenticate to the Studio after onboarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationMode {
    /// A pre-approved OTT was minted; the connector self-registers with no
    /// manual step. Carries the OTT JSON for `STRIKE48_REGISTRATION_TOKEN`.
    PreApproved,
    /// The Studio has no pre-approve endpoint; the connector registers in
    /// pending state and an operator must approve it in Studio once.
    PendingApproval,
}

/// The result of onboarding: everything a caller needs to start the connector.
#[derive(Debug, Clone)]
pub struct StudioConnection {
    /// HTTP API base, e.g. `https://studio.example.com` (no trailing slash).
    pub api_url: String,
    /// Persisted connector config (host, tenant, instance id, TLS).
    pub config: ConnectorConfig,
    /// OTT JSON for `STRIKE48_REGISTRATION_TOKEN`, when [`RegistrationMode::PreApproved`].
    pub ott: Option<String>,
    /// Whether registration is auto-approved or awaits Studio approval.
    pub mode: RegistrationMode,
}

/// Validate and normalize a user-typed Studio URL into an HTTP(S) API base.
///
/// Defaults a bare host to `https://`, trims a trailing slash, and rejects
/// userinfo (`user:pass@host`) to avoid confusion attacks. Returns `None` for
/// anything that is not a plausible `http(s)://host` URL. Ported from StrikeHub.
pub fn validate_studio_url(raw: &str) -> Option<String> {
    let mut u = raw.trim().to_string();
    if u.is_empty() {
        return None;
    }
    if !u.starts_with("http://") && !u.starts_with("https://") {
        u = format!("https://{u}");
    }
    let u = u.trim_end_matches('/').to_string();
    let host_part = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
        .unwrap_or("");
    let authority = host_part.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    // Reject userinfo (raw `@` or percent-encoded `%40`) in the authority.
    if authority.contains('@') || authority.to_lowercase().contains("%40") {
        return None;
    }
    if u.len() > 2048 {
        return None;
    }
    Some(u)
}

/// Derive the WebSocket host and TLS flag from a validated HTTP API base.
///
/// `https://host[:port]` -> (`wss://host[:port]`, true); `http://...` -> (`ws://...`, false).
///
/// Ungated (with pure `parse_tenant_id`) so their unit tests run on every CI
/// lane, not only where `browser-auth` is unified in; `allow(dead_code)` covers
/// the non-`browser-auth` build where only the tests exercise it.
#[cfg_attr(not(feature = "browser-auth"), allow(dead_code))]
fn derive_ws_host(api_url: &str) -> (String, bool) {
    if let Some(rest) = api_url.strip_prefix("https://") {
        (format!("wss://{rest}"), true)
    } else if let Some(rest) = api_url.strip_prefix("http://") {
        (format!("ws://{rest}"), false)
    } else {
        // validate_studio_url guarantees a scheme, but stay total.
        (format!("wss://{api_url}"), true)
    }
}

#[cfg(feature = "browser-auth")]
fn http_client() -> reqwest::Client {
    let insecure = std::env::var("MATRIX_TLS_INSECURE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Resolve the tenant UUID for the authenticated session via the Studio's
/// GraphQL API (`userDetails.details.domain.id`). Ported from StrikeHub.
#[cfg(feature = "browser-auth")]
async fn fetch_tenant_id(api_url: &str, jwt: &str) -> anyhow::Result<String> {
    let url = format!("{}/api/v1alpha/graphql", api_url.trim_end_matches('/'));
    let query = serde_json::json!({ "query": "query { userDetails { details } }" });
    let body = http_client()
        .post(&url)
        .header("Authorization", format!("Bearer {jwt}"))
        .json(&query)
        .send()
        .await?
        .text()
        .await?;
    parse_tenant_id(&body)
        .ok_or_else(|| anyhow::anyhow!("could not resolve tenant id from userDetails response"))
}

/// Extract `data.userDetails.details.domain.id` from a GraphQL response.
/// `details` may arrive as an object or as a stringified JSON blob.
#[cfg_attr(not(feature = "browser-auth"), allow(dead_code))]
fn parse_tenant_id(raw: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let details = v.pointer("/data/userDetails/details")?;
    let details = if let Some(s) = details.as_str() {
        serde_json::from_str::<serde_json::Value>(s).ok()?
    } else {
        details.clone()
    };
    details.pointer("/domain/id")?.as_str().map(String::from)
}

/// Mint a pre-approved OTT via the Studio's `/api/connectors/pre-approve`
/// endpoint. Returns the OTT as JSON `{"token","matrix_url"}` embedding the real
/// API base (the SDK register-with-ott path requires it, and a mismatched origin
/// is refused). `Ok(None)` means the endpoint is absent/forbidden — the caller
/// should fall back to the post-approval flow. Ported from StrikeHub.
#[cfg(feature = "browser-auth")]
async fn create_pre_approved_token(
    api_url: &str,
    jwt: &str,
    connector_type: &str,
) -> anyhow::Result<Option<String>> {
    let base = api_url.trim_end_matches('/');
    let url = format!("{base}/api/connectors/pre-approve");
    let payload = serde_json::json!({ "connector_type": connector_type, "ttl_minutes": 5 });
    let resp = http_client()
        .post(&url)
        .header("Authorization", format!("Bearer {jwt}"))
        .json(&payload)
        .send()
        .await?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::FORBIDDEN {
        tracing::warn!(
            "pre-approve endpoint unavailable ({status}); falling back to post-approval"
        );
        return Ok(None);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(300).collect();
        anyhow::bail!("pre-approve failed: {status} — {snippet}");
    }

    let body: serde_json::Value = resp.json().await?;
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("no token in pre-approve response"))?;
    Ok(Some(
        serde_json::json!({ "token": token, "matrix_url": base }).to_string(),
    ))
}

/// Build and persist the connector config for a resolved Studio + tenant.
/// Uses a URL-scoped instance id so a new Studio never replays another tenant's
/// saved credential (the recurring "Registration failed" cause).
#[cfg(feature = "browser-auth")]
fn persist_config(api_url: &str, tenant_id: String) -> anyhow::Result<ConnectorConfig> {
    let (ws_host, use_tls) = derive_ws_host(api_url);

    let mut settings = crate::settings::load_settings();
    settings.ensure_device_id();
    let instance_id = ConnectorConfig::env_scoped_instance_id(&settings.device_id, &ws_host);

    let mut config = ConnectorConfig::new(ws_host).tenant_id(tenant_id);
    config.instance_id = instance_id;
    config.use_tls = use_tls;

    settings.last_config = Some(config.clone());
    settings.auto_connect = true;
    crate::settings::save_settings(&settings)?;
    Ok(config)
}

/// Onboard Pick to a Prospector Studio from just a URL: browser login, tenant
/// discovery, pre-approve, and config persistence. Requires the `browser-auth`
/// feature and a local browser.
#[cfg(feature = "browser-auth")]
pub async fn connect_to_studio(raw_url: &str) -> anyhow::Result<StudioConnection> {
    let api_url = validate_studio_url(raw_url)
        .ok_or_else(|| anyhow::anyhow!("not a valid Studio URL: {raw_url}"))?;

    tracing::info!("onboarding: opening browser to sign in at {api_url}");
    let jwt = crate::matrix::fetch_matrix_token_browser(&api_url).await?;

    let tenant_id = fetch_tenant_id(&api_url, &jwt).await?;
    tracing::info!("onboarding: resolved tenant {tenant_id}");

    let (ott, mode) = match create_pre_approved_token(&api_url, &jwt, CONNECTOR_TYPE).await? {
        Some(token) => (Some(token), RegistrationMode::PreApproved),
        None => (None, RegistrationMode::PendingApproval),
    };

    let config = persist_config(&api_url, tenant_id)?;
    Ok(StudioConnection {
        api_url,
        config,
        ott,
        mode,
    })
}

/// Stub when the `browser-auth` feature is disabled: interactive login needs a
/// browser. Remote/headless hosts use the post-approval flow or `scripts/connect.sh`.
#[cfg(not(feature = "browser-auth"))]
pub async fn connect_to_studio(_raw_url: &str) -> anyhow::Result<StudioConnection> {
    anyhow::bail!(
        "`pick connect <url>` requires a browser (build with the `browser-auth` feature); \
         on a headless/remote host use scripts/connect.sh plus Studio approval"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_studio_url_defaults_https_and_trims_slash() {
        assert_eq!(
            validate_studio_url("discoball.example.com"),
            Some("https://discoball.example.com".to_string())
        );
        assert_eq!(
            validate_studio_url("https://foo.example.com/"),
            Some("https://foo.example.com".to_string())
        );
        assert_eq!(
            validate_studio_url("http://localhost:4000"),
            Some("http://localhost:4000".to_string())
        );
    }

    #[test]
    fn validate_studio_url_rejects_userinfo_and_empty() {
        assert_eq!(validate_studio_url(""), None);
        assert_eq!(
            validate_studio_url("https://user:pass@evil.example.com"),
            None
        );
        assert_eq!(
            validate_studio_url("https://evil.example.com%40attacker"),
            None
        );
    }

    #[test]
    fn derive_ws_host_maps_scheme_and_tls() {
        assert_eq!(
            derive_ws_host("https://foo.example.com"),
            ("wss://foo.example.com".to_string(), true)
        );
        assert_eq!(
            derive_ws_host("http://localhost:4000"),
            ("ws://localhost:4000".to_string(), false)
        );
    }

    #[test]
    fn parse_tenant_id_handles_object_and_stringified_details() {
        let object = r#"{"data":{"userDetails":{"details":{"domain":{"id":"tid-123"}}}}}"#;
        assert_eq!(parse_tenant_id(object), Some("tid-123".to_string()));

        let stringified =
            r#"{"data":{"userDetails":{"details":"{\"domain\":{\"id\":\"tid-456\"}}"}}}"#;
        assert_eq!(parse_tenant_id(stringified), Some("tid-456".to_string()));

        assert_eq!(parse_tenant_id(r#"{"data":{"userDetails":null}}"#), None);
        assert_eq!(parse_tenant_id("not json"), None);
    }
}

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

#[cfg(feature = "browser-auth")]
use anyhow::Context;

use crate::config::ConnectorConfig;

/// SDK connector type for Pick (matches the credential-file / gateway naming).
#[cfg(feature = "browser-auth")]
const CONNECTOR_TYPE: &str = "pentest-connector";

/// How the connector will authenticate to the Studio after onboarding.
///
/// The OTT is carried by the `PreApproved` variant so the illegal pairing
/// (pre-approved with no token, or pending-approval with one) cannot be
/// constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationMode {
    /// A pre-approved OTT was minted; the connector self-registers with no
    /// manual step. Holds the OTT JSON for `STRIKE48_REGISTRATION_TOKEN`.
    PreApproved { ott: String },
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
    /// Whether registration is auto-approved (carrying the OTT) or awaits
    /// Studio approval.
    pub mode: RegistrationMode,
}

/// Validate and normalize a user-typed Studio URL into an HTTP(S) API base.
///
/// The scheme is detected case-insensitively: a bare host and any non-`http`
/// scheme (`https`, `wss`, `grpcs`, uppercase, ...) normalize to `https://`;
/// only an explicit `http` scheme stays plaintext (local dev). Trims a trailing
/// slash and rejects userinfo (`user:pass@host`) to avoid confusion attacks.
/// Returns `None` for anything without a host or over 2048 chars. Derived from
/// StrikeHub's validator.
///
/// The only non-test caller is `connect_to_studio` (gated on `browser-auth`);
/// `allow(dead_code)` covers the build where only the tests exercise it, as with
/// the sibling pure helpers below.
#[cfg_attr(not(feature = "browser-auth"), allow(dead_code))]
pub(crate) fn validate_studio_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Split an existing scheme case-insensitively. The API base must be
    // http(s); coerce ws/wss/grpc-style (and unknown) schemes to https so a
    // pasted connector URL doesn't become `https://wss://host`.
    let (scheme, rest) = match trimmed.find("://") {
        Some(i) => {
            let scheme = if trimmed[..i].eq_ignore_ascii_case("http") {
                "http"
            } else {
                "https"
            };
            (scheme, &trimmed[i + 3..])
        }
        None => ("https", trimmed),
    };

    let rest = rest.trim_end_matches('/');
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    // Reject userinfo (raw `@` or percent-encoded `%40`) in the authority.
    if authority.contains('@') || authority.to_lowercase().contains("%40") {
        return None;
    }

    let normalized = format!("{scheme}://{rest}");
    if normalized.len() > 2048 {
        return None;
    }
    Some(normalized)
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
fn http_client() -> anyhow::Result<reqwest::Client> {
    // Honor both carriers, matching the canonical client (`matrix/client.rs`)
    // and the browser-login step (`matrix/auth.rs` reads `MATRIX_INSECURE`); a
    // single-var check here would fail TLS on a self-signed Studio that login
    // just succeeded against.
    let insecure = std::env::var("MATRIX_TLS_INSECURE")
        .or_else(|_| std::env::var("MATRIX_INSECURE"))
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    // Propagate builder failure rather than silently falling back to a default
    // client that would drop the TLS-insecure setting and the 15s timeout.
    reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("failed to build HTTP client for onboarding")
}

/// Resolve the tenant UUID for the authenticated session via the Studio's
/// GraphQL API (`userDetails.details.domain.id`). Ported from StrikeHub.
#[cfg(feature = "browser-auth")]
async fn fetch_tenant_id(api_url: &str, jwt: &str) -> anyhow::Result<String> {
    let url = format!("{}/api/v1alpha/graphql", api_url.trim_end_matches('/'));
    let query = serde_json::json!({ "query": "query { userDetails { details } }" });
    let resp = http_client()?
        .post(&url)
        .header("Authorization", format!("Bearer {jwt}"))
        .json(&query)
        .send()
        .await?;

    // Check status before parsing: a 401 (expired browser token), 403, or 5xx
    // returns a body with no `userDetails`, which would otherwise collapse to a
    // misleading "could not resolve tenant id" — pointing at tenant data when
    // the real cause is auth/availability. Mirrors `create_pre_approved_token`.
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(300).collect();
        anyhow::bail!("tenant lookup failed: {status} — {snippet}");
    }

    let body = resp.text().await?;
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
    details
        .pointer("/domain/id")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from)
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
    let resp = http_client()?
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
    Ok(Some(build_ott_json(&body, base)?))
}

/// Build the OTT JSON the SDK expects (`{"token","matrix_url"}`) from a
/// pre-approve response, embedding the real API base (a mismatched origin is
/// refused by the register-with-ott path). Errors if the response carries no
/// non-empty `token`. Pure, so it is unit-tested on every CI lane.
#[cfg_attr(not(feature = "browser-auth"), allow(dead_code))]
fn build_ott_json(response: &serde_json::Value, api_base: &str) -> anyhow::Result<String> {
    let token = response
        .get("token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("no token in pre-approve response"))?;
    Ok(serde_json::json!({ "token": token, "matrix_url": api_base }).to_string())
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

    let mode = match create_pre_approved_token(&api_url, &jwt, CONNECTOR_TYPE).await? {
        Some(ott) => RegistrationMode::PreApproved { ott },
        None => RegistrationMode::PendingApproval,
    };

    let config = persist_config(&api_url, tenant_id)?;
    Ok(StudioConnection {
        api_url,
        config,
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
        // A scheme with no authority is not a usable base.
        assert_eq!(validate_studio_url("https://"), None);
        assert_eq!(validate_studio_url("   "), None);
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
        // Scheme-less input is a defensive fallback (validate_studio_url always
        // supplies a scheme upstream): default to the secure wss host.
        assert_eq!(
            derive_ws_host("foo.example.com"),
            ("wss://foo.example.com".to_string(), true)
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
        // Empty, non-string, and missing ids resolve to None (never Some("")).
        assert_eq!(
            parse_tenant_id(r#"{"data":{"userDetails":{"details":{"domain":{"id":""}}}}}"#),
            None
        );
        assert_eq!(
            parse_tenant_id(r#"{"data":{"userDetails":{"details":{"domain":{"id":123}}}}}"#),
            None
        );
        assert_eq!(
            parse_tenant_id(r#"{"data":{"userDetails":{"details":{"domain":{}}}}}"#),
            None
        );
    }

    #[test]
    fn validate_studio_url_normalizes_scheme_and_rejects_overlong() {
        // Scheme detected case-insensitively; the value carries a lowercase scheme
        // (host case preserved).
        assert_eq!(
            validate_studio_url("HTTPS://Studio.example.com"),
            Some("https://Studio.example.com".to_string())
        );
        // Non-http(s) schemes coerce to https (the API base) — not double-prefixed.
        assert_eq!(
            validate_studio_url("wss://studio.example.com"),
            Some("https://studio.example.com".to_string())
        );
        // Explicit http stays plaintext (local dev), case-insensitively.
        assert_eq!(
            validate_studio_url("HTTP://localhost:4000"),
            Some("http://localhost:4000".to_string())
        );
        // Over-length is rejected.
        assert_eq!(
            validate_studio_url(&format!("https://{}", "a".repeat(2100))),
            None
        );
    }

    #[test]
    fn build_ott_json_requires_nonempty_token() {
        let ok = build_ott_json(
            &serde_json::json!({ "token": "ott_abc" }),
            "https://studio.example.com",
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&ok).unwrap();
        assert_eq!(parsed["token"], "ott_abc");
        assert_eq!(parsed["matrix_url"], "https://studio.example.com");

        assert!(build_ott_json(&serde_json::json!({ "token": "" }), "https://x").is_err());
        assert!(build_ott_json(&serde_json::json!({ "other": "x" }), "https://x").is_err());
    }
}

/// Exercises `create_pre_approved_token`'s status handling against a real HTTP
/// round trip — the 404/403 -> `Ok(None)` branch is the pivot that decides
/// `PreApproved` vs `PendingApproval`, and there is no seam to unit-test it
/// without a socket. `browser-auth` is unified on in the Linux `--workspace`
/// lane, so these run there (same gating as `matrix/auth.rs`'s tests).
#[cfg(all(test, feature = "browser-auth"))]
mod http_tests {
    use super::{create_pre_approved_token, fetch_tenant_id};

    const PRE_APPROVE: &str = "/api/connectors/pre-approve";
    const GRAPHQL: &str = "/api/v1alpha/graphql";

    /// Serve one canned `(status, body)` response for `POST <path>` from a local
    /// socket and return its base URL. The task is aborted when the returned
    /// handle is dropped at end of test.
    async fn stub(
        path: &'static str,
        status: u16,
        body: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub");
        let port = listener.local_addr().expect("addr").port();
        let code = axum::http::StatusCode::from_u16(status).expect("valid status");
        let app = axum::Router::new().route(
            path,
            axum::routing::post(move || {
                let body = body.clone();
                async move { (code, axum::Json(body)) }
            }),
        );
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://127.0.0.1:{port}"), handle)
    }

    #[tokio::test]
    async fn pre_approve_ok_with_token_yields_ott_embedding_base() {
        let (base, _srv) = stub(PRE_APPROVE, 200, serde_json::json!({ "token": "ott_live" })).await;
        let out = create_pre_approved_token(&base, "jwt", "pentest-connector")
            .await
            .expect("200 must not error");
        let json: serde_json::Value = serde_json::from_str(&out.expect("Some(ott)")).unwrap();
        assert_eq!(json["token"], "ott_live");
        // The OTT must embed the real base, or register-with-ott refuses it.
        assert_eq!(json["matrix_url"], base);
    }

    #[tokio::test]
    async fn pre_approve_not_found_degrades_to_none() {
        let (base, _srv) = stub(PRE_APPROVE, 404, serde_json::json!({ "error": "no route" })).await;
        let out = create_pre_approved_token(&base, "jwt", "pentest-connector")
            .await
            .expect("404 must degrade, not error");
        assert!(out.is_none(), "404 -> post-approval fallback");
    }

    #[tokio::test]
    async fn pre_approve_forbidden_degrades_to_none() {
        let (base, _srv) = stub(PRE_APPROVE, 403, serde_json::json!({ "error": "disabled" })).await;
        let out = create_pre_approved_token(&base, "jwt", "pentest-connector")
            .await
            .expect("403 must degrade, not error");
        assert!(out.is_none(), "403 -> post-approval fallback");
    }

    #[tokio::test]
    async fn pre_approve_empty_token_is_error() {
        let (base, _srv) = stub(PRE_APPROVE, 200, serde_json::json!({ "token": "" })).await;
        let out = create_pre_approved_token(&base, "jwt", "pentest-connector").await;
        assert!(
            out.is_err(),
            "200 with an empty token is a server contract violation"
        );
    }

    #[tokio::test]
    async fn pre_approve_server_error_is_error() {
        let (base, _srv) = stub(PRE_APPROVE, 500, serde_json::json!({ "error": "boom" })).await;
        let out = create_pre_approved_token(&base, "jwt", "pentest-connector").await;
        let err = out.expect_err("5xx must surface, not degrade").to_string();
        assert!(err.contains("500"), "error must name the status: {err}");
    }

    /// Guards the fix for the misleading-error bug: an auth failure on the tenant
    /// lookup must surface the HTTP status, not collapse to "could not resolve
    /// tenant id" (which points at tenant data when the cause is auth). Reverting
    /// the status check in `fetch_tenant_id` turns this red.
    #[tokio::test]
    async fn tenant_lookup_auth_failure_surfaces_status() {
        let (base, _srv) = stub(GRAPHQL, 401, serde_json::json!({ "error": "expired" })).await;
        let err = fetch_tenant_id(&base, "stale-jwt")
            .await
            .expect_err("401 must surface as an auth error")
            .to_string();
        assert!(
            err.contains("401") && !err.contains("could not resolve tenant id"),
            "auth failure must name the status, not blame tenant data: {err}"
        );
    }
}

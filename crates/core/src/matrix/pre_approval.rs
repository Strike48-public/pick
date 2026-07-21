//! PLG connector pre-approval: exchange a user OAuth JWT for a tenant-scoped
//! one-time registration token (OTT) and stage it for the SDK to register with.

use serde::Deserialize;

use crate::error::{Error, Result};
use reqwest;

/// A pre-approval OTT scoped to the user's personal tenant. `matrix_url` is the
/// SDK-facing field name; the endpoint returns it as `matrix_wss_url`.
#[derive(Debug, Clone, PartialEq)]
pub struct OttData {
    pub token: String,
    pub matrix_url: String,
    pub keycloak_url: String,
    pub tenant_id: String,
}

/// Wire shape of the `POST /api/connectors/pre-approve` 201 response.
#[derive(Debug, Deserialize)]
struct PreApproveResponse {
    token: String,
    tenant_id: String,
    keycloak_url: String,
    matrix_wss_url: String,
}

pub(crate) fn parse_pre_approve_response(body: &str) -> Result<OttData> {
    let raw: PreApproveResponse = serde_json::from_str(body)
        .map_err(|e| Error::Matrix(format!("pre-approve response parse error: {e}")))?;
    Ok(OttData {
        token: raw.token,
        matrix_url: raw.matrix_wss_url,
        keycloak_url: raw.keycloak_url,
        tenant_id: raw.tenant_id,
    })
}

/// Exchange a user OAuth JWT for a tenant-scoped OTT via the PLG pre-approval
/// endpoint. The endpoint recovers the PLG session server-side to determine the
/// authoritative personal tenant, so the JWT need not carry a tenant claim.
pub async fn pre_approve(api_url: &str, jwt: &str, connector_type: &str) -> Result<OttData> {
    let base = super::normalize_url(api_url);
    let url = format!("{}/api/connectors/pre-approve", base);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(
            std::env::var("MATRIX_TLS_INSECURE")
                .or_else(|_| std::env::var("MATRIX_INSECURE"))
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false),
        )
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {jwt}"))
        .json(&serde_json::json!({ "connector_type": connector_type }))
        .send()
        .await
        .map_err(|e| Error::Matrix(format!("pre-approve request failed: {e}")))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| Error::Matrix(format!("pre-approve body read failed: {e}")))?;

    if !status.is_success() {
        return Err(Error::Matrix(format!(
            "pre-approve returned HTTP {}: {}",
            status.as_u16(),
            body
        )));
    }

    parse_pre_approve_response(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_201: &str = r#"{
        "token": "ott_8Ucs8wG8RRMX-YEm2un24D4MrOiiF7tGaj5cArlwSN0",
        "tenant_id": "019f86b4-d2bf-7f56-89cf-30485d8a956b",
        "keycloak_url": "https://auth.strike48.test/realms/personal-f668ca45dbb0",
        "connector_type": "pentest-connector",
        "expires_at": "2026-07-21T22:32:42Z",
        "matrix_grpc_url": "grpc://localhost:50061",
        "matrix_wss_url": "wss://localhost:4000/socket/connector"
    }"#;

    #[test]
    fn parses_all_fields_and_maps_wss_to_matrix_url() {
        let ott = parse_pre_approve_response(SAMPLE_201).expect("should parse");
        assert_eq!(ott.token, "ott_8Ucs8wG8RRMX-YEm2un24D4MrOiiF7tGaj5cArlwSN0");
        assert_eq!(ott.tenant_id, "019f86b4-d2bf-7f56-89cf-30485d8a956b");
        assert_eq!(
            ott.keycloak_url,
            "https://auth.strike48.test/realms/personal-f668ca45dbb0"
        );
        assert_eq!(ott.matrix_url, "wss://localhost:4000/socket/connector");
    }

    #[test]
    fn parse_error_on_missing_token() {
        let body = r#"{"tenant_id":"t","keycloak_url":"k","matrix_wss_url":"w"}"#;
        assert!(parse_pre_approve_response(body).is_err());
    }

    #[tokio::test]
    async fn pre_approve_posts_bearer_and_parses_ott() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/pre-approve"))
            .and(header("authorization", "Bearer jwt-abc"))
            .respond_with(ResponseTemplate::new(201).set_body_raw(SAMPLE_201, "application/json"))
            .mount(&server)
            .await;

        let ott = pre_approve(&server.uri(), "jwt-abc", "pentest-connector")
            .await
            .expect("pre_approve should succeed");
        assert_eq!(ott.tenant_id, "019f86b4-d2bf-7f56-89cf-30485d8a956b");
        assert_eq!(ott.matrix_url, "wss://localhost:4000/socket/connector");
    }

    #[tokio::test]
    async fn pre_approve_maps_non_201_to_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/pre-approve"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let err = pre_approve(&server.uri(), "jwt-abc", "pentest-connector")
            .await
            .expect_err("403 should be an error");
        match err {
            Error::Matrix(msg) => assert!(msg.contains("403"), "msg should mention status: {msg}"),
            other => panic!("expected Error::Matrix, got {other:?}"),
        }
    }
}

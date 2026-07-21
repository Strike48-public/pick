//! PLG connector pre-approval: exchange a user OAuth JWT for a tenant-scoped
//! one-time registration token (OTT) and stage it for the SDK to register with.

use serde::Deserialize;

use crate::error::{Error, Result};

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

#[allow(dead_code)]
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
}

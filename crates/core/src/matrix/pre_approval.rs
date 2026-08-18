//! PLG connector pre-approval: exchange a user OAuth JWT for a tenant-scoped
//! one-time registration token (OTT) and stage it for the SDK to register with.

use serde::Deserialize;
use std::path::PathBuf;

use crate::error::{Error, Result};
use reqwest;

/// A pre-approval OTT scoped to the user's personal tenant. `matrix_url` is the
/// HTTPS API base used by the SDK for connector registration.
#[derive(Debug, Clone, PartialEq)]
pub struct OttData {
    pub token: String,
    pub matrix_url: String,
    pub keycloak_url: String,
    pub tenant_id: String,
}

/// Wire shape of the `POST /api/connectors/pre-approve` 201 response.
///
/// `matrix_wss_url` is optional: the connector derives its WebSocket URL from
/// the API base at runtime and never reads this field, but some deployments
/// (e.g. studio.strike48.com) omit it from the response entirely. Requiring it
/// made `serde_json::from_str` fail with "missing field `matrix_wss_url`",
/// which aborted registration after an otherwise-successful sign-in. Keep it
/// optional so its absence is tolerated.
#[derive(Debug, Deserialize)]
struct PreApproveResponse {
    token: String,
    tenant_id: String,
    keycloak_url: String,
    #[allow(dead_code)]
    #[serde(default)]
    matrix_wss_url: Option<String>,
}

pub(crate) fn parse_pre_approve_response(body: &str, api_base: &str) -> Result<OttData> {
    let raw: PreApproveResponse = serde_json::from_str(body)
        .map_err(|e| Error::Matrix(format!("pre-approve response parse error: {e}")))?;
    Ok(OttData {
        token: raw.token,
        matrix_url: api_base.to_string(),
        keycloak_url: raw.keycloak_url,
        tenant_id: raw.tenant_id,
    })
}

/// Path Pick writes the staged OTT to. `$HOME` is the app sandbox container on
/// iOS, so this lands in Pick's private, persisted storage.
pub fn staged_ott_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".strike48")
        .join("registration_token.json")
}

/// Write `ott` to [`staged_ott_path`] in the SDK's `{token, matrix_url,
/// keycloak_url}` shape (mode 0600 on Unix). Returns the path so the caller can
/// point `STRIKE48_REGISTRATION_TOKEN_FILE` at it.
pub fn stage_ott_for_sdk(ott: &OttData) -> Result<PathBuf> {
    let path = staged_ott_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Matrix(format!("cannot create OTT dir: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let json = serde_json::json!({
        "token": ott.token,
        "matrix_url": ott.matrix_url,
        "keycloak_url": ott.keycloak_url,
    })
    .to_string();

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // create AT 0600 — never a permissive window
            .open(&path)
            .map_err(|e| Error::Matrix(format!("cannot open OTT file: {e}")))?;
        f.write_all(json.as_bytes())
            .map_err(|e| Error::Matrix(format!("cannot write OTT file: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, json)
            .map_err(|e| Error::Matrix(format!("cannot write OTT file: {e}")))?;
    }

    Ok(path)
}

/// Remove the staged OTT file. OTTs are single-use, so this is called after a
/// successful registration and on failure to avoid reusing a stale token.
pub fn clear_staged_ott() {
    let _ = std::fs::remove_file(staged_ott_path());
}

/// Exchange a user OAuth JWT for a tenant-scoped OTT via the PLG pre-approval
/// endpoint. The endpoint recovers the PLG session server-side to determine the
/// authoritative personal tenant, so the JWT need not carry a tenant claim.
pub async fn pre_approve(api_url: &str, jwt: &str, connector_type: &str) -> Result<OttData> {
    let base = super::normalize_url(api_url);
    let url = format!("{}/api/connectors/pre-approve", base);

    // Resolve TLS trust the same way the GraphQL client does — build-time
    // `option_env!` OR runtime env. Reading only the runtime env here (the prior
    // bug) made this request verify-fail on mobile, where the runtime env is
    // always empty, even though the baked GraphQL client to the same host
    // succeeded. That surfaced as "pre-approve request failed: error sending
    // request" and the easy-mode retry card.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(super::insecure_tls())
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

    parse_pre_approve_response(&body, base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Both stage_writes_sdk_shaped_json_and_roundtrips and
    // stage_writes_0600_even_under_permissive_umask mutate process globals
    // (HOME and umask respectively). Lock to prevent concurrent runs from racing.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

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
    fn parses_token_tenant_keycloak_fields() {
        let api_base = "https://plg.strike48.test";
        let ott = parse_pre_approve_response(SAMPLE_201, api_base).expect("should parse");
        assert_eq!(ott.token, "ott_8Ucs8wG8RRMX-YEm2un24D4MrOiiF7tGaj5cArlwSN0");
        assert_eq!(ott.tenant_id, "019f86b4-d2bf-7f56-89cf-30485d8a956b");
        assert_eq!(
            ott.keycloak_url,
            "https://auth.strike48.test/realms/personal-f668ca45dbb0"
        );
        assert_eq!(ott.matrix_url, api_base);
    }

    #[test]
    fn parse_error_on_missing_token() {
        let body = r#"{"tenant_id":"t","keycloak_url":"k","matrix_wss_url":"w"}"#;
        assert!(parse_pre_approve_response(body, "https://api.test").is_err());
    }

    #[test]
    fn parses_when_matrix_wss_url_absent() {
        // Regression: studio.strike48.com omits matrix_wss_url from the
        // pre-approve response. The field is unused (the connector derives its
        // WS URL from the API base), so its absence must NOT fail parsing — it
        // previously aborted registration after a successful sign-in with
        // "missing field `matrix_wss_url`".
        let body = r#"{
            "token": "ott_abc",
            "tenant_id": "019f86b4-d2bf-7f56-89cf-30485d8a956b",
            "keycloak_url": "https://auth.strike48.com/realms/personal-x"
        }"#;
        let ott = parse_pre_approve_response(body, "https://studio.strike48.com")
            .expect("must parse without matrix_wss_url");
        assert_eq!(ott.token, "ott_abc");
        assert_eq!(ott.tenant_id, "019f86b4-d2bf-7f56-89cf-30485d8a956b");
        assert_eq!(ott.matrix_url, "https://studio.strike48.com");
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

        let server_uri = server.uri();
        let ott = pre_approve(&server_uri, "jwt-abc", "pentest-connector")
            .await
            .expect("pre_approve should succeed");
        assert_eq!(ott.tenant_id, "019f86b4-d2bf-7f56-89cf-30485d8a956b");
        // matrix_url should be the normalized api_url we called, not the wss response value
        let normalized = super::super::normalize_url(&server_uri);
        assert_eq!(ott.matrix_url, normalized);
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

    #[test]
    fn stage_writes_sdk_shaped_json_and_roundtrips() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let ott = OttData {
            token: "ott_xyz".to_string(),
            matrix_url: "https://api.strike48.test".to_string(),
            keycloak_url: "https://auth/realms/personal-abc".to_string(),
            tenant_id: "tid".to_string(),
        };

        // Redirect HOME to a temp dir so the test does not touch the real ~/.strike48.
        let tmp = std::env::temp_dir().join(format!("pick-ott-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", &tmp);

        let path = stage_ott_for_sdk(&ott).expect("stage should succeed");
        assert!(path.exists(), "staged file should exist");

        let written = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v["token"], "ott_xyz");
        assert_eq!(v["matrix_url"], "https://api.strike48.test");
        assert_eq!(v["keycloak_url"], "https://auth/realms/personal-abc");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "staged OTT must be 0600");
        }

        clear_staged_ott();
        assert!(!path.exists(), "clear_staged_ott should remove the file");

        // Restore HOME.
        match prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    struct UmaskGuard(u32);
    #[cfg(unix)]
    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe {
                libc_umask(self.0);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn stage_writes_0600_even_under_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // A permissive umask is the real-world hazard: std::fs::write creates the
        // file honoring umask, so a later chmod leaves a window at 0644/0664.
        let _umask_guard = UmaskGuard(unsafe { libc_umask(0o002) });
        let ott = OttData {
            token: "ott_perm".into(),
            matrix_url: "https://api.test".into(),
            keycloak_url: "https://auth/realms/x".into(),
            tenant_id: "tid".into(),
        };
        let tmp = std::env::temp_dir().join(format!("pick-ott-umask-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", &tmp);

        let path = stage_ott_for_sdk(&ott).expect("stage");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "OTT file must be 0600 regardless of umask"
        );
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "OTT dir must be 0700");

        match prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    extern "C" {
        fn umask(mask: u32) -> u32;
    }
    #[cfg(unix)]
    unsafe fn libc_umask(mask: u32) -> u32 {
        umask(mask)
    }
}

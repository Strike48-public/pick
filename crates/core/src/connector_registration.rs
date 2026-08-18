//! Shared connector-registration orchestration.
//!
//! Both the Dioxus app and the crux FFI must register a connector the SAME way:
//! via the PLG pre-approval one-time-token (OTT) flow. This module holds the
//! single implementation so the two front-ends cannot drift.
//!
//! The flow:
//!  1. [`derive_api_url`] turns a connector host string into the HTTPS API base.
//!  2. [`prepare_connector_registration`] exchanges the signed-in user JWT for a
//!     tenant-scoped OTT, stages it on disk, and points the SDK at it via the
//!     `STRIKE48_REGISTRATION_TOKEN_FILE` env var. It returns the [`OttData`] so
//!     the caller can adopt the AUTHORITATIVE tenant id.

use crate::error::{Error, Result};
use crate::matrix::OttData;

/// Derive the HTTP(S) Matrix API URL from a connector host string.
///
/// Strips a transport scheme prefix (grpc/grpcs/http/https/ws/wss), strips a
/// leading `connectors-` host label, trims a trailing `/`, and applies the TLS
/// choice as the scheme.
pub fn derive_api_url(host: &str, use_tls: bool) -> String {
    let host_lower = host.to_lowercase();
    let secure_schemes = ["https://", "wss://", "grpcs://"];
    let input_is_secure = secure_schemes.iter().any(|p| host_lower.starts_with(p));
    // An explicit secure input is never downgraded, even when use_tls is false.
    let scheme = if use_tls || input_is_secure {
        "https"
    } else {
        "http"
    };
    let schemes = [
        "grpc://", "grpcs://", "http://", "https://", "ws://", "wss://",
    ];
    let mut bare_host = host;
    for prefix in &schemes {
        if host_lower.starts_with(prefix) {
            bare_host = &host[prefix.len()..];
            break;
        }
    }
    let api_host = bare_host.strip_prefix("connectors-").unwrap_or(bare_host);
    let api_host = api_host.trim_end_matches('/');
    format!("{scheme}://{api_host}")
}

/// Orchestrate the pre-approval OTT registration flow.
///
/// Calls [`crate::matrix::pre_approve`] to exchange the signed-in user `jwt` for
/// a tenant-scoped OTT, stages it for the SDK via
/// [`crate::matrix::stage_ott_for_sdk`], and sets the process-global
/// `STRIKE48_REGISTRATION_TOKEN_FILE` env var so the SDK's `ConnectorRunner`
/// registers with that OTT.
///
/// IMPORTANT: this MUST run BEFORE the SDK `ConnectorRunner` starts (it reads
/// the env var at startup), and the caller MUST set
/// `config.tenant_id = ott.tenant_id` on the returned data — the OTT's
/// `tenant_id` is the authoritative tenant UUID, NOT a realm name.
///
/// The individual steps ([`crate::matrix::pre_approve`],
/// [`crate::matrix::stage_ott_for_sdk`]) remain callable directly; this is the
/// orchestration that wires them together.
///
/// ```no_run
/// # async fn run() -> pentest_core::error::Result<()> {
/// let api_url = pentest_core::connector_registration::derive_api_url(
///     "wss://connectors-studio.strike48.test:443",
///     true,
/// );
/// let ott = pentest_core::connector_registration::prepare_connector_registration(
///     &api_url,
///     "the-user-jwt",
///     "pentest-connector",
/// )
/// .await?;
/// // caller then sets config.tenant_id = ott.tenant_id before running the SDK.
/// let _ = ott.tenant_id;
/// # Ok(())
/// # }
/// ```
pub async fn prepare_connector_registration(
    api_url: &str,
    jwt: &str,
    connector_name: &str,
) -> Result<OttData> {
    let ott = crate::matrix::pre_approve(api_url, jwt, connector_name).await?;
    let staged = crate::matrix::stage_ott_for_sdk(&ott)?;
    let staged = staged
        .to_str()
        .ok_or_else(|| Error::Matrix("staged OTT path is not valid UTF-8".to_string()))?;
    std::env::set_var("STRIKE48_REGISTRATION_TOKEN_FILE", staged);
    Ok(ott)
}

#[cfg(test)]
mod tests {
    use super::derive_api_url;

    #[test]
    fn strips_ws_scheme_and_applies_tls() {
        assert_eq!(
            derive_api_url("wss://plg.strike48.test", true),
            "https://plg.strike48.test"
        );
    }

    #[test]
    fn strips_connectors_label() {
        assert_eq!(
            derive_api_url("wss://connectors-studio.strike48.test:443", true),
            "https://studio.strike48.test:443"
        );
    }

    #[test]
    fn no_tls_uses_http_and_trims_trailing_slash() {
        assert_eq!(
            derive_api_url("ws://localhost:3030/", false),
            "http://localhost:3030"
        );
    }

    #[test]
    fn bare_host_gets_scheme() {
        assert_eq!(derive_api_url("example.com", true), "https://example.com");
    }

    #[test]
    fn explicit_https_is_not_downgraded_to_http() {
        // A user who typed https must never have their bearer JWT sent over http.
        assert_eq!(
            derive_api_url("https://host.example", false),
            "https://host.example"
        );
        assert_eq!(
            derive_api_url("wss://host.example", false),
            "https://host.example"
        );
    }

    #[test]
    fn explicit_insecure_scheme_still_honors_use_tls_false() {
        // ws:// / http:// with use_tls=false stays http (localhost dev).
        assert_eq!(
            derive_api_url("ws://localhost:3030/", false),
            "http://localhost:3030"
        );
    }
}

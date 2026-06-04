//! Tool execution routing and result formatting.

use crate::ipc::{IpcAddr, IpcStream};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Perform an HTTP GET over the IPC transport, returning (status, content_type, body).
pub(crate) async fn ipc_http_get(addr: &IpcAddr, path: &str) -> Result<(u16, String, Vec<u8>), String> {
    let mut stream = IpcStream::connect(addr)
        .await
        .map_err(|e| format!("IPC connect to {}: {}", addr, e))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        path
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("Write request: {}", e))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("Read response: {}", e))?;

    let response = String::from_utf8_lossy(&buf);

    // Parse status line
    let status_line = response
        .lines()
        .next()
        .ok_or_else(|| "Empty response".to_string())?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(502);

    // Parse headers for content-type
    let mut content_type = "text/html".to_string();
    for line in response.lines().skip(1) {
        if line.is_empty() || line == "\r" {
            break;
        }
        if let Some(ct) = line
            .strip_prefix("content-type: ")
            .or_else(|| line.strip_prefix("Content-Type: "))
        {
            content_type = ct.trim().to_string();
        }
    }

    // Extract body (after \r\n\r\n)
    let body = if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        buf[pos + 4..].to_vec()
    } else {
        Vec::new()
    };

    Ok((status, content_type, body))
}

/// Redact a context value if its key looks sensitive.
///
/// Keys whose lowercase form contains any of `token`, `secret`, `key`,
/// `password`, or `auth` have their value replaced with
/// `<redacted:len=N>` where `N` is the byte length of the original value.
/// All other values are returned unchanged.
pub(crate) fn redact_sensitive(key: &str, value: &str) -> String {
    const SENSITIVE_NEEDLES: &[&str] = &["token", "secret", "key", "password", "auth"];
    let key_lc = key.to_ascii_lowercase();
    if SENSITIVE_NEEDLES
        .iter()
        .any(|needle| key_lc.contains(needle))
    {
        format!("<redacted:len={}>", value.len())
    } else {
        value.to_string()
    }
}

/// Log the full set of context key/value pairs from an ExecuteRequest at INFO,
/// one pair per line, with sensitive values redacted. Lines are prefixed with
/// `[execreq-ctx]` for grep-ability and tagged with request_id + tool name.
fn log_execute_request_context(
    request_id: &str,
    tool_name: &str,
    context: &HashMap<String, String>,
) {
    tracing::info!(
        "[execreq-ctx] request_id={} tool={} context_key_count={}",
        request_id,
        tool_name,
        context.len(),
    );
    if context.is_empty() {
        tracing::info!(
            "[execreq-ctx] request_id={} tool={} (no context keys)",
            request_id,
            tool_name,
        );
        return;
    }
    // Sort keys so log order is deterministic across runs — makes diffs against
    // the platform-side log readable.
    let mut keys: Vec<&String> = context.keys().collect();
    keys.sort();
    for key in keys {
        let raw = context.get(key).map(String::as_str).unwrap_or("");
        let rendered = redact_sensitive(key, raw);
        tracing::info!(
            "[execreq-ctx] request_id={} tool={} {}={}",
            request_id,
            tool_name,
            key,
            rendered,
        );
    }
}


/// Extract engagement_id from the execute request context.
/// Checks both a top-level key and the nested agent_context JSON.
fn extract_engagement_id(context: &HashMap<String, String>) -> Option<String> {
    // Direct key
    if let Some(eid) = context.get("engagement_id") {
        return Some(eid.clone());
    }
    // Nested in agent_context JSON
    let agent_ctx_str = context.get("agent_context")?;
    let parsed: Value = serde_json::from_str(agent_ctx_str).ok()?;
    parsed
        .get("engagement_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Reported outcome of a StrikeKit artifact upload batch.
///
/// Serialized into `data.artifacts.upload_status` on the webwright tool result
/// so the LLM and chat-panel widget can see whether artifacts actually
/// reached the platform. Counts cover the number of files we *tried* to upload
/// vs. the number that returned without error from the gRPC enqueue (the
/// platform's downstream processing is still asynchronous, so a success here
/// only proves the message was queued, not that it landed in storage).
///
/// `failed` is capped to avoid blowing up the tool result on pathological
/// runs where every file fails; overflow is preserved as a final synthetic
/// entry of the form `"... and N more"`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct UploadStatus {
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: Vec<String>,
    pub started_at_ms: i64,
    pub duration_ms: u64,
    pub engagement_id: String,
}

/// Cap on how many failed paths we keep verbatim before collapsing the rest
/// into a single overflow entry. Keeps the tool result payload bounded.
const UPLOAD_STATUS_FAILED_LIMIT: usize = 10;

/// Splice an [`UploadStatus`] into a serialized ToolResult JSON under
/// `data.artifacts.upload_status`. Defensively creates `data` and
/// `data.artifacts` as empty objects if either is missing so the splice
/// always lands somewhere queryable.
fn inject_upload_status(result_json: &mut Value, status: &UploadStatus) {
    let status_val = match serde_json::to_value(status) {
        Ok(v) => v,
        Err(_) => return,
    };

    let obj = match result_json.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    let data_entry = obj
        .entry("data".to_string())
        .or_insert_with(|| Value::Object(Default::default()));
    let data_obj = match data_entry.as_object_mut() {
        Some(o) => o,
        // data exists but is not an object (e.g. Null for error results) — overwrite
        None => {
            *data_entry = Value::Object(Default::default());
            data_entry.as_object_mut().unwrap()
        }
    };

    let artifacts_entry = data_obj
        .entry("artifacts".to_string())
        .or_insert_with(|| Value::Object(Default::default()));
    let artifacts_obj = match artifacts_entry.as_object_mut() {
        Some(o) => o,
        None => {
            *artifacts_entry = Value::Object(Default::default());
            artifacts_entry.as_object_mut().unwrap()
        }
    };

    artifacts_obj.insert("upload_status".to_string(), status_val);
}

/// Upload webwright artifacts (screenshots, scripts, DOM snapshots) to StrikeKit
/// via the SDK's `ConnectorRunner::invoke_capability` (request/response).
///
/// Returns an [`UploadStatus`] describing what was attempted vs. what landed,
/// so the caller can splice the outcome into the tool result payload for the
/// LLM/UI to observe.
pub(crate) async fn upload_artifacts_via_runner(
    runner: &strike48_connector::ConnectorRunner,
    engagement_id: &str,
    session_token: &str,
    artifacts: &Value,
    workspace_path: &str,
) -> UploadStatus {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    let started_at_ms = chrono::Utc::now().timestamp_millis();
    let start = std::time::Instant::now();

    let mut attempted: usize = 0;
    let mut succeeded: usize = 0;
    let mut failed: Vec<String> = Vec::new();
    let mut overflow: usize = 0;

    let resolve = |path: &str| -> String {
        if path.starts_with('/') {
            path.to_string()
        } else {
            format!("{}/{}", workspace_path, path)
        }
    };

    let categories: [(&str, &str); 3] = [
        ("screenshots", "screenshot"),
        ("scripts", "code"),
        ("dom_snapshots", "file"),
    ];

    for (key, evidence_type) in categories.iter() {
        if let Some(paths) = artifacts[*key].as_array() {
            for path_val in paths {
                if let Some(path) = path_val.as_str() {
                    attempted += 1;
                    let resolved = resolve(path);

                    let file_bytes = match tokio::fs::read(&resolved).await {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!("[strikekit] failed to read {}: {}", resolved, e);
                            if failed.len() < UPLOAD_STATUS_FAILED_LIMIT {
                                failed.push(path.to_string());
                            } else {
                                overflow += 1;
                            }
                            continue;
                        }
                    };

                    let filename = std::path::Path::new(&resolved)
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("unknown")
                        .to_string();

                    let payload = serde_json::json!({
                        "engagement_id": engagement_id,
                        "filename": filename,
                        "content_base64": BASE64.encode(&file_bytes),
                        "evidence_type": evidence_type,
                        "title": filename,
                        "source": "webwright",
                        "path": path,
                    });

                    let mut context = HashMap::new();
                    if !session_token.is_empty() {
                        context.insert("session_token".to_string(), session_token.to_string());
                    }

                    let options = strike48_connector::InvokeCapabilityOptions {
                        capability_id: Some("upload_artifact".to_string()),
                        timeout_ms: Some(30000),
                        fire_and_forget: Some(false),
                        context: Some(context),
                    };

                    match runner
                        .invoke_capability("strikekit://evidence", payload, options)
                        .await
                    {
                        Ok(Some(_)) => succeeded += 1,
                        Ok(None) => succeeded += 1,
                        Err(e) => {
                            tracing::warn!("[strikekit] invoke failed for {}: {}", path, e);
                            if failed.len() < UPLOAD_STATUS_FAILED_LIMIT {
                                failed.push(path.to_string());
                            } else {
                                overflow += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    if overflow > 0 {
        failed.push(format!("... and {} more", overflow));
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    if attempted > 0 {
        tracing::info!(
            "[strikekit] webwright artifact upload: attempted={} succeeded={} failed={} duration_ms={} engagement={}",
            attempted,
            succeeded,
            failed.len(),
            duration_ms,
            engagement_id,
        );
    }

    UploadStatus {
        attempted,
        succeeded,
        failed,
        started_at_ms,
        duration_ms,
        engagement_id: engagement_id.to_string(),
    }
}

// === Public wrappers for pick_connector ===

/// Public wrapper for `log_execute_request_context`.
pub(crate) fn log_execute_request_context_pub(
    request_id: &str,
    tool_name: &str,
    context: &HashMap<String, String>,
) {
    log_execute_request_context(request_id, tool_name, context);
}

/// Public wrapper for `extract_engagement_id`.
pub(crate) fn extract_engagement_id_pub(context: &HashMap<String, String>) -> Option<String> {
    extract_engagement_id(context)
}


/// Public wrapper for `inject_upload_status`.
pub(crate) fn inject_upload_status_pub(result_json: &mut Value, status: &UploadStatus) {
    inject_upload_status(result_json, status);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_payload_limit_value() {
        const MAX_TOOL_PAYLOAD: usize = 5 * 1024 * 1024;
        assert_eq!(MAX_TOOL_PAYLOAD, 5_242_880);
    }

    #[test]
    fn redact_sensitive_passes_plain_keys_through() {
        assert_eq!(
            redact_sensitive("tool_call_id", "call-abc-123"),
            "call-abc-123"
        );
        assert_eq!(redact_sensitive("engagement_id", "eng-42"), "eng-42");
        assert_eq!(
            redact_sensitive("agent_context", "{\"foo\":1}"),
            "{\"foo\":1}"
        );
    }

    #[test]
    fn redact_sensitive_redacts_session_token() {
        assert_eq!(
            redact_sensitive("session_token", "abcdef123456"),
            "<redacted:len=12>"
        );
    }

    #[test]
    fn redact_sensitive_redacts_auth_token() {
        assert_eq!(redact_sensitive("auth_token", "xyz"), "<redacted:len=3>");
    }

    #[test]
    fn redact_sensitive_redacts_api_key() {
        assert_eq!(
            redact_sensitive("api_key", "sk-1234567890"),
            "<redacted:len=13>"
        );
    }

    #[test]
    fn redact_sensitive_redacts_bare_secret() {
        assert_eq!(redact_sensitive("secret", "hunter2"), "<redacted:len=7>");
    }

    #[test]
    fn redact_sensitive_redacts_password() {
        assert_eq!(
            redact_sensitive("user_password", "letmein"),
            "<redacted:len=7>"
        );
    }

    #[test]
    fn redact_sensitive_matching_is_case_insensitive() {
        assert_eq!(redact_sensitive("Session_Token", "abc"), "<redacted:len=3>");
        assert_eq!(redact_sensitive("API_KEY", "abc"), "<redacted:len=3>");
        assert_eq!(redact_sensitive("AUTH", "abc"), "<redacted:len=3>");
        assert_eq!(redact_sensitive("PASSWORD", "abc"), "<redacted:len=3>");
    }

    #[test]
    fn redact_sensitive_empty_value_still_surfaces() {
        assert_eq!(redact_sensitive("session_token", ""), "<redacted:len=0>");
    }

    #[test]
    fn redact_sensitive_partial_substring_matches() {
        assert_eq!(
            redact_sensitive("x_custom_auth_header", "v"),
            "<redacted:len=1>"
        );
        assert_eq!(redact_sensitive("private_key_pem", "v"), "<redacted:len=1>");
    }

    #[test]
    fn extract_engagement_id_direct() {
        let mut ctx = HashMap::new();
        ctx.insert("engagement_id".to_string(), "abc-123".to_string());
        assert_eq!(extract_engagement_id(&ctx), Some("abc-123".to_string()));
    }

    #[test]
    fn extract_engagement_id_from_agent_context() {
        let mut ctx = HashMap::new();
        ctx.insert(
            "agent_context".to_string(),
            r#"{"engagement_id":"xyz-789","phase":"recon"}"#.to_string(),
        );
        assert_eq!(extract_engagement_id(&ctx), Some("xyz-789".to_string()));
    }

    #[test]
    fn extract_engagement_id_missing() {
        let ctx = HashMap::new();
        assert_eq!(extract_engagement_id(&ctx), None);
    }


    #[test]
    fn upload_status_serializes_with_expected_keys() {
        // The LLM/UI look up these exact keys on data.artifacts.upload_status.
        // Renaming any of them is a breaking change for downstream consumers.
        let status = UploadStatus {
            attempted: 3,
            succeeded: 2,
            failed: vec!["screenshots/foo.png".to_string()],
            started_at_ms: 1_700_000_000_000,
            duration_ms: 250,
            engagement_id: "eng-42".to_string(),
        };

        let v = serde_json::to_value(&status).expect("serialize UploadStatus");
        let obj = v
            .as_object()
            .expect("UploadStatus must serialize as object");

        // Field names are part of the contract; assert exact match.
        let expected_keys: std::collections::BTreeSet<&str> = [
            "attempted",
            "succeeded",
            "failed",
            "started_at_ms",
            "duration_ms",
            "engagement_id",
        ]
        .into_iter()
        .collect();
        let actual_keys: std::collections::BTreeSet<&str> =
            obj.keys().map(|s| s.as_str()).collect();
        assert_eq!(
            actual_keys, expected_keys,
            "UploadStatus JSON keys drifted from the LLM/UI contract"
        );

        assert_eq!(obj["attempted"], 3);
        assert_eq!(obj["succeeded"], 2);
        assert_eq!(obj["failed"][0], "screenshots/foo.png");
        assert_eq!(obj["started_at_ms"], 1_700_000_000_000_i64);
        assert_eq!(obj["duration_ms"], 250);
        assert_eq!(obj["engagement_id"], "eng-42");
    }

    #[test]
    fn inject_upload_status_lands_under_data_artifacts() {
        let mut result_json = serde_json::json!({
            "success": true,
            "data": {
                "artifacts": {
                    "screenshots": ["a.png"]
                }
            },
            "error": null,
            "duration_ms": 100
        });
        let status = UploadStatus {
            attempted: 1,
            succeeded: 1,
            failed: Vec::new(),
            started_at_ms: 0,
            duration_ms: 5,
            engagement_id: "e".to_string(),
        };
        inject_upload_status(&mut result_json, &status);
        let injected = &result_json["data"]["artifacts"]["upload_status"];
        assert_eq!(injected["attempted"], 1);
        assert_eq!(injected["succeeded"], 1);
        assert_eq!(injected["engagement_id"], "e");
        // Original siblings preserved
        assert_eq!(result_json["data"]["artifacts"]["screenshots"][0], "a.png");
    }

    #[test]
    fn inject_upload_status_creates_missing_artifacts_object() {
        let mut result_json = serde_json::json!({
            "success": true,
            "data": {},
            "error": null,
            "duration_ms": 0
        });
        let status = UploadStatus {
            attempted: 0,
            succeeded: 0,
            failed: Vec::new(),
            started_at_ms: 0,
            duration_ms: 0,
            engagement_id: "e".to_string(),
        };
        inject_upload_status(&mut result_json, &status);
        assert!(result_json["data"]["artifacts"]["upload_status"].is_object());
    }

    #[test]
    fn inject_upload_status_handles_null_data() {
        // Error results have data: null. We still want to surface upload_status
        // when present (though in practice we only inject on success).
        let mut result_json = serde_json::json!({
            "success": false,
            "data": null,
            "error": "boom",
            "duration_ms": 0
        });
        let status = UploadStatus {
            attempted: 0,
            succeeded: 0,
            failed: Vec::new(),
            started_at_ms: 0,
            duration_ms: 0,
            engagement_id: "e".to_string(),
        };
        inject_upload_status(&mut result_json, &status);
        assert!(result_json["data"]["artifacts"]["upload_status"].is_object());
    }
}

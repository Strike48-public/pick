use crate::error::{ConnectorError, Result};
use crate::types::PayloadEncoding;
use serde::{Deserialize, Serialize};

/// Serialize data to bytes with specified encoding
pub fn serialize_payload<T: Serialize>(data: &T, encoding: PayloadEncoding) -> Result<Vec<u8>> {
    match encoding {
        PayloadEncoding::Json => serde_json::to_vec(data).map_err(|e| {
            ConnectorError::SerializationError(format!("JSON serialization failed: {e}"))
        }),
        PayloadEncoding::RawBytes => {
            // For raw bytes, we expect Vec<u8> or String
            if let Ok(bytes) = serde_json::to_value(data) {
                if let Some(s) = bytes.as_str() {
                    Ok(s.as_bytes().to_vec())
                } else {
                    Err(ConnectorError::SerializationError(
                        "RAW_BYTES encoding requires string or bytes".to_string(),
                    ))
                }
            } else {
                Err(ConnectorError::SerializationError(
                    "Failed to serialize for RAW_BYTES".to_string(),
                ))
            }
        }
        PayloadEncoding::JsonLines => {
            // JSON Lines expects an array
            if let Ok(value) = serde_json::to_value(data) {
                if let Some(arr) = value.as_array() {
                    let lines: Vec<String> = arr
                        .iter()
                        .map(serde_json::to_string)
                        .collect::<std::result::Result<_, _>>()
                        .map_err(|e| {
                            ConnectorError::SerializationError(format!(
                                "JSON Lines serialization failed: {e}"
                            ))
                        })?;
                    Ok(lines.join("\n").into_bytes())
                } else {
                    Err(ConnectorError::SerializationError(
                        "JSON_LINES requires array".to_string(),
                    ))
                }
            } else {
                Err(ConnectorError::SerializationError(
                    "Failed to serialize for JSON_LINES".to_string(),
                ))
            }
        }
        _ => Err(ConnectorError::UnsupportedEncoding(format!(
            "Encoding {encoding:?} not yet implemented"
        ))),
    }
}

/// Deserialize bytes to data based on encoding
pub fn deserialize_payload<T: for<'de> Deserialize<'de>>(
    payload: &[u8],
    encoding: PayloadEncoding,
) -> Result<T> {
    match encoding {
        PayloadEncoding::Json => serde_json::from_slice(payload).map_err(|e| {
            ConnectorError::DeserializationError(format!("JSON deserialization failed: {e}"))
        }),
        PayloadEncoding::RawBytes => {
            // For raw bytes, return as string
            String::from_utf8(payload.to_vec())
                .map_err(|e| {
                    ConnectorError::DeserializationError(format!(
                        "Failed to convert raw bytes to string: {e}"
                    ))
                })
                .and_then(|s| {
                    serde_json::from_str(&s).map_err(|e| {
                        ConnectorError::DeserializationError(format!(
                            "Failed to parse raw bytes as JSON: {e}"
                        ))
                    })
                })
        }
        PayloadEncoding::JsonLines => {
            // Parse JSON Lines (newline-separated JSON)
            let lines: Vec<&str> = std::str::from_utf8(payload)
                .map_err(|e| {
                    ConnectorError::DeserializationError(format!(
                        "Failed to parse JSON Lines as UTF-8: {e}"
                    ))
                })?
                .lines()
                .collect();

            let items: Vec<serde_json::Value> = lines
                .iter()
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_str(line))
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| {
                    ConnectorError::DeserializationError(format!("Failed to parse JSON Lines: {e}"))
                })?;

            serde_json::from_value(serde_json::Value::Array(items)).map_err(|e| {
                ConnectorError::DeserializationError(format!(
                    "Failed to deserialize JSON Lines array: {e}"
                ))
            })
        }
        _ => Err(ConnectorError::UnsupportedEncoding(format!(
            "Encoding {encoding:?} not yet implemented"
        ))),
    }
}

/// Generate a unique request ID
pub fn generate_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Create a success response payload
pub fn success_response<T: Serialize>(data: T) -> Result<Vec<u8>> {
    serialize_payload(&data, PayloadEncoding::Json)
}

/// Create an error response payload
pub fn error_response(message: &str) -> Result<Vec<u8>> {
    let error_data = serde_json::json!({
        "error": message,
        "success": false
    });
    serialize_payload(&error_data, PayloadEncoding::Json)
}

/// Enforce the "never a blank failure" wire contract (Strike48/matrix#4715,
/// defect 2).
///
/// `execute_with_context` returns a `Value` the SDK wraps in an
/// `ExecuteResponse` with `success: true` and an EMPTY `error` — even when the
/// connector-level tool result inside the payload reports a failure. If that
/// payload failure carries a blank `error` (the exact failure mode that left
/// the agent "diagnosing blind" all night), this:
///
/// 1. patches the payload's `error` field with an actionable message, and
/// 2. returns that message so the caller can mirror it into the envelope's
///    `error` field (never blank on a failure).
///
/// Successful payloads and payloads with no recognizable failure shape are
/// returned untouched with `None`.
///
/// # Returns
/// `(patched_payload, envelope_error_message)`
pub fn sanitize_failure_payload(
    response_data: &serde_json::Value,
    capability_id: Option<&str>,
) -> (serde_json::Value, Option<String>) {
    let serde_json::Value::Object(fields) = response_data else {
        return (response_data.clone(), None);
    };

    // Only intervene on an explicit tool-level failure.
    let failed = fields
        .get("success")
        .and_then(serde_json::Value::as_bool)
        == Some(false);
    if !failed {
        return (response_data.clone(), None);
    }

    let blank = fields
        .get("error")
        .and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.trim().is_empty()),
            serde_json::Value::Null => Some(true),
            _ => Some(false),
        })
        .unwrap_or(true);

    if !blank {
        return (response_data.clone(), None);
    }

    let tool = capability_id
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "the requested tool".to_string());

    let message = format!(
        "Tool '{tool}' failed without returning an error message. Check the connector \
         pod logs for the underlying failure and retry — if the request was malformed, \
         retry with the tool's documented parameters (a minimal `target` alone is a \
         good starting point)."
    );

    let mut patched = fields.clone();
    patched.insert("error".to_string(), serde_json::json!(message));

    (serde_json::Value::Object(patched), Some(message))
}

//// Sanitize an identifier so it is safe to use in a connector address.
///
/// The Matrix server rejects `tenant_id` / `connector_type` / `instance_id`
/// values that contain `.`, `:`, tab, space, or newline (those characters
/// are reserved as address separators or are illegal in the dot-form
/// `tenant.type.instance` address). This helper rewrites every such
/// character to `-` so callers never put a forbidden character on the wire.
///
/// # Examples
/// ```
/// use strike48_connector::utils::sanitize_identifier;
/// assert_eq!(sanitize_identifier("rust1.k3s"), "rust1-k3s");
/// assert_eq!(sanitize_identifier("my:instance"), "my-instance");
/// assert_eq!(sanitize_identifier("ws connector"), "ws-connector");
/// assert_eq!(sanitize_identifier("with\ttab"), "with-tab");
/// assert_eq!(sanitize_identifier("with\nnewline"), "with-newline");
/// assert_eq!(sanitize_identifier("clean-id"), "clean-id");
/// ```
pub fn sanitize_identifier(id: &str) -> String {
    id.replace(['.', ':', ' ', '\t', '\n'], "-")
}

/// Format connector address as "tenant.type.instance"
pub fn format_address(tenant_id: &str, connector_type: &str, instance_id: &str) -> String {
    format!("{tenant_id}.{connector_type}.{instance_id}")
}

/// Parse connector address into components
pub fn parse_address(address: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = address.split('.').collect();
    if parts.len() != 3 {
        return Err(ConnectorError::InvalidConfig(format!(
            "Invalid address format: {address} (expected tenant.type.instance)"
        )));
    }
    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
    ))
}

/// Retry function with exponential backoff
pub async fn retry<F, Fut, T>(mut f: F, max_attempts: usize, delay_ms: u64) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_error = None;

    for attempt in 1..=max_attempts {
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                if attempt < max_attempts {
                    let backoff = delay_ms * 2_u64.pow((attempt - 1) as u32);
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff)).await;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| ConnectorError::Other("Retry exhausted".to_string())))
}

/// Normalize metadata to string key-value pairs
pub fn normalize_metadata(
    metadata: &serde_json::Value,
) -> std::collections::HashMap<String, String> {
    use std::collections::HashMap;

    let mut normalized = HashMap::new();

    if let Some(obj) = metadata.as_object() {
        for (key, value) in obj {
            if value.is_null() {
                continue;
            }

            let value_str = if value.is_object() || value.is_array() {
                serde_json::to_string(value).unwrap_or_else(|_| String::new())
            } else {
                value
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| value.to_string())
            };

            normalized.insert(key.clone(), value_str);
        }
    }

    normalized
}

/// Convert encoding name string to PayloadEncoding enum
pub fn encoding_from_string(name: &str) -> Result<PayloadEncoding> {
    let normalized = name.to_lowercase().replace('-', "_");
    match normalized.as_str() {
        "json" => Ok(PayloadEncoding::Json),
        "raw_bytes" => Ok(PayloadEncoding::RawBytes),
        "arrow_ipc" => Ok(PayloadEncoding::ArrowIpc),
        "json_lines" => Ok(PayloadEncoding::JsonLines),
        "protobuf" => Ok(PayloadEncoding::Protobuf),
        "msgpack" => Ok(PayloadEncoding::Msgpack),
        "parquet" => Ok(PayloadEncoding::Parquet),
        "unspecified" => Ok(PayloadEncoding::Unspecified),
        _ => Err(ConnectorError::InvalidConfig(format!(
            "Unknown encoding: {name}"
        ))),
    }
}

/// Convert PayloadEncoding enum to string name
pub fn encoding_to_string(encoding: PayloadEncoding) -> &'static str {
    match encoding {
        PayloadEncoding::Unspecified => "unspecified",
        PayloadEncoding::Json => "json",
        PayloadEncoding::RawBytes => "raw_bytes",
        PayloadEncoding::ArrowIpc => "arrow_ipc",
        PayloadEncoding::JsonLines => "json_lines",
        PayloadEncoding::Protobuf => "protobuf",
        PayloadEncoding::Msgpack => "msgpack",
        PayloadEncoding::Parquet => "parquet",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sanitize_failure_payload_patches_blank_failure() {
        // The wire contract (Strike48/matrix#4715, defect 2): a tool result
        // that reports a failure with a blank error must never leave the SDK
        // — the payload error is patched and the message returned for the
        // envelope.
        let payload = json!({
            "success": false,
            "data": Value::Null,
            "error": "",
            "outcome": "failed",
        });

        let (patched, envelope_error) = sanitize_failure_payload(&payload, Some("nmap"));

        let msg = envelope_error.expect("envelope error must be set on a blank failure");
        assert!(!msg.trim().is_empty());
        assert!(msg.contains("nmap"), "message should name the tool: {msg}");

        assert_eq!(patched["success"], false);
        assert_eq!(patched["error"], msg);
        // Non-error fields are preserved.
        assert_eq!(patched["outcome"], "failed");
    }

    #[test]
    fn sanitize_failure_payload_untouched_when_error_present() {
        let payload = json!({"success": false, "error": "target parameter is required"});

        let (patched, envelope_error) = sanitize_failure_payload(&payload, Some("nmap"));

        assert!(envelope_error.is_none());
        assert_eq!(patched["error"], "target parameter is required");
    }

    #[test]
    fn sanitize_failure_payload_untouched_on_success() {
        let payload = json!({"success": true, "data": json!({"count": 1})});

        let (patched, envelope_error) = sanitize_failure_payload(&payload, Some("nmap"));

        assert!(envelope_error.is_none());
        assert_eq!(patched["success"], true);
    }

    #[test]
    fn sanitize_failure_payload_handles_null_and_whitespace_errors() {
        for blank in [Value::Null, json!("   ")] {
            let payload = json!({"success": false, "error": blank});
            let (_, envelope_error) = sanitize_failure_payload(&payload, None);
            assert!(
                envelope_error.is_some(),
                "blank error {blank:?} must produce an envelope message"
            );
        }
    }

    #[test]
    fn sanitize_failure_payload_ignores_non_object_payloads() {
        let (patched, envelope_error) = sanitize_failure_payload(&json!("ok"), Some("nmap"));
        assert!(envelope_error.is_none());
        assert_eq!(patched, json!("ok"));
    }
}

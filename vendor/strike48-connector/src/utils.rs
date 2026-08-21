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

/// Sanitize an identifier so it is safe to use in a connector address.
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

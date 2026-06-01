//! Client for invoking StrikeKit capabilities via the connector gRPC stream.
//!
//! Sends `InvokeCapabilityRequest` messages to the platform's registered
//! prefix handler. Operations are fire-and-forget (non-blocking).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use strike48_proto::proto::{
    stream_message::Message, InvokeCapabilityRequest, PayloadEncoding, StreamMessage,
};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

/// Request to upload a binary artifact to StrikeKit.
#[derive(Debug, Serialize)]
pub struct UploadArtifactRequest {
    pub engagement_id: String,
    pub filename: String,
    pub content_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Client for StrikeKit operations via the connector stream.
///
/// Uses the same `Arc<RwLock<Option<UnboundedSender>>>` pattern as tool
/// execution so it works across reconnects.
#[derive(Clone)]
pub struct StrikeKitClient {
    stream_tx: Arc<RwLock<Option<mpsc::UnboundedSender<StreamMessage>>>>,
}

impl StrikeKitClient {
    /// Create a new client sharing the connector's stream sender.
    pub fn new(stream_tx: Arc<RwLock<Option<mpsc::UnboundedSender<StreamMessage>>>>) -> Self {
        Self { stream_tx }
    }

    /// Upload a binary artifact to StrikeKit. Fire-and-forget.
    pub async fn upload_artifact(&self, req: UploadArtifactRequest) {
        if let Err(e) = self.invoke("upload_artifact", &req).await {
            tracing::warn!("Failed to upload artifact to StrikeKit: {}", e);
        }
    }

    /// Upload a file from disk as an artifact. Convenience wrapper that reads
    /// the file and base64-encodes it.
    pub async fn upload_file(
        &self,
        engagement_id: &str,
        file_path: &str,
        evidence_type: &str,
        source: &str,
    ) {
        let path = std::path::Path::new(file_path);
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown")
            .to_string();

        match tokio::fs::read(file_path).await {
            Ok(bytes) => {
                let content_base64 = BASE64.encode(&bytes);
                self.upload_artifact(UploadArtifactRequest {
                    engagement_id: engagement_id.to_string(),
                    filename: filename.clone(),
                    content_base64,
                    evidence_type: Some(evidence_type.to_string()),
                    title: Some(filename),
                    source: Some(source.to_string()),
                    finding_id: None,
                    path: Some(file_path.to_string()),
                })
                .await;
            }
            Err(e) => {
                tracing::warn!("Failed to read artifact file {}: {}", file_path, e);
            }
        }
    }

    /// Send an invoke request over the gRPC stream.
    async fn invoke<T: Serialize>(&self, capability_id: &str, payload: &T) -> Result<(), String> {
        let payload_bytes =
            serde_json::to_vec(payload).map_err(|e| format!("serialize payload: {}", e))?;
        let payload_len = payload_bytes.len();

        let request = InvokeCapabilityRequest {
            request_id: Uuid::new_v4().to_string(),
            target_address: "strikekit://evidence".to_string(),
            capability_id: capability_id.to_string(),
            payload: payload_bytes,
            payload_encoding: PayloadEncoding::Json as i32,
            context: HashMap::new(),
            timeout_ms: 30000, // 30s for file uploads
            fire_and_forget: true,
        };

        let message = StreamMessage {
            message: Some(Message::InvokeRequest(request)),
        };

        let guard = self.stream_tx.read().await;
        match guard.as_ref() {
            Some(tx) => {
                let result = tx
                    .send(message)
                    .map_err(|_| "gRPC stream closed".to_string());
                if result.is_ok() {
                    tracing::info!(
                        "[strikekit] invoke sent: capability={} payload_size={}",
                        capability_id,
                        payload_len
                    );
                }
                result
            }
            None => {
                tracing::warn!("[strikekit] invoke failed: stream_tx is None (not connected)");
                Err("gRPC stream not connected".to_string())
            }
        }
    }
}

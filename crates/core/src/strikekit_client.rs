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

    /// Upload a binary artifact to StrikeKit.
    ///
    /// Returns `Ok(())` if the invoke message was handed off to the gRPC stream,
    /// or `Err(reason)` if the stream is closed/unavailable or serialization
    /// failed. The platform's actual processing is still asynchronous (this is
    /// a fire-and-forget invoke), so a successful return only proves the
    /// message was queued, not that the artifact landed.
    pub async fn upload_artifact(&self, req: UploadArtifactRequest) -> Result<(), String> {
        match self.invoke("upload_artifact", &req).await {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::warn!("Failed to upload artifact to StrikeKit: {}", e);
                Err(e)
            }
        }
    }

    /// Upload a file from disk as an artifact. Convenience wrapper that reads
    /// the file and base64-encodes it.
    ///
    /// Returns `Ok(())` on a queued upload, or `Err(reason)` if the file could
    /// not be read or the invoke failed to enqueue. Callers (e.g. webwright
    /// post-execution upload) use this to count successes vs. failures so the
    /// outcome can be reported back to the LLM/UI.
    pub async fn upload_file(
        &self,
        engagement_id: &str,
        file_path: &str,
        evidence_type: &str,
        source: &str,
    ) -> Result<(), String> {
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
                .await
            }
            Err(e) => {
                tracing::warn!("Failed to read artifact file {}: {}", file_path, e);
                Err(format!("read {}: {}", file_path, e))
            }
        }
    }

    /// Send an invoke request over the gRPC stream.
    async fn invoke<T: Serialize>(&self, capability_id: &str, payload: &T) -> Result<(), String> {
        let payload_bytes =
            serde_json::to_vec(payload).map_err(|e| format!("serialize payload: {}", e))?;

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
            Some(tx) => tx
                .send(message)
                .map_err(|_| "gRPC stream closed".to_string()),
            None => Err("gRPC stream not connected".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_artifact_request_serializes_required_fields() {
        let req = UploadArtifactRequest {
            engagement_id: "eng-123".to_string(),
            filename: "screenshot.png".to_string(),
            content_base64: "aGVsbG8=".to_string(),
            evidence_type: None,
            title: None,
            source: None,
            finding_id: None,
            path: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["engagement_id"], "eng-123");
        assert_eq!(json["filename"], "screenshot.png");
        assert_eq!(json["content_base64"], "aGVsbG8=");
        // Optional fields should be absent (skip_serializing_if)
        assert!(json.get("evidence_type").is_none());
        assert!(json.get("finding_id").is_none());
    }

    #[test]
    fn upload_artifact_request_includes_optional_fields_when_set() {
        let req = UploadArtifactRequest {
            engagement_id: "eng-456".to_string(),
            filename: "exploit.py".to_string(),
            content_base64: "cHJpbnQ=".to_string(),
            evidence_type: Some("script".to_string()),
            title: Some("XSS exploit".to_string()),
            source: Some("webwright".to_string()),
            finding_id: Some("finding-789".to_string()),
            path: Some("/workspace/exploit.py".to_string()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["evidence_type"], "script");
        assert_eq!(json["title"], "XSS exploit");
        assert_eq!(json["source"], "webwright");
        assert_eq!(json["finding_id"], "finding-789");
        assert_eq!(json["path"], "/workspace/exploit.py");
    }

    #[tokio::test]
    async fn client_returns_error_when_stream_not_connected() {
        let stream_tx = Arc::new(RwLock::new(None));
        let client = StrikeKitClient::new(stream_tx);
        let result = client
            .upload_artifact(UploadArtifactRequest {
                engagement_id: "eng".to_string(),
                filename: "f.txt".to_string(),
                content_base64: "".to_string(),
                evidence_type: None,
                title: None,
                source: None,
                finding_id: None,
                path: None,
            })
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not connected"));
    }

    #[tokio::test]
    async fn client_queues_message_when_stream_connected() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let stream_tx = Arc::new(RwLock::new(Some(tx)));
        let client = StrikeKitClient::new(stream_tx);
        let result = client
            .upload_artifact(UploadArtifactRequest {
                engagement_id: "eng".to_string(),
                filename: "f.txt".to_string(),
                content_base64: "".to_string(),
                evidence_type: None,
                title: None,
                source: None,
                finding_id: None,
                path: None,
            })
            .await;
        assert!(result.is_ok());
        // Verify a message was actually sent
        let msg = rx.try_recv().unwrap();
        assert!(msg.message.is_some());
    }
}

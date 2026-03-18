//! Structured output parsing for StrikeKit integration
//!
//! This module defines types and traits for converting tool outputs into
//! structured messages that StrikeKit can ingest.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Message Envelope
// ============================================================================

/// Message envelope for all Pick → StrikeKit communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub message_type: MessageType,
    pub engagement_id: String,
    pub connector_id: String,
    pub timestamp: DateTime<Utc>,
    pub tool_name: String,
    pub payload: serde_json::Value,
}

impl MessageEnvelope {
    /// Create a new message envelope
    pub fn new(
        message_type: MessageType,
        engagement_id: String,
        connector_id: String,
        tool_name: String,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            message_type,
            engagement_id,
            connector_id,
            timestamp: Utc::now(),
            tool_name,
            payload,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    TargetDiscovered,
    CredentialFound,
    FindingReported,
    ToolExecuted,
    ProgressUpdate,
}

// ============================================================================
// Target Messages
// ============================================================================

/// A discovered target (host, service, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetDiscovered {
    pub target_type: TargetType,
    pub name: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub domain: Option<String>,
    pub os: Option<String>,
    pub ports: Vec<PortInfo>,
    pub tags: Vec<String>,
    pub detection_source: String,
    pub confidence: Option<u8>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    Host,
    Domain,
    User,
    Service,
    Application,
    Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub number: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub state: PortState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

// ============================================================================
// Credential Messages
// ============================================================================

/// A discovered credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialFound {
    pub credential: CredentialInfo,
    pub target_id: Option<String>,
    pub privilege_tier: PrivilegeTier,
    pub test_result: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialInfo {
    pub credential_type: CredentialType,
    pub username: Option<String>,
    pub secret: String,
    pub domain: Option<String>,
    pub source: String,
    pub status: CredentialStatus,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    Plaintext,
    NtlmHash,
    KerberosTgt,
    KerberosTgs,
    SshKey,
    ApiToken,
    Cookie,
    Certificate,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Untested,
    Valid,
    Invalid,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeTier {
    DomainAdmin,
    LocalAdmin,
    User,
    Service,
    Unknown,
}

// ============================================================================
// Finding Messages
// ============================================================================

/// A security finding/vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingReported {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub status: FindingStatus,
    pub evidence: Vec<Evidence>,
    pub mitre_techniques: Vec<String>,
    pub remediation: Option<String>,
    pub cve_ids: Vec<String>,
    pub target_ids: Vec<String>,
    pub credential_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Draft,
    Confirmed,
    Exploited,
    Mitigated,
    Accepted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: String,
    pub description: String,
    pub data: String,
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// Activity Messages
// ============================================================================

/// Tool execution activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecuted {
    pub target_id: Option<String>,
    pub category: String,
    pub title: String,
    pub description: Option<String>,
    pub command: Option<String>,
    pub output: Option<String>,
    pub success: bool,
    pub duration_ms: u64,
    pub mitre_techniques: Vec<String>,
}

// ============================================================================
// Progress Messages
// ============================================================================

/// Real-time progress update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressUpdate {
    pub phase: String,
    pub status: ProgressStatus,
    pub current_tool: Option<String>,
    pub current_target: Option<String>,
    pub progress_percent: Option<u8>,
    pub eta_seconds: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressStatus {
    Starting,
    InProgress,
    Paused,
    Completed,
    Failed,
}

// ============================================================================
// Execution Finding (Automated Tool Output)
// ============================================================================

/// Raw automated finding from tool output (staging area before review)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionFinding {
    pub tool: String,
    pub finding_type: String,
    pub target: String,
    pub title: String,
    pub description: String,
    pub severity: Option<Severity>,
    pub confidence: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub mitre_techniques: Vec<String>,
    pub phase: Option<String>,
    pub evidence: Option<String>,
}

// ============================================================================
// Structured Message Union Type
// ============================================================================

/// All possible structured messages Pick can send to StrikeKit
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StructuredMessage {
    TargetDiscovered(TargetDiscovered),
    CredentialFound(CredentialFound),
    FindingReported(FindingReported),
    ToolExecuted(ToolExecuted),
    ProgressUpdate(ProgressUpdate),
    ExecutionFinding(ExecutionFinding),
}

impl StructuredMessage {
    /// Get the message type for this structured message
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::TargetDiscovered(_) => MessageType::TargetDiscovered,
            Self::CredentialFound(_) => MessageType::CredentialFound,
            Self::FindingReported(_) => MessageType::FindingReported,
            Self::ToolExecuted(_) => MessageType::ToolExecuted,
            Self::ProgressUpdate(_) => MessageType::ProgressUpdate,
            Self::ExecutionFinding(_) => MessageType::ToolExecuted, // Treat as tool execution
        }
    }

    /// Convert to message envelope for transmission
    pub fn into_envelope(
        self,
        engagement_id: String,
        connector_id: String,
        tool_name: String,
    ) -> crate::error::Result<MessageEnvelope> {
        let message_type = self.message_type();
        let payload = serde_json::to_value(&self).map_err(|e| {
            crate::error::Error::Serialization(format!("Failed to serialize message: {}", e))
        })?;

        Ok(MessageEnvelope::new(
            message_type,
            engagement_id,
            connector_id,
            tool_name,
            payload,
        ))
    }
}

// ============================================================================
// Output Parser Trait
// ============================================================================

/// Trait for parsing tool outputs into structured messages
pub trait OutputParser: Send + Sync {
    /// Parse tool output into structured messages for StrikeKit
    ///
    /// # Arguments
    /// * `tool_name` - Name of the tool that produced the output
    /// * `result` - The tool execution result
    /// * `context` - Additional context (engagement ID, connector ID, etc.)
    ///
    /// # Returns
    /// Vector of structured messages to send to StrikeKit
    fn parse(
        &self,
        tool_name: &str,
        result: &crate::tools::ToolResult,
        context: &ParserContext,
    ) -> Vec<StructuredMessage>;

    /// Get the name of this parser (usually matches tool name)
    fn parser_name(&self) -> &str;
}

/// Context provided to parsers
#[derive(Debug, Clone)]
pub struct ParserContext {
    pub engagement_id: String,
    pub connector_id: String,
    pub target_id: Option<String>,
}

impl ParserContext {
    /// Create a new parser context
    pub fn new(engagement_id: String, connector_id: String) -> Self {
        Self {
            engagement_id,
            connector_id,
            target_id: None,
        }
    }

    /// Set the target ID for this context
    pub fn with_target(mut self, target_id: String) -> Self {
        self.target_id = Some(target_id);
        self
    }
}

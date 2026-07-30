//! Phoenix/Absinthe WebSocket frame protocol and GraphQL subscription event parsing.
//!
//! This module provides pure functions for building Phoenix protocol frames,
//! parsing subscription events, and building WebSocket URLs for Absinthe GraphQL subscriptions.

use crate::matrix::types::{AgentStatus, ChatMessage};
use serde_json::Value;

// Phoenix protocol constants
const CONTROL_TOPIC: &str = "__absinthe__:control";
const HEARTBEAT_TOPIC: &str = "phoenix";
const JOIN_EVENT: &str = "phx_join";
const DOC_EVENT: &str = "doc";
const HEARTBEAT_EVENT: &str = "heartbeat";
const SUBSCRIPTION_DATA_EVENT: &str = "subscription:data";

/// GraphQL subscription document for conversation events.
/// This is the full selection set including all event types and their fields.
pub const CONVERSATION_EVENTS_SUBSCRIPTION: &str = r#"
subscription ConversationEvents($conversationId: ID!) {
  conversationEvents(conversationId: $conversationId) {
    __typename
    ... on Message {
      id
      timestamp
      conversationId
      parentId
      metadata
      parts {
        __typename
        ... on TextPart {
          id
          text
        }
        ... on ThinkingPart {
          id
          thinking {
            content
            signature
          }
        }
        ... on ToolCallPart {
          id
          toolCall {
            id
            name
            arguments
            result
            error
            status
          }
        }
        ... on ImageUrlPart {
          id
          imageUrl {
            url
            detail
          }
        }
      }
      profile {
        id
        type
        name
        avatarUrl
      }
    }
    ... on MessagePartStreamingEvent {
      id
      messageId
      content
      timestamp
    }
    ... on ThinkingStreamingEvent {
      id
      messageId
      thinkingPartId
      content
      signature
      timestamp
    }
    ... on AgentStatusEvent {
      id
      conversationId
      agentId
      agentStatus
      message
      error
      toolName
      timestamp
    }
    ... on ToolCallMessageEvent {
      id
      conversationId
      agentId
      toolCallId
      toolName
      arguments
      result
      error
      status
      timestamp
    }
    ... on ToolCallStartedEvent {
      id
      messageId
      toolCallId
      toolName
      timestamp
    }
    ... on ToolCallStreamingEvent {
      id
      messageId
      toolCallId
      delta
      timestamp
    }
    ... on ToolCallApprovalEvent {
      id
      conversationId
      agentId
      toolCallId
      approvalMode
      status
      timestamp
    }
    ... on ConversationUpdateEvent {
      id
      title
      summary
      metadata
      timestamp
    }
    ... on ChildMessageEvent {
      id
      type
      messageType
      sourceConversationId
      sourceConversationTitle
      timestamp
      data
    }
    ... on ToolResultCompactingEvent {
      id
      conversationId
      timestamp
      toolCallId
      toolName
      originalSizeBytes
    }
    ... on ToolResultCompactedEvent {
      id
      conversationId
      timestamp
      toolCallId
      toolName
      format
      originalSizeBytes
      encodedSizeBytes
      tokenSavingsPct
    }
    ... on ConversationCompactingEvent {
      id
      conversationId
      timestamp
      messageCount
    }
    ... on ConversationCompactedEvent {
      id
      conversationId
      snapshotId
      messagesSummarized
      lastMessageId
      snapshotTokens
      snapshotSizeBytes
      timestamp
    }
  }
}
"#;

/// Build WebSocket URL for Absinthe GraphQL subscription.
/// Converts http -> ws, https -> wss, sets path to /v1alpha/graphql_socket/websocket,
/// and adds the token query parameter (no vsn -> Phoenix v1 object frames).
pub fn build_ws_url(api_url: &str, token: &str) -> String {
    let api_url = api_url.trim_end_matches('/');

    // Determine scheme
    let (scheme, rest) = if let Some(rest) = api_url.strip_prefix("https://") {
        ("wss", rest)
    } else if let Some(rest) = api_url.strip_prefix("http://") {
        ("ws", rest)
    } else {
        // Default to wss if no scheme
        ("wss", api_url)
    };

    // URL-encode the token
    let encoded_token = urlencoding::encode(token);

    // NO `vsn` param. Phoenix then defaults to its v1 (object) serializer, which
    // matches the `{topic, event, payload, ref}` frames create_join/
    // create_subscription build. Passing `vsn=2.0.0` would demand v2 ARRAY
    // frames (`[join_ref, ref, topic, event, payload]`); sending object frames
    // under v2 makes the server silently fail to decode the join (never acks),
    // so no events ever arrive. This matches the working matrix-core client,
    // which also sends only `?token=`.
    format!(
        "{}://{}/v1alpha/graphql_socket/websocket?token={}",
        scheme, rest, encoded_token
    )
}

/// Create Phoenix join frame for the Absinthe control topic.
pub fn create_join(ref_id: &str) -> Value {
    serde_json::json!({
        "topic": CONTROL_TOPIC,
        "event": JOIN_EVENT,
        "payload": {},
        "ref": ref_id
    })
}

/// Create Phoenix subscription frame with the conversationEvents query.
pub fn create_subscription(conversation_id: &str, ref_id: &str) -> Value {
    serde_json::json!({
        "topic": CONTROL_TOPIC,
        "event": DOC_EVENT,
        "payload": {
            "query": CONVERSATION_EVENTS_SUBSCRIPTION,
            "variables": {
                "conversationId": conversation_id
            }
        },
        "ref": ref_id
    })
}

/// Create Phoenix heartbeat frame.
pub fn create_heartbeat(ref_id: &str) -> Value {
    serde_json::json!({
        "topic": HEARTBEAT_TOPIC,
        "event": HEARTBEAT_EVENT,
        "payload": {},
        "ref": ref_id
    })
}

/// Extract the conversationEvents data from a Phoenix subscription:data message.
/// Returns None if the message is not a subscription:data event or if the path is invalid.
pub fn extract_event(message: &Value) -> Option<Value> {
    // Only process subscription:data events
    if message.get("event")?.as_str()? != SUBSCRIPTION_DATA_EVENT {
        return None;
    }

    // Navigate: payload.result.data.conversationEvents
    let event = message
        .get("payload")?
        .get("result")?
        .get("data")?
        .get("conversationEvents")?
        .clone();

    Some(event)
}

/// Conversation stream event variants.
#[derive(Debug, Clone)]
pub enum ConversationStreamEvent {
    /// Full message with all parts (upsert by id).
    Message(ChatMessage),
    /// Text streaming delta for a message.
    PartStreaming { message_id: String, content: String },
    /// Thinking streaming delta for a message.
    ThinkingStreaming { message_id: String, content: String },
    /// Tool call update (from ToolCallMessageEvent).
    ToolCall {
        id: String,
        name: String,
        arguments: Option<String>,
        result: Option<String>,
        error: Option<String>,
        status: String,
    },
    /// Tool call started: carries the tool name at the START of a call, before
    /// any result. Lets the UI show "running <tool>" instead of a nameless
    /// spinner during a long-running tool.
    ToolCallStarted {
        tool_call_id: String,
        tool_name: String,
    },
    /// Tool call streaming delta.
    ToolCallStreaming { tool_call_id: String, delta: String },
    /// Agent status change.
    Status {
        status: AgentStatus,
        error: Option<String>,
        tool_name: Option<String>,
    },
    /// Conversation metadata update (title/summary).
    ConversationUpdate {
        title: String,
        summary: Option<String>,
    },
    /// Unknown or uninteresting event type.
    Other,
}

/// Parse a conversationEvents GraphQL event into a typed variant.
/// Unknown __typename values return Other. Missing fields are handled gracefully.
pub fn parse_event(event: &Value) -> ConversationStreamEvent {
    let typename = event
        .get("__typename")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match typename {
        "Message" => {
            // Parse full message using the shared parse_message_parts helper
            let parts_json = event
                .get("parts")
                .and_then(|v| v.as_array())
                .map(|arr| arr.as_slice())
                .unwrap_or(&[]);

            let (text, parts) = crate::matrix::client::parse_message_parts(parts_json);

            let profile = event.get("profile");
            let sender_type = profile
                .and_then(|p| p.get("type"))
                .and_then(|t| t.as_str())
                .unwrap_or("AGENT")
                .to_string();
            let sender_name = profile
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("Agent")
                .to_string();

            ConversationStreamEvent::Message(ChatMessage {
                id: event
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                sender_type,
                sender_name,
                text,
                parts,
            })
        }
        "MessagePartStreamingEvent" => {
            let message_id = event
                .get("messageId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let content = event
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ConversationStreamEvent::PartStreaming {
                message_id,
                content,
            }
        }
        "ThinkingStreamingEvent" => {
            let message_id = event
                .get("messageId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let content = event
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ConversationStreamEvent::ThinkingStreaming {
                message_id,
                content,
            }
        }
        "ToolCallMessageEvent" => {
            let id = event
                .get("toolCallId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = event
                .get("toolName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let arguments = event
                .get("arguments")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let result = event
                .get("result")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let error = event
                .get("error")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let status = event
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            ConversationStreamEvent::ToolCall {
                id,
                name,
                arguments,
                result,
                error,
                status,
            }
        }
        "ToolCallStartedEvent" => {
            let tool_call_id = event
                .get("toolCallId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let tool_name = event
                .get("toolName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ConversationStreamEvent::ToolCallStarted {
                tool_call_id,
                tool_name,
            }
        }
        "ToolCallStreamingEvent" => {
            let tool_call_id = event
                .get("toolCallId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let delta = event
                .get("delta")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ConversationStreamEvent::ToolCallStreaming {
                tool_call_id,
                delta,
            }
        }
        "AgentStatusEvent" => {
            let status_str = event
                .get("agentStatus")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN");
            let status = status_str
                .parse::<AgentStatus>()
                .unwrap_or(AgentStatus::Unknown);
            let error = event
                .get("error")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let tool_name = event
                .get("toolName")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            ConversationStreamEvent::Status {
                status,
                error,
                tool_name,
            }
        }
        "ConversationUpdateEvent" => {
            let title = event
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let summary = event
                .get("summary")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            ConversationStreamEvent::ConversationUpdate { title, summary }
        }
        _ => ConversationStreamEvent::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_https_to_wss_with_token_no_vsn() {
        let u = build_ws_url("https://plg.strike48.test", "tok en/+");
        assert!(u.starts_with("wss://plg.strike48.test/v1alpha/graphql_socket/websocket?"));
        assert!(u.contains("token=tok%20en%2F%2B")); // url-encoded
                                                     // No vsn param -> Phoenix v1 (object) serializer, matching our frames.
        assert!(!u.contains("vsn="));
        assert_eq!(
            build_ws_url("http://localhost:4000", "t")
                .split("://")
                .next(),
            Some("ws")
        );
    }

    #[test]
    fn join_and_subscription_frames() {
        let j = create_join("1");
        assert_eq!(j["topic"], "__absinthe__:control");
        assert_eq!(j["event"], "phx_join");
        assert_eq!(j["ref"], "1");
        let s = create_subscription("conv-9", "2");
        assert_eq!(s["event"], "doc");
        assert_eq!(s["payload"]["variables"]["conversationId"], "conv-9");
        assert!(s["payload"]["query"]
            .as_str()
            .unwrap()
            .contains("conversationEvents"));
        let h = create_heartbeat("3");
        assert_eq!(h["topic"], "phoenix");
        assert_eq!(h["event"], "heartbeat");
    }

    #[test]
    fn extract_only_subscription_data() {
        let non = serde_json::json!({"event":"phx_reply","payload":{}});
        assert!(extract_event(&non).is_none());
        let data = serde_json::json!({
            "event":"subscription:data",
            "payload":{"result":{"data":{"conversationEvents":{"__typename":"AgentStatusEvent","agentStatus":"IDLE"}}}}
        });
        let ev = extract_event(&data).expect("event");
        assert_eq!(ev["__typename"], "AgentStatusEvent");
    }

    #[test]
    fn parse_event_variants() {
        let m = serde_json::json!({"__typename":"MessagePartStreamingEvent","messageId":"m1","content":"hel"});
        assert!(
            matches!(parse_event(&m), ConversationStreamEvent::PartStreaming { message_id, content } if message_id=="m1" && content=="hel")
        );
        let s = serde_json::json!({"__typename":"AgentStatusEvent","agentStatus":"ERROR","error":"boom"});
        assert!(
            matches!(parse_event(&s), ConversationStreamEvent::Status { error: Some(e), .. } if e=="boom")
        );
        let u = serde_json::json!({"__typename":"SomethingNew"});
        assert!(matches!(parse_event(&u), ConversationStreamEvent::Other));
    }
}

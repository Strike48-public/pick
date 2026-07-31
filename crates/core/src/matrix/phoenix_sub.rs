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

/// Resolve the subscription WebSocket URL, honoring a proxy-advertised override.
///
/// When embedded in StrikeHub, the auth proxy injects `window.__MATRIX_WS_URL__`
/// (e.g. `ws://127.0.0.1:PORT/ws/graphql`) — a socket it terminates and relays
/// to Matrix's `/v1alpha/graphql_socket/websocket`. Honoring it keeps the
/// subscription on the same authenticated origin as the HTTP GraphQL calls
/// (avoiding a second TLS/cert path) instead of dialing Matrix directly. The
/// override already carries the correct scheme, host, AND path, so we only
/// append `?token=&vsn=2.0.0` — we must NOT re-derive the canonical path onto it.
///
/// When no override is present (standalone desktop dialing Matrix directly), we
/// fall back to [`build_ws_url`], which synthesizes the canonical path from
/// `api_url`. Both paths use `vsn=2.0.0` (v2 array frames).
pub fn resolve_ws_url(api_url: &str, ws_url_override: Option<&str>, token: &str) -> String {
    match ws_url_override {
        Some(base) if !base.is_empty() => {
            let base = base.trim_end_matches('/');
            let encoded_token = urlencoding::encode(token);
            // The proxy normally advertises a bare URL, but if it ever carries a
            // query string, append with `&` instead of a second `?` (which would
            // make a malformed URL the WS dial silently fails on).
            let sep = if base.contains('?') { '&' } else { '?' };
            format!("{base}{sep}token={encoded_token}&vsn=2.0.0")
        }
        _ => build_ws_url(api_url, token),
    }
}

/// Build WebSocket URL for Absinthe GraphQL subscription from a Matrix API URL.
/// Converts http -> ws, https -> wss, sets path to /v1alpha/graphql_socket/websocket,
/// and adds the token + `vsn=2.0.0` query params (Phoenix v2 array frames).
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

    // `vsn=2.0.0` selects Phoenix's v2 (array) serializer, matching the
    // `[join_ref, ref, topic, event, payload]` frames create_join/
    // create_subscription/create_heartbeat build. This is also what StrikeHub's
    // auth proxy forwards (its /ws/graphql route defaults absent clients to
    // vsn=2.0.0), so honoring the proxy-advertised WS URL and dialing Matrix
    // directly use the same wire format. The URL's vsn and the frame envelope
    // MUST agree: sending v1 object frames under vsn=2.0.0 (or vice versa) makes
    // Phoenix silently fail to decode the join, so it never acks and no events
    // arrive.
    format!(
        "{}://{}/v1alpha/graphql_socket/websocket?token={}&vsn=2.0.0",
        scheme, rest, encoded_token
    )
}

// Phoenix frames use the v2 serializer (array/"binary" format), matching the
// `vsn=2.0.0` we send on the socket URL. Every client->server and server->client
// message is a 5-element array:
//   [join_ref, ref, topic, event, payload]
// `join_ref` ties a message to the channel join; `ref` is the per-message id the
// server echoes back in `phx_reply`. Server-pushed messages (subscription data)
// carry null join_ref/ref. Passing `vsn=2.0.0` but sending v1 object frames makes
// Phoenix silently fail to decode the join (it never acks), so the envelope shape
// and the URL's vsn must always agree.

// Phoenix v2 array frame layout: [join_ref, ref, topic, event, payload].
// Only the indices the accessors below read are named; join_ref (0) and topic
// (2) are positional-only (we build them but never parse them back out).
const IDX_REF: usize = 1;
const IDX_EVENT: usize = 3;
const IDX_PAYLOAD: usize = 4;

/// Create a Phoenix v2 join frame for the Absinthe control topic.
///
/// `join_ref` identifies this channel join for its lifetime; it is echoed in the
/// `phx_reply` and reused as the join_ref on every later frame for this channel.
pub fn create_join(join_ref: &str, ref_id: &str) -> Value {
    serde_json::json!([join_ref, ref_id, CONTROL_TOPIC, JOIN_EVENT, {}])
}

/// Create a Phoenix v2 subscription (`doc`) frame with the conversationEvents query.
pub fn create_subscription(conversation_id: &str, join_ref: &str, ref_id: &str) -> Value {
    serde_json::json!([
        join_ref,
        ref_id,
        CONTROL_TOPIC,
        DOC_EVENT,
        {
            "query": CONVERSATION_EVENTS_SUBSCRIPTION,
            "variables": { "conversationId": conversation_id }
        }
    ])
}

/// Create a Phoenix v2 heartbeat frame. Heartbeats are not tied to a channel
/// join, so `join_ref` is null.
pub fn create_heartbeat(ref_id: &str) -> Value {
    serde_json::json!([Value::Null, ref_id, HEARTBEAT_TOPIC, HEARTBEAT_EVENT, {}])
}

/// The `event` name of a Phoenix v2 array frame, if it is well-formed.
pub fn frame_event(message: &Value) -> Option<&str> {
    message.get(IDX_EVENT)?.as_str()
}

/// The `ref` of a Phoenix v2 array frame, if present.
pub fn frame_ref(message: &Value) -> Option<&str> {
    message.get(IDX_REF)?.as_str()
}

/// The `payload` (5th element) of a Phoenix v2 array frame.
pub fn frame_payload(message: &Value) -> Option<&Value> {
    message.get(IDX_PAYLOAD)
}

/// Extract the conversationEvents data from a Phoenix v2 subscription:data frame.
/// Returns None if the frame is not a subscription:data event or the path is invalid.
pub fn extract_event(message: &Value) -> Option<Value> {
    // Only process subscription:data events (index 3 in the v2 array frame).
    if frame_event(message)? != SUBSCRIPTION_DATA_EVENT {
        return None;
    }

    // Navigate: payload.result.data.conversationEvents
    let event = frame_payload(message)?
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
    fn ws_url_https_to_wss_with_token_and_v2_vsn() {
        let u = build_ws_url("https://plg.strike48.test", "tok en/+");
        assert!(u.starts_with("wss://plg.strike48.test/v1alpha/graphql_socket/websocket?"));
        assert!(u.contains("token=tok%20en%2F%2B")); // url-encoded
                                                     // vsn=2.0.0 -> Phoenix v2 (array) serializer, matching our frames.
        assert!(u.contains("vsn=2.0.0"));
        assert_eq!(
            build_ws_url("http://localhost:4000", "t")
                .split("://")
                .next(),
            Some("ws")
        );
    }

    #[test]
    fn resolve_ws_url_prefers_override_and_appends_auth() {
        // With a proxy-advertised override, dial it verbatim + token + vsn — do
        // NOT re-append the canonical /v1alpha path.
        let u = resolve_ws_url(
            "https://plg.strike48.test",
            Some("ws://127.0.0.1:8765/ws/graphql"),
            "tok/+",
        );
        assert_eq!(
            u,
            "ws://127.0.0.1:8765/ws/graphql?token=tok%2F%2B&vsn=2.0.0"
        );
        assert!(!u.contains("/v1alpha/graphql_socket/websocket"));

        // No override (None or empty) -> fall back to build_ws_url from api_url.
        let fallback = resolve_ws_url("https://plg.strike48.test", None, "t");
        assert_eq!(fallback, build_ws_url("https://plg.strike48.test", "t"));
        let fallback_empty = resolve_ws_url("https://plg.strike48.test", Some(""), "t");
        assert_eq!(
            fallback_empty,
            build_ws_url("https://plg.strike48.test", "t")
        );
    }

    #[test]
    fn join_and_subscription_frames() {
        // v2 array envelope: [join_ref, ref, topic, event, payload]
        let j = create_join("10", "1");
        assert_eq!(j[0], "10"); // join_ref
        assert_eq!(j[IDX_REF], "1");
        assert_eq!(j[2], "__absinthe__:control"); // topic
        assert_eq!(j[IDX_EVENT], "phx_join");
        let s = create_subscription("conv-9", "10", "2");
        assert_eq!(s[0], "10"); // join_ref
        assert_eq!(s[IDX_EVENT], "doc");
        assert_eq!(s[IDX_PAYLOAD]["variables"]["conversationId"], "conv-9");
        assert!(s[IDX_PAYLOAD]["query"]
            .as_str()
            .unwrap()
            .contains("conversationEvents"));
        let h = create_heartbeat("3");
        assert_eq!(h[0], Value::Null); // heartbeat has no channel join
        assert_eq!(h[2], "phoenix"); // topic
        assert_eq!(h[IDX_EVENT], "heartbeat");
    }

    #[test]
    fn extract_only_subscription_data() {
        // v2 array frames: [join_ref, ref, topic, event, payload]
        let non = serde_json::json!([null, "1", "__absinthe__:control", "phx_reply", {}]);
        assert!(extract_event(&non).is_none());
        let data = serde_json::json!([
            null, null, "__absinthe__:doc:1", "subscription:data",
            {"result":{"data":{"conversationEvents":{"__typename":"AgentStatusEvent","agentStatus":"IDLE"}}}}
        ]);
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

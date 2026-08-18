//! Event applier for streaming conversation events.
//!
//! Pure function that folds `ConversationStreamEvent` into a message list,
//! updating messages in place for streaming updates and returning status/error
//! signals for the UI to consume.

use crate::matrix::phoenix_sub::ConversationStreamEvent;
use crate::matrix::types::{AgentStatus, ChatMessage, MessagePart, ToolCallInfo, ToolCallStatus};

/// Outcome of applying an event to the message list.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApplyOutcome {
    pub status: Option<AgentStatus>,
    pub error: Option<String>,
}

/// Apply a conversation stream event to the message list.
///
/// This is a pure function that mutates the message list in place and returns
/// status/error signals for the UI to update thinking/error displays.
///
/// # Event handling rules
///
/// - `Message(m)`: Upsert by id (replace if present, else push)
/// - `PartStreaming{message_id, content}`: Find or create message; append to trailing Text part
/// - `ThinkingStreaming{message_id, content}`: Find or create message; append to trailing Thinking part
/// - `ToolCall{...}`: Find or create owning message; upsert ToolCall part by id
/// - `ToolCallStreaming{...}`: Find or create owning message; append delta to arguments
/// - `Status{...}`: Return in outcome; no message mutation
/// - `ConversationUpdate` / `Other`: No-op
pub fn apply_event(msgs: &mut Vec<ChatMessage>, ev: &ConversationStreamEvent) -> ApplyOutcome {
    match ev {
        ConversationStreamEvent::Message(m) => {
            // Upsert by id: replace if present, else push.
            if let Some(pos) = msgs.iter().position(|msg| msg.id == m.id) {
                msgs[pos] = m.clone();
            } else if let Some(pos) = msgs.iter().position(|msg| {
                // The server echo of the user's own turn has a fresh UUID, but
                // we optimistically rendered it with a `local-*` id. Replace
                // that bubble in place so the live stream does not show a
                // duplicate "You" message (the reseed path dedups the same way).
                msg.id.starts_with("local-")
                    && m.sender_type == "USER"
                    && msg.sender_type == "USER"
                    && msg.text == m.text
            }) {
                msgs[pos] = m.clone();
            } else {
                msgs.push(m.clone());
            }
            ApplyOutcome::default()
        }

        ConversationStreamEvent::PartStreaming {
            message_id,
            content,
        } => {
            // Find or create the message
            let msg = match msgs.iter_mut().find(|m| m.id == *message_id) {
                Some(m) => m,
                None => {
                    // Create a new AGENT message
                    msgs.push(ChatMessage {
                        id: message_id.clone(),
                        sender_type: "AGENT".to_string(),
                        sender_name: "Agent".to_string(),
                        text: String::new(),
                        parts: vec![],
                    });
                    msgs.last_mut().unwrap()
                }
            };

            // `content` is CUMULATIVE (the full text so far), not a delta — the
            // backend/web client treat it as "grows rather than increments" and
            // reset the last text part. Appending would repeat text
            // ("Perfect" -> "PerfectPerfect!" -> ...). Replace instead.
            //
            // There is exactly one logical text part per message. Find and update
            // it in place, wherever it sits. Using `last_mut()` here caused a bug:
            // once a tool-call part became the last element (e.g. with parallel
            // tool calls), a later cumulative text delta pushed a SECOND Text part
            // after the tools, so the same text rendered both above and below the
            // calls until the stream settled.
            if let Some(MessagePart::Text(text)) = msg
                .parts
                .iter_mut()
                .find(|p| matches!(p, MessagePart::Text(_)))
            {
                text.clone_from(content);
            } else {
                msg.parts.push(MessagePart::Text(content.clone()));
            }

            // Keep .text in sync (also cumulative).
            msg.text.clone_from(content);

            ApplyOutcome::default()
        }

        ConversationStreamEvent::ThinkingStreaming {
            message_id,
            content,
        } => {
            // Find or create the message
            let msg = match msgs.iter_mut().find(|m| m.id == *message_id) {
                Some(m) => m,
                None => {
                    msgs.push(ChatMessage {
                        id: message_id.clone(),
                        sender_type: "AGENT".to_string(),
                        sender_name: "Agent".to_string(),
                        text: String::new(),
                        parts: vec![],
                    });
                    msgs.last_mut().unwrap()
                }
            };

            // Cumulative, like MessagePartStreamingEvent — replace, don't append.
            // Find and update the existing Thinking part in place (same fix as
            // Text handler to prevent duplication with parallel tool calls).
            if let Some(MessagePart::Thinking(thinking)) = msg
                .parts
                .iter_mut()
                .find(|p| matches!(p, MessagePart::Thinking(_)))
            {
                thinking.clone_from(content);
            } else {
                msg.parts.push(MessagePart::Thinking(content.clone()));
            }

            ApplyOutcome::default()
        }

        ConversationStreamEvent::ToolCallStarted {
            tool_call_id,
            tool_name,
        } => {
            // Show the tool name as soon as the call starts (before any result),
            // so a long-running tool renders "running <tool>" instead of a
            // nameless spinner. Upsert a Running tool-call part by id.
            let msg = match msgs.iter_mut().rev().find(|m| m.sender_type == "AGENT") {
                Some(m) => m,
                None => {
                    msgs.push(ChatMessage {
                        id: format!("tool-owner-{}", tool_call_id),
                        sender_type: "AGENT".to_string(),
                        sender_name: "Agent".to_string(),
                        text: String::new(),
                        parts: vec![],
                    });
                    msgs.last_mut().unwrap()
                }
            };
            if let Some(part) = msg.parts.iter_mut().find_map(|p| match p {
                MessagePart::ToolCall(tc) if tc.id == *tool_call_id => Some(tc),
                _ => None,
            }) {
                // Fill the name if we somehow saw the call before its start.
                if part.name.is_empty() {
                    part.name.clone_from(tool_name);
                }
            } else {
                msg.parts.push(MessagePart::ToolCall(ToolCallInfo {
                    id: tool_call_id.clone(),
                    name: tool_name.clone(),
                    arguments: None,
                    result: None,
                    error: None,
                    status: ToolCallStatus::Running,
                }));
            }
            ApplyOutcome::default()
        }

        ConversationStreamEvent::ToolCall {
            id,
            name,
            arguments,
            result,
            error,
            status,
        } => {
            // Find or create the owning message (most recent AGENT message)
            let msg = match msgs.iter_mut().rev().find(|m| m.sender_type == "AGENT") {
                Some(m) => m,
                None => {
                    // Create a new AGENT message
                    msgs.push(ChatMessage {
                        id: format!("tool-owner-{}", id),
                        sender_type: "AGENT".to_string(),
                        sender_name: "Agent".to_string(),
                        text: String::new(),
                        parts: vec![],
                    });
                    msgs.last_mut().unwrap()
                }
            };

            // Upsert ToolCall part by id
            let parsed_status = status
                .parse::<ToolCallStatus>()
                .unwrap_or(ToolCallStatus::Unknown);

            if let Some(part) = msg.parts.iter_mut().find_map(|p| match p {
                MessagePart::ToolCall(tc) if tc.id == *id => Some(tc),
                _ => None,
            }) {
                // Update existing
                part.status = parsed_status;
                if let Some(ref a) = arguments {
                    part.arguments = Some(a.clone());
                }
                if let Some(ref r) = result {
                    part.result = Some(r.clone());
                }
                if let Some(ref e) = error {
                    part.error = Some(e.clone());
                }
            } else {
                // Create new
                msg.parts.push(MessagePart::ToolCall(ToolCallInfo {
                    id: id.clone(),
                    name: name.clone(),
                    arguments: arguments.clone(),
                    result: result.clone(),
                    error: error.clone(),
                    status: parsed_status,
                }));
            }

            ApplyOutcome::default()
        }

        ConversationStreamEvent::ToolCallStreaming {
            tool_call_id,
            delta,
        } => {
            // Find the owning message (most recent AGENT message with this tool call)
            let msg_opt = msgs.iter_mut().rev().find(|m| {
                m.sender_type == "AGENT"
                    && m.parts
                        .iter()
                        .any(|p| matches!(p, MessagePart::ToolCall(tc) if tc.id == *tool_call_id))
            });

            let msg = if msg_opt.is_some() {
                msg_opt
            } else {
                // Try to find most recent AGENT message
                let agent_msg = msgs.iter_mut().rev().find(|m| m.sender_type == "AGENT");

                if agent_msg.is_some() {
                    agent_msg
                } else {
                    // Create a new AGENT message
                    msgs.push(ChatMessage {
                        id: format!("tool-stream-owner-{}", tool_call_id),
                        sender_type: "AGENT".to_string(),
                        sender_name: "Agent".to_string(),
                        text: String::new(),
                        parts: vec![],
                    });
                    msgs.last_mut()
                }
            };

            if let Some(msg) = msg {
                // Find or create the tool call part
                if let Some(part) = msg.parts.iter_mut().find_map(|p| match p {
                    MessagePart::ToolCall(tc) if tc.id == *tool_call_id => Some(tc),
                    _ => None,
                }) {
                    // Append delta to arguments
                    match &mut part.arguments {
                        Some(args) => args.push_str(delta),
                        None => part.arguments = Some(delta.clone()),
                    }
                } else {
                    // Create new tool call part
                    msg.parts.push(MessagePart::ToolCall(ToolCallInfo {
                        id: tool_call_id.clone(),
                        name: String::new(),
                        arguments: Some(delta.clone()),
                        result: None,
                        error: None,
                        status: ToolCallStatus::Running,
                    }));
                }
            }

            ApplyOutcome::default()
        }

        ConversationStreamEvent::Status {
            status,
            error,
            tool_name: _,
        } => ApplyOutcome {
            status: Some(*status),
            error: error.clone(),
        },

        ConversationStreamEvent::ConversationUpdate { .. } | ConversationStreamEvent::Other => {
            ApplyOutcome::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_msg(id: &str, text: &str) -> ChatMessage {
        ChatMessage {
            id: id.to_string(),
            sender_type: "AGENT".to_string(),
            sender_name: "Agent".to_string(),
            text: text.to_string(),
            parts: vec![MessagePart::Text(text.to_string())],
        }
    }

    fn user_msg(id: &str, text: &str) -> ChatMessage {
        ChatMessage {
            id: id.to_string(),
            sender_type: "USER".to_string(),
            sender_name: "You".to_string(),
            text: text.to_string(),
            parts: vec![MessagePart::Text(text.to_string())],
        }
    }

    #[test]
    fn server_user_echo_replaces_optimistic_local_bubble() {
        // Optimistic bubble rendered on send with a local-* id.
        let mut msgs = vec![user_msg("local-0", "scan my net")];
        // Server echoes the same turn with a real UUID during live streaming.
        apply_event(
            &mut msgs,
            &ConversationStreamEvent::Message(user_msg("uuid-123", "scan my net")),
        );
        // Replaced in place, not duplicated.
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].id, "uuid-123");
        // A different user turn is NOT collapsed onto the local bubble.
        let mut msgs2 = vec![user_msg("local-0", "first")];
        apply_event(
            &mut msgs2,
            &ConversationStreamEvent::Message(user_msg("uuid-9", "second")),
        );
        assert_eq!(msgs2.len(), 2);
    }

    #[test]
    fn tool_call_started_shows_name_while_running() {
        let mut msgs = vec![agent_msg("m1", "working")];
        apply_event(
            &mut msgs,
            &ConversationStreamEvent::ToolCallStarted {
                tool_call_id: "t1".into(),
                tool_name: "port_scan".into(),
            },
        );
        let tc = msgs
            .iter()
            .flat_map(|m| &m.parts)
            .find_map(|p| match p {
                MessagePart::ToolCall(tc) if tc.id == "t1" => Some(tc),
                _ => None,
            })
            .expect("tool call part created");
        assert_eq!(tc.name, "port_scan");
        assert!(matches!(tc.status, ToolCallStatus::Running));
    }

    #[test]
    fn part_streaming_replaces_with_cumulative_content() {
        // MessagePartStreamingEvent.content is CUMULATIVE (full text so far),
        // not a delta — each event carries the whole string, so we replace the
        // text part rather than append (appending repeated: "Hel"->"Hello"
        // becoming "HelHello").
        let mut msgs = vec![];
        apply_event(
            &mut msgs,
            &ConversationStreamEvent::PartStreaming {
                message_id: "m1".into(),
                content: "Hel".into(),
            },
        );
        apply_event(
            &mut msgs,
            &ConversationStreamEvent::PartStreaming {
                message_id: "m1".into(),
                content: "Hello".into(),
            },
        );
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text, "Hello");
    }

    #[test]
    fn full_message_upserts_by_id_no_dup() {
        let mut msgs = vec![];
        apply_event(
            &mut msgs,
            &ConversationStreamEvent::PartStreaming {
                message_id: "m1".into(),
                content: "Hi".into(),
            },
        );
        apply_event(
            &mut msgs,
            &ConversationStreamEvent::Message(agent_msg("m1", "Hi there")),
        );
        assert_eq!(msgs.len(), 1); // same id -> replaced, not duplicated
        assert_eq!(msgs[0].text, "Hi there");
    }

    #[test]
    fn tool_call_upserts_by_id() {
        let mut msgs = vec![];
        apply_event(
            &mut msgs,
            &ConversationStreamEvent::ToolCall {
                id: "t1".into(),
                name: "port_scan".into(),
                arguments: None,
                result: None,
                error: None,
                status: "RUNNING".into(),
            },
        );
        apply_event(
            &mut msgs,
            &ConversationStreamEvent::ToolCall {
                id: "t1".into(),
                name: "port_scan".into(),
                arguments: None,
                result: Some("done".into()),
                error: None,
                status: "SUCCESS".into(),
            },
        );
        // one tool-call part, updated in place
        let tool_parts: Vec<_> = msgs
            .iter()
            .flat_map(|m| &m.parts)
            .filter(|p| matches!(p, MessagePart::ToolCall(_)))
            .collect();
        assert_eq!(tool_parts.len(), 1);
    }

    #[test]
    fn status_error_propagates() {
        let mut msgs = vec![];
        let out = apply_event(
            &mut msgs,
            &ConversationStreamEvent::Status {
                status: AgentStatus::Error,
                error: Some("rate limited".into()),
                tool_name: None,
            },
        );
        assert_eq!(out.error.as_deref(), Some("rate limited"));
        assert_eq!(out.status, Some(AgentStatus::Error));
    }

    #[test]
    fn parallel_tool_calls_do_not_duplicate_text() {
        // Regression test: when multiple parallel tool calls are invoked,
        // cumulative text deltas should update the FIRST Text part in place,
        // not push a second Text part after the tool calls.
        let mut msgs = vec![];

        // 1. Text delta arrives
        apply_event(
            &mut msgs,
            &ConversationStreamEvent::PartStreaming {
                message_id: "m1".into(),
                content: "Starting tools".into(),
            },
        );

        // 2. First tool call starts
        apply_event(
            &mut msgs,
            &ConversationStreamEvent::ToolCallStarted {
                tool_call_id: "t1".into(),
                tool_name: "tool_a".into(),
            },
        );

        // 3. Second tool call starts (parallel)
        apply_event(
            &mut msgs,
            &ConversationStreamEvent::ToolCallStarted {
                tool_call_id: "t2".into(),
                tool_name: "tool_b".into(),
            },
        );

        // 4. Another cumulative text delta arrives
        apply_event(
            &mut msgs,
            &ConversationStreamEvent::PartStreaming {
                message_id: "m1".into(),
                content: "Starting tools now".into(),
            },
        );

        // Should have exactly ONE message with ONE Text part (before the tools)
        assert_eq!(msgs.len(), 1);
        let text_parts: Vec<_> = msgs[0]
            .parts
            .iter()
            .filter(|p| matches!(p, MessagePart::Text(_)))
            .collect();
        assert_eq!(
            text_parts.len(),
            1,
            "Expected exactly 1 Text part, found {}",
            text_parts.len()
        );

        // Text part should have the latest cumulative content
        match &msgs[0].parts[0] {
            MessagePart::Text(text) => assert_eq!(text, "Starting tools now"),
            _ => panic!("First part should be Text"),
        }

        // Text part should appear BEFORE the tool calls
        assert!(matches!(msgs[0].parts[0], MessagePart::Text(_)));
        assert!(matches!(msgs[0].parts[1], MessagePart::ToolCall(_)));
        assert!(matches!(msgs[0].parts[2], MessagePart::ToolCall(_)));
    }
}

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
            // Upsert by id: replace if present, else push
            if let Some(pos) = msgs.iter().position(|msg| msg.id == m.id) {
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

            // Append to trailing Text part or create one
            match msg.parts.last_mut() {
                Some(MessagePart::Text(text)) => {
                    text.push_str(content);
                }
                _ => {
                    msg.parts.push(MessagePart::Text(content.clone()));
                }
            }

            // Keep .text in sync
            msg.text.push_str(content);

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

            // Append to trailing Thinking part or create one
            match msg.parts.last_mut() {
                Some(MessagePart::Thinking(thinking)) => {
                    thinking.push_str(content);
                }
                _ => {
                    msg.parts.push(MessagePart::Thinking(content.clone()));
                }
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
            let msg = match msgs
                .iter_mut()
                .rev()
                .find(|m| m.sender_type == "AGENT")
            {
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
            let parsed_status = status.parse::<ToolCallStatus>().unwrap_or(ToolCallStatus::Unknown);

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
            let msg_opt = msgs
                .iter_mut()
                .rev()
                .find(|m| {
                    m.sender_type == "AGENT"
                        && m.parts.iter().any(|p| matches!(p, MessagePart::ToolCall(tc) if tc.id == *tool_call_id))
                });

            let msg = if msg_opt.is_some() {
                msg_opt
            } else {
                // Try to find most recent AGENT message
                let agent_msg = msgs
                    .iter_mut()
                    .rev()
                    .find(|m| m.sender_type == "AGENT");

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

    #[test]
    fn part_streaming_appends_to_in_flight_message() {
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
                content: "lo".into(),
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
}

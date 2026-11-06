//! Scan-in-progress UX: phase-based progress for a running network scan.
//!
//! The running scan log (the chat message stream) is kept as-is; this module
//! adds a compact progress strip above it that expresses the scan as
//! identifiable phases, states the expected duration (grounded in the user's
//! own observed run times, see `pentest_core::scan_stats`), and shows a live
//! elapsed timer so there is never a silent gap long enough to read as a
//! hang. A genuinely stalled scan — silence beyond normal slowness — is
//! flagged in a distinct warning state.
//!
//! The derivation is a pure function over the conversation's messages
//! (unit-tested without dioxus); the component adds the wall-clock timers.

use dioxus::prelude::*;
use pentest_core::matrix::{ChatMessage, MessagePart, ToolCallStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Phase 0 has no tools of its own: it is "the scan has started but the first
/// tool hasn't fired yet". The rest map tool calls onto an ordered pipeline,
/// matching the batched scan strategy in the red-team system prompt
/// (network discovery -> subnet port scan -> service banners / risk checks ->
/// report document).
const PHASES: [(&str, &[&str]); 5] = [
    ("Getting ready", &[]),
    (
        "Finding devices on your network",
        &["network_discover", "arp_table", "ssdp_discover"],
    ),
    ("Checking each device for open services", &["port_scan"]),
    (
        "Identifying services and known risks",
        &[
            "service_banner",
            "cve_lookup",
            "default_creds_test",
            "web_vuln_scan",
        ],
    ),
    ("Writing up your report", &["document_write"]),
];

/// All tools that identify a conversation as a scan, in any phase (kept in
/// sync with `PHASES` — the const assertion below guards the count).
const SCAN_TOOLS: &[&str] = &[
    "network_discover",
    "arp_table",
    "ssdp_discover",
    "port_scan",
    "service_banner",
    "cve_lookup",
    "default_creds_test",
    "web_vuln_scan",
    "document_write",
];

/// Signature of the Easy Mode "Scan My Network" prompt. Matching on the user
/// message lets the strip appear in phase 0, before any tool has started.
const SCAN_PROMPT_SIGNATURE: &str = "Scan my local network";

/// Ordered, user-facing scan phases (labels only — see `PHASES`).
pub fn phase_labels() -> Vec<&'static str> {
    PHASES.iter().map(|(l, _)| *l).collect()
}

/// True when the conversation is a network scan: it contains at least one
/// scan-tool call, or the user's scan prompt is present.
pub fn is_scan_conversation(messages: &[ChatMessage]) -> bool {
    messages.iter().any(|m| {
        m.parts.iter().any(|p| match p {
            MessagePart::ToolCall(tc) => SCAN_TOOLS.contains(&tc.name.as_str()),
            _ => false,
        }) || (m.sender_type == "USER" && m.text.contains(SCAN_PROMPT_SIGNATURE))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseStatus {
    /// Not started yet (or the scan hasn't reached this step).
    Upcoming,
    /// The scan is currently in this step.
    Active,
    /// Finished, or skipped (a later phase already has tool activity).
    Complete,
    /// The last thing this step did was fail, and nothing has moved on since.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseView {
    pub label: &'static str,
    pub status: PhaseStatus,
}

/// Derived scan progress for a conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanProgress {
    pub phases: Vec<PhaseView>,
    /// A scan tool is currently running/pending.
    pub has_active_tool: bool,
    /// Name of the most recently failed scan tool (if any).
    pub last_failed_tool: Option<String>,
}

impl ScanProgress {
    /// True while the scan should keep showing its progress strip: the agent
    /// is still working, or a scan tool is still running.
    pub fn is_in_progress(&self, agent_thinking: bool) -> bool {
        agent_thinking || self.has_active_tool
    }
}

/// Derive phase progress from the conversation's messages.
///
/// Returns `None` when the conversation is not a scan. A tool call's *current*
/// status (the messages are upserted in place by the stream applier) drives
/// each phase: the newest event in a phase decides, and a failed phase
/// "recovers" to Complete as soon as any later phase shows activity.
pub fn derive_scan_progress(
    messages: &[ChatMessage],
    agent_thinking: bool,
) -> Option<ScanProgress> {
    if !is_scan_conversation(messages) {
        return None;
    }

    // Newest status per phase, plus overall scan-tool activity facts.
    let mut last_by_phase: [Option<ToolCallStatus>; 5] = [None; 5];
    let mut any_phase_event = false;
    let mut has_active_tool = false;
    let mut last_failed_tool: Option<String> = None;
    // Index (in scan order) of the newest event of any kind, per phase, so a
    // phase that failed can be told apart from one that was retried.
    let mut max_event_order: i64 = -1;
    let mut last_failed_order: i64 = -1;

    for msg in messages {
        for part in &msg.parts {
            let MessagePart::ToolCall(tc) = part else {
                continue;
            };
            let Some(pi) = PHASES
                .iter()
                .position(|(_, tools)| tools.contains(&tc.name.as_str()))
            else {
                continue; // tool outside the scan pipeline (e.g. execute_command)
            };
            any_phase_event = true;
            last_by_phase[pi] = Some(tc.status);
            max_event_order += 1;
            match tc.status {
                ToolCallStatus::Running | ToolCallStatus::Pending => has_active_tool = true,
                ToolCallStatus::Failed => {
                    last_failed_tool = Some(tc.name.clone());
                    last_failed_order = max_event_order;
                }
                _ => {}
            }
        }
    }

    let last_event_order = max_event_order;
    let has_later_phase_event = |pi: usize| (pi + 1..5).any(|later| last_by_phase[later].is_some());

    let phases: Vec<PhaseView> = (0..5)
        .map(|pi| {
            let label = PHASES[pi].0;
            let status = match last_by_phase[pi] {
                None => {
                    // No tool activity in this phase: phase 0 is the "just
                    // started" state, later phases are upcoming — unless a
                    // later phase already ran (this one was skipped), in which
                    // case show it as done so the checklist reads cleanly.
                    if pi == 0 && !any_phase_event {
                        PhaseStatus::Active
                    } else if has_later_phase_event(pi) {
                        PhaseStatus::Complete
                    } else {
                        PhaseStatus::Upcoming
                    }
                }
                Some(ToolCallStatus::Success) => PhaseStatus::Complete,
                Some(ToolCallStatus::Running | ToolCallStatus::Pending) => PhaseStatus::Active,
                Some(ToolCallStatus::Failed) => {
                    if last_failed_order == last_event_order {
                        // Nothing has moved on since the failure: the agent is
                        // either working a response (still active) or has gone
                        // silent (genuinely stalled — the timer below flags it).
                        if agent_thinking {
                            PhaseStatus::Active
                        } else {
                            PhaseStatus::Failed
                        }
                    } else {
                        // The agent moved on after the failure (retried or
                        // worked around it): treat the step as done.
                        PhaseStatus::Complete
                    }
                }
                Some(ToolCallStatus::Unknown) => PhaseStatus::Active,
            };
            PhaseView { label, status }
        })
        .collect();

    let mut phases = phases;
    // "Writing up your report" becomes active once the scan tools are all
    // done and the agent is still working (it narrates the findings, then
    // calls document_write). While a scan tool is still running the phase
    // stays upcoming; document_write's own status wins once it has fired.
    if phases[4].status == PhaseStatus::Upcoming
        && any_phase_event
        && agent_thinking
        && !has_active_tool
    {
        phases[4].status = PhaseStatus::Active;
    }

    Some(ScanProgress {
        phases,
        has_active_tool,
        last_failed_tool,
    })
}

/// Fingerprint of the conversation content: changes when any message text or
/// tool-call status changes. Drives the "last activity" clock for stall
/// detection (content changes are the only activity signal the client has).
pub fn conversation_fingerprint(messages: &[ChatMessage]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    h.write_usize(messages.len());
    for m in messages {
        h.write(b"|m");
        m.id.hash(&mut h);
        m.text.len().hash(&mut h);
        for p in &m.parts {
            match p {
                MessagePart::Text(t) => {
                    h.write(b"t");
                    t.len().hash(&mut h);
                }
                MessagePart::Thinking(t) => {
                    h.write(b"k");
                    t.len().hash(&mut h);
                }
                MessagePart::ToolCall(tc) => {
                    h.write(b"c");
                    tc.id.hash(&mut h);
                    (tc.status as u8).hash(&mut h);
                    tc.result.as_deref().map(|r| r.len()).hash(&mut h);
                    tc.error.as_deref().map(|e| e.len()).hash(&mut h);
                }
            }
        }
    }
    h.finish()
}

/// Scan-in-progress strip: phase checklist + expected duration + live elapsed
/// timer, with a distinct warning state when the scan has genuinely stalled.
#[component]
pub fn ScanProgressStrip(
    messages: Signal<Vec<ChatMessage>>,
    agent_thinking: Signal<bool>,
) -> Element {
    // 1s tick while mounted: the elapsed timer (and the silence/stall
    // thresholds) re-evaluate every second, so the strip is always visibly
    // advancing even when the agent is between events. `spawn` is a detached
    // global task in dioxus, so the loop self-terminates on unmount via the
    // alive flag instead of leaking one ticker per scan session.
    let mut tick = use_signal(|| 0u32);
    let alive = use_hook(|| Arc::new(AtomicBool::new(true)));
    let alive_unmount = alive.clone();
    use_drop(move || alive_unmount.store(false, Ordering::SeqCst));
    use_hook(move || {
        let alive = alive.clone();
        spawn(async move {
            while alive.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if !alive.load(Ordering::SeqCst) {
                    break;
                }
                tick.with_mut(|t| *t = t.wrapping_add(1));
            }
        });
    });

    // Wall-clock anchors, fixed the first time the strip mounts.
    let mut started_at = use_signal(|| None::<Instant>);
    if started_at.peek().is_none() {
        started_at.set(Some(Instant::now()));
    }
    let mut last_change = use_signal(Instant::now);
    let fp = conversation_fingerprint(&messages());
    let at = agent_thinking();
    use_effect(move || {
        // Re-runs whenever the fingerprint (or the thinking flag) changes:
        // that IS "new activity" from the client's point of view.
        let _ = fp;
        let _ = at;
        last_change.set(Instant::now());
    });

    let msgs = messages.read();
    let thinking = agent_thinking();
    let Some(progress) = derive_scan_progress(&msgs, thinking) else {
        return rsx! {};
    };
    if !progress.is_in_progress(thinking) {
        return rsx! {};
    }

    let _ = tick();
    let now = Instant::now();
    let started = started_at.cloned().unwrap_or(now);
    let elapsed = now - started;
    let silence = now - *last_change.peek();

    let stalled = pentest_core::scan_stats::is_silence_stall(silence)
        || pentest_core::scan_stats::is_overall_stall(elapsed);

    let estimate = pentest_core::scan_stats::typical_scan_duration_label();
    let elapsed_label = pentest_core::scan_stats::format_elapsed(elapsed.as_secs());
    let silence_label = pentest_core::scan_stats::format_elapsed(silence.as_secs());

    rsx! {
        style { {include_str!("scan_progress.css")} }
        div {
            class: if stalled {
                "scan-progress scan-progress-stalled"
            } else {
                "scan-progress"
            },
            // ---- header: what is happening + how long + live clock ----
            div { class: "scan-progress-header",
                if stalled {
                    div { class: "scan-progress-title scan-progress-title-warn",
                        "This scan is taking longer than usual"
                    }
                    div { class: "scan-progress-sub scan-progress-sub-warn",
                        if silence.as_secs() > 180 {
                            "No new activity for {silence_label}. It may be stalled — you can keep waiting, or send a message asking where it's stuck."
                        } else {
                            "It has been running {elapsed_label}, well past the usual {estimate}. It may be stalled — you can keep waiting, or send a message asking where it's stuck."
                        }
                    }
                } else {
                    div { class: "scan-progress-title", "Scanning your network" }
                    div { class: "scan-progress-sub",
                        "Usually takes {estimate} · {elapsed_label} so far"
                    }
                }
            }
            // ---- phase checklist: identifiable steps, not a spinner ----
            div { class: "scan-progress-phases",
                for phase in &progress.phases {
                    {
                        let cls = match phase.status {
                            PhaseStatus::Complete => "scan-phase scan-phase-done",
                            PhaseStatus::Active => "scan-phase scan-phase-active",
                            PhaseStatus::Failed => "scan-phase scan-phase-failed",
                            PhaseStatus::Upcoming => "scan-phase",
                        };
                        let marker = match phase.status {
                            PhaseStatus::Complete => "✓",
                            PhaseStatus::Active => "●",
                            PhaseStatus::Failed => "✕",
                            PhaseStatus::Upcoming => "○",
                        };
                        rsx! {
                            div { class: "{cls}",
                                span { class: "scan-phase-marker", "{marker}" }
                                span { class: "scan-phase-label", "{phase.label}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::matrix::ToolCallInfo;

    fn user_msg(text: &str) -> ChatMessage {
        ChatMessage {
            id: "u1".into(),
            sender_type: "USER".into(),
            sender_name: "You".into(),
            text: text.into(),
            parts: vec![MessagePart::Text(text.into())],
        }
    }

    fn agent_msg(calls: Vec<(&str, ToolCallStatus)>) -> ChatMessage {
        ChatMessage {
            id: "a1".into(),
            sender_type: "AGENT".into(),
            sender_name: "Pick".into(),
            text: String::new(),
            parts: calls
                .into_iter()
                .enumerate()
                .map(|(i, (name, status))| {
                    MessagePart::ToolCall(ToolCallInfo {
                        id: format!("{name}-{i}"),
                        name: name.into(),
                        arguments: None,
                        result: None,
                        error: None,
                        status,
                    })
                })
                .collect(),
        }
    }

    const S: ToolCallStatus = ToolCallStatus::Success;
    const R: ToolCallStatus = ToolCallStatus::Running;
    const F: ToolCallStatus = ToolCallStatus::Failed;

    fn statuses(p: &ScanProgress) -> Vec<PhaseStatus> {
        p.phases.iter().map(|ph| ph.status).collect()
    }

    #[test]
    fn non_scan_conversation_yields_none() {
        let msgs = vec![user_msg("hello"), agent_msg(vec![("execute_command", R)])];
        assert!(derive_scan_progress(&msgs, true).is_none());
    }

    #[test]
    fn scan_prompt_before_any_tool_is_phase_zero() {
        let msgs = vec![user_msg("Scan my local network: find the devices…")];
        let p = derive_scan_progress(&msgs, true).unwrap();
        let st = statuses(&p);
        assert_eq!(
            st,
            vec![
                PhaseStatus::Active,
                PhaseStatus::Upcoming,
                PhaseStatus::Upcoming,
                PhaseStatus::Upcoming,
                PhaseStatus::Upcoming
            ]
        );
        assert!(!p.has_active_tool);
    }

    #[test]
    fn discovery_running_marks_phase_one_active() {
        let msgs = vec![
            user_msg("Scan my local network: find the devices…"),
            agent_msg(vec![("network_discover", R)]),
        ];
        let p = derive_scan_progress(&msgs, true).unwrap();
        let st = statuses(&p);
        assert_eq!(st[0], PhaseStatus::Complete);
        assert_eq!(st[1], PhaseStatus::Active);
        assert!(p.has_active_tool);
    }

    #[test]
    fn completed_discovery_and_running_port_scan() {
        let msgs = vec![
            user_msg("Scan my local network: find the devices…"),
            agent_msg(vec![("network_discover", S), ("port_scan", R)]),
        ];
        let p = derive_scan_progress(&msgs, true).unwrap();
        let st = statuses(&p);
        assert_eq!(st[0], PhaseStatus::Complete);
        assert_eq!(st[1], PhaseStatus::Complete);
        assert_eq!(st[2], PhaseStatus::Active);
        assert_eq!(st[3], PhaseStatus::Upcoming);
        assert_eq!(st[4], PhaseStatus::Upcoming);
    }

    #[test]
    fn skipped_phases_render_complete() {
        // No discovery at all (user knows their subnet): the skipped phase
        // shows as done so the checklist never looks stuck in phase one.
        let msgs = vec![
            user_msg("Scan my local network: find the devices…"),
            agent_msg(vec![("port_scan", S)]),
        ];
        let p = derive_scan_progress(&msgs, true).unwrap();
        let st = statuses(&p);
        assert_eq!(st[1], PhaseStatus::Complete);
        assert_eq!(st[2], PhaseStatus::Complete);
    }

    #[test]
    fn report_phase_activates_after_tools_finish() {
        let msgs = vec![
            user_msg("Scan my local network: find the devices…"),
            agent_msg(vec![
                ("network_discover", S),
                ("port_scan", S),
                ("service_banner", S),
            ]),
        ];
        let p = derive_scan_progress(&msgs, true).unwrap();
        let st = statuses(&p);
        assert_eq!(st[1], PhaseStatus::Complete);
        assert_eq!(st[2], PhaseStatus::Complete);
        assert_eq!(st[3], PhaseStatus::Complete);
        assert_eq!(st[4], PhaseStatus::Active);
    }

    #[test]
    fn document_write_success_completes_report_phase() {
        let msgs = vec![
            user_msg("Scan my local network: find the devices…"),
            agent_msg(vec![("port_scan", S), ("document_write", S)]),
        ];
        let p = derive_scan_progress(&msgs, false).unwrap();
        assert_eq!(statuses(&p)[4], PhaseStatus::Complete);
        // Agent idle and nothing running: the scan is done, strip hides.
        assert!(!p.is_in_progress(false));
    }

    #[test]
    fn failed_last_tool_fails_the_phase() {
        let msgs = vec![
            user_msg("Scan my local network: find the devices…"),
            agent_msg(vec![("network_discover", S), ("port_scan", F)]),
        ];
        let p = derive_scan_progress(&msgs, false).unwrap();
        assert_eq!(statuses(&p)[2], PhaseStatus::Failed);
        assert_eq!(p.last_failed_tool.as_deref(), Some("port_scan"));
        // Agent idle with no running tool: the scan is over, strip hides —
        // the red "failed" chip on the tool call in the running log is the
        // persistent failure signal.
        assert!(!p.is_in_progress(false));
    }

    #[test]
    fn failed_last_tool_agent_still_thinking_stays_active() {
        let msgs = vec![
            user_msg("Scan my local network: find the devices…"),
            agent_msg(vec![("port_scan", F)]),
        ];
        let p = derive_scan_progress(&msgs, true).unwrap();
        assert_eq!(statuses(&p)[2], PhaseStatus::Active);
        assert!(p.is_in_progress(true));
    }

    #[test]
    fn failure_recovered_by_later_activity_completes_phase() {
        let msgs = vec![
            user_msg("Scan my local network: find the devices…"),
            agent_msg(vec![
                ("network_discover", F),
                ("network_discover", S),
                ("port_scan", S),
            ]),
        ];
        let p = derive_scan_progress(&msgs, true).unwrap();
        assert_eq!(statuses(&p)[1], PhaseStatus::Complete);
    }

    #[test]
    fn running_tool_keeps_strip_visible_when_agent_idle() {
        // The agent can report IDLE while a long-running tool (a big port
        // scan) is still executing — the strip must stay up.
        let msgs = vec![
            user_msg("Scan my local network: find the devices…"),
            agent_msg(vec![("port_scan", R)]),
        ];
        let p = derive_scan_progress(&msgs, false).unwrap();
        assert!(p.is_in_progress(false));
    }

    #[test]
    fn fingerprint_changes_with_content() {
        let a = vec![user_msg("Scan my local network: find the devices…")];
        let b = vec![user_msg("Scan my local network: find the devices…")];
        let mut c = a.clone();
        c[0].text.push_str(" more");
        assert_eq!(conversation_fingerprint(&a), conversation_fingerprint(&b));
        assert_ne!(conversation_fingerprint(&a), conversation_fingerprint(&c));
        let d = vec![
            user_msg("Scan my local network: find the devices…"),
            agent_msg(vec![("port_scan", R)]),
        ];
        assert_ne!(conversation_fingerprint(&a), conversation_fingerprint(&d));
    }

    #[test]
    fn scan_tools_match_phase_table() {
        // Guard against PHASES and SCAN_TOOLS drifting apart.
        let mut from_phases: Vec<&str> =
            PHASES.iter().flat_map(|(_, t)| t.iter().copied()).collect();
        let mut from_const = SCAN_TOOLS.to_vec();
        from_phases.sort_unstable();
        from_const.sort_unstable();
        assert_eq!(from_phases, from_const);
    }

    #[test]
    fn phase_labels_cover_all_five_phases() {
        assert_eq!(phase_labels().len(), 5);
        assert_eq!(phase_labels()[4], "Writing up your report");
    }
}

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
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
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

/// True for a user message that STARTS with the scan prompt signature.
/// Start-of-message (prefix) matching, not substring: a question like
/// "Can I scan my local network from a locked phone?" must not flip the
/// strip on for the whole conversation (review nit on pick#610).
pub fn is_scan_prompt_message(text: &str) -> bool {
    text.trim_start().starts_with(SCAN_PROMPT_SIGNATURE)
}

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
        }) || (m.sender_type == "USER" && is_scan_prompt_message(&m.text))
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

/// Wall-clock anchors for the strip, keyed by conversation so they survive
/// the strip's unmount/remount cycles while a scan is still running
/// (navigating away and back, agent-idle gaps between tool batches,
/// reconnect re-seeds). The strip only renders while the scan is in
/// progress, so instance-scoped signals would reset the elapsed timer and
/// the stall clocks on every remount (blocker A5 in the review of
/// pick#610). `ChatMessage` carries no timestamps, so the clocks cannot be
/// derived from the message list and must be held outside the strip.
#[derive(Debug, Clone, Copy)]
pub struct ScanClocks {
    /// When the current scan first went in-progress (drives the elapsed
    /// label and the 10-minute overall stall cap).
    pub started_at: Instant,
    /// Last observed activity (content fingerprint or agent-thinking
    /// change). Drives the 3-minute silence stall clock.
    pub last_change: Instant,
    /// How many scan-prompt user messages were in the conversation when this
    /// clock was anchored. A NEW prompt message means a NEW scan started in
    /// this conversation -> the clocks reset.
    pub prompt_count: u32,
    /// Conversation fingerprint at the last activity observation.
    pub last_fp: u64,
    /// Agent-thinking flag at the last activity observation.
    pub last_thinking: bool,
}

/// One render's view of the conversation, for stepping its scan clocks.
#[derive(Debug, Clone, Copy)]
pub struct ScanClockObservation {
    pub prompt_count: u32,
    pub fingerprint: u64,
    pub agent_thinking: bool,
}

/// Pure step for a conversation's scan clocks:
///
/// - No previous clock (first sighting of an in-progress scan): anchor now.
/// - The prompt count grew (a new "Scan my local network" was sent after a
///   finished scan): a new scan started — anchor now.
/// - The fingerprint or the thinking flag changed since the last
///   observation: that IS activity — refresh `last_change` only.
/// - Nothing changed (the common remount case: the scan is still running,
///   nothing new since we last looked): the clocks carry over untouched.
pub fn step_scan_clocks(
    prev: Option<ScanClocks>,
    obs: ScanClockObservation,
    now: Instant,
) -> ScanClocks {
    match prev {
        Some(c)
            if c.prompt_count == obs.prompt_count
                && (c.last_fp != obs.fingerprint || c.last_thinking != obs.agent_thinking) =>
        {
            ScanClocks {
                last_change: now,
                last_fp: obs.fingerprint,
                last_thinking: obs.agent_thinking,
                ..c
            }
        }
        Some(c) if c.prompt_count == obs.prompt_count => c,
        _ => ScanClocks {
            started_at: now,
            last_change: now,
            prompt_count: obs.prompt_count,
            last_fp: obs.fingerprint,
            last_thinking: obs.agent_thinking,
        },
    }
}

/// Count of user messages that start a scan — the "a new scan began in this
/// conversation" marker (see [`step_scan_clocks`]).
pub fn scan_prompt_count(messages: &[ChatMessage]) -> u32 {
    messages
        .iter()
        .filter(|m| m.sender_type == "USER" && is_scan_prompt_message(&m.text))
        .count() as u32
}

fn scan_clocks_registry() -> &'static OnceLock<Mutex<HashMap<String, ScanClocks>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, ScanClocks>>> = OnceLock::new();
    &REGISTRY
}

/// Step this conversation's clocks for one render and return the resulting
/// anchors. Plain data under a lock — NOT a dioxus signal — so stepping
/// during render cannot trip re-render semantics (the pre-fix code set a
/// signal during render). The registry is bounded: the app realistically
/// has few active conversations, and clearing beats unbounded growth.
fn step_conversation_clocks(
    conversation_id: &str,
    obs: ScanClockObservation,
    now: Instant,
) -> ScanClocks {
    let mut reg = scan_clocks_registry()
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if reg.len() >= 16 {
        reg.clear();
    }
    let next = step_scan_clocks(reg.get(conversation_id).copied(), obs, now);
    reg.insert(conversation_id.to_string(), next);
    next
}

/// Test seam: drop all registered clocks between tests.
#[cfg(test)]
pub fn clear_scan_clocks_registry() {
    if let Some(reg) = scan_clocks_registry().get() {
        reg.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// Scan-in-progress strip: phase checklist + expected duration + live elapsed
/// timer, with a distinct warning state when the scan has genuinely stalled.
#[component]
pub fn ScanProgressStrip(
    messages: Signal<Vec<ChatMessage>>,
    agent_thinking: Signal<bool>,
    /// The conversation these messages belong to — the key for the
    /// conversation-keyed wall-clock anchors (see [`ScanClocks`]).
    conversation_id: Signal<Option<String>>,
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
    // Conversation-keyed clocks, held OUTSIDE the strip (see `ScanClocks`):
    // they survive this component's unmount/remount cycles while the scan is
    // still running, so the elapsed timer and the stall clocks never restart
    // mid-scan (blocker A5 in the review of pick#610).
    let conv_key = conversation_id.cloned().unwrap_or_default();
    let clocks = step_conversation_clocks(
        &conv_key,
        ScanClockObservation {
            prompt_count: scan_prompt_count(&msgs),
            fingerprint: conversation_fingerprint(&msgs),
            agent_thinking: thinking,
        },
        now,
    );
    let elapsed = now - clocks.started_at;
    let silence = now - clocks.last_change;

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

    #[test]
    fn scan_prompt_match_is_start_of_message() {
        assert!(is_scan_prompt_message(
            "Scan my local network: find the devices…"
        ));
        assert!(is_scan_prompt_message("  Scan my local network"));
        // Mid-sentence questions must NOT flip the strip on (review nit).
        assert!(!is_scan_prompt_message(
            "Can I scan my local network from a locked phone?"
        ));
        assert!(!is_scan_prompt_message(
            "Please say \"Scan my local network\" later"
        ));
    }

    fn obs(fp: u64, thinking: bool, prompts: u32) -> ScanClockObservation {
        ScanClockObservation {
            prompt_count: prompts,
            fingerprint: fp,
            agent_thinking: thinking,
        }
    }

    #[test]
    fn clocks_anchor_on_first_sighting() {
        let now = Instant::now();
        let c = step_scan_clocks(None, obs(1, true, 1), now);
        assert_eq!(c.started_at, now);
        assert_eq!(c.last_change, now);
        assert_eq!(c.prompt_count, 1);
        assert_eq!(c.last_fp, 1);
        assert!(c.last_thinking);
    }

    #[test]
    fn clocks_survive_remount_without_activity() {
        // The A5 scenario: the strip unmounts (navigate away / agent-idle
        // gap) and remounts with no new events — the elapsed anchor and the
        // silence clock must carry over, not restart.
        let t0 = Instant::now();
        let first = step_scan_clocks(None, obs(1, true, 1), t0);
        let t1 = t0 + Duration::from_secs(300);
        let remounted = step_scan_clocks(Some(first), obs(1, true, 1), t1);
        assert_eq!(remounted.started_at, first.started_at);
        assert_eq!(remounted.last_change, first.last_change);
        // A scan that was already past the silence threshold when the user
        // left must still read as stalled on return — the pre-fix code gave
        // it a fresh 3-minute grace period.
        assert!(pentest_core::scan_stats::is_silence_stall(
            t1 - remounted.last_change
        ));
    }

    #[test]
    fn activity_refreshes_last_change_only() {
        let t0 = Instant::now();
        let first = step_scan_clocks(None, obs(1, true, 1), t0);
        // Content changed: last_change moves, started_at does not.
        let t1 = t0 + Duration::from_secs(60);
        let stepped = step_scan_clocks(Some(first), obs(2, true, 1), t1);
        assert_eq!(stepped.started_at, first.started_at);
        assert_eq!(stepped.last_change, t1);
        // Thinking-flag flip with unchanged content also counts as activity.
        let t2 = t1 + Duration::from_secs(30);
        let stepped2 = step_scan_clocks(Some(stepped), obs(2, false, 1), t2);
        assert_eq!(stepped2.started_at, first.started_at);
        assert_eq!(stepped2.last_change, t2);
    }

    #[test]
    fn new_scan_prompt_resets_clocks() {
        let t0 = Instant::now();
        let first = step_scan_clocks(None, obs(1, true, 1), t0);
        let t1 = t0 + Duration::from_secs(600);
        // A second "Scan my local network" in the same conversation starts a
        // NEW scan: the elapsed timer restarts instead of counting from the
        // first run.
        let reset = step_scan_clocks(Some(first), obs(2, true, 2), t1);
        assert_eq!(reset.started_at, t1);
        assert_eq!(reset.last_change, t1);
        assert_eq!(reset.prompt_count, 2);
    }

    #[test]
    fn prompt_count_counts_only_scan_prompt_user_messages() {
        let msgs = vec![
            user_msg("Scan my local network: find the devices…"),
            user_msg("Can I scan my local network from a locked phone?"),
            user_msg("Scan my local network"),
            agent_msg(vec![]),
        ];
        assert_eq!(scan_prompt_count(&msgs), 2);
    }
}

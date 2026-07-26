# Streaming Chat via GraphQL Subscription — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace ChatPanel's 800ms HTTP polling with a live Absinthe/Phoenix WebSocket subscription to the GraphQL `conversationEvents` subscription, giving token-level streaming, live tool/thinking cards, and the real agent error reason. Stream-only (polling removed); full event union; transport in `crates/core`, always compiled; a "Reconnecting…"/Retry UX is the safety net.

**Architecture:** Three units — (1) a pure Phoenix/Absinthe frame + event-parse module in `crates/core/src/matrix/phoenix_sub.rs`; (2) an async subscription transport in `crates/core/src/matrix/subscription.rs` (connect/join/subscribe/heartbeat/reconnect, emits a typed event stream + connection-state); (3) ChatPanel rewire that applies events to the existing signals and deletes `poll_and_update`.

**Tech Stack:** Rust, Dioxus 0.7, tokio-tungstenite, serde_json.

## Global Constraints

- **Stream-only.** `poll_and_update` and `POLL_INTERVAL_MS` are deleted. The ONLY remaining HTTP fetch in the chat path is a single `get_conversation` on (re)connect to seed/catch-up history.
- It IS the GraphQL `conversationEvents` subscription, delivered over Absinthe's Phoenix socket (backend `absinthe_phoenix`; web uses `@absinthe/socket`). Join `__absinthe__:control` (payload `{}`, token in URL), send the subscription as a `doc` frame. No raw-topic API, no separate graphql-ws endpoint.
- Malformed/unknown events must NEVER panic or break the stream: unknown `__typename` -> `Other` (ignored); a decode error on one frame is logged and skipped, not fatal.
- Legacy behavior parity: sending a message, receiving a reply, tool cards, thinking, and error surfacing all work end-to-end with no polling.
- `cargo clippy -p pentest-core -- -D warnings` and `-p pentest-ui --features "desktop,connector" -- -D warnings` clean (under `nix develop --command`).
- No Claude attribution, customer names, emojis, or em-dashes in commits. Conventional commits.

## Reference sources (READ-ONLY, in the Matrix repo)

- `~/src/github.com/Strike48/init-dev/matrix/src/tui/matrix-core/src/websocket.rs` — Phoenix frame helpers (`phoenix` consts, `create_phoenix_join`, `create_phoenix_subscription`, `extract_event_from_phoenix_message`) + `CONVERSATION_EVENTS_SUBSCRIPTION`. Object envelope `{topic,event,payload,ref}`.
- `.../matrix-core/src/streaming.rs:265` — URL: path `/v1alpha/graphql_socket/websocket`, query `token=<__st>&vsn=2.0.0`.
- `~/src/github.com/Strike48-public/strikehub/crates/sh-core/src/ws_relay.rs:135-146` — `tokio_tungstenite::connect_async_tls_with_config` + native-tls connector honoring an insecure-certs flag.
- `matrix/src/web/packages/graphql-client/src/generated/studio.ts:5734` (`ConversationEventsSubscription`) — the FULL current selection set (superset of matrix-core's): Message (TextPart/ThinkingPart/ToolCallPart/ImageUrlPart), MessagePartStreamingEvent, ThinkingStreamingEvent, AgentStatusEvent, ToolCallMessageEvent, ToolCallStartedEvent, ToolCallStreamingEvent, ToolCallApprovalEvent, ConversationUpdateEvent, ChildMessageEvent, compaction events.
- `matrix/src/schema.graphql:1266,3419,3798` — field + event type + union definitions.

## Existing Pick facts

- `crates/core/src/matrix/types.rs`: `ChatMessage { id, sender_type, sender_name, text, parts }`; `MessagePart::{Text(String), ToolCall(ToolCallInfo), Thinking(String)}`; `ToolCallInfo { id, name, arguments, result, error, status: ToolCallStatus }`; `AgentStatus::{Idle,Thinking,Running,StreamEnd,Error,...}` with `FromStr`/`Display`/`is_terminal`.
- `crates/core/src/matrix/client.rs:368` `parse_message_parts(&[Value]) -> (String, Vec<MessagePart>)` — reuse for `Message` events. `get_conversation(id) -> ConversationState { messages, agent_status }` at `:670`.
- ChatPanel: `crates/ui/src/components/chat_panel/mod.rs` — 4 `poll_and_update` spawns (~712/825/883/1135) writing signals `messages`, `agent_thinking`, `agent_status_text`, `error_msg`, `chat_notice`. `polling.rs` holds `poll_and_update`; `constants.rs:9` holds `POLL_INTERVAL_MS`. `make_client()` builds an auth'd `MatrixChatClient`. Session token via `crate::session::get_auth_token()`.
- `derive_api_url` (`crates/core/src/connector_registration.rs:22`) forces `https://`; the config carries `use_tls` + host. Insecure-certs today: `STRIKE48_ACCEPT_INVALID_CERTS` env.
- Deps: `tokio-tungstenite` 0.26 is a workspace dep (`Cargo.toml:44`), used in `crates/ui` only; `futures` is in `crates/core`.

---

### Task 1: Phoenix/Absinthe frame + event-parse module (pure, `crates/core`)

**Files:**
- Create: `crates/core/src/matrix/phoenix_sub.rs`
- Modify: `crates/core/src/matrix/mod.rs` (declare `mod phoenix_sub;` + re-export the event enum)

**Interfaces:**
- Produces: `ConversationStreamEvent` enum; `build_ws_url(api_url, token) -> String`; `create_join(ref) / create_subscription(conv_id, ref) / create_heartbeat(ref) -> serde_json::Value`; `CONVERSATION_EVENTS_SUBSCRIPTION: &str`; `extract_event(&Value) -> Option<Value>`; `parse_event(&Value) -> ConversationStreamEvent`.

- [ ] **Step 1: Write the failing tests**

Create `crates/core/src/matrix/phoenix_sub.rs` with tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_https_to_wss_with_token_and_vsn() {
        let u = build_ws_url("https://plg.strike48.test", "tok en/+");
        assert!(u.starts_with("wss://plg.strike48.test/v1alpha/graphql_socket/websocket?"));
        assert!(u.contains("token=tok%20en%2F%2B")); // url-encoded
        assert!(u.contains("vsn=2.0.0"));
        assert_eq!(build_ws_url("http://localhost:4000", "t").split("://").next(), Some("ws"));
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
        assert!(s["payload"]["query"].as_str().unwrap().contains("conversationEvents"));
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
        assert!(matches!(parse_event(&m), ConversationStreamEvent::PartStreaming { message_id, content } if message_id=="m1" && content=="hel"));
        let s = serde_json::json!({"__typename":"AgentStatusEvent","agentStatus":"ERROR","error":"boom"});
        assert!(matches!(parse_event(&s), ConversationStreamEvent::Status { error: Some(e), .. } if e=="boom"));
        let u = serde_json::json!({"__typename":"SomethingNew"});
        assert!(matches!(parse_event(&u), ConversationStreamEvent::Other));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command cargo test -p pentest-core phoenix_sub`
Expected: FAIL (module/types absent).

- [ ] **Step 3: Implement the module**

Port from matrix-core `websocket.rs`. Key pieces:

- Constants: `CONTROL_TOPIC="__absinthe__:control"`, events `phx_join`/`doc`/`phx_reply`/`subscription:data`/`phx_error`, heartbeat topic `phoenix`/event `heartbeat`.
- `CONVERSATION_EVENTS_SUBSCRIPTION`: author from the web generated set (studio.ts:5734) — select on Message (id, parts{TextPart{id text}, ThinkingPart{id thinking{content signature}}, ToolCallPart{id toolCall{id name arguments result error status}}}, profile{id type name avatarUrl}, timestamp, conversationId, parentId, metadata), MessagePartStreamingEvent{id messageId content timestamp}, ThinkingStreamingEvent{id messageId thinkingPartId content signature timestamp}, AgentStatusEvent{id conversationId agentId agentStatus message error toolName timestamp}, ToolCallMessageEvent{id conversationId agentId toolCallId toolName arguments result error status timestamp}, ToolCallStartedEvent{id messageId toolCallId toolName timestamp}, ToolCallStreamingEvent{id messageId toolCallId delta timestamp}, ToolCallApprovalEvent{id conversationId agentId toolCallId status timestamp}, ConversationUpdateEvent{id title summary metadata timestamp}. Always include `__typename` at each level.
- `build_ws_url(api_url, token)`: strip scheme, pick ws/wss from http/https, set path `/v1alpha/graphql_socket/websocket`, query `token=<urlencoding::encode>&vsn=2.0.0`. (urlencoding is available — used in ws_relay.rs; if not a core dep, use `form_urlencoded` or percent-encode manually.)
- `create_join(ref)` / `create_subscription(conv_id, ref)` / `create_heartbeat(ref)` -> the object frames above.
- `extract_event(&Value) -> Option<Value>`: guard `event == "subscription:data"`, then `payload.result.data.conversationEvents` cloned.
- `ConversationStreamEvent` enum + `parse_event(&Value)` matching on `__typename`:
  - `Message(ChatMessage)` — build via `crate::matrix::client`'s parse or a shared `parse_message_parts` (make that fn `pub(crate)` if needed) + profile -> sender_type/name.
  - `PartStreaming { message_id, content }`
  - `ThinkingStreaming { message_id, content }`
  - `ToolCall { id (toolCallId), name, arguments, result, error, status }`
  - `ToolCallStreaming { tool_call_id, delta }`
  - `Status { status: AgentStatus, error: Option<String>, tool_name: Option<String> }`
  - `ConversationUpdate { title, summary }`
  - `Other` (unknown/uninteresting).
  Never `unwrap` on missing fields — use `Option`/defaults; unknown `__typename` -> `Other`.

Wire `pub mod phoenix_sub;` + `pub use phoenix_sub::{ConversationStreamEvent, ...};` in `mod.rs`.

- [ ] **Step 4: Run to verify it passes + clippy**

Run: `nix develop --command cargo test -p pentest-core phoenix_sub`
Run: `nix develop --command cargo clippy -p pentest-core -- -D warnings`
Expected: tests pass, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/matrix/phoenix_sub.rs crates/core/src/matrix/mod.rs
git commit -m "feat(core): Absinthe conversationEvents subscription frames + event parser"
```

---

### Task 2: Subscription transport (connect/join/subscribe/heartbeat/reconnect)

**Files:**
- Create: `crates/core/src/matrix/subscription.rs`
- Modify: `crates/core/Cargo.toml` (add `tokio-tungstenite`), `crates/core/src/matrix/mod.rs` (declare + re-export)

**Interfaces:**
- Consumes: Task 1 (`build_ws_url`, frames, `extract_event`, `parse_event`, `ConversationStreamEvent`).
- Produces: `fn subscribe_conversation(api_url: String, conversation_id: String, insecure_tls: bool) -> ConversationSubscription` where `ConversationSubscription { events: mpsc::UnboundedReceiver<ConversationStreamEvent>, state: watch::Receiver<ConnectionState>, _handle: AbortOnDrop }`; `enum ConnectionState { Connecting, Live, Reconnecting, Failed }`.

- [ ] **Step 1: Add the dependency**

`crates/core/Cargo.toml` `[dependencies]`: `tokio-tungstenite = { workspace = true }`. Confirm the workspace dep has the TLS feature the connector needs (native-tls or rustls) matching ws_relay.rs; if the workspace default lacks tls, add features here.

- [ ] **Step 2: Write tests for the pure bits**

Transport is I/O-heavy; unit-test the isolatable logic:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backoff_sequence_caps() {
        let mut b = Backoff::new();
        let ds: Vec<u64> = (0..6).map(|_| b.next_delay_ms()).collect();
        assert_eq!(ds[0], 500);
        assert!(ds.iter().all(|d| *d <= 5000));
        assert!(ds[5] == 5000); // capped
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `nix develop --command cargo test -p pentest-core subscription::`
Expected: FAIL (Backoff absent).

- [ ] **Step 4: Implement the transport**

- `Backoff` helper: 500, 1000, 2000, 4000, 5000(cap) ms — with the test above.
- `subscribe_conversation(...)`: create `mpsc::unbounded_channel` for events and `watch::channel(ConnectionState::Connecting)`. Spawn a supervisor task; return the receivers + an `AbortOnDrop` wrapping the JoinHandle (abort on drop = teardown on conversation switch).
- Supervisor loop:
  1. Set `Connecting`. Read the freshest token (`crate::session::get_auth_token()` is a UI concept — instead accept the token via a closure/refresh fn, OR pass api_url+token and let the CALLER (Task 3) resupply on reconnect; simplest: take a `token_fn: Arc<dyn Fn() -> String + Send + Sync>` so reconnect always reads fresh). Build `build_ws_url`.
  2. Connect with `connect_async_tls_with_config` + native-tls connector (`danger_accept_invalid_certs(insecure_tls)`), per ws_relay.rs.
  3. Send join frame; await a `phx_reply` ok. Send subscription frame; await ok. Set `Live`.
  4. Spawn a heartbeat task: every 25s send `create_heartbeat(next_ref)`.
  5. Read loop: for each text frame, `serde_json::from_str::<Value>`, `extract_event`, `parse_event`, forward on the mpsc. Skip/log decode errors (never break the loop).
  6. On socket close/error or heartbeat send failure: set `Reconnecting`, sleep `Backoff::next_delay_ms()`, `continue` (reconnect + re-join + re-subscribe). After 5 consecutive failed connects, set `Failed` but keep retrying at the 5s cap.
  7. If the events receiver is dropped (consumer gone), exit.
- `AbortOnDrop(JoinHandle)` with a `Drop` that calls `.abort()`.

- [ ] **Step 5: Run tests + clippy**

Run: `nix develop --command cargo test -p pentest-core subscription::`
Run: `nix develop --command cargo clippy -p pentest-core -- -D warnings`
Expected: pass + clean.

- [ ] **Step 6: Commit**

```bash
git add crates/core/Cargo.toml Cargo.lock crates/core/src/matrix/subscription.rs crates/core/src/matrix/mod.rs
git commit -m "feat(core): conversationEvents subscription transport with heartbeat and reconnect"
```

---

### Task 3: Event->message applier (pure, `crates/core` or `crates/ui`)

**Files:**
- Create: `crates/core/src/matrix/stream_apply.rs` (pure fn; keep it in core so it is unit-tested without Dioxus)
- Modify: `crates/core/src/matrix/mod.rs`

**Interfaces:**
- Consumes: `ConversationStreamEvent`, `ChatMessage`, `MessagePart`, `AgentStatus`.
- Produces: `apply_event(msgs: &mut Vec<ChatMessage>, ev: &ConversationStreamEvent) -> ApplyOutcome` where `ApplyOutcome { status: Option<AgentStatus>, error: Option<String> }` so the UI can update thinking/error signals from the same call.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn agent_msg(id: &str, text: &str) -> ChatMessage { /* build with Text part */ }

    #[test]
    fn part_streaming_appends_to_in_flight_message() {
        let mut msgs = vec![];
        apply_event(&mut msgs, &ConversationStreamEvent::PartStreaming { message_id: "m1".into(), content: "Hel".into() });
        apply_event(&mut msgs, &ConversationStreamEvent::PartStreaming { message_id: "m1".into(), content: "lo".into() });
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text, "Hello");
    }

    #[test]
    fn full_message_upserts_by_id_no_dup() {
        let mut msgs = vec![];
        apply_event(&mut msgs, &ConversationStreamEvent::PartStreaming { message_id: "m1".into(), content: "Hi".into() });
        apply_event(&mut msgs, &ConversationStreamEvent::Message(agent_msg("m1", "Hi there")));
        assert_eq!(msgs.len(), 1); // same id -> replaced, not duplicated
        assert_eq!(msgs[0].text, "Hi there");
    }

    #[test]
    fn tool_call_upserts_by_id() {
        let mut msgs = vec![];
        apply_event(&mut msgs, &ConversationStreamEvent::ToolCall { id: "t1".into(), name: "port_scan".into(), arguments: None, result: None, error: None, status: "RUNNING".into() });
        apply_event(&mut msgs, &ConversationStreamEvent::ToolCall { id: "t1".into(), name: "port_scan".into(), arguments: None, result: Some("done".into()), error: None, status: "SUCCESS".into() });
        // one tool-call part, updated in place
        let tool_parts: Vec<_> = msgs.iter().flat_map(|m| &m.parts).filter(|p| matches!(p, MessagePart::ToolCall(_))).collect();
        assert_eq!(tool_parts.len(), 1);
    }

    #[test]
    fn status_error_propagates() {
        let mut msgs = vec![];
        let out = apply_event(&mut msgs, &ConversationStreamEvent::Status { status: AgentStatus::Error, error: Some("rate limited".into()), tool_name: None });
        assert_eq!(out.error.as_deref(), Some("rate limited"));
        assert_eq!(out.status, Some(AgentStatus::Error));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command cargo test -p pentest-core stream_apply`
Expected: FAIL.

- [ ] **Step 3: Implement `apply_event`**

- `Message(m)` -> upsert into `msgs` by `m.id` (replace if present, else push).
- `PartStreaming{message_id,content}` -> find msg by id; if absent, push a new agent `ChatMessage` (id=message_id, sender_type "AGENT") with a single `Text` part; else append `content` to its trailing `Text` part (create one if the trailing part isn't Text). Keep `.text` in sync (append there too, since the empty-state/agent-detection reads `.text`).
- `ThinkingStreaming{message_id,content}` -> same, into a `Thinking` part.
- `ToolCall{...}` / `ToolCallStreaming{...}` -> find (or create) the owning message, upsert a `ToolCall` part by tool-call id (update status/result/error; append arg delta for streaming). Which message owns it: the in-flight agent message (last agent msg) or by messageId when present; for `ToolCallMessageEvent` there is no messageId, so attach to the most recent agent message (create one if none).
- `Status{status,error,tool_name}` -> return in `ApplyOutcome`; no message mutation.
- `ConversationUpdate` / `Other` -> no-op (return default outcome).

- [ ] **Step 4: Run tests + clippy**

Run: `nix develop --command cargo test -p pentest-core stream_apply`
Run: `nix develop --command cargo clippy -p pentest-core -- -D warnings`
Expected: pass + clean.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/matrix/stream_apply.rs crates/core/src/matrix/mod.rs
git commit -m "feat(core): apply streaming conversation events to the message list"
```

---

### Task 4: ChatPanel rewire — subscribe, apply, reconnecting UX; delete polling

**Files:**
- Modify: `crates/ui/src/components/chat_panel/mod.rs`
- Delete: `crates/ui/src/components/chat_panel/polling.rs`
- Modify: `crates/ui/src/components/chat_panel/constants.rs` (remove `POLL_INTERVAL_MS`)
- Modify: `crates/ui/src/components/chat_panel/agent_selector.rs` or header (reconnecting indicator)
- Modify: `crates/ui/src/components/chat_panel/css/style.css` (indicator style)

**Interfaces:**
- Consumes: Task 2 (`subscribe_conversation`, `ConnectionState`), Task 3 (`apply_event`), existing `get_conversation`, signals.

- [ ] **Step 1: Replace the poll spawns with a subscription task**

Add a `connection_state: Signal<ConnectionState>` signal. Introduce one helper (e.g. `spawn_subscription(...)`) that, for the active conversation id:
1. does one `client.get_conversation(id)` to seed `messages` + initial status,
2. calls `subscribe_conversation(api_url, id, insecure_tls)`,
3. loops: `tokio::select!` on the events receiver and the state watch; for each event call `apply_event(&mut messages.write(), &ev)` and update `agent_thinking`/`agent_status_text`/`error_msg`/`chat_notice` from the `ApplyOutcome`; mirror `state` into `connection_state`,
4. on `Reconnecting -> Live` transition, re-run the `get_conversation` catch-up fetch,
5. exits when the conversation changes (guard on active id, like the old `is_active`).

Replace the 4 `poll_and_update(...)` call sites (mod.rs ~712/825/883/1135) with this subscription task. The send path (`ask`) stays HTTP; after sending, the reply arrives via the subscription (no post-send poll).

`insecure_tls`: read the same flag the app uses (`STRIKE48_ACCEPT_INVALID_CERTS`); thread it in.

Token freshness on reconnect: pass a `token_fn` closure that reads `crate::session::get_auth_token()` so each (re)connect uses the current token.

- [ ] **Step 2: Delete polling**

Remove `mod polling;` + its `use`, delete `polling.rs`, remove `POLL_INTERVAL_MS` from `constants.rs`. Keep `ChatNotice`/`ChatNoticeKind`/`build_error_notice` (move them if they lived in `polling.rs` — grep; they are referenced elsewhere). Update imports.

- [ ] **Step 3: Reconnecting indicator + Retry**

In the chat header (agent_selector.rs `chat-panel-header` area), when `connection_state()` is `Reconnecting`, show a subtle "Reconnecting…" chip; when `Failed`, show it with a Retry button that respawns the subscription task (bump a `retry_tick` signal the task effect keys on). History stays rendered. Add minimal `.chat-reconnecting` CSS (mono, `--sage-dim`/muted).

- [ ] **Step 4: Verify compilation + clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: clean (no references to `poll_and_update`/`POLL_INTERVAL_MS` remain — grep to confirm).

- [ ] **Step 5: Commit**

```bash
git add crates/ui/src/components/chat_panel/
git commit -m "feat(chat): stream conversation via subscription, remove polling"
```

---

### Task 5: Verification

**Files:** none.

- [ ] **Step 1: Full clippy (both crates)**

Run: `nix develop --command cargo clippy -p pentest-core -- -D warnings`
Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: both clean.

- [ ] **Step 2: Unit tests**

Run: `nix develop --command cargo test -p pentest-core phoenix_sub subscription stream_apply`
Expected: all pass.

- [ ] **Step 3: No polling remnants**

Run: `grep -rn "poll_and_update\|POLL_INTERVAL_MS" crates/`
Expected: no matches.

- [ ] **Step 4: Manual live test (dev cluster)**

Build + launch desktop easy mode against `plg.strike48.test`. Run a scan. Confirm: tokens stream (typewriter), tool cards update live, thinking shows, an induced error surfaces its reason, and cutting the network shows "Reconnecting…" then recovers + catches up. Document the result in the PR.

- [ ] **Step 5: Commit (if fixups)**

```bash
git add -A && git commit -m "test(chat): verify streaming end-to-end, no polling remains"
```

---

## Notes for the implementer

- The transport is the load-bearing part (no poll fallback): heartbeat every 25s, reconnect with backoff, catch-up `get_conversation` on reconnect, and the visible Reconnecting/Retry state are all required, not optional.
- Reuse `parse_message_parts` (client.rs:368) for `Message` events — make it `pub(crate)` if needed rather than duplicating the parts mapping.
- Dedup by message id (upsert) so the streamed text and the final `Message` don't double up.
- All Dioxus signals are Copy; re-`let` inside spawned tasks.
- Do not change the send/`ask` path or agent selection — only how updates arrive.
- Confirm the workspace `tokio-tungstenite` TLS feature matches what `connect_async_tls_with_config` needs; align with ws_relay.rs (native-tls).

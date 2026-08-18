# Streaming Chat via GraphQL Subscription — Design

**Status:** Approved design, pending spec review
**Date:** 2026-07-25
**Investigation:** `docs/superpowers/specs/2026-07-25-chat-streaming-investigation.md`

## Goal

Replace ChatPanel's 800ms HTTP polling with a live Phoenix/Absinthe WebSocket
subscription to Matrix's `conversationEvents`, giving:
- token-level streaming (typewriter assistant output),
- live tool-call cards (running -> done) and thinking indicators,
- the real agent error reason (which polling never sees), immediately.

**Scope decisions (approved):**
- **Stream-only** — `poll_and_update` and `POLL_INTERVAL_MS` are removed. There
  is no periodic-poll fallback.
- **Full event union** — Message, MessagePartStreamingEvent, ThinkingStreamingEvent,
  ToolCallMessageEvent, AgentStatusEvent (+ pass-through of the rest).
- **Transport in `crates/core`, always compiled** (no cargo feature gate).
- **WS-down UX:** a non-blocking "Reconnecting..." indicator with auto-retry
  (backoff) and a manual Retry after repeated failures; chat history stays
  visible.

## Backend facts (confirmed from `~/src/github.com/Strike48/init-dev/matrix`)

- `conversationEvents(conversationId: ID!): ConversationEvent`
  (`src/schema.graphql:1266`). `ConversationEvent` is a union
  (`schema.graphql:3798`): `Message | AgentStatusEvent | ToolCallMessageEvent |
  ToolCallApprovalEvent | MessagePartStreamingEvent | ThinkingStreamingEvent |
  ConversationUpdateEvent | ChildMessageEvent | ToolResultCompacting/Compacted |
  ConversationCompacting/Compacted`.
- Event fields (`schema.graphql:3419+`):
  - `MessagePartStreamingEvent { id, messageId, content, timestamp }` — token chunk.
  - `ThinkingStreamingEvent { id, messageId, thinkingPartId, content, signature, timestamp }`.
  - `ToolCallMessageEvent { id, conversationId, agentId, toolCallId, toolName, arguments, result, error, status, timestamp }`.
  - `AgentStatusEvent { id, conversationId, agentId, agentStatus, message, error, toolName, timestamp, toolCallDetails, toolCallResults }`.
  - `Message { id, parts[TextPart|ToolCallPart], profile, timestamp, conversationId, parentId, metadata }`.
- **Transport:** Phoenix Channels over WS.
  - URL: `wss://<matrix-host>/v1alpha/graphql_socket/websocket?token=<url-encoded __st>&vsn=2.0.0`
    (`matrix-core/src/streaming.rs:265`; scheme from https/http).
  - Join: topic **`__absinthe__:control`** (the Absinthe control channel),
    event `phx_join`, payload `{}` (empty — the `__st` token rides in the URL,
    NOT the join payload), `ref:"1"` (`websocket.rs:128-135`,
    `phoenix::CONTROL_TOPIC`).
  - Subscribe: event `doc`, payload `{query: CONVERSATION_EVENTS_SUBSCRIPTION,
    variables: {conversationId}}`, `ref:"2"` (`websocket.rs:139-149`).
  - Data arrives as Phoenix `subscription:data` events; the GraphQL event object
    is at `message.payload.result.data.conversationEvents`
    (`extract_event_from_phoenix_message`, `websocket.rs:152-206`). `phx_reply`
    acks the join/subscribe; `phx_error` signals a channel error.
  - **It is the GraphQL `conversationEvents` subscription** — Absinthe delivers
    GraphQL subscriptions over the Phoenix socket (backend uses `absinthe_phoenix`;
    the web app subscribes the same way via `@absinthe/socket-apollo-link`). The
    `__absinthe__:control` join + `doc` frame is just Absinthe's envelope for the
    subscription document; there is no raw-Phoenix-topic API and no separate
    `graphql-ws` endpoint. We send the `subscription ConversationEvents(...)`
    document, exactly like every other client.
  - **Selection set:** matrix-core's `CONVERSATION_EVENTS_SUBSCRIPTION`
    (`websocket.rs:46-127`) is a good base but OMITS some current union members.
    Use the fuller set the web client generates
    (`matrix/src/web/packages/graphql-client/src/generated/studio.ts:5734`,
    `ConversationEventsSubscription`), which includes: Message (TextPart /
    ThinkingPart / ToolCallPart / ImageUrlPart), MessagePartStreamingEvent,
    **ThinkingStreamingEvent**, AgentStatusEvent, ToolCallMessageEvent,
    **ToolCallStartedEvent**, **ToolCallStreamingEvent** (tool-arg deltas),
    ToolCallApprovalEvent, ConversationUpdateEvent, ChildMessageEvent, and the
    compaction events. Author the Pick subscription document from that set so we
    do not miss events; unknown `__typename` still maps to `Other` (ignored).
- **Reference clients:** `matrix-core` (`src/tui/matrix-core/src/{websocket,streaming}.rs`)
  — port the frame protocol + subscribe doc verbatim. `strikehub`
  (`crates/sh-core/src/ws_relay.rs`) — TLS/insecure-cert connector setup.
- **GAP in the references (Pick must add):** matrix-core does NOT implement a
  Phoenix heartbeat or a reconnect loop — it's fire-and-forget. Phoenix drops
  idle sockets without a `phoenix`-topic `phx_heartbeat` every ~25-30s. Since
  Pick removes polling, both **heartbeat** and **reconnect-with-catch-up** are
  load-bearing here.

## Pick's model already fits

`crates/core/src/matrix/types.rs`:
- `ChatMessage { id, sender_type, sender_name, text, parts: Vec<MessagePart> }`
- `MessagePart::{ Text(String), ToolCall(ToolCallInfo), Thinking(String) }`
- `ToolCallInfo { id, name, arguments, result, error, status: ToolCallStatus }`
- `AgentStatus::{ Idle, Thinking, Running, StreamEnd, Error, ... }` with
  `FromStr`/`Display` and `is_terminal()`.

Streaming events map directly:
- `Message` -> upsert a `ChatMessage` (by id) with its parts.
- `MessagePartStreamingEvent` -> append `content` to the in-flight assistant
  message's Text part (create the message if not present yet).
- `ThinkingStreamingEvent` -> append to a `Thinking` part.
- `ToolCallMessageEvent` -> upsert a `ToolCall` part (by toolCallId), updating
  status/result/error.
- `AgentStatusEvent` -> drive `agent_thinking` / `agent_status_text`; on
  `agentStatus == ERROR`, surface `error` (the reason polling couldn't get).

## Architecture — three units

### Unit 1 — Phoenix frame protocol (`crates/core/src/matrix/phoenix.rs`, new)

Ported from matrix-core `websocket.rs`. Pure, no I/O, unit-testable.
- Phoenix envelope is the OBJECT form: `{topic, event, payload, ref}` — match
  matrix-core's `websocket.rs` exactly.
- `create_join(ref) -> Value` — topic `__absinthe__:control`, event `phx_join`,
  payload `{}` (token is in the URL).
- `create_subscription(conversation_id, ref) -> Value` — topic
  `__absinthe__:control`, event `doc`, payload `{query:
  CONVERSATION_EVENTS_SUBSCRIPTION, variables:{conversationId}}`.
- `create_heartbeat(ref) -> Value` (topic `phoenix`, event `heartbeat`, payload
  `{}`). NEW — not in matrix-core.
- `extract_event(phoenix_msg: &Value) -> Option<Value>` — only for `event ==
  "subscription:data"`; navigate `payload.result.data.conversationEvents`.
- `parse_event(gql: &Value) -> Option<ConversationStreamEvent>` where
  `ConversationStreamEvent` is a Pick enum mirroring the union subset we handle
  (Message, PartStreaming, ThinkingStreaming, ToolCall, Status, Other). Uses
  `__typename`.
- `is_reply_ok(msg) -> bool` for `phx_reply`.

Tests: join/subscribe/heartbeat frame shape; extract from a sample
`subscription:data` envelope; parse each event `__typename` to the right variant;
unknown `__typename` -> `Other` (never panics).

### Unit 2 — Subscription transport (`crates/core/src/matrix/subscription.rs`, new)

- `MatrixChatClient::subscribe_conversation(conversation_id) -> ConversationEventStream`
  (or a free fn taking api_url + token). Returns a stream/receiver of
  `ConversationStreamEvent` plus a `ConnectionState` channel
  (`Connecting | Live | Reconnecting | Failed`).
- `build_ws_url(api_url, token)` — derive `wss://…/v1alpha/graphql_socket/websocket?token=…&vsn=2.0.0`
  from the https api_url (new `derive_ws_url`, sibling of `derive_api_url`).
- Connect with `tokio_tungstenite::connect_async_tls_with_config` + native-tls
  connector honoring an insecure-certs flag (from `STRIKE48_ACCEPT_INVALID_CERTS`
  / existing config), per `ws_relay.rs`.
- On connect: send join, await `phx_reply` ok, send subscribe.
- **Heartbeat task:** send `phx_heartbeat` every 25s.
- **Read loop:** decode frames -> `extract_event` -> `parse_event` -> forward on
  the mpsc.
- **Reconnect loop:** on socket close/error, set state `Reconnecting`, backoff
  (e.g. 0.5s, 1s, 2s, 5s cap), reconnect + re-join + re-subscribe. On successful
  reconnect, the CONSUMER does one `get_conversation` catch-up fetch (see Unit 3)
  to fill events missed during the gap. After N (~5) consecutive failures, set
  `Failed` (drives the Retry button); keep retrying at the capped interval.
- Token: read the freshest `__st` from the session store at each (re)connect, so
  a refreshed token is picked up. Teardown (abort tasks) on stream drop /
  conversation switch.

Tests: `build_ws_url` (https->wss, path, token encoding, vsn); backoff sequence;
state transitions on simulated connect/drop (transport logic isolated from real
sockets where practical).

### Unit 3 — ChatPanel rewire (`crates/ui/src/components/chat_panel/`)

- Delete `polling.rs` (`poll_and_update`) and `POLL_INTERVAL_MS`. Keep
  `ChatNotice`/`build_error_notice` (still used for surfacing errors, now fed by
  `AgentStatusEvent.error`).
- Replace the 4 poll spawns (mod.rs ~712/825/883/1135) with a single
  per-conversation subscription task (keyed on active conversation id; torn down
  + respawned on switch). It applies `ConversationStreamEvent`s to the existing
  signals (`messages`, `agent_thinking`, `agent_status_text`, `error_msg`,
  `chat_notice`) via the mapping above.
- On (re)connect `Live`, and on the initial subscribe, do ONE
  `client.get_conversation(id)` to seed/catch-up the message list (subscriptions
  deliver events from subscribe-time forward; the initial fetch fills history and
  the reconnect fetch fills the gap). This is the ONLY remaining HTTP fetch in
  the chat path and it is event-driven, not timed.
- Reconnecting UX: a `connection_state` signal drives a non-blocking header
  indicator ("Reconnecting...") and, on `Failed`, a Retry button that restarts
  the transport. History stays rendered throughout.
- Typewriter: `MessagePartStreamingEvent` appends to the in-flight assistant
  message; when the terminal `Message`/`AgentStatus IDLE` arrives, the message is
  finalized (dedup by message id so the streamed text and the final Message don't
  double up).

### Deps

Add to `crates/core/Cargo.toml`: `tokio-tungstenite = { workspace = true }`
(features for tls) and confirm `futures` (already present). `tokio-tungstenite`
0.26 is already a workspace dep (ui-only today).

## Testing

- **Unit (core):** phoenix frame build/extract/parse (all event types + unknown),
  `build_ws_url`, backoff, state machine. Message-mapping helpers: applying each
  event to a `Vec<ChatMessage>` produces the expected upserts (typewriter append,
  tool-call upsert by id, message dedup by id).
- **Manual/live (dev cluster, `plg.strike48.test`):** run an easy-mode scan;
  confirm tokens stream in (typewriter), tool cards update live, thinking shows,
  an induced error surfaces its reason, and killing the network shows
  "Reconnecting..." then recovers + catches up. Confirm standalone Pick reaches
  `graphql_socket` directly.
- **Regression:** `cargo clippy -p pentest-core -- -D warnings` and
  `-p pentest-ui --features "desktop,connector" -- -D warnings` clean; sending a
  message and receiving a reply works end-to-end with NO polling.

## Risks / notes

- **No poll fallback is load-bearing** — heartbeat + reconnect + catch-up-fetch
  must be solid; the "Reconnecting/Retry" UX is the user-visible safety net.
- **Standalone network path:** matrix-core connects directly to
  `graphql_socket`, evidence it's reachable; verify on the dev cluster and (if
  hosted-mode differs) confirm StrikeHub doesn't require relaying. If a hosted
  Pick can't reach it directly, a follow-up could relay through the host — out of
  scope for v1.
- **Token expiry mid-stream:** reconnect re-reads the session token; a hard-expired
  token surfaces as `Failed` -> the existing re-auth path.
- **Event/`Message` dedup:** the backend sends both streaming parts AND a final
  `Message`; upsert-by-id prevents duplication.
- **Absinthe `subscriptionId` correlation:** confirm during port whether events
  are keyed by a subscription id in the Phoenix payload (matrix-core's
  `extract_event_from_phoenix_message` handles this — copy its logic).

## Non-goals

- Streaming the report-list polls (easy-mode docs / DocumentsPanel) — could reuse
  the transport later; not v1.
- Server-side Matrix changes (subscription exists).
- A polling fallback (explicitly removed).

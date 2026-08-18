# Chat Streaming / Subscriptions vs. Polling — Investigation

**Status:** Investigation / findings (not a design). No code written.
**Date:** 2026-07-25
**Question:** What would it take for Pick to replace HTTP polling of chat with
real streaming / GraphQL subscriptions?

## TL;DR

- **The backend subscription is real, and there is a complete working Rust
  client we can copy** — `matrix-core` in the Matrix repo
  (`~/src/github.com/Strike48/init-dev/matrix/src/tui/matrix-core/`) is a
  Rust GraphQL-subscription client hitting this exact backend. StrikeHub also
  consumes it via a WsRelay. This removes essentially all transport risk.
- **The subscription carries FULL streaming, not just status.**
  `conversationEvents(conversationId: ID!): ConversationEvent` where
  `ConversationEvent` is a union of `Message | AgentStatusEvent |
  ToolCallMessageEvent | ToolCallApprovalEvent | MessagePartStreamingEvent |
  ThinkingStreamingEvent | ConversationUpdateEvent | ChildMessageEvent | …`
  (`matrix/src/schema.graphql:3798`). So Pick can get **token-level streaming**
  (`MessagePartStreamingEvent.content`), live thinking, live tool status, full
  message objects, AND the agent error reason — no refetch required.
- **Protocol:** Phoenix Channels over WebSocket (Absinthe) at
  `wss://<matrix-host>/v1alpha/graphql_socket/websocket?token=<__st>&vsn=2.0.0`;
  join topic **`conversation:<conversationId>`** with `phx_join` (payload
  `{token}`), then send the subscribe doc. Not plain `graphql-ws`.
- **Pick's chat client (`crates/core`) has zero WS/subscription code today** —
  HTTP POST to `{https}/api/v1alpha`, polled every **800 ms**
  (`POLL_INTERVAL_MS`, 4 call sites).
- **Feasible, medium effort, low risk.** Two Rust references (matrix-core client
  + StrikeHub relay), `tokio-tungstenite` already a workspace dep. Work = a new
  subscription transport in `crates/core` + rewiring the ChatPanel's 4 poll
  sites, with polling retained as fallback.
- **Recommendation:** worth doing. The prior "confirm the schema first" blocker
  is RESOLVED (schema + payloads below). Remaining unknowns are operational
  (direct-vs-relayed network path for standalone Pick, token lifetime), not
  design-blocking.

## Current architecture (polling)

- **Transport:** `crates/core/src/matrix/client.rs` — `execute_gql` does
  `reqwest` HTTP POST to `{api_url}/api/v1alpha` (`client.rs:87`). Auth is the
  `__st` token sent three ways (query `?__st=`, `Authorization: Bearer`, and
  `Cookie: __st=` — `client.rs:59-64`). The `resp.bytes_stream()` at
  `client.rs:135` is just a size-capped finite-body read, NOT incremental
  streaming.
- **Poller:** `crates/ui/src/components/chat_panel/polling.rs::poll_and_update`
  loops calling `client.get_conversation(conv_id)` and sleeps
  `POLL_INTERVAL_MS = 800ms` (`constants.rs:9`, `polling.rs:137`). It writes the
  chat's reactive signals: `messages`, `agent_thinking`, `agent_status_text`,
  `error_msg`, `chat_notice`.
- **Call sites:** 4 in `crates/ui/src/components/chat_panel/mod.rs` (~lines 712,
  825, 883, 1135) — after send, on conversation open, on resume, on validate.
- **Known limitation the poller works around:** the human-readable agent error
  reason ships ONLY on the `conversationEvents` subscription
  (`AgentStatusEvent.error`); polling can't see it, so
  `chat_notice.rs`/`build_error_notice` cross-references `tokenUsageStats` over
  HTTP to *guess* the reason (`chat_notice.rs:4-5,24-26`). Streaming would give
  the real reason directly.

Also polling (would benefit but out of primary scope): the easy-mode `docs`
poll (5s), `DocumentsPanel` (5s), `ConversationDocs` (5s) — report lists.

## The subscription DOES exist — reference impl in StrikeHub

StrikeHub's README: *"Single-port WsRelay bridges Dioxus liveview and Matrix
GraphQL subscriptions."* Its `Cargo.toml`: *"WebSocket proxy (for GraphQL
subscriptions through self-signed certs) — tokio-tungstenite native-tls."*

Reference: `strikehub/crates/sh-core/src/ws_relay.rs`:
- Connects upstream to
  `{ws|wss}://<matrix-host>/v1alpha/graphql_socket/websocket?token=<url-encoded __st>&vsn=2.0.0`
  (`ws_relay.rs:127-133`) — a **Phoenix Channels** socket (the `vsn=2.0.0` +
  `graphql_socket` path is Absinthe/Phoenix, not `graphql-ws`).
- Uses `tokio_tungstenite::connect_async_tls_with_config` with a native-tls
  connector that honors an insecure-certs flag (`ws_relay.rs:135-146`) — needed
  for dev/self-signed Matrix.
- Then relays frames bidirectionally.

**Implication:** the client protocol Pick would speak is Phoenix Channel frames
(join a topic like `conversation:<id>` or `__absinthe__:control`, then receive
`AgentStatusEvent`/message pushes). We have a working Rust example of the
handshake and TLS setup to copy.

## What Pick would need to build

1. **A subscription transport in `crates/core`** (new module, e.g.
   `matrix/subscription.rs`):
   - Add `tokio-tungstenite` to `crates/core/Cargo.toml` (currently only in
     `crates/ui` under the `connector` feature; workspace dep exists at
     `Cargo.toml:44`).
   - Derive a `wss://…/v1alpha/graphql_socket/websocket?token=…&vsn=2.0.0` URL
     from the existing `api_url` (today `derive_api_url` forces `https://` and
     strips ws schemes — a parallel `derive_ws_url` is needed).
   - Implement the Phoenix Channel join + Absinthe subscription handshake
     (`phx_join` on the control topic, `doc`/`subscribe` the
     `conversationEvents(conversationId:)` subscription, handle `phx_reply` and
     `subscription:data` pushes, heartbeat every ~30s). Copy the TLS/insecure
     handling from `ws_relay.rs`.
   - Expose it as a stream of typed events (`AgentStatusEvent` { status, error,
     … } + new-message events) — likely a `tokio::sync::mpsc`/`watch` or a
     `futures::Stream` the UI can await.

2. **Rewire the ChatPanel** (`crates/ui/src/components/chat_panel/`):
   - Replace the 4 `poll_and_update` spawns with a single per-conversation
     subscription task that writes the same signals (`messages`,
     `agent_thinking`, `agent_status_text`, `error_msg`, `chat_notice`).
   - Because the subscription may push status but not full message bodies (TBD —
     depends on what `conversationEvents` includes), likely a hybrid: subscribe
     for status/turn-complete/error, then do ONE `get_conversation` fetch on
     each push to pull the new messages (event-driven refetch, not timed
     polling). This removes the 800ms cadence and gets the real error reason.
   - Keep `poll_and_update` as a **fallback** when the WS fails to connect or
     drops (bad network, proxy). This is important — do not delete polling.

3. **Reconnection + lifecycle:** WS drop/reconnect with backoff, token refresh
   (the `__st` chat token is short-lived — a dropped/expired token needs the
   existing re-auth path), and teardown when the user leaves the conversation
   (mirror `poll_and_update`'s `is_active` guard).

## Effort / risk

- **Deps:** low — `tokio-tungstenite` 0.26 + `futures` already in the workspace;
  add `tokio-tungstenite` to `crates/core`. No `async-graphql`/`graphql-client`
  needed (hand-rolled Phoenix frames, as everywhere else in this client).
- **New code:** a ~200-300 line subscription module + Phoenix frame (de)serialize
  + the ChatPanel rewire. The `ws_relay.rs` reference cuts the transport
  unknowns significantly.
- **Resolved (was the biggest unknown): schema + payloads are confirmed** from
  the Matrix repo (`~/src/github.com/Strike48/init-dev/matrix`):
  - `conversationEvents(conversationId: ID!): ConversationEvent` union
    (`src/schema.graphql:1266,3798`) — carries `Message` (full body + parts),
    `MessagePartStreamingEvent { messageId, content }` (token chunks),
    `ThinkingStreamingEvent`, `ToolCallMessageEvent { toolCallId, toolName,
    arguments, result, error, status }`, `AgentStatusEvent { agentStatus, error,
    toolName, … }` (`schema.graphql:3419,3433,…`).
  - Working subscribe doc: `matrix-core`'s `CONVERSATION_EVENTS_SUBSCRIPTION`
    (`src/tui/matrix-core/src/websocket.rs:46`) and
    `src/tui/matrix-graphql-client/queries/conversation_subscription.graphql` —
    copy verbatim.
  - Phoenix transport: `streaming.rs` sets path
    `/v1alpha/graphql_socket/websocket`, `?token=<__st>&vsn=2.0.0`, joins topic
    **`conversation:<conversationId>`** with `phx_join` payload `{token}`, then
    sends the subscribe doc (`src/tui/matrix-core/src/streaming.rs:265,357-360`).
- **Remaining operational unknowns (not design-blocking):**
  1. **Network path for standalone Pick.** StrikeHub-hosted mode can relay
     through the host's WsRelay; standalone Pick (desktop/mobile) connects
     directly to Matrix — confirm the `graphql_socket` WS is reachable directly
     (ingress/cert) the way `/api/v1alpha` is. `matrix-core` connects directly,
     which is evidence it works.
  2. **Auth token lifetime on a long-lived socket.** The `__st` token is
     short-lived; a subscription outliving it needs reconnect-with-fresh-token
     (Pick already has the re-auth path).

## Recommendation

Worth doing — token-level streaming (typewriter output + live tool/thinking
status), the real agent-error reason for free, no 800ms cadence, lower request
volume. The prior "confirm the schema first" blocker is **resolved**; there are
two Rust references against this exact backend.

1. Build the `crates/core` subscription transport by porting `matrix-core`'s
   `websocket.rs`/`streaming.rs` (Phoenix join on `conversation:<id>` +
   `CONVERSATION_EVENTS_SUBSCRIPTION` + heartbeat), behind a feature/flag, TLS +
   insecure-cert handling from `ws_relay.rs`. Emit a typed
   `Stream<ConversationEvent>`.
2. Rewire ChatPanel: on conversation open, subscribe and apply events directly
   (append `Message`, apply `MessagePartStreamingEvent.content` to the in-flight
   message for typewriter effect, drive `agent_thinking`/`agent_status_text`
   from `AgentStatusEvent`, surface `error`). **Keep `poll_and_update` as
   fallback** on WS connect failure / drop.
3. Handle reconnect + token refresh; tear down on conversation switch.
4. Later: extend the same transport to the report-list polls if useful.

No schema blocker remains — start with the transport port.

## Out of scope / non-goals

- The connector's own gRPC/wss tool-execution channel (`strike48-connector`
  `ConnectorRunner`) is a DIFFERENT credential (connector JWT, no DB session) and
  the SDK exposes no hook to receive conversation events on it — not a viable
  piggyback per the current SDK surface.
- Server-side changes to Matrix (the subscription already exists).

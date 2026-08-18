# Easy Mode — Design Spec

- **Date:** 2026-07-18
- **Status:** Design approved (brainstorm); pending spec review → implementation plan
- **Repo:** Strike48-public/pick
- **Related:** Strike48/matrix PR #1390 (`feat/matrix/doc-share-link`) — shareable-link backend (deployed by operator)

## 1. Overview & purpose

"Easy Mode" is a simplified, non-expert ("wife-friendly") app mode for Pick, available across
all app targets (mobile primary; desktop/web opt-in). It strips the expert pentest UI to three
things a lay user can use:

1. A single **Scan** button that discovers hosts/services on the local network.
2. A **solid chat** interface to talk to the assistant.
3. A **documents** list where scan results are captured as documents, each with a **Share**
   button that produces a public link.

It composes existing Pick components and existing Strike48 platform rails. The only external
dependency is the operator-deployed `matrix_share` feature (PR #1390).

## 2. Goals / non-goals

**Goals**
- One-tap network scan producing human-readable results.
- Clean standalone chat with no expert pentest-pipeline chrome.
- Scan output captured as a listed document; each document shareable via a `/s/:token` link
  created from within Pick (in-app Share button — no trip to Studio).
- Works on mobile (primary); desktop/web opt-in. Degrades gracefully on iOS (port scan only).

**Non-goals (YAGNI)**
- No new connector→document API — the server-side agent writes documents (platform's normal
  "agent tools write objects" pattern).
- We do not revive/merge #1390 ourselves; the operator deploys it and enables the flag.
- No auto-update, signing, or expert-UI changes (separate efforts).

## 3. Integration spine

No new backend beyond the operator's #1390 deploy. The "connector→document gap" is sidestepped:
the **agent** writes the document; Pick drives the scan and handles listing + sharing.

```
Pick easy-mode chat  ──(1 conversation)──►  Matrix GenAssistant agent
  │  seed: "discover my local network + write a report document"
  │                                          agent runs Pick scan tools (execute_request):
  │                                            port_scan (all platforms incl iOS),
  │                                            ARP/mDNS/SSDP (desktop/Android)
  │                                          agent calls document_write
  │                                            → conversation document (in conversation metadata)
  ├─ list docs  ◄── document_list (conversation tool_state)
  └─ Share btn  ──► GraphQL createSharedLink{
                        resource_type: "conversation_document",
                        resource_id:   "{conversationId}:{documentId}" }
                    ──► /s/:token  (matrix_share / #1390)
```

Key backend facts this relies on (verified on matrix `origin/develop` + PR #1390):
- `matrix_agents/.../tools/document_operations.ex` — agent tool set `document_write` /
  `document_list` / `document_read` / `document_delete`; documents persist in conversation
  metadata via `MatrixData.Conversations` tool-state.
- #1390 `conversation_document` resolver: `resource_id = "{conversationId}:{documentId}"`,
  resolved through `MatrixData.Conversations.find_document`, shared as its markdown content.
- #1390 create path: GraphQL `createSharedLink` mutation → `MatrixShare.create_link/2`
  (requires `Matrix.Ctx{tenant, user}`; per-tenant feature flag `document_sharing_enabled`).

## 4. Components

### 4.1 Easy-mode shell (Pick UI)
- Add `easy_mode: bool` to `ConnectorAppConfig` (`crates/ui/src/connector_app.rs:38`). When
  true, `connector_app()` renders a new `EasyModeShell` instead of the standard
  `ConnectorPages` + sidebar.
- `EasyModeShell` = one responsive screen: header, a prominent **Scan** action card, an
  embedded full-page chat, and a **Documents** list. Reuse `.action-card` / `.dashboard-card`
  from `crates/ui/src/styles/mobile.css`.
- Default `easy_mode = true` in `MOBILE_CONFIG` (`apps/mobile/src/main.rs:8`). Add a persisted
  settings toggle (`pentest_core::settings`) so desktop/web can switch at runtime.
- Expert nav (Tools/Shell/CyberChef/Logs) hidden. Optional small "Advanced" escape hatch to the
  full UI.

### 4.2 Scan (one button)
- Button seeds a canned chat message (reusing the Dashboard `on_open_chat.call(prompt)` pattern,
  `crates/ui/src/components/dashboard.rs:62`) instructing the agent to enumerate interfaces,
  scan the local subnet, and **write a report document**.
- Reuses existing tools (`port_scan.rs`, `network_discover.rs`, `ssdp_discover.rs`,
  `arp_table.rs`) via the agent — no new scanner code.
- Progress shown in chat (tool-call rendering). iOS degrades to `port_scan` +
  `get_network_interfaces` only.

### 4.3 Chat (solid, standalone)
- Mount `ChatPanel { full_page: true, .. }` (`crates/ui/src/components/chat_panel/mod.rs`) with
  a fixed auto-selected agent and expert header actions (validate/report/agent-select/history)
  suppressed (already suppressed in `full_page`).
- Backend unchanged: `MatrixChatClient` → conversation polling.

### 4.4 Documents + share
- **List:** read the conversation's documents (`document_list` tool result, or a direct Matrix
  read of conversation tool-state documents). Render title, created time, open/preview, Share.
- **Open:** render document markdown in-app (reuse chat markdown rendering) or open the share
  link.
- **Share:** call GraphQL `createSharedLink` over `MATRIX_API_URL` with
  `resource_type: "conversation_document"`, `resource_id: "{conversationId}:{documentId}"`,
  `access_scope` (default `tenant_only`; see risk R2), optional `expires_in_seconds`. Display
  the `/s/:token` URL with copy + mobile OS share sheet.
- **Manage (later):** list/revoke existing links (`SharedLinks` / `RevokeSharedLink`).

## 5. Dependencies & assumptions
- `matrix_share` (#1390) deployed in the target cluster; `document_sharing_enabled` ON for the
  tenant. (Operator owns — confirmed in progress.)
- The tenant's agent has the `document_operations` tool enabled. **(Verify.)**
- `MATRIX_API_URL` reachable; Pick authenticated with a context that satisfies
  `createSharedLink`'s `Ctx{tenant, user}`. **(Verify — see R1.)**

## 6. Platform coverage
- **Mobile (primary):** Android = full scan; iOS = `port_scan` + interface enumeration only.
- **Desktop/web:** opt-in via settings toggle.
- Chat + documents + share behave identically across platforms (all server-side).

## 7. Phasing
- **Phase 1 — Shell + scan + chat.** A usable easy mode with no document/share dependency.
  Ships independent of #1390.
- **Phase 2 — Documents list + in-app Share.** Conversation-document list + `createSharedLink`
  + copy/share-sheet. Depends on #1390 deployed + flag on.
- **Phase 3 (optional) — Manage/revoke links; public-vs-recipient scoping UI; local export
  fallback.**

## 8. Error handling
- Scan/tool errors surface in chat; the Scan button re-enables.
- Sharing unavailable (flag off / #1390 absent / quota): Share button hidden or shows a clear
  message; the document list still works.
- No `MATRIX_API_URL` / offline: chat + scan degrade with a clear message; documents/share
  disabled.
- iOS: communicate "limited scan on this device."

## 9. Testing
- **Unit (Rust):** `easy_mode` config branch renders `EasyModeShell`; seed-prompt builder;
  `createSharedLink` request/response mapping; document-list parsing.
- **Integration:** mock Matrix GraphQL for `createSharedLink` (success / quota / flag-off);
  mock conversation `document_list`.
- **Manual/E2E** (tenant with #1390 + flag on): scan → agent writes doc → doc appears in list →
  Share → `/s/:token` opens. Mobile + desktop. iOS degraded-scan path.
- **Regression:** standard (non-easy) mode and the desktop app unaffected when
  `easy_mode = false`.

## 10. Risks / open questions
- **R1 — Auth context for share creation.** `createSharedLink` / `MatrixShare.create_link`
  require `Ctx{tenant, user}` (used for ownership + quota). Confirm Pick's session carries a
  *user* identity, not just a connector identity. If not, sharing needs a user-scoped token or
  a server-side path.
- **R2 — "Public" links still require login.** In #1390 the `/s/:token` controller runs
  `ensure_authenticated_access` for humans (redirects to `/auth/login`) *before* `access_scope`
  is evaluated — so even `public`-scope links require a logged-in session. This breaks the
  core "share with a spouse who has no account" use case. **Likely a small #1390 tweak the
  operator wants when rebasing** (allow unauthenticated access for `public` scope). Flag before
  committing to the share UX.
- **R3 — Agent reliably writes the report.** The easy-mode agent must call `document_write` for
  scan output — prompt engineering, and possibly a dedicated "write report" step. Confirm the
  easy-mode agent config includes `document_operations`.
- **R4 — Document listing read path.** Confirm a clean way for Pick to read the conversation's
  documents (agent `document_list` vs a Matrix API endpoint for conversation tool-state docs).
- **R5 — iOS scan is thin.** `port_scan`-only; set user expectations in the UI.

## 11. Out of scope (parked)
- Cross-platform background auto-update (separate brainstorm; design decisions captured
  separately: Strike48-hosted signed manifest, silent-download-then-restart-banner,
  Ed25519 app-verified trust, phased all-platform).

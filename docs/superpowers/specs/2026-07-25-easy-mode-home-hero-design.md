# Easy Mode Home Hero + Resume Card — Design

**Status:** Approved design, pending spec review
**Date:** 2026-07-25

## Goal

Bring Pick's easy-mode Home screen closer to the StrikeHub Desktop App Template
(`~/Downloads/StrikeHub Desktop App Template.html`, Home screen ~lines 1812-1843).
Today the easy-mode empty state is a single bare "Scan My Network" tile. The
template frames it as a **hero** (brand badge + headline + subtitle + a large
scan pill) followed by contextual cards.

This pass ships the two elements we can back with real data, with **zero
fabricated numbers**:

1. **Hero block** — brand "S" badge, headline "What's on your network?",
   subtitle "One click enumerates every live host, its open services, and the
   risk they carry.", and the large pill "Scan My Network" button.
2. **"Pick up where you left off" card** — the most recent conversation's title,
   a relative timestamp, and an "Open report" action (opens the latest report
   for that conversation, or opens the conversation if it has no report yet).

Explicitly **deferred** (documented, not built): the template's **"Last scan"**
stats card (hosts/services/severity counts). Pick is a dumb executor with no
findings/host store; those counts do not exist connector-side. Deferred until a
real stats source exists — see "Non-goals".

Also in scope (real chrome gap): a **Reports count badge** on the drawer's
Reports item, mirroring the template's "Reports 11" tag.

## Source of truth

Template Home (`.stage` easy-mode screen):

```
[48 badge, 54px, --pri fill]
"What's on your network?"          (s-disp, 28px)
"One click enumerates every live host, its open services, and the risk they carry."  (s-body, 14px)
( Scan My Network )                (btn pri, full-width, 62px, 999px radius, 17px)

grid 1fr 1fr, gap 12px:
  card "Last scan"  -> 8 hosts . 21 services / [2 high][3 medium]   <-- DEFERRED (no data)
  card "Pick up where you left off" -> title / "1h ago . report attached" / (Open report)  <-- BUILD
```

## Architecture

All changes are contained to `crates/ui/src/components/easy_mode.rs` plus CSS
(`crates/ui/src/styles/mobile.css` for `.easy-*` rules; `.sage` shape rules
already inherited by cards). No core/backend change; no new data fetch beyond
what already flows into the shell.

### Data sources (all already present)

- **Recent conversations:** `chat_header_ctx` (a `Signal<Option<ChatHeaderCtx>>`
  already provided in `EasyModeShell`) exposes `conversations: Vec<ConversationInfo>`
  (`{id, title, summary, updated_at}`), `on_select_conversation: EventHandler<String>`,
  and `on_new_chat`. The most recent conversation = `conversations.first()` (the
  chat panel already sorts newest-first when it publishes the context). No new
  query.
- **Latest report for that conversation:** reuse `MatrixChatClient::new(api_url)
  .with_auth_token(token).list_documents(agent_id)` (same call `DocumentsPanel`
  uses), filter `doc.conversation_id == conv.id`, take newest by `timestamp`.
  Opening it reuses the existing `viewing.set(Some(doc))` overlay path.
- **Relative timestamp:** `ConversationInfo.updated_at` is ISO-8601; format with
  the existing `crate::components::chat_panel::format_relative_time` helper
  (already used by the sidebar recent list).

### Component structure (in `EasyModeShell`)

Replace the current scan-card block (the `if !conversation_active() && matches!(flow, Connected)`
region) with a **Home hero** region rendered under the same guard:

```
if !conversation_active() && matches!(flow(), AuthFlow::Connected { .. }) {
    div { class: "easy-home",
        // Hero
        div { class: "easy-home-hero",
            span { class: "easy-hero-badge", dangerous_inner_html: STRIKE48_S_BADGE_SVG }
            h1  { class: "easy-hero-title", "What's on your network?" }
            p   { class: "easy-hero-sub", "One click enumerates every live host, its open services, and the risk they carry." }
            button { class: "easy-hero-scan", onclick: <same scan telemetry + chat_mailbox.set(scan_prompt)>,
                span { class: "easy-hero-scan-icon", Network { size: 21 } }
                "Scan My Network"
            }
        }
        // Resume card — only when there is a recent conversation
        if let Some(conv) = recent_conversation() {
            div { class: "easy-home-cards",
                ResumeCard { conv, latest_report, on_open_conversation, on_open_report }
            }
        }
    }
}
```

The scan `onclick` keeps the existing telemetry (`ScanStart`, channel=easy,
source=easy_mode_button) and `chat_mailbox.set(easy_mode_scan_prompt())`.

The resume card:
- Eyebrow label "Pick up where you left off" (`.easy-card-eye`, uppercase mono).
- Conversation title (fallback "Untitled chat" when blank), single-line ellipsis.
- Sub line: `"{relative_time} ago"` + `" · report attached"` when a report
  exists.
- Button: "Open report" (calls `viewing.set(Some(latest_report))`) when a report
  exists; otherwise "Resume chat" (calls `on_select_conversation(conv.id)`).

### Reports count badge (chrome gap)

The drawer's Reports item gains a count tag when > 0, using the same
`list_documents` count (fetched once for the resume card, reused). Rendered as a
mono pill matching the template `.navlink .tag` (and Sage `.sidebar-badge`).

## Styling

New `.easy-*` rules in `mobile.css`, inheriting Sage tokens (`--em-*` /
`--sage-*` where the shell is `.sage`):

- `.easy-home` — column, centered, `max-width: 660px`, generous top padding.
- `.easy-home-hero` — centered column, `gap: 22px`.
- `.easy-hero-badge` — 54px, 15px radius, `--em-brand` fill, dark glyph.
- `.easy-hero-title` — 28px, weight 700.
- `.easy-hero-sub` — 14px, muted, `text-wrap: pretty`.
- `.easy-hero-scan` — full-width, 62px, `border-radius: 999px`, 17px, sage fill
  (`--em-scan-bg` / `--em-on-scan`), hover `filter: brightness(1.06)`. Reuses
  the existing scan CTA colors so it matches the current button's palette.
- `.easy-home-cards` — grid; single column now (one card), ready for 2-col when
  "Last scan" lands.
- `.easy-home-card` — 16px radius, glass surface (matches `.card`), padding
  16px 18px.
- `.easy-card-eye` — uppercase mono, dim, letter-spacing.

The current `.action-card` / `.action-grid` scan tile is removed in favor of the
hero (the hero's pill IS the scan action).

## Testing

- **Unit:** a small pure helper `resume_sub_line(relative: &str, has_report: bool) -> String`
  returns `"1h ago · report attached"` vs `"1h ago"`; test both branches.
  (The rest is view code verified visually.)
- **Manual/visual:** launch desktop easy mode (Sage), confirm: hero renders with
  headline + big pill; Scan pill still sends the scan prompt; with an existing
  conversation the resume card shows real title + time; "Open report" opens the
  latest report; with no report the button reads "Resume chat" and opens the
  conversation; the drawer Reports item shows the count badge.
- **Regression:** `cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
  clean; expert mode unchanged; the scan flow (button -> chat) still works;
  conversation-active still hides the Home (chat takes over).

## Non-goals

- **"Last scan" stats card.** No connector-side findings/host/service store
  exists (Pick logs activities, does not create evidence/findings). Host/service
  counts live only as raw tool-result JSON inside chat messages; severity counts
  ("2 high") do not exist anywhere connector-side. Deferred until a real stats
  source (platform GraphQL endpoint or a connector-side aggregation) exists.
  When it does, the `.easy-home-cards` grid flips to 2-col and the card slots in.
- Template "Flow index" nav — mockup-only screen index, not a product feature.
- Template "2 of 3 hubs connected" footer — multi-hub mockup scaffolding; a
  single Pick connector has the existing status dot.
- No change to the chat, report viewer, or scan prompt behavior.

## Risks / notes

- `chat_header_ctx` is `None` until the ChatPanel mounts and publishes it; the
  resume card must treat `None`/empty conversations as "no card" (hero only).
- `list_documents` is async; fetch in a `use_effect`/`use_future` keyed on
  agent_id + token, mirroring `DocumentsPanel`. Show the hero immediately;
  the resume card appears when data arrives (no blocking spinner on Home).
- Keep the scan CTA's telemetry and prompt identical so scan analytics and the
  server-side agent behavior are unchanged.

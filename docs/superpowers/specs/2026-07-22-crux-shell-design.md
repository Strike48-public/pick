# Crux Native Shells — Design System (match the Dioxus Easy Mode)

The SwiftUI (iOS) and Jetpack Compose (Android) shells must render Easy Mode with
the SAME look as the Dioxus app (`crates/ui/src/styles/mobile.css`, the `--em-*`
tokens). This is the single source of truth for both native shells. Do NOT use
default Material purple / iOS blue.

## Theme: "Sage dark" (Material 3 shapes, muted sage-green pastel, dark surfaces)

### Colors (hex / rgba on a dark shell)
- Brand (primary): `#9cbfae` (sage). Deeper sage (pressed/hover): `#7fa894`.
- On-brand text/glyph (dark ink used on sage fills): `#17201b`.
- Screen background (page behind everything): neutral near-black `oklch(0.145 0 0)`
  ≈ `#1c1c1c` (the shadcn dark base `--background`; NOT sage-tinted). Cards / elevated
  surface: `#242b27` (sage-tinted, reads as elevated against the neutral bg).
- Primary text / headings: `#e9eeeb`. Muted / secondary text: `rgba(233,238,235,0.6)`.
- Subtle fill (ghost buttons, refresh): `rgba(233,238,235,0.08)`.
- Faint wash (doc strip bg): `rgba(233,238,235,0.03)`.
- Hairline divider / border: `rgba(233,238,235,0.12)`; strong border (ghost outline)
  `rgba(233,238,235,0.22)`; list-row separator `rgba(233,238,235,0.08)`.
- Error text: `#d99a9a`. Toast bg `#2f3a34`, toast fg `#8fc4ab`.
- Social: X `#000000`, LinkedIn `#0a66c2`, Facebook `#1877f2`, on-social `#ffffff`.
- Status (tool-call badges): success `#8fc4ab`, error `#d99a9a`, warning `#d9b07c`.

### Shape scale (Material 3)
- Pill (buttons, chips, the Scan CTA): fully rounded (radius 999 / `.infinity`).
- Card / row: 16px corner radius.
- Control (inputs, notes): 12px corner radius.
- Brand badge: 30x30, 9px corner radius, sage fill, dark "S" glyph.

### Spacing scale (4px base)
1=4, 2=8, 3=12, 4=16. Chat list edge padding = 16. Between stacked chat blocks = 12.

### Type
- Sans (body, headings, "Pick" wordmark): IBM Plex Sans if bundled, else the
  platform system sans. "Pick" wordmark: bold (700), 20px, letter-spacing -0.01em.
- Mono (tool names, code, IDs): IBM Plex Mono / platform monospace.

### Brand badge SVG (the "S")
30x30 rounded-square sage badge (`#9cbfae`) containing this stroke path in dark ink
(`#17201b`), stroke-width ~3.2, round caps/joins, viewBox 0 0 32 32:
`M23 9 C23 6 19 5 16 5 C12 5 9 7 9 10 C9 16 23 14 23 21 C23 25 19 27 15 27 C11 27 8 25 8 22`
Render as a vector (SwiftUI Path / Compose Canvas or a bundled asset). Top bar shows:
[badge] "Pick" on the left; action icons (New chat +, History clock, Reports doc) on
the right — icon buttons are 40px touch targets, glyphs ~20px, `--em-text` color,
pressed bg = subtle fill.

## Screens (each is a pure function of `ViewModel`; the shell only renders + emits Events)

`ViewModel.screen` selects the screen: `Scan | Chat | Documents | DocViewer | NeedsSignIn`.
Plus overlays driven by fields (`openDocument`, `needsSignIn`, `error`).

1. **Top bar (always visible in the main shell)**: badge + "Pick" wordmark + the 3
   action icons. 4px 20px 12px padding. Icons emit: New chat -> `Event.NewChat`;
   History -> `Event.OpenHistory` (and `CloseHistory` to dismiss); Reports -> opens the
   Documents list (render `allDocuments`).

2. **Scan screen** (`showScanCard == true`, i.e. no active conversation): the sage
   **pill** CTA card — a 16px card containing a centered "Scan your network" title,
   "Discover hosts and services on the local network." body, and a full-width sage
   **pill** button "Scan My Network" -> `Event.StartScan`. Min-height 64, padding 18x20.
   When `scanInProgress`, the button shows a spinner / "Scanning..." and is disabled.

3. **Chat screen** (a conversation is active — `messages` non-empty / `showScanCard`
   false): a scrolling message list + a bottom input row.
   - `MessageView.kind`: **User** = sage-filled bubble (`#9cbfae` bg, dark text, 16px
     radius, 8x12 padding), right-aligned; **AgentText** = transparent, no bubble, full
     width, `--em-text` markdown (render markdown: bold, lists, code, headings);
     **ToolCall** = a 16px card, surface bg `#242b27`, hairline border, with the tool
     name (mono) + a pill status badge colored by `ToolStatus` (Running=warning,
     Success=success, Error=error). `toolCalls` may also be shown as a live "running
     tools" strip while scanning — hide the empty agent-name label above it.
   - Uniform vertical rhythm: 12px gap between blocks (do not double-pad bubbles).
   - Input row: rounded 12px text field + a 44px sage **pill** Send button (matching
     input height). Send -> `Event.SendMessage(text)`.

4. **Documents / Reports list** (`allDocuments`, opened from the top-bar Reports icon;
   also a conversation-scoped strip `conversationDocs` pinned above the chat input,
   max 30vh, faint wash bg, hairline top border): each row = doc title, tappable ->
   `Event.OpenDocument(id)`. Row press bg = subtle fill.

5. **Document viewer** (`openDocument: DocView?`): full-screen overlay. Top bar with a
   left chevron (‹, 40px touch target, NO "Back" word) -> `Event.CloseDocument`, and the
   doc title. Body renders `markdown_body`. A Share action: if `share_url` present, offer
   native share sheet (iOS UIActivityViewController / Android ACTION_SEND) + the social
   buttons; the button that creates a link emits `Event.CreateShareLink(docId)` and the
   resulting `share_url` lands back in `openDocument`.

6. **Needs sign-in** (`needsSignIn == true`): centered column — "Sign in to connect to
   Strike48" title, a muted sub-line, and a sage pill "Retry sign-in" (or "Sign in")
   button. In this phase the button triggers the shell's native OAuth (see below);
   `Event.RetrySignIn` re-drives the sign-in effect.

7. **Error**: `error: String?` — a card (surface bg, error-colored "Error" heading,
   the message in body text). Dismiss -> `Event.DismissError`.

8. **Connection status**: `connection.label` (e.g. "Connecting...", "Connected") shown
   as a small muted line under the wordmark; `connection.phase` can tint a dot.

## Native capabilities the shell owns (not the core)
- **OAuth sign-in**: iOS `ASWebAuthenticationSession`, Android Custom Tabs / browser
  intent. On success the shell feeds the token to the core (a new FFI entrypoint to set
  the token + re-drive, or reconstruct the core). `needsSignIn`/`RetrySignIn` gate this.
  Reuse pentest-core's OAuth where possible.
- **Share sheet / open URL**: native share for `share_url`.

## Fidelity bar
"Match our designs generally" = same palette, same sage pill CTA, same dark cards, same
top-bar layout, same message-bubble treatment, same 16px/pill/12px radii, IBM Plex (or
system) type. It does not need to be pixel-identical to the WebView, but a screenshot
should be unmistakably the same product as the Dioxus Easy Mode.

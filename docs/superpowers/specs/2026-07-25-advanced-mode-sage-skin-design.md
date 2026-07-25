# Advanced Mode Sage Skin — Design

**Status:** Approved design, pending spec review
**Date:** 2026-07-25

## Goal

Reskin Pick's **advanced mode** (the expert `AppLayout` shell: sidebar, header,
status bar, cards, settings) to match the "Sage" design language already used
by **easy mode** and captured in the StrikeHub Desktop App Template. Deliver it
as a new selectable theme, **`Sage`** (dark) plus **`SageLight`** (light), and
make `Sage` the application default.

## Source of truth

`~/Downloads/StrikeHub Desktop App Template.html` is a component gallery of the
Sage DS. Its palette is the same family already scoped to `.easy-mode` in
`crates/ui/src/styles/mobile.css` (`--surf: #242b27`, `--ok: #8fc4ab`,
`--warn: #d9b07c`, `--err: #d99a9a` all match the existing `--em-*` tokens), but
richer: radial-gradient backgrounds, glass surfaces, a gold accent, panel
shades, and tinted status backgrounds. The template's component vocabulary
(`.side`, `.navlink`, `.apphdr`, `.pageh`, `.statusbar`, `.btn` pill, `.chip`,
`.kpi`) maps 1:1 onto advanced mode's chrome.

### Dark palette (`.stage`)

```
--bg: #141715;   --p1: #1b201d;   --p3: #101312;   --surf: #242b27;   --surf2: #2c352f;
--line: rgba(255,255,255,.09);    --line2: rgba(255,255,255,.17);
--tx: #e9eeeb;   --mut: #a7b2ab;  --dim: #78847d;
--pri: #9cbfae;  --pri2: #b3d2c3; --acc/--gold: #c9b27e;   --on-pri: #151a17;
--ok: #8fc4ab;   --warn: #d9b07c; --err: #d99a9a;  --info: #9cb8bf;
--glass-bg: rgba(255,255,255,.05); --glass-line: rgba(255,255,255,.09);
--glass-sh: 0 14px 34px rgba(6,12,9,.3), inset 0 1px 0 rgba(255,255,255,.06);
--tint: rgba(156,191,174,.16);
--ok-bg: rgba(143,196,171,.14);  --warn-bg: rgba(217,176,124,.14);
--err-bg: rgba(217,154,154,.14); --info-bg: rgba(156,184,191,.14);
--mut-bg: rgba(167,178,171,.13);
background: radial-gradient(1000px 620px at 78% -12%, rgba(156,191,174,.13), transparent 60%),
            radial-gradient(800px 560px at -8% 95%, rgba(156,191,174,.08), transparent 55%),
            var(--bg);
```

### Light palette (`.stage.t-light`)

```
--bg: #f2f4f1;   --p1: #ffffff;   --p3: #edf0ec;   --surf: #e5eae4;   --surf2: #dbe2da;
--line: rgba(30,45,36,.10);       --line2: rgba(30,45,36,.18);
--tx: #2a332d;   --mut: #5e6a62;  --dim: #8b968e;
--pri: #5f8f7a;  --pri2: #4e7d69; --acc/--gold: #a08a4e;   --on-pri: #ffffff;
--ok: #4f9377;   --warn: #b5834a; --err: #b56e6e;  --info: #5f8f8f;
--glass-bg: rgba(255,255,255,.62); --glass-line: rgba(255,255,255,.75);
--glass-sh: 0 14px 34px rgba(44,60,50,.1), inset 0 1px 0 rgba(255,255,255,.8);
--tint: rgba(95,143,122,.14);
--ok-bg: rgba(79,147,119,.14);   --warn-bg: rgba(181,131,74,.15);
--err-bg: rgba(181,110,110,.15); --info-bg: rgba(95,143,143,.14);
--mut-bg: rgba(94,106,98,.12);   --ok-tx: #33664f; --warn-tx: #7d5426;
--err-tx: #7d3e3e; --info-tx: #3d6363; --gold-tx: #7d6526;
background: radial-gradient(1000px 620px at 78% -12%, rgba(156,191,174,.33), transparent 60%),
            radial-gradient(800px 560px at -8% 95%, rgba(156,191,174,.2), transparent 55%),
            var(--bg);
```

### Fonts / shapes

```
--sans: 'IBM Plex Sans', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
--mono: 'IBM Plex Mono', ui-monospace, 'SF Mono', Menlo, 'Cascadia Code', monospace;
```

- Buttons: pill, `height: 40px`, `border-radius: 999px`, `--pri` fill with
  `--on-pri` text, hover `filter: brightness(1.06)`.
- Nav links / chips / cards: `border-radius: 9–10px`.
- Selected nav / chip: `background: var(--tint)`, `color: var(--pri2)`.
- Role chips: outlined in `--gold`, mono, uppercase.
- Sidebar + header: glass — `rgba(255,255,255,.03)` fill, `1px` `--line`
  border, `backdrop-filter: blur(20px)` on the header.
- Status bar labels / metadata: `--mono`, uppercase, `--dim`.

## Architecture — two coordinated layers

### Layer 1 — Color tokens (`crates/ui/src/theme.rs`, `crates/core/src/config.rs`)

1. Add `Sage` and `SageLight` variants to `enum Theme` (`config.rs`). Move
   `#[default]` from `Strike48` to `Sage`.
2. Add `sage_theme()` and `sage_light_theme()` returning `ThemeColors`, mapping
   the palettes above onto the existing struct fields:
   - `background → --bg`, `card/popover → --surf`, `foreground → --tx`,
     `primary → --pri`, `primary_foreground → --on-pri`,
     `secondary/muted → --surf2 / --p1`, `muted_foreground → --mut`,
     `accent → --acc (gold)`, `border/input → --line`, `ring → --pri`,
     `sidebar → --p3` (or the glass fill), `success → --ok`, `warning → --warn`,
     `info → --info`, `destructive → --err`. `color_scheme` `"dark"` / `"light"`.
   - Colors stay as hex (the struct already accepts arbitrary CSS color
     strings; no oklch conversion required).
3. Wire both variants into `get_theme_colors`, the Settings `<select>` (option +
   match arm), and the random-theme list (`settings_page.rs`).
4. Fonts: extend the `generate_theme_css` font branch so `Sage`/`SageLight`
   (like `Strike48`) import IBM Plex and set `--font-sans`/`--font-mono` to the
   Plex stacks.
5. Extra Sage-only tokens (`--acc/--gold`, `--surf2`, `--p1`, `--p3`, `--tint`,
   `--glass-bg`, `--glass-line`, `--glass-sh`, `--ok-bg`/`--warn-bg`/`--err-bg`/
   `--info-bg`/`--mut-bg`, `--line2`, `--dim`, `--pri2`, status `-tx` vars) are
   emitted into `:root` by `generate_theme_css` **only when the theme is
   Sage/SageLight** — a dedicated helper (e.g. `sage_extra_tokens_css(theme)`)
   returns the block for those two themes and an empty string otherwise, and
   `generate_theme_css` appends its result. Non-Sage themes get no extra
   tokens, keeping their emitted CSS byte-for-byte unchanged.

### Layer 2 — Chrome shape CSS (new `sage_theme_css()` + root class)

The chrome CSS has ~85 hardcoded `border-radius: Npx` and fixed backgrounds that
a token swap alone won't reshape. Add a **Sage-scoped stylesheet** that
restyles the chrome to the template, applied **only when Sage/SageLight is
active**, scoped under a `sage` root class so no other theme is touched.

- New function `sage_theme_css() -> &'static str` (co-located with the other
  css helpers; likely `theme.rs` or a new `crates/ui/src/styles/sage.css`
  `include_str!`d).
- Rules are scoped `.sage .app-layout`, `.sage .sidebar`, `.sage .navlink`,
  `.sage .desktop-header`, `.sage .status-bar`, `.sage .button`, `.sage .card`,
  `.sage .chip`, etc., mirroring the template component styles: pill buttons,
  9–10px radii, glass sidebar/header (`backdrop-filter: blur(20px)`), the
  radial-gradient page background on `.sage .app-layout`, gold-accent chips,
  IBM Plex.
- **Root class hook:** both shells wrap their content in an element that gets
  the `sage` class when `theme ∈ {Sage, SageLight}`:
  - `connector_app.rs`: the existing `div { class: "{container_class}" }` gains
    `sage` when Sage is active (compute a `class="{container_class} sage"`).
  - `workspace_app.rs`: the top-level rsx has no single wrapper today; wrap the
    shell in a `div { class: "workspace-root sage?" }` (or add the class to the
    outermost existing element that encloses both the easy/expert branches).
- Injection: append `sage_theme_css()` to the injected `<style>` set **only when
  the active theme is Sage/SageLight**, next to `combined_css` (workspace_app)
  and the `css_block` styles (connector_app). Since it's both class-scoped and
  conditionally injected, other themes are doubly protected.

## Scope

- **Both dark (`Sage`) and light (`SageLight`)** in this pass.
- **Both roots**: `connector_app` (standalone desktop/mobile/web) and
  `WorkspaceApp` (connector/liveview under StrikeHub).
- **Default theme = `Sage`.** Existing persisted user theme choices are
  respected (the default only applies to fresh installs / unset config).
- **Density** stays user-controlled; the Sage chrome respects the existing
  `--spacing-*` density tokens rather than hardcoding the template's spacing.
- Easy mode is **unchanged** — it already uses the Sage palette via `--em-*`;
  this design does not touch `easy_mode.rs` or the `.easy-*` rules.

## Non-goals

- No change to the chat panel, tool tiles, or document viewer styling beyond
  what the shared theme tokens already drive.
- No new components; this is a reskin of existing chrome.
- No removal of existing themes (Strike48/Dark/Dracula/etc. remain selectable
  and byte-for-byte unchanged).

## Testing

- **Unit:** `get_theme_colors(Theme::Sage)` / `(Theme::SageLight)` return the
  expected `color_scheme` and key tokens; `Theme::default() == Theme::Sage`;
  the Settings `<select>` match arm round-trips `"Sage"`/`"SageLight"`.
- **Snapshot/string:** `generate_theme_css(Sage, ..)` contains the IBM Plex font
  import, `--pri: #9cbfae`, and the Sage-only token block; `generate_theme_css`
  for a non-Sage theme does **not** contain the Sage-only block.
- **Manual/visual:** build both shells, switch to Sage and SageLight in
  Settings, confirm the sidebar/header/buttons/cards match the template in each,
  and confirm switching to another theme fully reverts (no leaked Sage shapes).
- **Regression:** `cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
  clean; other themes render unchanged.

## Risks / notes

- The `sage` root class must sit on an ancestor of **all** chrome (sidebar +
  header + content). Verify the chosen wrapper in each shell encloses the whole
  `AppLayout`.
- `backdrop-filter` support: webkitgtk (liveview) supports it; confirm it
  degrades gracefully (opaque fallback) rather than rendering transparent.
- The template's `--acc`/`--gold` maps to the theme `accent` token; check no
  existing advanced-mode component relies on `accent` being a near-background
  neutral (as in some other themes) in a way that gold would break.

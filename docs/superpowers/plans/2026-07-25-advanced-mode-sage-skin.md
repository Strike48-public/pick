# Advanced Mode Sage Skin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reskin Pick's advanced mode (`AppLayout` chrome) to the Sage design language via two new themes — `Sage` (dark, default) and `SageLight` — a color-token layer plus a root-class-scoped chrome stylesheet, leaving all other themes byte-for-byte unchanged.

**Architecture:** Add `Theme::Sage`/`Theme::SageLight` with `ThemeColors` palettes mapped onto the existing `--background`/`--card`/`--primary`/`--sidebar`/… tokens the chrome already reads. Extend `generate_theme_css` to (a) import IBM Plex for Sage, (b) append Sage-only extra tokens (`--acc`, glass, tints) and the Sage chrome stylesheet — but ONLY for the two Sage themes. The chrome stylesheet is scoped under a `sage` root class applied to each shell's root element when a Sage theme is active. Because `generate_theme_css` is the single funnel all three CSS-injection paths use (desktop static head, mobile reactive, liveview reactive), folding the Sage CSS in there covers every entry point from one site.

**Tech Stack:** Rust, Dioxus 0.7, CSS custom properties.

## Global Constraints

- Non-Sage themes (Strike48/Dark/Light/Dracula/Gruvbox/TokyoNight/Matrix/Cyberpunk/Nord) must emit byte-for-byte identical CSS to today. The Sage extra-token block and chrome stylesheet must return `""` for any non-Sage theme.
- Sage chrome rules are ALL scoped under `.sage ` — no bare selector may leak shape/color into other themes.
- Palettes are the exact hex values from the approved spec (`docs/superpowers/specs/2026-07-25-advanced-mode-sage-skin-design.md`). Colors are hex strings (no oklch conversion).
- Fonts: Sage/SageLight use IBM Plex Sans (`--font-sans`) and IBM Plex Mono (`--font-mono`), same import mechanism as `Theme::Strike48`.
- No commit may contain Claude attribution, customer/tenant names, emojis, or em-dashes. Conventional-commit messages.
- `cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings` must be clean (run under `nix develop --command`).
- Easy mode (`easy_mode.rs`, `.easy-*` rules) must not be touched.

---

### Task 1: Add Sage + SageLight to the Theme enum and make Sage the default

**Files:**
- Modify: `crates/core/src/config.rs` (the `pub enum Theme` at ~line 21)
- Test: `crates/core/src/config.rs` (existing `#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `Theme::Sage`, `Theme::SageLight` variants; `Theme::default() == Theme::Sage`.

- [ ] **Step 1: Write the failing test**

Add to the existing tests module in `crates/core/src/config.rs`:

```rust
#[test]
fn sage_is_default_theme() {
    assert_eq!(Theme::default(), Theme::Sage);
}

#[test]
fn sage_themes_roundtrip_serde() {
    for t in [Theme::Sage, Theme::SageLight] {
        let json = serde_json::to_string(&t).unwrap();
        let back: Theme = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-core sage_is_default_theme sage_themes_roundtrip_serde`
Expected: FAIL — `no variant named Sage` / `Sage` not found.

- [ ] **Step 3: Edit the enum**

Move `#[default]` off `Strike48` and add the two variants. The enum becomes:

```rust
pub enum Theme {
    Strike48,
    Dark,
    Light,
    Dracula,
    Gruvbox,
    TokyoNight,
    Matrix,
    Cyberpunk,
    Nord,
    #[default]
    Sage,
    SageLight,
}
```

(Only the `#[default]` attribute moves and two variants are appended — order of the existing variants is otherwise unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-core sage_is_default_theme sage_themes_roundtrip_serde`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/config.rs
git commit -m "feat(theme): add Sage and SageLight theme variants, default to Sage"
```

---

### Task 2: Add sage_theme() and sage_light_theme() color palettes

**Files:**
- Modify: `crates/ui/src/theme.rs` (add two `ThemeColors` builder fns near `strike48_theme()`; wire into `get_theme_colors` match at ~line 757)
- Test: `crates/ui/src/theme.rs` (new `#[cfg(test)] mod tests` if none exists)

**Interfaces:**
- Consumes: `Theme::Sage`, `Theme::SageLight` (Task 1); the private `struct ThemeColors` (fields listed below).
- Produces: `get_theme_colors(Theme::Sage)` / `(Theme::SageLight)` return the Sage palettes.

`ThemeColors` fields (all `&'static str`): `color_scheme, background, foreground, card, popover, primary, primary_foreground, secondary, secondary_foreground, muted, muted_foreground, accent, accent_foreground, destructive, border, input, ring, sidebar, sidebar_foreground, sidebar_primary, sidebar_primary_foreground, sidebar_accent, sidebar_accent_foreground, sidebar_border, sidebar_ring, chart_1..chart_5, success, warning, info`.

- [ ] **Step 1: Write the failing test**

Add to `crates/ui/src/theme.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::config::{BorderRadius, Density, Theme};

    #[test]
    fn sage_dark_palette_tokens() {
        let c = get_theme_colors(Theme::Sage);
        assert_eq!(c.color_scheme, "dark");
        assert_eq!(c.background, "#141715");
        assert_eq!(c.primary, "#9cbfae");
        assert_eq!(c.primary_foreground, "#151a17");
        assert_eq!(c.card, "#242b27");
        assert_eq!(c.foreground, "#e9eeeb");
        assert_eq!(c.accent, "#c9b27e");
    }

    #[test]
    fn sage_light_palette_tokens() {
        let c = get_theme_colors(Theme::SageLight);
        assert_eq!(c.color_scheme, "light");
        assert_eq!(c.background, "#f2f4f1");
        assert_eq!(c.primary, "#5f8f7a");
        assert_eq!(c.primary_foreground, "#ffffff");
        assert_eq!(c.accent, "#a08a4e");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-ui sage_dark_palette_tokens sage_light_palette_tokens`
Expected: FAIL — non-exhaustive match / missing arms (won't compile).

- [ ] **Step 3: Add the two palette functions**

Add near `strike48_theme()` in `crates/ui/src/theme.rs`. Map the spec palettes onto the struct. Chart colors reuse status/brand hues.

```rust
fn sage_theme() -> ThemeColors {
    ThemeColors {
        color_scheme: "dark",
        background: "#141715",               // --bg
        foreground: "#e9eeeb",               // --tx
        card: "#242b27",                     // --surf
        popover: "#242b27",                  // --surf
        primary: "#9cbfae",                  // --pri
        primary_foreground: "#151a17",       // --on-pri
        secondary: "#2c352f",                // --surf2
        secondary_foreground: "#e9eeeb",     // --tx
        muted: "#1b201d",                    // --p1
        muted_foreground: "#a7b2ab",         // --mut
        accent: "#c9b27e",                   // --acc (gold)
        accent_foreground: "#151a17",        // --on-pri
        destructive: "#d99a9a",              // --err
        border: "rgba(255,255,255,0.09)",    // --line
        input: "#242b27",                    // --surf
        ring: "#9cbfae",                     // --pri
        sidebar: "#101312",                  // --p3
        sidebar_foreground: "#e9eeeb",       // --tx
        sidebar_primary: "#9cbfae",          // --pri
        sidebar_primary_foreground: "#151a17", // --on-pri
        sidebar_accent: "#2c352f",           // --surf2
        sidebar_accent_foreground: "#e9eeeb",
        sidebar_border: "rgba(255,255,255,0.09)", // --line
        sidebar_ring: "#9cbfae",
        chart_1: "#9cbfae",                  // --pri
        chart_2: "#8fc4ab",                  // --ok
        chart_3: "#d9b07c",                  // --warn
        chart_4: "#9cb8bf",                  // --info
        chart_5: "#d99a9a",                  // --err
        success: "#8fc4ab",                  // --ok
        warning: "#d9b07c",                  // --warn
        info: "#9cb8bf",                     // --info
    }
}

fn sage_light_theme() -> ThemeColors {
    ThemeColors {
        color_scheme: "light",
        background: "#f2f4f1",
        foreground: "#2a332d",
        card: "#e5eae4",
        popover: "#e5eae4",
        primary: "#5f8f7a",
        primary_foreground: "#ffffff",
        secondary: "#dbe2da",
        secondary_foreground: "#2a332d",
        muted: "#ffffff",
        muted_foreground: "#5e6a62",
        accent: "#a08a4e",
        accent_foreground: "#ffffff",
        destructive: "#b56e6e",
        border: "rgba(30,45,36,0.10)",
        input: "#e5eae4",
        ring: "#5f8f7a",
        sidebar: "#edf0ec",
        sidebar_foreground: "#2a332d",
        sidebar_primary: "#5f8f7a",
        sidebar_primary_foreground: "#ffffff",
        sidebar_accent: "#dbe2da",
        sidebar_accent_foreground: "#2a332d",
        sidebar_border: "rgba(30,45,36,0.10)",
        sidebar_ring: "#5f8f7a",
        chart_1: "#5f8f7a",
        chart_2: "#4f9377",
        chart_3: "#b5834a",
        chart_4: "#5f8f8f",
        chart_5: "#b56e6e",
        success: "#4f9377",
        warning: "#b5834a",
        info: "#5f8f8f",
    }
}
```

Then add the arms to `get_theme_colors`:

```rust
Theme::Sage => sage_theme(),
Theme::SageLight => sage_light_theme(),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-ui sage_dark_palette_tokens sage_light_palette_tokens`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/ui/src/theme.rs
git commit -m "feat(theme): add Sage and SageLight color palettes"
```

---

### Task 3: Sage fonts + Sage-only extra tokens in generate_theme_css

**Files:**
- Modify: `crates/ui/src/theme.rs` (`generate_theme_css` font branch ~line 16; add `sage_extra_tokens_css` helper; append its result)
- Test: `crates/ui/src/theme.rs` tests module

**Interfaces:**
- Consumes: `Theme::Sage`/`SageLight`.
- Produces: `generate_theme_css(Theme::Sage, ..)` contains the IBM Plex import, `--pri`-family extra tokens (`--em`-parity vars for the chrome stylesheet), and returns them ONLY for Sage themes.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn sage_css_has_plex_font_and_extra_tokens() {
    let css = generate_theme_css(Theme::Sage, BorderRadius::Soft, Density::Comfortable);
    assert!(css.contains("IBM+Plex+Sans"), "Sage should import IBM Plex");
    assert!(css.contains("--sage-tint:"), "Sage should emit extra tokens");
    assert!(css.contains("--sage-glass-bg:"));
}

#[test]
fn non_sage_css_has_no_sage_tokens() {
    let css = generate_theme_css(Theme::Dark, BorderRadius::Soft, Density::Comfortable);
    assert!(!css.contains("--sage-tint:"), "non-Sage must not emit Sage tokens");
    assert!(!css.contains("--sage-glass-bg:"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-ui sage_css_has_plex_font_and_extra_tokens non_sage_css_has_no_sage_tokens`
Expected: FAIL — tokens/import absent.

- [ ] **Step 3: Extend the font branch and append extra tokens**

Change the font selector at the top of `generate_theme_css` from `if theme == Theme::Strike48` to include Sage:

```rust
let (font_import, font_sans, font_mono) = if matches!(
    theme,
    Theme::Strike48 | Theme::Sage | Theme::SageLight
) {
    (
        "@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');\n",
        "'IBM Plex Sans', ui-sans-serif, system-ui, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji'",
        "'IBM Plex Mono', ui-monospace, monospace",
    )
} else {
    (
        "",
        "ui-sans-serif, system-ui, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji'",
        "\"Cascadia Code\", \"Fira Code\", \"Consolas\", \"Courier New\", monospace",
    )
};
```

Add a helper (below `generate_theme_css`):

```rust
/// Extra Sage-only CSS custom properties (glass surfaces, gold accent, tints,
/// panel shades, status backgrounds) that the shared ThemeColors struct does
/// not carry. Returns "" for any non-Sage theme so their emitted CSS is
/// unchanged. `sage`-scoped chrome rules (see sage_theme_css) read these.
fn sage_extra_tokens_css(theme: Theme) -> &'static str {
    match theme {
        Theme::Sage => {
            r#"
:root {
    --sage-p1: #1b201d;
    --sage-p3: #101312;
    --sage-surf2: #2c352f;
    --sage-line2: rgba(255,255,255,0.17);
    --sage-dim: #78847d;
    --sage-pri2: #b3d2c3;
    --sage-gold: #c9b27e;
    --sage-tint: rgba(156,191,174,0.16);
    --sage-glass-bg: rgba(255,255,255,0.05);
    --sage-glass-line: rgba(255,255,255,0.09);
    --sage-glass-sh: 0 14px 34px rgba(6,12,9,0.3), inset 0 1px 0 rgba(255,255,255,0.06);
    --sage-ok-bg: rgba(143,196,171,0.14);
    --sage-warn-bg: rgba(217,176,124,0.14);
    --sage-err-bg: rgba(217,154,154,0.14);
    --sage-info-bg: rgba(156,184,191,0.14);
    --sage-grad-a: rgba(156,191,174,0.13);
    --sage-grad-b: rgba(156,191,174,0.08);
}
"#
        }
        Theme::SageLight => {
            r#"
:root {
    --sage-p1: #ffffff;
    --sage-p3: #edf0ec;
    --sage-surf2: #dbe2da;
    --sage-line2: rgba(30,45,36,0.18);
    --sage-dim: #8b968e;
    --sage-pri2: #4e7d69;
    --sage-gold: #a08a4e;
    --sage-tint: rgba(95,143,122,0.14);
    --sage-glass-bg: rgba(255,255,255,0.62);
    --sage-glass-line: rgba(255,255,255,0.75);
    --sage-glass-sh: 0 14px 34px rgba(44,60,50,0.1), inset 0 1px 0 rgba(255,255,255,0.8);
    --sage-ok-bg: rgba(79,147,119,0.14);
    --sage-warn-bg: rgba(181,131,74,0.15);
    --sage-err-bg: rgba(181,110,110,0.15);
    --sage-info-bg: rgba(95,143,143,0.14);
    --sage-grad-a: rgba(156,191,174,0.33);
    --sage-grad-b: rgba(156,191,174,0.2);
}
"#
        }
        _ => "",
    }
}
```

Change the final expression of `generate_theme_css` from `) + BASE_COMPONENT_STYLES` to append both the extra tokens and (Task 4) the chrome stylesheet:

```rust
    ) + BASE_COMPONENT_STYLES
        + sage_extra_tokens_css(theme)
        + sage_theme_css(theme)
```

(NOTE: `sage_theme_css` is added in Task 4. For THIS task, append only `+ sage_extra_tokens_css(theme)`; Task 4 adds the `+ sage_theme_css(theme)` term.)

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-ui sage_css_has_plex_font_and_extra_tokens non_sage_css_has_no_sage_tokens`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/ui/src/theme.rs
git commit -m "feat(theme): emit IBM Plex fonts and Sage-only tokens for Sage themes"
```

---

### Task 4: Sage chrome stylesheet (sage_theme_css) scoped under .sage

**Files:**
- Create: `crates/ui/src/styles/sage.css`
- Modify: `crates/ui/src/theme.rs` (add `sage_theme_css(theme)` returning the stylesheet for Sage themes only, `""` otherwise; append it in `generate_theme_css` per Task 3's note)
- Test: `crates/ui/src/theme.rs` tests module

**Interfaces:**
- Consumes: the `--sage-*` tokens (Task 3) and the standard `--card`/`--border`/`--foreground`/`--primary`/`--radius` tokens.
- Produces: `sage_theme_css(Theme::Sage)` returns the scoped stylesheet; `sage_theme_css(<non-sage>)` returns `""`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn sage_chrome_css_scoped_and_gated() {
    let sage = generate_theme_css(Theme::Sage, BorderRadius::Soft, Density::Comfortable);
    assert!(sage.contains(".sage .sidebar"), "Sage chrome must be present + scoped");
    assert!(sage.contains("border-radius: 999px"), "Sage buttons are pills");
    let dark = generate_theme_css(Theme::Dark, BorderRadius::Soft, Density::Comfortable);
    assert!(!dark.contains(".sage .sidebar"), "non-Sage must not emit chrome rules");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-ui sage_chrome_css_scoped_and_gated`
Expected: FAIL — `.sage .sidebar` absent (and `sage_theme_css` undefined).

- [ ] **Step 3: Create the stylesheet**

Create `crates/ui/src/styles/sage.css`. Every rule is scoped under `.sage`. This restyles shapes/glass/gradient; colors come from tokens the chrome already reads.

```css
/* Sage skin for advanced-mode chrome. Scoped under .sage so no other theme is
   affected. Colors flow from the theme tokens the chrome already reads
   (--card/--border/--foreground/--primary); these rules add Sage shapes, glass
   surfaces, the gradient page background, and the gold accent. */

/* Radial-gradient page background (matches the template .stage). */
.sage .app-layout {
    background:
        radial-gradient(1000px 620px at 78% -12%, var(--sage-grad-a), transparent 60%),
        radial-gradient(800px 560px at -8% 95%, var(--sage-grad-b), transparent 55%),
        var(--background);
}

/* Glass sidebar + header. */
.sage .sidebar {
    background: var(--sage-glass-bg);
    border-right: 1px solid var(--sage-glass-line);
    backdrop-filter: blur(20px);
    /* Opaque fallback if backdrop-filter is unsupported. */
    background-color: var(--sidebar);
}
.sage .desktop-header,
.sage .page-header {
    background: var(--sage-glass-bg);
    border-bottom: 1px solid var(--sage-glass-line);
    backdrop-filter: blur(20px);
}

/* Nav items: rounded, sage tint on hover/active, mint text when active. */
.sage .sidebar-flat-item {
    border-radius: 10px;
}
.sage .sidebar-flat-item:hover {
    background-color: var(--sage-tint);
}
.sage .sidebar-flat-item.active {
    background-color: var(--sage-tint);
    color: var(--sage-pri2);
}

/* Header icon buttons: rounded, tinted hover. */
.sage .desktop-header-btn {
    border-radius: 10px;
}
.sage .desktop-header-btn:hover {
    background-color: var(--sage-tint);
    color: var(--foreground);
}

/* Pill buttons (Material-3). */
.sage .button {
    border-radius: 999px;
    font-family: var(--font-sans);
}
.sage .button[data-style="primary"] {
    background-color: var(--primary);
    color: var(--primary-foreground);
}
.sage .button[data-style="primary"]:hover {
    filter: brightness(1.06);
}

/* Cards: 16px radius, subtle surface. */
.sage .card {
    border-radius: 16px;
    background: var(--card);
    border: 1px solid var(--border);
}

/* Settings cards + rows follow the same rounding. */
.sage .settings-card,
.sage .dashboard-card {
    border-radius: 16px;
}

/* Uppercase mono section labels + status bar, matching the template. */
.sage .status-bar {
    font-family: var(--font-mono);
    color: var(--sage-dim);
}
```

Add `sage_theme_css` to `theme.rs`:

```rust
/// Sage chrome stylesheet, scoped under `.sage`. Restyles the advanced-mode
/// shell (sidebar, header, nav, buttons, cards, status bar) to the Sage design
/// language. Returns "" for non-Sage themes so their CSS is unchanged; the
/// `.sage` scoping is a second guard so the rules cannot leak even if injected.
fn sage_theme_css(theme: Theme) -> &'static str {
    match theme {
        Theme::Sage | Theme::SageLight => include_str!("styles/sage.css"),
        _ => "",
    }
}
```

Ensure `generate_theme_css`'s tail is now `) + BASE_COMPONENT_STYLES + sage_extra_tokens_css(theme) + sage_theme_css(theme)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-ui sage_chrome_css_scoped_and_gated`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/ui/src/styles/sage.css crates/ui/src/theme.rs
git commit -m "feat(theme): add Sage chrome stylesheet scoped under .sage"
```

---

### Task 5: Apply the `sage` root class in both shells

**Files:**
- Modify: `crates/ui/src/connector_app.rs` (the root `div { class: "{container_class}" }` ~line 1071)
- Modify: `crates/ui/src/components/workspace_app.rs` (wrap the top-level rsx content in a root `div` carrying the class; `theme` signal at ~line 289)

**Interfaces:**
- Consumes: the reactive `theme` signal already present in both components; `Theme::Sage`/`SageLight`.
- Produces: DOM root gains the `sage` class exactly when the active theme is Sage/SageLight, so `sage_theme_css` rules apply.

- [ ] **Step 1: connector_app — compute and apply the class**

In `crates/ui/src/connector_app.rs`, just before `let container_class = cfg.container_class;` (~line 1062), the `theme` signal is in scope (declared ~line 394). Replace the container-class usage so it appends `sage` when active:

```rust
let is_sage = matches!(*theme.read(), Theme::Sage | Theme::SageLight);
let root_class = if is_sage {
    format!("{} sage", cfg.container_class)
} else {
    cfg.container_class.to_string()
};
```

Then change the root element from `div { class: "{container_class}",` to `div { class: "{root_class}",`. Remove the now-unused `let container_class = cfg.container_class;` if it is no longer referenced elsewhere (grep first; `platform_name` stays).

Ensure `Theme` is imported in `connector_app.rs` (it uses `pentest_core::config::Theme` already for the theme signal — confirm the `use` path or reference it fully as `pentest_core::config::Theme`).

- [ ] **Step 2: workspace_app — wrap the root and apply the class**

In `crates/ui/src/components/workspace_app.rs`, the top-level `rsx!` (~line 465) currently emits sibling nodes (style, KeyboardShortcuts/EasyModeShell branch, HelpModal, WifiWarningDialog, MatrixRainOverlay) with no single wrapper. The `.sage` class must sit on an ancestor of the whole shell.

Compute the class near the other derived values (after `let combined_css = ...`):

```rust
let is_sage = matches!(*theme.read(), Theme::Sage | Theme::SageLight);
let root_class = if is_sage { "workspace-root sage" } else { "workspace-root" };
```

Wrap the existing shell body in a root `div`. The `<style>` nodes may stay outside the wrapper (they are global), but the app content (the `if easy_mode() {...} else { KeyboardShortcuts {...} }` block and the overlay components) must be INSIDE `div { class: "{root_class}", ... }`. Concretely: keep the two `style { ... }` nodes first, then wrap everything from the `if easy_mode()` branch through `MatrixRainOverlay` in:

```rust
div { class: "{root_class}",
    // ...existing shell + overlays, unchanged...
}
```

Add a minimal layout rule so the wrapper does not disturb sizing — append to `crates/ui/src/styles/sage.css` is wrong (it is Sage-scoped); instead add to an always-present stylesheet the component already injects. Simplest: the wrapper needs `display: contents` so it is layout-transparent when present. Add this ONE rule to `crates/ui/src/components/css/app_layout.css` (always loaded by AppLayout, but AppLayout may not render in easy mode — so instead inject it inline):

Use an inline style on the wrapper to avoid a new global rule:

```rust
div { class: "{root_class}", style: "display: contents;",
    // ...
}
```

`display: contents` makes the wrapper generate no box, so it cannot affect the existing fl/grid layout, while still carrying the `sage` class for descendant selectors. (Descendant combinator `.sage .sidebar` still matches through a `display: contents` ancestor.)

- [ ] **Step 3: Verify compilation + clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: clean (no warnings, no errors).

- [ ] **Step 4: Confirm Theme import in workspace_app**

`workspace_app.rs` already references theme types; confirm `Theme` is in scope (it is used via `settings.peek().theme` and `on_theme_change: move |t: Theme|`). If `matches!(*theme.read(), Theme::Sage | ..)` fails to resolve `Theme`, add `use pentest_core::config::Theme;` (grep existing imports first).

- [ ] **Step 5: Commit**

```bash
git add crates/ui/src/connector_app.rs crates/ui/src/components/workspace_app.rs
git commit -m "feat(theme): apply sage root class in connector and workspace shells"
```

---

### Task 6: Add Sage + SageLight to the Settings theme picker and random list

**Files:**
- Modify: `crates/ui/src/components/settings_page.rs` (the `<select>` onchange match + `option`s ~line 1100-1122; the `all_themes` array ~line 1129-1139)

**Interfaces:**
- Consumes: `Theme::Sage`, `Theme::SageLight`.
- Produces: user-selectable Sage/SageLight in Settings; both included in the random rotation.

- [ ] **Step 1: Add to the onchange match**

In the `match theme_str.as_str()` (~line 1100), add before the `_ =>` arm:

```rust
"Sage" => Theme::Sage,
"SageLight" => Theme::SageLight,
```

- [ ] **Step 2: Add the options**

After `option { value: "Nord", "Nord" }` (~line 1122) add:

```rust
option { value: "Sage", "Sage" }
option { value: "SageLight", "Sage Light" }
```

- [ ] **Step 3: Add to the random-theme array**

In the `let all_themes = [ ... ]` array (~line 1129), append:

```rust
Theme::Sage,
Theme::SageLight,
```

- [ ] **Step 4: Verify compilation + clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/ui/src/components/settings_page.rs
git commit -m "feat(settings): add Sage and SageLight to the theme picker"
```

---

### Task 7: Full-suite verification

**Files:** none (verification only)

- [ ] **Step 1: Full clippy across the desktop+connector feature set**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: clean.

- [ ] **Step 2: Run the theme + config unit tests**

Run: `nix develop --command cargo test -p pentest-core -p pentest-ui`
Expected: all pass, including the Sage tests from Tasks 1-4.

- [ ] **Step 3: Confirm non-Sage output is unchanged**

Run: `nix develop --command cargo test -p pentest-ui non_sage_css_has_no_sage_tokens sage_chrome_css_scoped_and_gated`
Expected: PASS — proves other themes emit no Sage tokens or chrome rules.

- [ ] **Step 4: Commit (if any incidental fixups were needed)**

```bash
git add -A
git commit -m "test(theme): verify Sage skin and non-Sage isolation"
```

(Skip if nothing changed.)

---

## Notes for the implementer

- The chrome CSS (`app_layout.css`, `sidebar.css`, `button.css`, `settings_page.css`) is injected per-component via `style { include_str!(...) }`, rendering AFTER the top-level theme `<style>`. `.sage`-scoped selectors win on specificity (class + descendant) regardless of order — do not rely on injection order.
- `generate_theme_css` is called from THREE places (desktop `apps/desktop/src/main.rs` static `with_custom_head`, mobile `connector_app` reactive `css_block`, liveview `workspace_app` reactive `combined_css`). Appending the Sage CSS inside `generate_theme_css` (Tasks 3-4) covers all three; do NOT inject at the call sites.
- Desktop injects theme CSS once at startup from persisted settings; a live theme switch to Sage on desktop updates the reactive component tree (`sage` class) but the static head CSS was generated for the startup theme. The class toggles correctly; the extra-token/chrome CSS on desktop comes from the startup theme's `generate_theme_css`. If desktop live-switching into Sage shows unstyled chrome, that is a known desktop-only limitation (restart picks it up) — note it, do not block on it. Mobile and liveview are fully reactive.
- `display: contents` on the workspace wrapper keeps layout identical; verify the shell still fills the viewport after wrapping.

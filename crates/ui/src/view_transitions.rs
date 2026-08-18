//! Smooth theme transition CSS

/// CSS that fades the whole app in on first paint.
///
/// Under the liveview/connector transport the initial HTML shell is served
/// bare (no app CSS in `<head>`); the DOM and its `<style>` arrive together
/// over the WebSocket, so for a sub-second window elements render at their
/// intrinsic size before the app rules apply — most visibly the brand "S"
/// badge, which flashes huge on a white background. Starting `body` at
/// `opacity: 0` (via `both` fill) and easing it up hides that unstyled window:
/// content stays invisible until layout settles, then fades in styled.
///
/// This lives in its own `<style>` node whose text never changes, so a theme
/// switch (which re-injects the main CSS) does not re-trigger the fade.
pub fn first_paint_fade_css() -> &'static str {
    r#"
@keyframes pick-first-paint-fade {
    from { opacity: 0; }
    to { opacity: 1; }
}

body {
    animation: pick-first-paint-fade 320ms cubic-bezier(0.4, 0, 0.2, 1) both;
}

@media (prefers-reduced-motion: reduce) {
    body {
        animation-duration: 0.01s;
    }
}
"#
}

/// CSS for smooth theme transitions
/// Uses CSS transitions on CSS custom properties for cross-platform support
pub fn theme_transitions_css() -> &'static str {
    r#"
/* Smooth transitions for theme changes */
:root {
    transition:
        background-color 0.3s cubic-bezier(0.4, 0, 0.2, 1),
        color 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

body,
.card,
.sidebar,
.nav-button,
.button,
.input,
.terminal,
.chat-panel {
    transition:
        background-color 0.3s cubic-bezier(0.4, 0, 0.2, 1),
        color 0.3s cubic-bezier(0.4, 0, 0.2, 1),
        border-color 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

/* Reduce motion for accessibility */
@media (prefers-reduced-motion: reduce) {
    :root,
    body,
    .card,
    .sidebar,
    .nav-button,
    .button,
    .input,
    .terminal,
    .chat-panel {
        transition-duration: 0.01s;
    }
}
"#
}

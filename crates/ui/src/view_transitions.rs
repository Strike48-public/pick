//! Smooth theme transition CSS

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

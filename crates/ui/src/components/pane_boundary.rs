//! `PaneBoundary` — reusable render-panic containment for connector UI regions.
//!
//! Dioxus catches a component's render panic via `catch_unwind` and hands it to
//! the nearest [`ErrorBoundary`]; with no explicit boundary, the *root* boundary
//! renders `"Encountered panic: Any { .. }"` in place of the whole tree, blanking
//! the entire connector pane (issue #288). Wrapping a subtree in `PaneBoundary`
//! contains a render panic to that region: siblings keep rendering, and the user
//! sees a short, readable message plus a Retry affordance instead of a blank pane.
//!
//! Scope: this only catches **render-time** panics. `dioxus-liveview`
//! event-converter panics and event-handler panics run outside the render
//! `catch_unwind` and abort the process (see #130/#191/#224) — a boundary cannot
//! help those. Fix known render panics at the source (e.g. #287); this is the
//! backstop for the unanticipated ones.
//!
//! ## Usage
//!
//! Wrap any subtree that should degrade gracefully instead of blanking its
//! pane. Give each region a short `name` shown in the fallback message:
//!
//! ```ignore
//! PaneBoundary { name: "settings".to_string(),
//!     SettingsPage { /* ... */ }
//! }
//! ```
//!
//! Prefer one boundary per independently-recoverable region (see `AppLayout`
//! for the sidebar/content split). Always-mounted background panes (e.g. the
//! Files/Shell panes in `WorkspaceApp`) should each get their own boundary so a
//! panic in a hidden pane cannot blank the visible page.

use dioxus::prelude::*;

/// Wrap a UI subtree so a render panic inside it degrades to a localized,
/// readable fallback (with Retry) instead of blanking the whole pane.
///
/// `name` is a short human label for the region (e.g. `"sidebar"`,
/// `"page content"`) used in the fallback message.
#[component]
pub fn PaneBoundary(name: String, children: Element) -> Element {
    rsx! {
        ErrorBoundary {
            handle_error: move |errors: ErrorContext| {
                // Owned label for this render of the fallback.
                let region = name.clone();
                rsx! {
                    div {
                        class: "pane-boundary-fallback",
                        role: "alert",
                        // Inline styles: a render panic may have occurred before this
                        // region's stylesheet mounted, so don't depend on external CSS.
                        style: "display:flex;flex-direction:column;gap:0.5rem;align-items:flex-start;\
                                padding:1rem;margin:0.75rem;border:1px solid var(--color-border,#3a3a3a);\
                                border-radius:8px;background:var(--color-surface-2,#1e1e1e);\
                                color:var(--color-text,#e6e6e6);font-size:0.875rem;max-width:32rem;",
                        span {
                            style: "font-weight:600;",
                            "Couldn't load the {region}."
                        }
                        span {
                            style: "opacity:0.8;",
                            "This section hit an unexpected error. The rest of the connector is still usable."
                        }
                        button {
                            class: "pane-boundary-retry",
                            style: "align-self:flex-start;padding:0.35rem 0.85rem;border-radius:6px;\
                                    border:1px solid var(--color-accent,#4f8cff);background:transparent;\
                                    color:var(--color-accent,#4f8cff);cursor:pointer;font-size:0.8125rem;",
                            onclick: move |_| errors.clear_errors(),
                            "Retry"
                        }
                    }
                }
            },
            {children}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dioxus::dioxus_core::NoOpMutations;

    // A component whose render panics on demand — stands in for any component
    // that hits a render-time panic (e.g. the #287 byte-slice) on bad data.
    #[component]
    fn Boom(should_panic: bool) -> Element {
        if should_panic {
            panic!("boom: induced render panic");
        }
        rsx! { div { "boom-ok" } }
    }

    // Sibling that must survive when a wrapped sibling panics.
    #[component]
    fn Sibling() -> Element {
        rsx! { div { "sibling-alive" } }
    }

    // The tree under test: one panicking region wrapped in a PaneBoundary,
    // rendered next to an unwrapped healthy sibling.
    #[component]
    fn Harness() -> Element {
        rsx! {
            PaneBoundary { name: "sidebar".to_string(),
                Boom { should_panic: true }
            }
            Sibling {}
        }
    }

    fn render(app: fn() -> Element) -> String {
        let mut dom = VirtualDom::new(app);
        // catch_unwind inside dioxus-core turns the panic into an Element::Err;
        // rebuild must therefore complete without unwinding out of the VirtualDom.
        dom.rebuild(&mut NoOpMutations);
        // The caught panic routes to the boundary via throw_error -> insert_error
        // -> mark_dirty, which dirties the boundary scope *after* it rendered its
        // children this pass. The fallback appears on the next render tick — the
        // same tick the liveview event loop drives in production. Flush it here.
        dom.render_immediate(&mut NoOpMutations);
        dioxus_ssr::render(&dom)
    }

    #[test]
    fn contains_render_panic_and_keeps_sibling_alive() {
        let html = render(Harness);

        // The panicking region degraded to the readable fallback naming the
        // region. (SSR HTML-escapes the apostrophe in "Couldn't", so match on
        // the region label + the alert role rather than the raw apostrophe.)
        assert!(
            html.contains("load the sidebar") && html.contains(r#"role="alert""#),
            "expected contained fallback, got: {html}"
        );
        assert!(
            html.contains("Retry"),
            "expected a Retry affordance, got: {html}"
        );
        // ...and did NOT surface the raw opaque panic string.
        assert!(
            !html.contains("Any {"),
            "raw panic payload leaked into output: {html}"
        );
        // ...while the sibling subtree still rendered.
        assert!(
            html.contains("sibling-alive"),
            "sibling should survive a contained panic, got: {html}"
        );
    }

    #[test]
    fn renders_children_normally_when_no_panic() {
        #[component]
        fn Ok() -> Element {
            rsx! {
                PaneBoundary { name: "page content".to_string(),
                    Boom { should_panic: false }
                }
            }
        }
        let html = render(Ok);
        assert!(html.contains("boom-ok"), "expected children, got: {html}");
        assert!(
            !html.contains("Couldn't load"),
            "fallback should not show without a panic: {html}"
        );
    }
}

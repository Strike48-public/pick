//! Extension / ViewProvider system for dynamic UI views.
//!
//! This module provides a trait-based plugin system that allows registering
//! custom view providers at runtime.  A `ViewProvider` can supply its own
//! sidebar entry, icon, and rendered content — making it possible for
//! extensions (MCP servers, hub apps, etc.) to inject their own pages into
//! the workspace UI.
//!
//! ## Architecture
//!
//! ```text
//!  ┌──────────────┐
//!  │ ViewRegistry  │  ← Provided via Dioxus context (Signal)
//!  │              │
//!  │  providers:  │
//!  │   [          │
//!  │     BoxedViewProvider("mcp-logs", "MCP Logs", ...),
//!  │     BoxedViewProvider("recon-map", "Recon Map", ...),
//!  │   ]          │
//!  └──────────────┘
//!           │
//!           ▼
//!  ┌──────────────┐     ┌────────────────────┐
//!  │ Sidebar      │────▶│ ExtensionView      │
//!  │  (dynamic    │     │  provider_id="..."  │
//!  │   entries)   │     │  → calls render()   │
//!  └──────────────┘     └────────────────────┘
//! ```
//!
//! ## Usage
//!
//! 1. Implement `ViewProvider` for your extension.
//! 2. Register it via `ViewRegistry::register()`.
//! 3. The sidebar automatically picks up new entries.
//! 4. Use `ExtensionView { provider_id: "my-ext" }` to render it.
//!
//! ## Thread safety
//!
//! `ViewProvider` requires `Send + Sync` because the registry is shared
//! across async tasks and component renders.  The `render()` method returns
//! an `Element` which is constructed on the calling thread.

use std::collections::HashMap;
use std::sync::Arc;

use dioxus::prelude::*;

// ---------------------------------------------------------------------------
// ViewProvider trait
// ---------------------------------------------------------------------------

/// Trait for dynamic view providers that can inject UI into the workspace.
///
/// Implementors supply metadata (id, label, icon) and a `render()` method
/// that produces the Dioxus `Element` for the view's content area.
///
/// ## Example
///
/// ```ignore
/// struct McpLogsView;
///
/// impl ViewProvider for McpLogsView {
///     fn id(&self) -> &str { "mcp-logs" }
///     fn label(&self) -> &str { "MCP Logs" }
///     fn icon(&self) -> Option<&str> { Some(ICON_SCROLL_TEXT) }
///     fn category(&self) -> ViewCategory { ViewCategory::Tool }
///
///     fn render(&self, cx: &ScopeState) -> Element {
///         rsx! {
///             div { class: "main-content",
///                 h1 { "MCP Server Logs" }
///                 // ... log viewer UI
///             }
///         }
///     }
/// }
/// ```
pub trait ViewProvider: Send + Sync {
    /// Unique identifier for this view provider.
    ///
    /// Used as the key in the registry and in URL routes
    /// (e.g. `/ext/mcp-logs`).
    fn id(&self) -> &str;

    /// Human-readable label shown in the sidebar and page header.
    fn label(&self) -> &str;

    /// Optional SVG icon markup (same format as `icons.rs` constants).
    ///
    /// Returns `None` if the provider uses the default extension icon.
    fn icon(&self) -> Option<&str> {
        None
    }

    /// Category for grouping in the sidebar.
    fn category(&self) -> ViewCategory {
        ViewCategory::Extension
    }

    /// Whether this view provider is currently available.
    ///
    /// Extensions can become unavailable when their backing service
    /// disconnects.  Unavailable views are shown greyed-out in the sidebar.
    fn is_available(&self) -> bool {
        true
    }

    /// Render the view's content.
    ///
    /// Called each time the router navigates to this extension's page.
    /// The returned `Element` is placed inside the content area (alongside
    /// the sidebar).
    ///
    /// TODO: In the current scaffolding this returns a static placeholder.
    /// The actual implementation will need access to component scope for
    /// hooks (signals, effects, etc.).  This may require changing the
    /// signature to accept a scope parameter or using a component factory
    /// pattern instead.
    fn render(&self) -> Element;

    /// Optional: render a sidebar widget below the nav item.
    ///
    /// Some extensions may want to show a mini-status or quick-action
    /// widget in the sidebar itself (e.g. a list of connected MCP servers).
    fn render_sidebar_widget(&self) -> Option<Element> {
        None
    }
}

// ---------------------------------------------------------------------------
// ViewCategory
// ---------------------------------------------------------------------------

/// Categories for organizing extension views in the sidebar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewCategory {
    /// Core workspace views (Dashboard, Files, Shell, etc.)
    /// These are registered by the workspace itself, not extensions.
    Core,

    /// Tool-related views (MCP servers, tool results, etc.)
    Tool,

    /// Extension/plugin views (hub apps, custom views).
    Extension,

    /// Administrative views (settings, preferences).
    Admin,
}

impl ViewCategory {
    /// Human-readable label for the category.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Core => "Workspace",
            Self::Tool => "Tools",
            Self::Extension => "Extensions",
            Self::Admin => "Administration",
        }
    }
}

// ---------------------------------------------------------------------------
// ViewRegistry
// ---------------------------------------------------------------------------

/// Registry of dynamic view providers.
///
/// Stored in Dioxus context as `Signal<ViewRegistry>` so that components
/// can reactively update when extensions are added or removed.
///
/// ## Thread safety
///
/// Providers are stored behind `Arc` for cheap cloning.  The registry
/// itself lives in a `Signal` which handles interior mutability.
#[derive(Clone, Default)]
pub struct ViewRegistry {
    /// Registered providers keyed by their ID.
    providers: HashMap<String, Arc<dyn ViewProvider>>,

    /// Insertion order for deterministic sidebar rendering.
    order: Vec<String>,
}

impl ViewRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            order: Vec::new(),
        }
    }

    /// Register a view provider.
    ///
    /// If a provider with the same ID already exists, it is replaced.
    pub fn register(&mut self, provider: impl ViewProvider + 'static) {
        let id = provider.id().to_string();
        let arc = Arc::new(provider);

        if !self.providers.contains_key(&id) {
            self.order.push(id.clone());
        }

        self.providers.insert(id, arc);
    }

    /// Remove a view provider by ID.
    pub fn unregister(&mut self, id: &str) {
        self.providers.remove(id);
        self.order.retain(|k| k != id);
    }

    /// Look up a provider by ID.
    pub fn get(&self, id: &str) -> Option<Arc<dyn ViewProvider>> {
        self.providers.get(id).cloned()
    }

    /// Iterate over all registered providers in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn ViewProvider>> {
        self.order
            .iter()
            .filter_map(move |id| self.providers.get(id))
    }

    /// Get providers filtered by category, in insertion order.
    pub fn by_category(&self, category: ViewCategory) -> Vec<Arc<dyn ViewProvider>> {
        self.iter()
            .filter(|p| p.category() == category)
            .cloned()
            .collect()
    }

    /// Number of registered providers.
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

/// Provide the `ViewRegistry` to the component tree.
///
/// Call once at the top-level (alongside `provide_app_state()`).
pub fn provide_view_registry() -> Signal<ViewRegistry> {
    use_context_provider(|| Signal::new(ViewRegistry::new()))
}

/// Consume the `ViewRegistry` from any child component.
pub fn use_view_registry() -> Signal<ViewRegistry> {
    use_context::<Signal<ViewRegistry>>()
}

// ---------------------------------------------------------------------------
// ExtensionView component
// ---------------------------------------------------------------------------

/// Component that renders a dynamic view from the registry.
///
/// Used by the router to display extension pages:
/// ```ignore
/// #[route("/ext/:provider_id")]
/// ExtensionPage { provider_id: String },
/// ```
///
/// If the provider is not found, shows a "not found" message.
#[component]
pub fn ExtensionView(provider_id: String) -> Element {
    let registry = use_view_registry();
    let registry_read = registry.read();

    match registry_read.get(&provider_id) {
        Some(provider) => {
            if !provider.is_available() {
                rsx! {
                    div { class: "main-content flex-col-full",
                        div { class: "empty-state",
                            h3 { "Extension Unavailable" }
                            p { class: "text-dim-sm",
                                "The \"{provider.label()}\" extension is currently "
                                "unavailable. It may require a service connection."
                            }
                        }
                    }
                }
            } else {
                // Delegate rendering to the provider
                provider.render()
            }
        }
        None => {
            rsx! {
                div { class: "main-content flex-col-full",
                    div { class: "empty-state",
                        h3 { "Extension Not Found" }
                        p { class: "text-dim-sm",
                            "No extension with ID \"{provider_id}\" is registered."
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ExtensionSidebarEntries component
// ---------------------------------------------------------------------------

/// Renders sidebar navigation entries for all registered extensions.
///
/// Intended to be placed inside the `Sidebar` component after the core
/// navigation items.
///
/// ## Example usage in Sidebar
///
/// ```ignore
/// // After ALL_PAGES loop in sidebar.rs:
/// ExtensionSidebarEntries {
///     on_select: move |id: String| {
///         // nav.push(Route::ExtensionPage { provider_id: id });
///     },
///     active_id: None,
/// }
/// ```
#[component]
pub fn ExtensionSidebarEntries(
    /// Callback when an extension entry is clicked.
    on_select: EventHandler<String>,
    /// Currently active extension ID (for highlighting), or None.
    #[props(default)]
    active_id: Option<String>,
) -> Element {
    let registry = use_view_registry();
    let registry_read = registry.read();

    let extensions: Vec<Arc<dyn ViewProvider>> = registry_read.by_category(ViewCategory::Extension);

    let tools: Vec<Arc<dyn ViewProvider>> = registry_read.by_category(ViewCategory::Tool);

    // Don't render anything if no extensions are registered
    if extensions.is_empty() && tools.is_empty() {
        return rsx! {};
    }

    rsx! {
        // Separator
        div {
            style: "margin: 4px 14px; border-top: 1px solid var(--border);",
        }

        // Tool views
        for provider in tools.iter() {
            {
                let id = provider.id().to_string();
                let is_active = active_id.as_deref() == Some(&id);
                let is_available = provider.is_available();
                let class_name = match (is_active, is_available) {
                    (true, _) => "sidebar-nav-item active",
                    (false, true) => "sidebar-nav-item",
                    (false, false) => "sidebar-nav-item disabled",
                };

                rsx! {
                    div {
                        class: "{class_name}",
                        onclick: {
                            let id = id.clone();
                            move |_| {
                                if is_available {
                                    on_select.call(id.clone());
                                }
                            }
                        },
                        if let Some(icon) = provider.icon() {
                            span { class: "sidebar-nav-icon", dangerous_inner_html: icon }
                        }
                        span { class: "sidebar-nav-label", "{provider.label()}" }
                    }
                }
            }
        }

        // Extension views
        for provider in extensions.iter() {
            {
                let id = provider.id().to_string();
                let is_active = active_id.as_deref() == Some(&id);
                let is_available = provider.is_available();
                let class_name = match (is_active, is_available) {
                    (true, _) => "sidebar-nav-item active",
                    (false, true) => "sidebar-nav-item",
                    (false, false) => "sidebar-nav-item disabled",
                };

                rsx! {
                    div {
                        class: "{class_name}",
                        onclick: {
                            let id = id.clone();
                            move |_| {
                                if is_available {
                                    on_select.call(id.clone());
                                }
                            }
                        },
                        if let Some(icon) = provider.icon() {
                            span { class: "sidebar-nav-icon", dangerous_inner_html: icon }
                        }
                        span { class: "sidebar-nav-label", "{provider.label()}" }
                    }
                }
            }
        }
    }
}

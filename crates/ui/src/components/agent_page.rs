//! Agent management pages — list, create, and edit AI agents.
//!
//! This module provides the UI for managing agents used by the chat system.
//! It follows the patterns established in the `strike48/ui` reference codebase:
//!
//! - `AgentsPage`: list view with create button
//! - `AgentDetail`: tabbed form (General, Model, System Prompt, Tools)
//!
//! ## Data flow
//!
//! Agent data is fetched from the server via the chat/Matrix API and stored
//! in `AppState`.  The pages read from and write to `AppState` context.
//!
//! ## Route integration
//!
//! These components are mounted by the router:
//! ```ignore
//! #[route("/agents")]        -> AgentsPage
//! #[route("/agents/:id")]    -> AgentDetail { id }
//! ```

use dioxus::prelude::*;

use super::app_state::use_app_state;
use super::button::{Button, ButtonVariant};
use super::icons::{Settings, Wrench};

// ---------------------------------------------------------------------------
// Agent data types
// ---------------------------------------------------------------------------

// TODO: Move these types to pentest_core::types once the agent API is
// integrated.  For now they live here as UI-layer scaffolding.

/// An AI agent configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Agent {
    /// Unique identifier (server-assigned UUID).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Model identifier (e.g. "claude-sonnet-4-20250514").
    pub model: String,
    /// Custom system prompt.
    pub system_prompt: Option<String>,
    /// Per-agent tool permission overrides.
    pub tool_configs: Vec<AgentToolConfig>,
    /// ISO 8601 creation timestamp.
    pub created_at: Option<String>,
    /// ISO 8601 last-modified timestamp.
    pub updated_at: Option<String>,
}

/// Per-agent tool permission configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentToolConfig {
    /// Tool name (unique identifier).
    pub name: String,
    /// Whether the tool is enabled for this agent.
    pub enabled: bool,
    /// Consent mode: "always", "ask", or "disabled".
    pub consent: String,
    /// Source of the tool (e.g. "mcp:server_name" or "builtin").
    pub source: String,
}

// ---------------------------------------------------------------------------
// Form tabs — mirrors strike48/ui AgentFormTab
// ---------------------------------------------------------------------------

/// Tabs available in the agent create/edit form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AgentFormTab {
    #[default]
    General,
    Model,
    SystemPrompt,
    Tools,
}

impl AgentFormTab {
    /// Human-readable label for this tab.
    pub fn label(&self) -> &'static str {
        match self {
            Self::General => "General",
            Self::Model => "Model",
            Self::SystemPrompt => "System Prompt",
            Self::Tools => "Tools",
        }
    }

    /// All tabs in display order.
    pub fn all() -> &'static [Self] {
        &[Self::General, Self::Model, Self::SystemPrompt, Self::Tools]
    }
}

// ---------------------------------------------------------------------------
// AgentsPage — list all agents
// ---------------------------------------------------------------------------

/// Page listing all AI agents with a "Create Agent" action.
///
/// Accessed via `Route::Agents` (`/agents`).
///
/// ## Layout
/// ```text
/// ┌──────────────────────────────────────┐
/// │  Agents                [+ New Agent] │
/// ├──────────────────────────────────────┤
/// │  ┌─────────────────────────────────┐ │
/// │  │ Agent Name                      │ │
/// │  │ Model: claude-sonnet ...        │ │
/// │  │ Description text ...            │ │
/// │  └─────────────────────────────────┘ │
/// │  ┌─────────────────────────────────┐ │
/// │  │ Another Agent                   │ │
/// │  │ ...                             │ │
/// │  └─────────────────────────────────┘ │
/// │                                      │
/// │  (empty state when no agents)        │
/// └──────────────────────────────────────┘
/// ```
#[component]
pub fn AgentsPage() -> Element {
    let _state = use_app_state();

    // TODO: Load agents from API on mount.
    // let agents: Signal<Vec<Agent>> = use_signal(Vec::new);
    // let loading: Signal<bool> = use_signal(|| true);
    //
    // use_effect(move || {
    //     spawn(async move {
    //         // Fetch agents from server
    //         // agents.set(fetched_agents);
    //         // loading.set(false);
    //     });
    // });

    // Placeholder agent list for scaffolding
    let agents: Vec<Agent> = Vec::new();
    let loading = false;

    rsx! {
        div { class: "main-content flex-col-full",
            // Page header
            div { class: "page-header",
                h1 { class: "page-header-title", "Agents" }
                Button {
                    on_click: move |_| {
                        // TODO: Navigate to agent creation page
                        // nav.push(Route::AgentDetail { id: "new".to_string() });
                        tracing::info!("Create new agent clicked");
                    },
                    "+ New Agent"
                }
            }

            // Agent list
            div { class: "flex-scroll",
                if loading {
                    div { class: "empty-state",
                        div { class: "animate-pulse", "Loading agents..." }
                    }
                } else if agents.is_empty() {
                    // Empty state
                    div { class: "empty-state",
                        div { class: "empty-state-icon",
                            Wrench { size: 24 }
                        }
                        h3 { "No agents configured" }
                        p { class: "text-dim-sm",
                            "Create an agent to customize AI behavior, model selection, "
                            "system prompts, and tool permissions."
                        }
                        Button {
                            on_click: move |_| {
                                // TODO: nav.push(Route::AgentDetail { id: "new".into() });
                                tracing::info!("Create first agent clicked");
                            },
                            "Create Your First Agent"
                        }
                    }
                } else {
                    // Agent cards
                    div { class: "settings-body",
                        for agent in agents.iter() {
                            AgentCard {
                                key: "{agent.id}",
                                agent: agent.clone(),
                                on_click: move |id: String| {
                                    // TODO: nav.push(Route::AgentDetail { id });
                                    tracing::info!("Agent clicked: {id}");
                                },
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AgentCard — individual agent in the list
// ---------------------------------------------------------------------------

/// A card displaying a single agent's summary info.
#[component]
fn AgentCard(agent: Agent, on_click: EventHandler<String>) -> Element {
    let agent_id = agent.id.clone();
    let description = agent
        .description
        .clone()
        .unwrap_or_else(|| "No description".to_string());

    rsx! {
        div {
            class: "settings-card dashboard-card",
            style: "cursor: pointer;",
            onclick: move |_| on_click.call(agent_id.clone()),

            div { class: "settings-card-header",
                h2 { "{agent.name}" }
            }
            div { class: "settings-card-body",
                div { class: "text-dim-xs", "Model: {agent.model}" }
                div { class: "text-dim-sm", "{description}" }
                if let Some(ref updated) = agent.updated_at {
                    div { class: "text-dim-xs", "Updated: {updated}" }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AgentDetail — create/edit form with tabs
// ---------------------------------------------------------------------------

/// Agent create/edit form with a tabbed interface.
///
/// Accessed via `Route::AgentDetail` (`/agents/:id`).
///
/// When `id` is `"new"`, creates a new agent.  Otherwise, loads and edits
/// the agent with the given ID.
///
/// ## Tabs
///
/// | Tab             | Contents                                        |
/// |-----------------|-------------------------------------------------|
/// | **General**     | Name, description                               |
/// | **Model**       | Model selection, temperature, max tokens        |
/// | **System Prompt** | Multi-line system prompt editor               |
/// | **Tools**       | Per-tool enable/disable and consent mode         |
#[component]
pub fn AgentDetail(id: String) -> Element {
    let _state = use_app_state();

    let is_new = id == "new";
    let title = if is_new { "New Agent" } else { "Edit Agent" };

    // Form state
    let mut active_tab = use_signal(|| AgentFormTab::General);
    let name = use_signal(String::new);
    let description = use_signal(String::new);
    let model = use_signal(|| "claude-sonnet-4-20250514".to_string());
    let system_prompt = use_signal(String::new);

    // TODO: Load agent data when editing
    // use_effect(move || {
    //     if !is_new {
    //         spawn(async move {
    //             // Fetch agent by id from API
    //             // Populate form fields
    //         });
    //     }
    // });

    let current_tab = *active_tab.read();

    rsx! {
        div { class: "main-content flex-col-full",
            // Header with back/save buttons
            div { class: "page-header",
                div { style: "display: flex; align-items: center; gap: 12px;",
                    Button {
                        variant: ButtonVariant::Ghost,
                        on_click: move |_| {
                            // TODO: nav.push(Route::Agents {});
                            tracing::info!("Back to agents list");
                        },
                        // Left arrow
                        "\u{2190} Back"
                    }
                    h1 { class: "page-header-title", "{title}" }
                }
                div { style: "display: flex; gap: 8px;",
                    Button {
                        variant: ButtonVariant::Ghost,
                        on_click: move |_| {
                            // TODO: nav.push(Route::Agents {});
                        },
                        "Cancel"
                    }
                    Button {
                        on_click: move |_| {
                            // TODO: Save agent via API
                            tracing::info!(
                                "Save agent: name={}, model={}",
                                name.read(),
                                model.read()
                            );
                        },
                        if is_new { "Create" } else { "Save" }
                    }
                }
            }

            // Tab navigation bar
            div {
                class: "settings-body",
                style: "border-bottom: 1px solid var(--border); padding: 0 16px;",
                div { style: "display: flex; gap: 4px;",
                    for tab in AgentFormTab::all() {
                        {
                            let is_active = current_tab == *tab;
                            let tab_val = *tab;
                            let tab_style = if is_active {
                                "padding: 12px 16px; font-weight: 500; border-bottom: 2px solid var(--primary); color: var(--text-primary);"
                            } else {
                                "padding: 12px 16px; color: var(--text-secondary); border-bottom: 2px solid transparent;"
                            };
                            rsx! {
                                button {
                                    key: "{tab.label()}",
                                    class: if is_active { "tab-btn active" } else { "tab-btn" },
                                    style: tab_style,
                                    onclick: move |_| active_tab.set(tab_val),
                                    "{tab.label()}"
                                }
                            }
                        }
                    }
                }
            }

            // Tab content
            div { class: "flex-scroll",
                div { style: "max-width: 640px; padding: 24px 16px;",
                    match current_tab {
                        AgentFormTab::General => rsx! {
                            GeneralTab {
                                name,
                                description,
                            }
                        },
                        AgentFormTab::Model => rsx! {
                            ModelTab {
                                model,
                            }
                        },
                        AgentFormTab::SystemPrompt => rsx! {
                            SystemPromptTab {
                                system_prompt,
                            }
                        },
                        AgentFormTab::Tools => rsx! {
                            ToolsTab {}
                        },
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tab: General
// ---------------------------------------------------------------------------

/// General settings tab — name and description.
#[component]
fn GeneralTab(name: Signal<String>, description: Signal<String>) -> Element {
    rsx! {
        div { class: "settings-card dashboard-card",
            div { class: "settings-card-header",
                h2 { "General" }
            }
            div { class: "settings-card-body",
                // Name field
                div { class: "setting-row",
                    label { class: "setting-name", "Name" }
                    input {
                        class: "form-input",
                        r#type: "text",
                        placeholder: "My Agent",
                        value: "{name.read()}",
                        oninput: move |e: FormEvent| name.set(e.value()),
                    }
                }

                // Description field
                div { class: "setting-row",
                    label { class: "setting-name", "Description" }
                    textarea {
                        class: "form-input",
                        rows: "3",
                        placeholder: "Describe what this agent does...",
                        value: "{description.read()}",
                        oninput: move |e: FormEvent| description.set(e.value()),
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tab: Model
// ---------------------------------------------------------------------------

/// Model configuration tab — model selection, temperature, etc.
#[component]
fn ModelTab(model: Signal<String>) -> Element {
    // TODO: Fetch available models from server.
    // let models: Vec<ModelInfo> = vec![];

    rsx! {
        div { class: "settings-card dashboard-card",
            div { class: "settings-card-header",
                h2 { "Model Configuration" }
            }
            div { class: "settings-card-body",
                // Model selection
                div { class: "setting-row",
                    label { class: "setting-name", "Model" }
                    // TODO: Replace with a dropdown populated from available models.
                    input {
                        class: "form-input",
                        r#type: "text",
                        placeholder: "claude-sonnet-4-20250514",
                        value: "{model.read()}",
                        oninput: move |e: FormEvent| model.set(e.value()),
                    }
                }

                // TODO: Temperature slider
                div { class: "setting-row",
                    label { class: "setting-name", "Temperature" }
                    div { class: "text-dim-sm",
                        "Temperature control coming soon. Default: 1.0"
                    }
                }

                // TODO: Max tokens
                div { class: "setting-row",
                    label { class: "setting-name", "Max Output Tokens" }
                    div { class: "text-dim-sm",
                        "Token limit control coming soon. Default: model limit"
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tab: System Prompt
// ---------------------------------------------------------------------------

/// System prompt editor tab.
#[component]
fn SystemPromptTab(system_prompt: Signal<String>) -> Element {
    rsx! {
        div { class: "settings-card dashboard-card",
            div { class: "settings-card-header",
                h2 { "System Prompt" }
            }
            div { class: "settings-card-body",
                div { class: "text-dim-sm", style: "margin-bottom: 12px;",
                    "The system prompt is sent at the beginning of every conversation "
                    "with this agent.  Use it to define the agent's personality, "
                    "expertise, and behavioral guidelines."
                }
                textarea {
                    class: "form-input",
                    rows: "12",
                    style: "font-family: monospace; font-size: 13px;",
                    placeholder: "You are a helpful security researcher assistant...",
                    value: "{system_prompt.read()}",
                    oninput: move |e: FormEvent| system_prompt.set(e.value()),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tab: Tools
// ---------------------------------------------------------------------------

/// Tool permissions tab — enable/disable tools and set consent modes.
#[component]
fn ToolsTab() -> Element {
    // TODO: Populate from AppState's available tools (MCP servers, built-in tools).
    // let tool_configs: Signal<Vec<AgentToolConfig>> = use_signal(Vec::new);

    rsx! {
        div { class: "settings-card dashboard-card",
            div { class: "settings-card-header",
                span { class: "settings-card-icon", Settings { size: 16 } }
                h2 { "Tool Permissions" }
            }
            div { class: "settings-card-body",
                div { class: "text-dim-sm", style: "margin-bottom: 12px;",
                    "Control which tools this agent can use and whether it needs "
                    "permission before executing them."
                }

                // TODO: Render tool list with toggle and consent mode selector.
                //
                // For each tool:
                // ┌─────────────────────────────────────────────────────────────┐
                // │ [toggle] tool_name         [always | ask | disabled]   │
                // │          Description of what the tool does             │
                // │          Source: mcp:server_name                       │
                // └─────────────────────────────────────────────────────────────┘
                //
                // Consent modes (cycle on click, matching strike48/ui pattern):
                //   "always"  → tool executes without asking
                //   "ask"     → user must approve each invocation
                //   "disabled"→ tool cannot be used by this agent

                div { class: "empty-state",
                    p { class: "text-dim-sm",
                        "No tools available. Connect an MCP server or enable "
                        "built-in tools to configure permissions."
                    }
                }
            }
        }
    }
}

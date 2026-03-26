//! Quick Action Registry
//!
//! This module provides a registry system for tool-specific quick actions that appear
//! in the UI after tool execution. Actions are context-aware and can parse tool output
//! to provide intelligent follow-up suggestions.

mod actions;
mod providers;
mod types;

pub use actions::register_all_actions;
pub use providers::{ActionProvider, QuickActionProvider};
pub use types::{ActionStyle, QuickAction, TablerIcon};

use std::collections::HashMap;

/// Registry for tool-specific quick actions
pub struct QuickActionRegistry {
    providers: HashMap<String, ActionProvider>,
}

impl QuickActionRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    /// Register a static action provider (simple templates)
    pub fn register_static(&mut self, tool_name: impl Into<String>, templates: Vec<ActionTemplate>) {
        self.providers.insert(
            tool_name.into(),
            ActionProvider::Static(templates),
        );
    }

    /// Register a dynamic action provider (smart, output-parsing)
    pub fn register_dynamic(&mut self, provider: Box<dyn QuickActionProvider>) {
        let tool_name = provider.tool_name().to_string();
        self.providers.insert(tool_name, ActionProvider::Dynamic(provider));
    }

    /// Get actions for a tool based on its result
    pub fn get_actions(&self, tool_name: &str, result_json: &str) -> Vec<QuickAction> {
        match self.providers.get(tool_name) {
            Some(ActionProvider::Static(templates)) => {
                templates.iter().map(|t| t.to_action()).collect()
            }
            Some(ActionProvider::Dynamic(provider)) => provider.provide_actions(result_json),
            None => vec![],
        }
    }

    /// Check if a tool has registered actions
    pub fn has_actions(&self, tool_name: &str) -> bool {
        self.providers.contains_key(tool_name)
    }

    /// Get all registered tool names
    pub fn registered_tools(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for QuickActionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Static action template (no output parsing)
#[derive(Clone)]
pub struct ActionTemplate {
    pub id: String,
    pub label: String,
    pub description: String,
    pub icon: TablerIcon,
    pub style: ActionStyle,
    pub prompt: String,
}

impl ActionTemplate {
    /// Convert template to a concrete action
    pub fn to_action(&self) -> QuickAction {
        QuickAction {
            id: self.id.clone(),
            label: self.label.clone(),
            description: self.description.clone(),
            icon: self.icon.clone(),
            style: self.style,
            prompt: self.prompt.clone(),
        }
    }
}

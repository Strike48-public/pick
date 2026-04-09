//! Action providers (trait and implementations)

use super::types::QuickAction;

/// Trait for dynamic action providers that parse tool output
pub trait QuickActionProvider: Send + Sync {
    /// The tool name this provider handles
    fn tool_name(&self) -> &str;

    /// Generate actions based on tool output JSON
    fn provide_actions(&self, result_json: &str) -> Vec<QuickAction>;
}

/// Action provider variants
pub enum ActionProvider {
    /// Static actions (no parsing)
    Static(Vec<super::ActionTemplate>),
    /// Dynamic actions (parses output)
    Dynamic(Box<dyn QuickActionProvider>),
}

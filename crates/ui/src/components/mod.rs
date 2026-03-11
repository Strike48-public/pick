//! UI Components

pub mod agent_page;
pub mod alert_dialog;
mod app_layout;
pub mod app_state;
pub mod button;
pub mod chat_panel;
mod config_form;
mod connecting_screen;
pub mod context_menu;
mod dashboard;
pub mod extension;
pub mod file_browser;
pub mod help_modal;
pub mod icons;
pub mod keyboard_shortcuts;
pub mod loading_spinner;
mod log_filter_bar;
// router module requires dioxus-router dependency — kept as scaffolding reference
// #[cfg(feature = "liveview")]
// pub mod router;
pub mod scroll_area;
pub mod selectable_list;
mod settings_page;
mod shell;
mod sidebar;
pub mod status_bar;
mod terminal;
pub mod text_input;
pub mod tools_page;
mod wifi_warning_dialog;
#[cfg(feature = "liveview")]
pub mod workspace_app;

pub use agent_page::{AgentDetail, AgentsPage};
pub use alert_dialog::AlertDialog;
pub use app_layout::*;
pub use app_state::{provide_app_state, use_app_state, AppState};
pub use button::{Button, ButtonSize, ButtonVariant};
pub use chat_panel::*;
pub use config_form::*;
pub use connecting_screen::*;
pub use context_menu::{ContextMenu, ContextMenuItem};
pub use dashboard::*;
pub use extension::{
    provide_view_registry, use_view_registry, ExtensionView, ViewCategory, ViewProvider,
    ViewRegistry,
};
pub use file_browser::{FileBrowser, FileBrowserProps};
pub use help_modal::HelpModal;
pub use keyboard_shortcuts::KeyboardShortcuts;
pub use loading_spinner::{LoadingSpinner, SpinnerSize};
pub use log_filter_bar::LogFilterBar;
// #[cfg(feature = "liveview")]
// pub use router::{Route, WorkspaceRouter};
pub use icons::STRIKE48_SIDEBAR_LOGO_SVG;
pub use scroll_area::ScrollArea;
pub use selectable_list::{ListItem, SelectableList};
pub use settings_page::*;
pub use shell::*;
pub use sidebar::*;
pub use status_bar::{ShortcutHint, StatusBar};
pub use terminal::*;
pub use text_input::TextInput;
pub use tools_page::ToolsPage;
pub use wifi_warning_dialog::WifiWarningDialog;
#[cfg(feature = "liveview")]
pub use workspace_app::WorkspaceApp;

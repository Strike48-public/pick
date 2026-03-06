//! Centralized application state provided via Dioxus context.
//!
//! This module replaces the ad-hoc signal-per-field pattern in `WorkspaceApp`
//! with a single `AppState` struct distributed through the component tree via
//! `use_context_provider` / `use_context`.
//!
//! ## Migration guide
//!
//! **Before (workspace_app.rs):**
//! ```ignore
//! let mut sidebar_open = use_signal(|| false);
//! let mut chat_visible = use_signal(|| false);
//! let mut matrix_api_url = use_signal(String::new);
//! // ... 10+ independent signals threaded through props
//! ```
//!
//! **After:**
//! ```ignore
//! // Top-level: provide once
//! let state = provide_app_state();
//!
//! // Any child: consume anywhere
//! let state = use_app_state();
//! state.write().sidebar_open = true;
//! ```
//!
//! ## Design decisions
//!
//! - The state is wrapped in `Signal<AppState>` (not bare `AppState`) so that
//!   writes to individual fields trigger reactivity across the tree.
//! - `AppSettings` from `pentest_core` is stored as a sub-signal so that
//!   settings persistence can be triggered independently of other state changes.
//! - The struct derives `Clone` + `PartialEq` so that Dioxus can diff it.

use crate::download_manager::{get_download_progress, is_blackarch_ready};
use dioxus::prelude::*;
use pentest_core::config::ShellMode;
use pentest_core::settings::{load_settings, save_settings};
use pentest_core::terminal::TerminalLine;

// ---------------------------------------------------------------------------
// AppState
// ---------------------------------------------------------------------------

/// Centralized application state for the workspace UI.
///
/// Access in any component:
/// ```ignore
/// let state = use_app_state();
/// let is_open = state.read().sidebar_open;
/// state.write().sidebar_open = true;
/// ```
#[derive(Clone, PartialEq)]
pub struct AppState {
    // -- Navigation ----------------------------------------------------------
    /// Whether the mobile sidebar drawer is open.
    pub sidebar_open: bool,

    /// Whether the chat overlay panel is visible.
    pub chat_visible: bool,

    // -- Chat credentials (fetched from /auth/refresh) -----------------------
    /// Origin URL for the Matrix/Studio API (e.g. "https://studio.example.com").
    pub matrix_api_url: String,

    /// Access token obtained from the Studio session.
    pub matrix_auth_token: String,

    /// Optional pre-filled message to send when the chat panel opens.
    pub chat_mailbox: Option<String>,

    // -- Settings (persisted via pentest_core) --------------------------------
    /// Current shell execution mode.
    pub shell_mode: ShellMode,

    /// Whether the BlackArch ISO has been downloaded.
    pub blackarch_downloaded: bool,

    /// Active download progress (0.0 .. 1.0), or `None` when idle.
    pub download_progress: Option<f64>,

    /// Error message from the last BlackArch setup attempt, if any.
    pub setup_error: Option<String>,

    // -- Terminal output ------------------------------------------------------
    /// Live terminal output lines (log / command output).
    pub terminal_lines: Vec<TerminalLine>,

    /// Number of terminal lines the user has "seen" (for unread badge).
    pub last_seen_terminal_count: usize,

    // -- Error / status -------------------------------------------------------
    /// Transient error message displayed to the user.
    pub error_message: Option<String>,

    /// Transient status/info message.
    pub status_message: Option<String>,
}

// ---------------------------------------------------------------------------
// Default
// ---------------------------------------------------------------------------

impl Default for AppState {
    fn default() -> Self {
        let settings = load_settings();

        Self {
            // Navigation
            sidebar_open: false,
            chat_visible: false,

            // Chat credentials — populated asynchronously after mount
            matrix_api_url: String::new(),
            matrix_auth_token: String::new(),
            chat_mailbox: None,

            // Settings from disk
            shell_mode: settings.shell_mode,
            blackarch_downloaded: is_blackarch_ready(),
            download_progress: get_download_progress(),
            setup_error: None,

            // Terminal
            terminal_lines: Vec::new(),
            last_seen_terminal_count: 0,

            // Error / status
            error_message: None,
            status_message: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience methods
// ---------------------------------------------------------------------------

impl AppState {
    /// Compute the number of unread terminal lines.
    pub fn unread_log_count(&self) -> usize {
        self.terminal_lines
            .len()
            .saturating_sub(self.last_seen_terminal_count)
    }

    /// Mark all current terminal lines as "seen".
    pub fn mark_logs_read(&mut self) {
        self.last_seen_terminal_count = self.terminal_lines.len();
    }

    /// Open the chat panel, optionally pre-filling a message.
    pub fn open_chat(&mut self, prefill: Option<String>) {
        if let Some(msg) = prefill {
            if !msg.is_empty() {
                self.chat_mailbox = Some(msg);
            }
        }
        self.chat_visible = true;
    }

    /// Close the chat panel.
    pub fn close_chat(&mut self) {
        self.chat_visible = false;
    }

    /// Toggle the chat panel open/closed.
    pub fn toggle_chat(&mut self) {
        self.chat_visible = !self.chat_visible;
    }

    /// Set a transient error message.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.error_message = Some(message.into());
    }

    /// Clear the current error message.
    pub fn clear_error(&mut self) {
        self.error_message = None;
    }

    /// Set a transient status/info message.
    pub fn set_status(&mut self, message: impl Into<String>) {
        self.status_message = Some(message.into());
    }

    /// Clear the current status message.
    pub fn clear_status(&mut self) {
        self.status_message = None;
    }

    /// Update shell mode and persist to disk.
    pub fn set_shell_mode(&mut self, mode: ShellMode) {
        self.shell_mode = mode;
        self.persist_settings();
    }

    /// Persist current settings-related fields to disk.
    fn persist_settings(&self) {
        let mut settings = load_settings();
        settings.shell_mode = self.shell_mode;
        // blackarch_downloaded is derived from filesystem — not persisted in settings
        let _ = save_settings(&settings);
    }

    /// Record a successful BlackArch download and persist.
    pub fn mark_blackarch_downloaded(&mut self) {
        self.blackarch_downloaded = true;
        self.download_progress = None;
        self.persist_settings();
    }

    /// Push a terminal line to the log.
    pub fn push_terminal_line(&mut self, line: TerminalLine) {
        self.terminal_lines.push(line);
    }

    /// Set chat credentials obtained from /auth/refresh.
    pub fn set_chat_credentials(&mut self, api_url: String, auth_token: String) {
        self.matrix_api_url = api_url;
        self.matrix_auth_token = auth_token;
    }
}

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

/// Provide `AppState` to the component tree.
///
/// Call this **once** at the top-level component (e.g. `WorkspaceApp`).
/// Returns the signal so the provider can also read/write it.
///
/// ```ignore
/// #[component]
/// pub fn WorkspaceApp() -> Element {
///     let state = provide_app_state();
///     // ...
/// }
/// ```
pub fn provide_app_state() -> Signal<AppState> {
    use_context_provider(|| Signal::new(AppState::default()))
}

/// Consume `AppState` from any child component.
///
/// Panics at runtime if `provide_app_state()` was not called by an ancestor.
///
/// ```ignore
/// #[component]
/// fn MyWidget() -> Element {
///     let state = use_app_state();
///     let is_open = state.read().sidebar_open;
///     rsx! { div { "sidebar open: {is_open}" } }
/// }
/// ```
pub fn use_app_state() -> Signal<AppState> {
    use_context::<Signal<AppState>>()
}

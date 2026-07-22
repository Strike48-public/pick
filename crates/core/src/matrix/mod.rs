//! Matrix GraphQL client for agent chat integration.
//!
//! Provides a trait-based abstraction (`ChatClient`) so the backend
//! can be swapped without touching UI code.

mod agent_defaults;
mod auth;
pub mod chat_notice;
mod client;
pub mod documents;
pub mod pre_approval;
mod types;

pub use agent_defaults::default_pentest_agent_input;
pub use auth::*;
pub use chat_notice::{build_error_notice, studio_url_from_api, ChatNotice, ChatNoticeKind};
pub use client::MatrixChatClient;
pub use documents::{latest_document, preview_url, DocumentSummary};
pub use pre_approval::{
    clear_staged_ott, pre_approve, stage_ott_for_sdk, staged_ott_path, OttData,
};
pub use types::*;

/// Strip trailing slashes from a URL.
pub(crate) fn normalize_url(url: &str) -> &str {
    url.trim_end_matches('/')
}

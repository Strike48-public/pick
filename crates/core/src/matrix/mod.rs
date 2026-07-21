//! Matrix GraphQL client for agent chat integration.
//!
//! Provides a trait-based abstraction (`ChatClient`) so the backend
//! can be swapped without touching UI code.

mod auth;
mod client;
pub mod documents;
mod types;

pub use auth::*;
pub use client::MatrixChatClient;
pub use documents::{latest_document, DocumentSummary};
pub use types::*;

/// Strip trailing slashes from a URL.
pub(crate) fn normalize_url(url: &str) -> &str {
    url.trim_end_matches('/')
}

//! Workspace file browser served as a Strike48 App behavior.
//!
//! Provides server-rendered HTML pages for browsing the AgentFS workspace
//! directory. All path operations are sandboxed via [`crate::workspace::resolve_path`].

mod fs;
mod render;

#[cfg(test)]
mod tests;

use std::path::Path;

use strike48_connector::{AppManifest, AppPageRequest, AppPageResponse};

use render::{file_browser_css, handle_browse, handle_raw, handle_view, layout};

/// A single entry in a directory listing.
#[derive(Debug)]
pub(crate) struct FileEntry {
    pub name: String,
    /// Path relative to the workspace root.
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: String,
}

/// File content with metadata (bd-32).
#[derive(Debug)]
pub(crate) struct FileContent {
    pub content: String,
    pub size: u64,
    pub modified: String,
    pub line_count: usize,
}

/// Build the [`AppManifest`] that describes this file browser app.
pub fn file_browser_manifest() -> AppManifest {
    AppManifest::new("Workspace Files", "/")
        .description("Browse the connector workspace filesystem")
        .icon("hero-folder-open")
        .routes(&["/", "/browse", "/view", "/raw", "/styles.css"])
}

/// Route an incoming [`AppPageRequest`] to the appropriate handler.
pub fn handle_request(workspace: &Path, request: &AppPageRequest) -> AppPageResponse {
    let path = request.path.as_str();

    match path {
        "/" | "/browse" => {
            let rel_path = request.params.get("path").map(|s| s.as_str()).unwrap_or("");
            handle_browse(workspace, rel_path)
        }
        "/view" => {
            let rel_path = request.params.get("path").map(|s| s.as_str()).unwrap_or("");
            handle_view(workspace, rel_path)
        }
        "/raw" => {
            let rel_path = request.params.get("path").map(|s| s.as_str()).unwrap_or("");
            handle_raw(workspace, rel_path)
        }
        "/styles.css" => AppPageResponse::css(file_browser_css()),
        _ => AppPageResponse::not_found_with(layout(
            "Not Found",
            "",
            "<p class=\"empty\">404 &mdash; Page not found</p>",
        )),
    }
}

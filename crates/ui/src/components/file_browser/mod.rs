//! File Browser Dioxus Components
//!
//! A native Dioxus implementation of the workspace file browser.

mod directory;
mod file_viewer;
mod header;
mod image_viewer;

use directory::DirectoryListing;
use file_viewer::FileViewer;
use header::Header;
use image_viewer::ImageViewer;

use dioxus::prelude::*;
use std::path::Path;

use pentest_core::workspace;

use pentest_core::rendering::{format_size, image_mime_type, syntect_css};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A file or directory entry
#[derive(Clone, Debug, PartialEq)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: String,
}

/// File content with metadata
#[derive(Clone, Debug)]
pub(super) struct FileContent {
    pub content: String,
    pub size: u64,
    pub modified: String,
}

/// Current view state for the file browser
#[derive(Clone, Debug, PartialEq)]
pub(super) enum ViewState {
    /// Directory listing
    Directory { path: String },
    /// File viewer
    File { path: String },
    /// Image viewer
    Image { path: String },
}

impl Default for ViewState {
    fn default() -> Self {
        ViewState::Directory {
            path: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Filesystem operations
// ---------------------------------------------------------------------------

/// List directory contents
pub(super) fn list_directory(
    workspace_path: &Path,
    rel_path: &str,
) -> Result<Vec<FileEntry>, String> {
    let target = if rel_path.is_empty() {
        workspace_path.to_path_buf()
    } else {
        workspace::resolve_path(workspace_path, rel_path)
            .map_err(|e| format!("Access denied: {}", e))?
    };

    if !target.is_dir() {
        return Err("Not a directory".to_string());
    }

    let mut entries: Vec<FileEntry> = std::fs::read_dir(&target)
        .map_err(|e| format!("Cannot read directory: {}", e))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let meta = entry.metadata().ok()?;
            let name = entry.file_name().to_string_lossy().to_string();

            let entry_rel = if rel_path.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", rel_path, name)
            };

            let modified = meta
                .modified()
                .ok()
                .map(|t| {
                    let datetime: chrono::DateTime<chrono::Utc> = t.into();
                    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
                })
                .unwrap_or_else(|| "-".to_string());

            Some(FileEntry {
                name,
                path: entry_rel,
                is_dir: meta.is_dir(),
                size: meta.len(),
                modified,
            })
        })
        .collect();

    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    Ok(entries)
}

/// Read a text file
pub(super) fn read_file(workspace_path: &Path, rel_path: &str) -> Result<FileContent, String> {
    if rel_path.is_empty() {
        return Err("No file path specified".to_string());
    }

    let target = workspace::resolve_path(workspace_path, rel_path)
        .map_err(|e| format!("Access denied: {}", e))?;

    if target.is_dir() {
        return Err("Path is a directory".to_string());
    }

    let meta = std::fs::metadata(&target).map_err(|e| format!("Cannot stat file: {}", e))?;

    const MAX_SIZE: u64 = 1_048_576;
    if meta.len() > MAX_SIZE {
        return Err(format!(
            "File too large ({}) — limit is 1 MB",
            format_size(meta.len())
        ));
    }

    let size = meta.len();
    let modified = meta
        .modified()
        .ok()
        .map(|t| {
            let datetime: chrono::DateTime<chrono::Utc> = t.into();
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        })
        .unwrap_or_else(|| "-".to_string());

    let bytes = std::fs::read(&target).map_err(|e| format!("Cannot read file: {}", e))?;

    if bytes.iter().take(8192).any(|&b| b == 0) {
        return Err("File appears to be binary".to_string());
    }

    let content = String::from_utf8(bytes).map_err(|_| "File is not valid UTF-8".to_string())?;

    Ok(FileContent {
        content,
        size,
        modified,
    })
}

/// Read image bytes
pub(super) fn read_image(
    workspace_path: &Path,
    rel_path: &str,
) -> Result<(Vec<u8>, String, u64, String), String> {
    if rel_path.is_empty() {
        return Err("No file path specified".to_string());
    }

    let target = workspace::resolve_path(workspace_path, rel_path)
        .map_err(|e| format!("Access denied: {}", e))?;

    let meta = std::fs::metadata(&target).map_err(|e| format!("Cannot stat file: {}", e))?;

    const MAX_SIZE: u64 = 10_485_760;
    if meta.len() > MAX_SIZE {
        return Err(format!(
            "Image too large ({}) — limit is 10 MB",
            format_size(meta.len())
        ));
    }

    let mime = image_mime_type(rel_path).ok_or("Unknown image type")?;
    let size = meta.len();
    let modified = meta
        .modified()
        .ok()
        .map(|t| {
            let datetime: chrono::DateTime<chrono::Utc> = t.into();
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        })
        .unwrap_or_else(|| "-".to_string());

    let bytes = std::fs::read(&target).map_err(|e| format!("Cannot read file: {}", e))?;

    Ok((bytes, mime.to_string(), size, modified))
}

// ---------------------------------------------------------------------------
// Utility functions (local helpers only)
// ---------------------------------------------------------------------------

pub(super) fn is_image(path: &str) -> bool {
    image_mime_type(path).is_some()
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

/// Props for the main FileBrowser component
#[derive(Props, Clone, PartialEq)]
pub struct FileBrowserProps {
    /// Path to the workspace directory
    pub workspace_path: String,
    /// Initial path to display (for SSR)
    #[props(default)]
    pub initial_path: Option<String>,
}

/// Main file browser component
#[component]
pub fn FileBrowser(props: FileBrowserProps) -> Element {
    // Use initial_path for SSR or default to root
    let initial_state = props
        .initial_path
        .clone()
        .map(|p| {
            if p == "/" || p.is_empty() {
                ViewState::Directory {
                    path: String::new(),
                }
            } else {
                ViewState::Directory { path: p }
            }
        })
        .unwrap_or_default();

    let mut view_state = use_signal(move || initial_state.clone());
    let workspace = props.workspace_path.clone();

    // Navigation handler
    let mut navigate = move |new_state: ViewState| {
        view_state.set(new_state);
    };

    let current_path = match view_state.read().clone() {
        ViewState::Directory { path } => path,
        ViewState::File { path } => path,
        ViewState::Image { path } => path,
    };

    let is_viewing_file = matches!(
        *view_state.read(),
        ViewState::File { .. } | ViewState::Image { .. }
    );
    let browser_class = if is_viewing_file {
        "file-browser file-browser--viewing"
    } else {
        "file-browser"
    };

    rsx! {
        style { {include_str!("../../styles/file_browser.css")} }
        style { {syntect_css()} }

        div { class: "{browser_class}",
            // Header with breadcrumbs — only in directory view
            if !is_viewing_file {
                Header {
                    current_path: current_path.clone(),
                    on_navigate: move |path: String| {
                        navigate(ViewState::Directory { path });
                    },
                }
            }

            // Main content area
            div { class: "file-browser-content",
                match view_state.read().clone() {
                    ViewState::Directory { path } => rsx! {
                        DirectoryListing {
                            workspace_path: workspace.clone(),
                            rel_path: path,
                            on_navigate: move |entry: FileEntry| {
                                if entry.is_dir {
                                    view_state.set(ViewState::Directory { path: entry.path });
                                } else if is_image(&entry.path) {
                                    view_state.set(ViewState::Image { path: entry.path });
                                } else {
                                    view_state.set(ViewState::File { path: entry.path });
                                }
                            },
                        }
                    },
                    ViewState::File { path } => rsx! {
                        FileViewer {
                            workspace_path: workspace.clone(),
                            rel_path: path.clone(),
                            on_back: move |_| {
                                let parent = path.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_default();
                                view_state.set(ViewState::Directory { path: parent });
                            },
                        }
                    },
                    ViewState::Image { path } => rsx! {
                        ImageViewer {
                            workspace_path: workspace.clone(),
                            rel_path: path.clone(),
                            on_back: move |_| {
                                let parent = path.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_default();
                                view_state.set(ViewState::Directory { path: parent });
                            },
                        }
                    },
                }
            }
        }
    }
}

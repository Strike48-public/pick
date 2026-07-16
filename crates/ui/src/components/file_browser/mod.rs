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

#[cfg(test)]
mod tests {
    //! End-to-end guard for pick#35: a report the agent writes must be visible
    //! to the operator's file browser.
    //!
    //! The orchestrator unit tests prove the *seed path* is deterministic and
    //! flat, but they stop at the string. These tests close the remaining seam
    //! by driving the real production chain — the `write_file` tool executor
    //! that the LLM invokes, then the `list_directory` function the browser UI
    //! calls — against a real filesystem, and asserting the report surfaces
    //! where the operator looks.

    use super::*;
    use pentest_core::orchestrator::{report_relative_path, EngagementInfo};
    use pentest_core::tools::{PentestTool, ToolContext};
    use pentest_tools::WriteFileTool;
    use serde_json::json;

    /// A fixed engagement start so the derived report path is deterministic.
    fn engagement() -> EngagementInfo {
        EngagementInfo {
            target: "10.0.0.0/24".to_string(),
            started_at: "2026-04-17T12:00:00Z".parse().unwrap(),
            completed_at: None,
        }
    }

    #[tokio::test]
    async fn written_report_is_visible_to_the_file_browser() {
        // Arrange: an instance workspace, exactly as create_workspace() lays it
        // out, and the tool context the connector hands the write_file tool.
        let ws = tempfile::tempdir().unwrap();
        let ctx = ToolContext::default().with_workspace(ws.path().to_path_buf());
        let report_path = report_relative_path(&engagement());

        // Act 1: the LLM's write_file call — the real tool executor, real fs.
        let result = WriteFileTool
            .execute(
                json!({ "path": report_path, "content": "# Pentest Report\n\nFindings." }),
                &ctx,
            )
            .await
            .expect("write_file should succeed for the seeded report path");
        assert!(result.success, "write_file reported failure: {result:?}");

        // Act 2: the operator opens the file browser at the workspace root — the
        // real list_directory the UI calls.
        let root = list_directory(ws.path(), "").expect("root listing should succeed");

        // Assert: the report is reachable. pick#35's failure was the report
        // landing somewhere the browser never showed. The report lives under a
        // single `reports/` dir (no per-instance nesting), visible from root.
        let reports_dir = root
            .iter()
            .find(|e| e.name == "reports" && e.is_dir)
            .expect("`reports/` must appear at the workspace root");

        let inside =
            list_directory(ws.path(), &reports_dir.path).expect("listing reports/ should succeed");
        let report = inside
            .iter()
            .find(|e| e.name.starts_with("pentest-report-") && e.name.ends_with(".md"))
            .expect("the generated report must be listed inside reports/");
        assert!(!report.is_dir, "report should be a file, not a directory");

        // And the browser can actually open it (read path agrees with write).
        let content = read_file(ws.path(), &report.path).expect("browser should read the report");
        assert!(content.content.contains("Pentest Report"));
    }

    #[tokio::test]
    async fn report_is_not_buried_under_a_per_instance_subdir() {
        // pick#35 defect #2: the old prompt produced reports/<instance_id>/...,
        // two levels below where the browser opens. Guard that the current path
        // keeps `reports/` one level deep with the file directly inside it.
        let ws = tempfile::tempdir().unwrap();
        let ctx = ToolContext::default().with_workspace(ws.path().to_path_buf());
        let report_path = report_relative_path(&engagement());

        WriteFileTool
            .execute(json!({ "path": report_path, "content": "x" }), &ctx)
            .await
            .expect("write_file should succeed");

        let inside = list_directory(ws.path(), "reports").expect("reports/ should exist");
        // Every entry directly under reports/ is the report file itself — no
        // intermediate <instance_id> directory.
        assert!(
            inside.iter().all(|e| !e.is_dir),
            "reports/ must contain the report directly, not a nested subdir: {inside:?}"
        );
    }
}

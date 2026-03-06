//! Filesystem operations (sandboxed) for the file browser.

use std::path::Path;

use crate::error::Error;
use crate::rendering::{format_size, format_system_time};

use super::{FileContent, FileEntry};

/// List directory contents, sorted with directories first then by name.
pub(super) fn list_directory(
    workspace: &Path,
    rel_path: &str,
) -> crate::error::Result<Vec<FileEntry>> {
    let target = if rel_path.is_empty() {
        workspace.to_path_buf()
    } else {
        crate::workspace::resolve_path(workspace, rel_path)
            .map_err(|e| Error::FileBrowser(format!("Access denied: {}", e)))?
    };

    if !target.is_dir() {
        return Err(Error::FileBrowser("Not a directory".into()));
    }

    let mut entries: Vec<FileEntry> = std::fs::read_dir(&target)
        .map_err(|e| Error::FileBrowser(format!("Cannot read directory: {}", e)))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let meta = entry.metadata().ok()?;
            let name = entry.file_name().to_string_lossy().to_string();

            // Build relative path from workspace root
            let entry_rel = if rel_path.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", rel_path, name)
            };

            let modified = meta
                .modified()
                .ok()
                .map(format_system_time)
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

    // Sort: directories first, then alphabetical by name
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    Ok(entries)
}

/// Read a text file from the workspace. Rejects files larger than 1 MB.
/// Returns `FileContent` with metadata (bd-32).
pub(super) fn read_file(workspace: &Path, rel_path: &str) -> crate::error::Result<FileContent> {
    if rel_path.is_empty() {
        return Err(Error::FileBrowser("No file path specified".into()));
    }

    let target = crate::workspace::resolve_path(workspace, rel_path)
        .map_err(|e| Error::FileBrowser(format!("Access denied: {}", e)))?;

    if target.is_dir() {
        return Err(Error::FileBrowser("Path is a directory, not a file".into()));
    }

    let meta = std::fs::metadata(&target)
        .map_err(|e| Error::FileBrowser(format!("Cannot stat file: {}", e)))?;

    const MAX_SIZE: u64 = 1_048_576; // 1 MB
    if meta.len() > MAX_SIZE {
        return Err(Error::FileBrowser(format!(
            "File too large ({}) — limit is 1 MB",
            format_size(meta.len())
        )));
    }

    let size = meta.len();
    let modified = meta
        .modified()
        .ok()
        .map(format_system_time)
        .unwrap_or_else(|| "-".to_string());

    let bytes = std::fs::read(&target)
        .map_err(|e| Error::FileBrowser(format!("Cannot read file: {}", e)))?;

    // Reject likely-binary content
    if bytes.iter().take(8192).any(|&b| b == 0) {
        return Err(Error::FileBrowser("File appears to be binary".into()));
    }

    let content = String::from_utf8(bytes)
        .map_err(|_| Error::FileBrowser("File is not valid UTF-8 text".into()))?;
    let line_count = content.lines().count();

    Ok(FileContent {
        content,
        size,
        modified,
        line_count,
    })
}

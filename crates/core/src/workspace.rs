//! Workspace lifecycle management and path sandboxing
//!
//! Each connected instance gets a managed workspace directory under
//! `~/.local/share/pentest-connector/workspaces/<instance_id>/`.
//! Paths are sandboxed to prevent directory traversal attacks.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

/// Get the root directory for all workspaces.
pub fn workspace_root() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pentest-connector")
        .join("workspaces")
}

/// Sanitize an instance ID to be safe for use as a directory name.
pub fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Create a workspace directory for the given instance ID.
/// Returns the canonicalized path to the workspace.
pub fn create_workspace(instance_id: &str) -> Result<PathBuf> {
    let safe_id = sanitize_id(instance_id);
    let workspace = workspace_root().join(&safe_id);
    std::fs::create_dir_all(&workspace)?;
    let canonical = workspace.canonicalize()?;
    Ok(canonical)
}

/// Remove the workspace directory for the given instance ID.
pub fn cleanup_workspace(instance_id: &str) {
    let safe_id = sanitize_id(instance_id);
    let workspace = workspace_root().join(&safe_id);
    if workspace.exists() {
        let _ = std::fs::remove_dir_all(&workspace);
    }
}

/// Resolve a user-provided path against the workspace directory.
///
/// Returns the canonicalized path if it is within the workspace.
/// Rejects directory traversal attempts (`../`, symlink escapes, absolute paths
/// outside the workspace).
pub fn resolve_path(workspace: &Path, user_path: &str) -> Result<PathBuf> {
    let workspace = workspace
        .canonicalize()
        .map_err(|e| Error::PermissionDenied(format!("Workspace does not exist: {}", e)))?;

    let joined = workspace.join(user_path);

    // For paths that exist, canonicalize and verify prefix
    if joined.exists() {
        let canonical = joined.canonicalize()?;
        if canonical.starts_with(&workspace) {
            return Ok(canonical);
        }
        return Err(Error::PermissionDenied(
            "Path escapes workspace boundary".to_string(),
        ));
    }

    // For paths that don't exist yet (e.g. write_file target),
    // canonicalize the longest existing ancestor then re-attach the remainder.
    safe_canonicalize(&workspace, &joined)
}

/// Canonicalize a path that may not fully exist yet.
///
/// Walks up from `target` until an existing ancestor is found, canonicalizes
/// that ancestor, re-appends the remaining components, and verifies the result
/// is still under `workspace`.
fn safe_canonicalize(workspace: &Path, target: &Path) -> Result<PathBuf> {
    let mut existing = target.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();

    while !existing.exists() {
        match existing.file_name() {
            Some(name) => {
                tail.push(name.to_os_string());
                existing.pop();
            }
            None => break,
        }
    }

    let mut canonical = existing.canonicalize()?;
    for component in tail.into_iter().rev() {
        // Reject path components that are traversal attempts
        let s = component.to_string_lossy();
        if s == ".." || s == "." {
            return Err(Error::PermissionDenied(
                "Path contains traversal components".to_string(),
            ));
        }
        canonical.push(component);
    }

    if canonical.starts_with(workspace) {
        Ok(canonical)
    } else {
        Err(Error::PermissionDenied(
            "Path escapes workspace boundary".to_string(),
        ))
    }
}

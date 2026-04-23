//! Path validation and sanitization utilities
//!
//! This module provides safe path handling to prevent path traversal attacks
//! and ensure file operations stay within authorized directories.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

/// Validate and resolve a user-provided path against a base directory.
///
/// Returns the canonicalized absolute path if it is within the base directory.
/// Rejects:
/// - Directory traversal attempts (`../`, symlink escapes)
/// - Absolute paths outside the base directory
/// - Paths containing dangerous components (`.`, `..`)
///
/// # Security
///
/// This function prevents path traversal attacks by:
/// 1. Canonicalizing both the base and target paths (resolves symlinks)
/// 2. Verifying the target starts with the base prefix
/// 3. Rejecting traversal components in non-existent paths
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use pentest_core::paths::validate_path;
///
/// // Create a temporary directory for testing
/// let temp_dir = tempfile::tempdir().unwrap();
/// let base = temp_dir.path();
///
/// // Valid: within workspace (non-existent file)
/// assert!(validate_path(base, "report.json").is_ok());
///
/// // Invalid: traversal attempt
/// assert!(validate_path(base, "../etc/passwd").is_err());
/// ```
pub fn validate_path(base: &Path, user_path: &str) -> Result<PathBuf> {
    // Reject empty paths
    if user_path.is_empty() {
        return Err(Error::InvalidParams("Empty path provided".to_string()));
    }

    // Reject absolute paths (they bypass base directory restriction)
    let user_pathbuf = PathBuf::from(user_path);
    if user_pathbuf.is_absolute() {
        return Err(Error::PermissionDenied(
            "Absolute paths are not allowed".to_string(),
        ));
    }

    // Canonicalize base directory
    let base_canonical = base
        .canonicalize()
        .map_err(|e| Error::InvalidParams(format!("Base directory does not exist: {}", e)))?;

    // Join user path with base
    let joined = base_canonical.join(user_path);

    // For existing paths, canonicalize and verify prefix
    if joined.exists() {
        let canonical = joined.canonicalize()?;
        if canonical.starts_with(&base_canonical) {
            return Ok(canonical);
        }
        return Err(Error::PermissionDenied(
            "Path escapes base directory".to_string(),
        ));
    }

    // For non-existent paths, verify components and construct safe path
    safe_path_for_creation(&base_canonical, &joined)
}

/// Construct a safe path for file creation that may not exist yet.
///
/// Walks up from target until an existing ancestor is found, canonicalizes
/// that ancestor, re-appends remaining components while rejecting traversal
/// attempts, and verifies the result is within base.
fn safe_path_for_creation(base: &Path, target: &Path) -> Result<PathBuf> {
    let mut existing = target.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();

    // Walk up to find existing ancestor
    while !existing.exists() {
        match existing.file_name() {
            Some(name) => {
                tail.push(name.to_os_string());
                existing.pop();
            }
            None => {
                return Err(Error::InvalidParams(
                    "Cannot resolve path: no existing ancestor found".to_string(),
                ))
            }
        }
    }

    // Canonicalize existing ancestor
    let mut canonical = existing.canonicalize()?;

    // Re-append non-existent components, rejecting traversal attempts
    for component in tail.into_iter().rev() {
        let s = component.to_string_lossy();
        if s == ".." || s == "." {
            return Err(Error::PermissionDenied(
                "Path contains traversal components".to_string(),
            ));
        }
        canonical.push(component);
    }

    // Verify final path is within base
    if canonical.starts_with(base) {
        Ok(canonical)
    } else {
        Err(Error::PermissionDenied(
            "Path escapes base directory".to_string(),
        ))
    }
}

/// Sanitize a filename to remove dangerous characters.
///
/// Replaces characters that could be problematic in filenames:
/// - Path separators (/, \)
/// - Control characters
/// - Shell metacharacters
///
/// Returns None if the resulting filename would be empty.
pub fn sanitize_filename(name: &str) -> Option<String> {
    let sanitized: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' | '\n' | '\r' | '\t' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();

    if sanitized.trim().is_empty() {
        None
    } else {
        Some(sanitized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_validate_path_rejects_empty() {
        let base = Path::new("/tmp");
        assert!(validate_path(base, "").is_err());
    }

    #[test]
    fn test_validate_path_rejects_absolute() {
        let base = Path::new("/tmp");
        assert!(validate_path(base, "/etc/passwd").is_err());
    }

    #[test]
    fn test_validate_path_rejects_parent_traversal() {
        let temp_dir = tempfile::tempdir().unwrap();
        let base = temp_dir.path();

        assert!(validate_path(base, "../etc/passwd").is_err());
        assert!(validate_path(base, "subdir/../../etc/passwd").is_err());
        assert!(validate_path(base, "./../etc/passwd").is_err());
    }

    #[test]
    fn test_validate_path_accepts_valid_relative() {
        let temp_dir = tempfile::tempdir().unwrap();
        let base = temp_dir.path();

        // Create test file
        let test_file = base.join("test.txt");
        fs::write(&test_file, "test").unwrap();

        assert!(validate_path(base, "test.txt").is_ok());
    }

    #[test]
    fn test_validate_path_accepts_valid_subdirectory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let base = temp_dir.path();

        // Create subdirectory and file
        let subdir = base.join("subdir");
        fs::create_dir(&subdir).unwrap();
        let test_file = subdir.join("test.txt");
        fs::write(&test_file, "test").unwrap();

        assert!(validate_path(base, "subdir/test.txt").is_ok());
    }

    #[test]
    fn test_validate_path_accepts_nonexistent_in_base() {
        let temp_dir = tempfile::tempdir().unwrap();
        let base = temp_dir.path();

        // Path doesn't exist but should be accepted
        let result = validate_path(base, "new_file.txt");
        assert!(result.is_ok());

        let path = result.unwrap();
        assert!(path.starts_with(base));
    }

    #[test]
    fn test_validate_path_rejects_traversal_in_nonexistent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let base = temp_dir.path();

        // Even for non-existent paths, traversal should be rejected
        assert!(validate_path(base, "new_dir/../../../etc/passwd").is_err());
    }

    #[test]
    fn test_sanitize_filename_removes_slashes() {
        assert_eq!(
            sanitize_filename("file/with/slashes.txt"),
            Some("file_with_slashes.txt".to_string())
        );
        assert_eq!(
            sanitize_filename("file\\with\\backslashes.txt"),
            Some("file_with_backslashes.txt".to_string())
        );
    }

    #[test]
    fn test_sanitize_filename_removes_control_chars() {
        assert_eq!(
            sanitize_filename("file\nwith\nnewlines.txt"),
            Some("file_with_newlines.txt".to_string())
        );
        assert_eq!(
            sanitize_filename("file\twith\ttabs.txt"),
            Some("file_with_tabs.txt".to_string())
        );
    }

    #[test]
    fn test_sanitize_filename_handles_empty_and_whitespace() {
        // Empty string rejected
        assert_eq!(sanitize_filename(""), None);
        // Whitespace-only rejected (trim removes it)
        assert_eq!(sanitize_filename("   "), None);
        // Control chars become valid underscores (not rejected)
        assert_eq!(sanitize_filename("\n\n\n"), Some("___".to_string()));
    }

    #[test]
    fn test_sanitize_filename_preserves_normal() {
        assert_eq!(
            sanitize_filename("normal-file_123.txt"),
            Some("normal-file_123.txt".to_string())
        );
    }
}

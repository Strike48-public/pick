//! Theme directory management and custom theme discovery

use std::fs;
use std::path::PathBuf;

use crate::error::{Error, Result};

/// Get the user's custom themes directory
pub fn get_themes_dir() -> Result<PathBuf> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| Error::Config("Could not determine config directory".to_string()))?;

    let themes_dir = config_dir.join("pentest-connector").join("themes");

    // Create directory if it doesn't exist
    if !themes_dir.exists() {
        fs::create_dir_all(&themes_dir).map_err(|e| {
            Error::Config(format!("Failed to create themes directory: {}", e))
        })?;
    }

    Ok(themes_dir)
}

/// Discovered custom theme file
#[derive(Debug, Clone)]
pub struct DiscoveredTheme {
    pub file_name: String,
    pub file_path: PathBuf,
}

/// Scan the themes directory for .css files
pub fn discover_custom_themes() -> Result<Vec<DiscoveredTheme>> {
    let themes_dir = get_themes_dir()?;

    let mut themes = Vec::new();

    if !themes_dir.exists() {
        return Ok(themes);
    }

    let entries = fs::read_dir(&themes_dir).map_err(|e| {
        Error::Config(format!("Failed to read themes directory: {}", e))
    })?;

    for entry in entries.flatten() {
        let path = entry.path();

        // Only include .css files
        if path.extension().and_then(|s| s.to_str()) == Some("css") {
            if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                themes.push(DiscoveredTheme {
                    file_name: file_name.to_string(),
                    file_path: path,
                });
            }
        }
    }

    // Sort by file name for consistent ordering
    themes.sort_by(|a, b| a.file_name.cmp(&b.file_name));

    Ok(themes)
}

/// Load a custom theme file's content
pub fn load_theme_file(path: &PathBuf) -> Result<String> {
    fs::read_to_string(path).map_err(|e| {
        Error::Config(format!("Failed to read theme file: {}", e))
    })
}

/// Import a theme file from an external path to the user's themes directory
///
/// This function:
/// 1. Validates the source file exists and is readable
/// 2. Extracts the filename
/// 3. Copies the file to ~/.config/pentest-connector/themes/
/// 4. Returns the new path
pub fn import_theme_file(source_path: &str) -> Result<PathBuf> {
    let source = PathBuf::from(source_path);

    // Security: Canonicalize path to prevent path traversal
    let source = source.canonicalize().map_err(|_| {
        Error::Config("Invalid theme file path".to_string())
    })?;

    // Validate it's a file (not a directory)
    if !source.is_file() {
        return Err(Error::Config(
            "Path must be a file".to_string(),
        ));
    }

    // Validate .css extension
    if source.extension().and_then(|s| s.to_str()) != Some("css") {
        return Err(Error::Config(
            "Theme file must have .css extension".to_string(),
        ));
    }

    // Security: Limit file size to prevent DoS (100KB max)
    let metadata = fs::metadata(&source).map_err(|_| {
        Error::Config("Cannot read theme file".to_string())
    })?;

    if metadata.len() > 100 * 1024 {
        return Err(Error::Config(
            "Theme file too large (max 100KB)".to_string(),
        ));
    }

    // Get filename
    let file_name = source
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| Error::Config("Invalid file name".to_string()))?;

    // Get destination directory
    let themes_dir = get_themes_dir()?;
    let dest_path = themes_dir.join(file_name);

    // Check if file already exists
    if dest_path.exists() {
        return Err(Error::Config(format!(
            "Theme '{}' already exists. Please rename the file or delete the existing theme.",
            file_name
        )));
    }

    // Copy file to themes directory
    fs::copy(&source, &dest_path).map_err(|e| {
        Error::Config(format!("Failed to copy theme file: {}", e))
    })?;

    tracing::info!("Imported theme: {} -> {:?}", source_path, dest_path);

    Ok(dest_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_themes_dir() {
        let dir = get_themes_dir().unwrap();
        assert!(dir.ends_with("pentest-connector/themes"));
    }

    #[test]
    fn test_discover_custom_themes() {
        // Should not error even if directory is empty
        let result = discover_custom_themes();
        assert!(result.is_ok());
    }
}

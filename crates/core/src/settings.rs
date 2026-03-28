//! Settings persistence — load/save AppSettings to disk

use crate::config::AppSettings;
use std::fs;
use std::path::PathBuf;

/// Returns the settings directory, creating it if needed.
/// Uses platform-appropriate config dir (e.g. ~/.config/pentest-connector/ on Linux).
/// On Android, uses $HOME/.config/pentest-connector/ since dirs::config_dir() returns None.
pub fn settings_dir() -> PathBuf {
    let dir = dirs::config_dir()
        .or_else(|| {
            // Android fallback: use $HOME/.config/ if dirs::config_dir() returns None
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".config"))
        })
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pentest-connector");
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Returns the path to the settings JSON file.
pub fn settings_path() -> PathBuf {
    settings_dir().join("settings.json")
}

/// Load settings from disk. Returns defaults on any error (missing file, corrupt JSON, etc.).
/// Automatically validates and clears expired JWT tokens.
pub fn load_settings() -> AppSettings {
    let path = settings_path();
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let mut settings: AppSettings = serde_json::from_str(&contents).unwrap_or_default();

            // Validate and clear expired auth token
            if let Some(last_config) = &mut settings.last_config {
                if let Some(validated) = crate::jwt_validator::validate_token(&last_config.auth_token) {
                    last_config.auth_token = validated;
                } else {
                    // Token is expired or invalid, clear it
                    tracing::info!("Cleared expired/invalid auth token from settings");
                    last_config.auth_token.clear();

                    // Save the updated settings to persist the change
                    if let Err(e) = save_settings(&settings) {
                        tracing::warn!("Failed to save settings after clearing expired token: {}", e);
                    }
                }
            }

            settings
        }
        Err(_) => AppSettings::default(),
    }
}

/// Save settings to disk. Uses atomic write (tmp + rename) to prevent corruption.
pub fn save_settings(settings: &AppSettings) -> anyhow::Result<()> {
    let path = settings_path();
    let tmp_path = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(settings)?;
    fs::write(&tmp_path, json)?;
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

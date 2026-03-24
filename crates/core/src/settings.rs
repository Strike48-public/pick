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
pub fn load_settings() -> AppSettings {
    let path = settings_path();
    let mut settings = match fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => AppSettings::default(),
    };

    // On Android, default to wlan0 if no adapter is explicitly configured.
    // Android always has a built-in WiFi adapter and cellular fallback.
    #[cfg(target_os = "android")]
    if settings.wifi_adapter.is_none() {
        settings.wifi_adapter = Some("wlan0".to_string());
    }

    settings
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

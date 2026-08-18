//! Desktop clipboard via the OS-native clipboard (`arboard`).
//!
//! Registered with `pentest_core::clipboard` at desktop startup so "Copy link"
//! works on Windows, where the WebView2 renderer does not expose
//! `navigator.clipboard` from Dioxus's custom protocol origin. macOS/Linux also
//! route through here for a single, reliable native path.

/// Copy `text` to the OS clipboard. Returns the backend's error message as a
/// `String` so the caller can fall back to the JS clipboard path.
pub fn copy_text(text: &str) -> Result<(), String> {
    // A fresh Clipboard per call keeps this stateless and thread-safe. On X11
    // the clipboard contents live only as long as the owning connection, but
    // arboard hands ownership to the OS/session clipboard manager on drop, so a
    // short-lived instance is fine for set_text on all desktop platforms.
    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    clipboard
        .set_text(text.to_owned())
        .map_err(|e| e.to_string())
}

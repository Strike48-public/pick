import Foundation

/// Persists non-secret user settings (feature flags) across launches via
/// UserDefaults. Unlike the auth token (Keychain), these values aren't
/// sensitive. The core is the runtime source of truth; this seeds it at startup
/// and records the user's choices.
enum SettingsStore {
    private static let telemetryKey = "telemetry_enabled"

    /// Telemetry opt-out flag. Defaults to true (on) to match the core default
    /// when nothing has been persisted yet.
    static var telemetryEnabled: Bool {
        get {
            if UserDefaults.standard.object(forKey: telemetryKey) == nil {
                return true // opt-out: on until the user turns it off
            }
            return UserDefaults.standard.bool(forKey: telemetryKey)
        }
        set { UserDefaults.standard.set(newValue, forKey: telemetryKey) }
    }
}

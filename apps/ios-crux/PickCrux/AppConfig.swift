import Foundation

/// Build-time app configuration read from Info.plist (values substituted from
/// build settings, which come from the build env). Nothing is hardcoded in
/// source except the dev-cluster fallback used when no value was injected.
enum AppConfig {
    /// Strike48 PLG host, e.g. "https://plg.strike48.test". Comes from the
    /// STRIKE48_HOST build setting -> Info.plist `Strike48Host`. Falls back to
    /// the dev PLG cluster when empty or left as the unsubstituted placeholder.
    static var strike48Host: String {
        let raw = Bundle.main.infoDictionary?["Strike48Host"] as? String
        if let h = raw, !h.isEmpty, !h.hasPrefix("$(") {
            return h.trimmingCharacters(in: .whitespaces)
        }
        return "https://plg.strike48.test"
    }

    /// The OAuth login URL for the configured host, with our custom-scheme
    /// callback. `redirect` returns the token to `com.strike48.pentest://oauth/callback`.
    static var authURL: String {
        "\(strike48Host)/auth/login?redirect=com.strike48.pentest://oauth/callback"
    }
}

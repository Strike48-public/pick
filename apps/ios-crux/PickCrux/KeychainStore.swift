import Foundation
import Security

/// Persists the workspace-scoped Studio session token in the iOS Keychain so a
/// relaunch can skip the browser sign-in, mirroring what the Dioxus app does
/// via `pentest_core::secure_store` (Keychain on iOS / Keystore on Android).
///
/// The token is a bearer credential and must never sit in plaintext
/// UserDefaults; the Keychain is the OS secure store. Note the underlying
/// Studio session token is short-lived, so restore still falls back to sign-in
/// once it expires (see `isTokenExpired`) — same limitation the Dioxus app has.
enum KeychainStore {
    private static let service = "com.strike48.pickcrux"
    private static let account = "matrix_auth_token"

    /// Save (or overwrite) the token. Silently no-ops on failure — a failed
    /// persist just means the next launch re-signs-in, never a plaintext leak.
    static func save(_ token: String) {
        guard let data = token.data(using: .utf8) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        // Replace any existing item.
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        SecItemAdd(add as CFDictionary, nil)
    }

    /// Load the token, or nil if none is stored.
    static func load() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let token = String(data: data, encoding: .utf8),
              !token.isEmpty else {
            return nil
        }
        return token
    }

    /// Delete the stored token (sign-out).
    static func clear() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Best-effort JWT-expiry check so we don't seed the core with a dead token
    /// on startup (matches the Dioxus `restore_matrix_token` expiry guard).
    /// Returns true if the token is a JWT whose `exp` is in the past. Tokens we
    /// can't parse are treated as NOT expired — let the backend reject them.
    static func isTokenExpired(_ token: String) -> Bool {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else { return false }
        guard let payload = base64UrlDecode(String(parts[1])),
              let obj = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let exp = obj["exp"] as? Double else {
            return false
        }
        return Date().timeIntervalSince1970 >= exp
    }

    private static func base64UrlDecode(_ s: String) -> Data? {
        var b64 = s.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        // Pad to a multiple of 4.
        while b64.count % 4 != 0 { b64.append("=") }
        return Data(base64Encoded: b64)
    }
}

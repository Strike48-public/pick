import AuthenticationServices
import Foundation
import UIKit

/// Runs the native browser SSO flow with `ASWebAuthenticationSession`.
///
/// A raw Keycloak password-grant JWT does not carry workspace scope (the core
/// then sees zero agents); only the browser SSO flow yields the workspace-scoped
/// Studio session token (the `__st` token). So the shell owns OAuth and hands the
/// resulting token to the core via `CoreBridge.setToken`.
final class OAuthManager: NSObject, ObservableObject, ASWebAuthenticationPresentationContextProviding {
    /// Custom scheme the platform redirects back to. Must also be declared in
    /// the app's `Info.plist` `CFBundleURLTypes`, or the session errors out.
    static let callbackScheme = "com.strike48.pentest"

    /// PLG login endpoint; `redirect` returns the token to our custom scheme.
    static let authURL =
        "https://plg.strike48.test/auth/login?redirect=com.strike48.pentest://oauth/callback"

    @Published var inProgress = false
    @Published var lastError: String?

    /// Held for the session lifetime so it is not deallocated mid-flight.
    private var session: ASWebAuthenticationSession?

    /// Start the browser SSO flow. Calls `onToken` with the extracted
    /// `access_token` on success; sets `lastError` on failure or cancel.
    func signIn(onToken: @escaping (String) -> Void) {
        guard let url = URL(string: Self.authURL) else {
            lastError = "invalid auth URL"
            return
        }
        inProgress = true
        lastError = nil

        let session = ASWebAuthenticationSession(
            url: url,
            callbackURLScheme: Self.callbackScheme
        ) { [weak self] callbackURL, error in
            guard let self else { return }
            DispatchQueue.main.async { self.inProgress = false }

            if let error {
                DispatchQueue.main.async { self.lastError = error.localizedDescription }
                return
            }
            guard let callbackURL,
                  let token = Self.extractAccessToken(from: callbackURL)
            else {
                DispatchQueue.main.async { self.lastError = "no access_token in callback" }
                return
            }
            DispatchQueue.main.async { onToken(token) }
        }
        session.presentationContextProvider = self
        self.session = session
        session.start()
    }

    /// Extract `access_token` from either the query string or the URL fragment
    /// (the platform may return it as `#access_token=...`).
    static func extractAccessToken(from url: URL) -> String? {
        guard var comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return nil
        }
        if let q = comps.queryItems?.first(where: { $0.name == "access_token" })?.value,
           !q.isEmpty {
            return q
        }
        // The fragment may itself be a query-like string: access_token=...&foo=bar
        if let fragment = comps.fragment, !fragment.isEmpty {
            comps.query = fragment
            if let f = comps.queryItems?.first(where: { $0.name == "access_token" })?.value,
               !f.isEmpty {
                return f
            }
        }
        return nil
    }

    // MARK: - ASWebAuthenticationPresentationContextProviding

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        let scene = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive }
            ?? UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first
        return scene?.windows.first { $0.isKeyWindow }
            ?? scene?.windows.first
            ?? ASPresentationAnchor()
    }
}

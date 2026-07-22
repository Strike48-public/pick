import SwiftUI
import PickShared

/// Needs-sign-in screen. The button runs the shell's native OAuth flow
/// (`ASWebAuthenticationSession`); on success the caller adopts the
/// workspace-scoped token into the core and advances to the Scan screen.
struct SignInView: View {
    @ObservedObject var core: CoreBridge
    @ObservedObject var oauth: OAuthManager
    /// Invoked with the extracted `access_token` after a successful browser flow.
    var onToken: (String) -> Void

    var body: some View {
        VStack(spacing: 16) {
            Spacer()
            BrandBadge(size: 56)
            Text("Sign in to connect to Strike48")
                .font(.system(size: 20, weight: .bold))
                .foregroundStyle(Theme.text)
                .multilineTextAlignment(.center)
            Text("Authenticate to start scanning your network and chatting with the agent.")
                .font(.system(size: 15))
                .foregroundStyle(Theme.muted)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)

            if let err = oauth.lastError {
                Text(err)
                    .font(.system(size: 13))
                    .foregroundStyle(Theme.error)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
            }

            Button {
                // The shell owns OAuth: run the native browser flow directly.
                // Do NOT drive the in-core SignIn effect — that path hits the
                // browser-auth stub in this build and pushes the model into
                // NeedsSignIn, which would trap the UI on this screen even after
                // a successful native sign-in.
                oauth.signIn(onToken: onToken)
            } label: {
                if oauth.inProgress {
                    ProgressView()
                        .frame(maxWidth: .infinity, minHeight: 44)
                } else {
                    Text("Sign in")
                        .frame(maxWidth: .infinity, minHeight: 44)
                }
            }
            .buttonStyle(SagePillButtonStyle())
            .disabled(oauth.inProgress)
            .padding(.horizontal, 32)
            .padding(.top, 8)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

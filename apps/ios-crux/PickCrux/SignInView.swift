import SwiftUI
import PickShared

/// Needs-sign-in screen. Native OAuth is a later task; the button emits
/// `.retrySignIn` to re-drive the sign-in effect.
struct SignInView: View {
    @ObservedObject var core: CoreBridge

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

            Button {
                core.send(.retrySignIn)
            } label: {
                Text("Sign in")
                    .frame(maxWidth: .infinity, minHeight: 44)
            }
            .buttonStyle(SagePillButtonStyle())
            .padding(.horizontal, 32)
            .padding(.top, 8)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

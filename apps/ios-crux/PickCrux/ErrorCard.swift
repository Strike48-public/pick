import SwiftUI
import PickShared

/// Error card overlay; dismiss -> .dismissError.
struct ErrorCard: View {
    @ObservedObject var core: CoreBridge
    let message: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Error")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Theme.error)
                Spacer()
                Button {
                    core.send(.dismissError)
                } label: {
                    Image(systemName: "xmark")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundStyle(Theme.muted)
                }
            }
            Text(message)
                .font(.system(size: 14))
                .foregroundStyle(Theme.text)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: Theme.radiusCard).fill(Theme.surface)
        )
        .overlay(
            RoundedRectangle(cornerRadius: Theme.radiusCard).stroke(Theme.error.opacity(0.4), lineWidth: 1)
        )
        .padding(.horizontal, 16)
    }
}

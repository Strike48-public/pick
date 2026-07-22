import SwiftUI
import PickShared

/// Always-visible top bar: brand badge + "Pick" wordmark + 3 action icons.
/// New chat -> .newChat, History -> .openHistory, Reports -> opens documents.
struct TopBar: View {
    @ObservedObject var core: CoreBridge
    @Binding var showHistory: Bool
    @Binding var showDocuments: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 12) {
                BrandBadge(size: 30)
                Text("Pick")
                    .font(.system(size: 20, weight: .bold))
                    .kerning(-0.2)
                    .foregroundStyle(Theme.text)

                Spacer()

                iconButton(system: "plus") { core.send(.newChat) }
                iconButton(system: "clock") {
                    core.send(.openHistory)
                    showHistory = true
                }
                iconButton(system: "doc.text") {
                    core.send(.openDocuments)
                    showDocuments = true
                }
            }

            Text(core.vm.connection.label)
                .font(.system(size: 12))
                .foregroundStyle(Theme.muted)
        }
        .padding(.top, 4)
        .padding(.horizontal, 20)
        .padding(.bottom, 12)
    }

    private func iconButton(system: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: system)
                .font(.system(size: 20, weight: .medium))
                .foregroundStyle(Theme.text)
                .frame(width: 40, height: 40)
                .contentShape(Rectangle())
        }
        .buttonStyle(SubtleIconButtonStyle())
    }
}

struct SubtleIconButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(
                RoundedRectangle(cornerRadius: Theme.radiusControl)
                    .fill(configuration.isPressed ? Theme.subtleFill : Color.clear)
            )
    }
}

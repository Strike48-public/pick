import SwiftUI
import PickShared

/// Always-visible top bar: brand badge + "Pick" wordmark + 3 action icons.
/// New chat -> .newChat, History -> .openHistory, Reports -> opens documents.
struct TopBar: View {
    @ObservedObject var core: CoreBridge
    let onMenu: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            // Hamburger (left) opens the navigation drawer.
            iconButton(system: "line.3.horizontal", action: onMenu)
            BrandBadge(size: 30, connected: core.vm.connection.phase == .connected)
            Text("Pick")
                .font(.system(size: 20, weight: .bold))
                .kerning(-0.2)
                .foregroundStyle(Theme.text)

            Spacer()

            iconButton(system: "plus") { core.send(.newChat) }
        }
        .padding(.top, 4)
        .padding(.horizontal, 16)
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

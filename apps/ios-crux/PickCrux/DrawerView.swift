import SwiftUI
import PickShared

/// Contents of the navigation drawer (the sidebar column of the
/// `NavigationSplitView` in ContentView, which slides over on iPhone). Holds the
/// primary destinations, a live list of recent chats, and Log out at the bottom.
struct DrawerView: View {
    @ObservedObject var core: CoreBridge
    let onNewChat: () -> Void
    let onOpenReports: () -> Void
    let onOpenSettings: () -> Void
    let onSelectChat: (String) -> Void
    let onLogout: () -> Void

    var body: some View {
        ZStack {
            Theme.background.ignoresSafeArea()
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 10) {
                    BrandBadge(size: 28)
                    Text("Pick")
                        .font(.system(size: 20, weight: .bold))
                        .foregroundStyle(Theme.text)
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                .padding(.bottom, 12)

                Divider().overlay(Theme.hairline)

                drawerItem("plus", "New chat", action: onNewChat)
                drawerItem("doc.text", "Reports", action: onOpenReports)
                drawerItem("gearshape", "Settings", action: onOpenSettings)

                Divider().overlay(Theme.hairline).padding(.vertical, 6)

                Text("Recent chats")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(Theme.muted)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 4)

                if core.vm.history.isEmpty {
                    Text("No conversations yet")
                        .font(.system(size: 14))
                        .foregroundStyle(Theme.muted)
                        .padding(.horizontal, 20)
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(core.vm.history, id: \.id) { conv in
                                Button { onSelectChat(conv.id) } label: {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(conv.title.isEmpty ? "Untitled chat" : conv.title)
                                            .font(.system(size: 15))
                                            .foregroundStyle(Theme.text)
                                            .lineLimit(1)
                                        if !conv.relativeTime.isEmpty {
                                            Text(conv.relativeTime)
                                                .font(.system(size: 12))
                                                .foregroundStyle(Theme.muted)
                                        }
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(.horizontal, 20)
                                    .padding(.vertical, 10)
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }

                Spacer()
                Divider().overlay(Theme.hairline)
                Button(action: onLogout) {
                    HStack(spacing: 16) {
                        Image(systemName: "rectangle.portrait.and.arrow.right")
                            .font(.system(size: 18))
                        Text("Log out").font(.system(size: 16))
                    }
                    .foregroundStyle(Theme.error)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 20)
                    .padding(.vertical, 14)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
    }

    private func drawerItem(_ system: String, _ label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 16) {
                Image(systemName: system).font(.system(size: 18)).frame(width: 22)
                Text(label).font(.system(size: 16))
            }
            .foregroundStyle(Theme.text)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// Settings surface: feature-flag toggles. Telemetry is opt-out (on by default);
/// flipping it applies immediately in the core (Sentry on/off) and is persisted
/// by the shell.
struct SettingsScreen: View {
    @ObservedObject var core: CoreBridge
    let onClose: () -> Void
    let onTelemetryChange: (Bool) -> Void

    // Local mirror so the Toggle animates immediately; the core is the source of
    // truth and re-renders confirm it.
    @State private var telemetryOn: Bool

    init(core: CoreBridge, onClose: @escaping () -> Void, onTelemetryChange: @escaping (Bool) -> Void) {
        self.core = core
        self.onClose = onClose
        self.onTelemetryChange = onTelemetryChange
        _telemetryOn = State(initialValue: core.vm.settings.telemetryEnabled)
    }

    var body: some View {
        ZStack {
            Theme.background.ignoresSafeArea()
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    Button(action: onClose) {
                        Image(systemName: "chevron.left")
                            .font(.system(size: 20, weight: .semibold))
                            .foregroundStyle(Theme.text)
                            .frame(width: 40, height: 40)
                            .contentShape(Rectangle())
                    }
                    Text("Settings")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(Theme.text)
                    Spacer()
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .overlay(Rectangle().frame(height: 1).foregroundStyle(Theme.hairline), alignment: .bottom)

                HStack(alignment: .top, spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Usage analytics")
                            .font(.system(size: 16))
                            .foregroundStyle(Theme.text)
                        Text("Share anonymous usage + crash data to help improve Pick. No scan results, targets, or personal data are sent.")
                            .font(.system(size: 13))
                            .foregroundStyle(Theme.muted)
                    }
                    Spacer()
                    Toggle("", isOn: $telemetryOn)
                        .labelsHidden()
                        .tint(Theme.brand)
                        .onChange(of: telemetryOn) { newValue in
                            onTelemetryChange(newValue)
                        }
                }
                .padding(20)

                Spacer()
            }
        }
    }
}

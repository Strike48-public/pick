import SwiftUI
import PickShared

/// Conversation history sheet listing `history`; tap -> selectConversation.
struct HistorySheet: View {
    @ObservedObject var core: CoreBridge
    @Binding var isPresented: Bool

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.background.ignoresSafeArea()
                Group {
                    if core.vm.history.isEmpty {
                        Text("No conversations yet")
                            .font(.system(size: 15))
                            .foregroundStyle(Theme.muted)
                    } else {
                        ScrollView {
                            VStack(spacing: 0) {
                                ForEach(Array(core.vm.history.enumerated()), id: \.offset) { _, conv in
                                    Button {
                                        core.send(.selectConversation(conv.id))
                                        isPresented = false
                                    } label: {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(conv.title)
                                                .font(.system(size: 16, weight: .medium))
                                                .foregroundStyle(Theme.text)
                                            Text(conv.relativeTime)
                                                .font(.system(size: 13))
                                                .foregroundStyle(Theme.muted)
                                        }
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .padding(.vertical, 12)
                                        .padding(.horizontal, 16)
                                        .contentShape(Rectangle())
                                    }
                                    .buttonStyle(.plain)
                                    Divider().overlay(Theme.rowSeparator)
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("History")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { isPresented = false }
                        .foregroundStyle(Theme.brand)
                }
            }
            .toolbarBackground(Theme.background, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
        }
    }
}

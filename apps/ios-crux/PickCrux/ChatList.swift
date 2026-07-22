import SwiftUI
import PickShared

/// Scrolling message list + live running-tools strip + conversation doc strip.
struct ChatList: View {
    @ObservedObject var core: CoreBridge

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(Array(core.vm.messages.enumerated()), id: \.offset) { _, msg in
                        MessageRow(message: msg)
                    }

                    // Live "running tools" strip while scanning.
                    if core.vm.scanInProgress && !core.vm.toolCalls.isEmpty {
                        ForEach(Array(core.vm.toolCalls.enumerated()), id: \.offset) { _, tool in
                            ToolCallRow(tool: tool)
                        }
                    }

                    if core.vm.scanInProgress && core.vm.toolCalls.isEmpty {
                        HStack(spacing: 8) {
                            ProgressView().tint(Theme.brand)
                            Text("Working...")
                                .font(.system(size: 14))
                                .foregroundStyle(Theme.muted)
                        }
                    }
                }
                .padding(16)
            }

            // Conversation-scoped documents strip pinned above the input.
            if !core.vm.conversationDocs.isEmpty {
                conversationDocsStrip
            }

            InputRow(core: core)
        }
    }

    private var conversationDocsStrip: some View {
        ScrollView {
            VStack(spacing: 0) {
                ForEach(Array(core.vm.conversationDocs.enumerated()), id: \.offset) { _, doc in
                    Button {
                        core.send(.openDocument(doc.id))
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: "doc.text")
                                .font(.system(size: 14))
                                .foregroundStyle(Theme.muted)
                            Text(doc.title)
                                .font(.system(size: 14))
                                .foregroundStyle(Theme.text)
                            Spacer()
                        }
                        .padding(.vertical, 10)
                        .padding(.horizontal, 16)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .frame(maxHeight: 220)
        .background(Theme.faintWash)
        .overlay(Rectangle().frame(height: 1).foregroundStyle(Theme.hairline), alignment: .top)
    }
}

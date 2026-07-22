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

    // Rows are laid out directly (no greedy ScrollView, which stretched the
    // strip to its max height leaving a big empty drawer). The strip hugs its
    // content; if many docs accumulate it scrolls, capped at ~3 rows tall.
    private var conversationDocsStrip: some View {
        let rowHeight: CGFloat = 40
        let maxRows = 3
        let docs = core.vm.conversationDocs
        return ScrollView(.vertical, showsIndicators: docs.count > maxRows) {
            VStack(spacing: 0) {
                ForEach(Array(docs.enumerated()), id: \.offset) { _, doc in
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
                        .frame(height: rowHeight)
                        .padding(.horizontal, 16)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        // Hug content up to maxRows, then scroll — no empty drawer.
        .frame(height: min(CGFloat(docs.count), CGFloat(maxRows)) * rowHeight)
        .background(Theme.faintWash)
        .overlay(Rectangle().frame(height: 1).foregroundStyle(Theme.hairline), alignment: .top)
    }
}

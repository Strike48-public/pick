import SwiftUI
import PickShared

/// Scrolling message list + live running-tools strip + conversation doc strip.
struct ChatList: View {
    @ObservedObject var core: CoreBridge

    private static let bottomAnchor = "pick.chat.bottom"

    // Signature of what's on screen; when it grows we auto-scroll to the
    // bottom (unless the user has scrolled up — see `userPinnedUp`).
    private var streamSignature: Int {
        core.vm.messages.count &* 31 &+ core.vm.toolCalls.count &+ (core.vm.agentActivity != .idle ? 1 : 0)
    }

    @State private var userPinnedUp = false

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        ForEach(Array(core.vm.messages.enumerated()), id: \.offset) { _, msg in
                            MessageRow(message: msg)
                        }

                        // Animated agent-activity status line (no spinner). Shown
                        // whenever the agent is working; the label reflects what it
                        // is doing (Thinking.../Running tools.../Responding...).
                        if core.vm.agentActivity != .idle {
                            TypingIndicator(label: core.vm.activityLabel)
                        }

                        // Invisible bottom anchor we scroll to as content streams.
                        Color.clear.frame(height: 1).id(Self.bottomAnchor)
                    }
                    .padding(16)
                }
                // Auto-scroll to the newest content as it streams in, unless the
                // user scrolled up to read history (they can drag back down to
                // re-enable). Dragging sets `userPinnedUp`.
                .simultaneousGesture(
                    DragGesture().onChanged { value in
                        // Dragging DOWN (positive height) scrolls toward older
                        // messages -> the user is reading back, so stop
                        // auto-scrolling. Dragging UP toward the newest content
                        // re-enables it.
                        if value.translation.height > 12 {
                            userPinnedUp = true
                        } else if value.translation.height < -12 {
                            userPinnedUp = false
                        }
                    }
                )
                .onChange(of: streamSignature) { _ in
                    guard !userPinnedUp else { return }
                    withAnimation(.easeOut(duration: 0.2)) {
                        proxy.scrollTo(Self.bottomAnchor, anchor: .bottom)
                    }
                }
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

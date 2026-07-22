import SwiftUI
import PickShared

/// Renders one chat message according to its kind:
/// user = right-aligned sage bubble, agentText = full-width markdown,
/// toolCall = surface card with status pill.
struct MessageRow: View {
    let message: MessageView

    var body: some View {
        switch message.kind {
        case .user:
            HStack {
                Spacer(minLength: 40)
                Text(markdown(message.markdown))
                    .font(.system(size: 15))
                    .foregroundStyle(Theme.onBrand)
                    .padding(.vertical, 8)
                    .padding(.horizontal, 12)
                    .background(
                        RoundedRectangle(cornerRadius: Theme.radiusCard).fill(Theme.brand)
                    )
            }
        case .agentText:
            // Render the ordered parts (text/thinking/tool) so an agent message
            // reads exactly as it does in the Dioxus app. Falls back to the
            // legacy flattened blocks when a message carries no parts.
            if message.parts.isEmpty {
                MarkdownText(blocks: message.blocks)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(Array(message.parts.enumerated()), id: \.offset) { _, part in
                        switch part {
                        case let .text(blocks):
                            MarkdownText(blocks: blocks)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        case let .thinking(text):
                            ThinkingBlock(text: text)
                        case let .tool(tool):
                            ToolCallRow(tool: tool)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        case .toolCall:
            if let tool = message.tool {
                ToolCallRow(tool: tool)
            } else {
                ToolCallRow(tool: ToolCallView(
                    name: message.markdown,
                    status: .running,
                    arguments: nil,
                    result: nil,
                    error: nil
                ))
            }
        }
    }

    /// Inline-only markdown for the user bubble (single-line, no block structure).
    private func markdown(_ raw: String) -> AttributedString {
        (try? AttributedString(markdown: raw, options: .init(interpretedSyntax: .inlineOnly)))
            ?? AttributedString(raw)
    }
}

/// A muted "Thinking" block mirroring the Dioxus chat-thinking-block.
struct ThinkingBlock: View {
    let text: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Thinking")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Theme.muted)
            Text(text)
                .font(.system(size: 13))
                .foregroundStyle(Theme.muted)
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: Theme.radiusCard).fill(Theme.subtleFill)
        )
    }
}

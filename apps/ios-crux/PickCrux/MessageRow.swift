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
            // Block-level markdown (headings/lists/code/paragraphs), not the
            // inline-only AttributedString which collapses block structure.
            MarkdownText(blocks: message.blocks)
                .frame(maxWidth: .infinity, alignment: .leading)
        case .toolCall:
            if let tool = message.tool {
                ToolCallRow(tool: tool)
            } else {
                ToolCallRow(tool: ToolCallView(name: message.markdown, status: .running))
            }
        }
    }

    /// Inline-only markdown for the user bubble (single-line, no block structure).
    private func markdown(_ raw: String) -> AttributedString {
        (try? AttributedString(markdown: raw, options: .init(interpretedSyntax: .inlineOnly)))
            ?? AttributedString(raw)
    }
}

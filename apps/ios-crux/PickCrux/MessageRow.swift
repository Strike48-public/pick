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
            Text(markdown(message.markdown))
                .font(.system(size: 15))
                .foregroundStyle(Theme.text)
                .frame(maxWidth: .infinity, alignment: .leading)
        case .toolCall:
            if let tool = message.tool {
                ToolCallRow(tool: tool)
            } else {
                ToolCallRow(tool: ToolCallView(name: message.markdown, status: .running))
            }
        }
    }

    /// Best-effort markdown -> AttributedString (bold, lists, code, headings).
    private func markdown(_ raw: String) -> AttributedString {
        if let attributed = try? AttributedString(
            markdown: raw,
            options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        ) {
            return attributed
        }
        return AttributedString(raw)
    }
}

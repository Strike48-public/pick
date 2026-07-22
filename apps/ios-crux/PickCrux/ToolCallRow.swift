import SwiftUI
import PickShared

/// A tool-call card: surface bg, hairline border, mono tool name + status pill.
struct ToolCallRow: View {
    let tool: ToolCallView

    var body: some View {
        HStack {
            Text(tool.name)
                .font(.system(size: 14, design: .monospaced))
                .foregroundStyle(Theme.text)
            Spacer()
            ToolStatusBadge(status: tool.status)
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: Theme.radiusCard).fill(Theme.surface)
        )
        .overlay(
            RoundedRectangle(cornerRadius: Theme.radiusCard).stroke(Theme.hairline, lineWidth: 1)
        )
    }
}

struct ToolStatusBadge: View {
    let status: ToolStatus

    var body: some View {
        Text(label)
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(color)
            .padding(.vertical, 3)
            .padding(.horizontal, 10)
            .background(Capsule().fill(color.opacity(0.15)))
    }

    private var label: String {
        switch status {
        case .running: return "Running"
        case .success: return "Success"
        case .error: return "Error"
        }
    }

    private var color: Color {
        switch status {
        case .running: return Theme.warning
        case .success: return Theme.success
        case .error: return Theme.error
        }
    }
}

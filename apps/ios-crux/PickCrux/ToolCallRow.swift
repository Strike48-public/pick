import SwiftUI
import PickShared

/// A tool-call card: surface bg, hairline border, mono tool name + status pill.
/// Tappable to expand the arguments / result / error, when any are present.
struct ToolCallRow: View {
    let tool: ToolCallView
    @State private var expanded = false

    private var hasDetail: Bool {
        (tool.arguments?.isEmpty == false)
            || (tool.result?.isEmpty == false)
            || (tool.error?.isEmpty == false)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                if hasDetail {
                    Image(systemName: expanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.muted)
                }
                Text(tool.name)
                    .font(.system(size: 14, design: .monospaced))
                    .foregroundStyle(Theme.text)
                Spacer()
                ToolStatusBadge(status: tool.status)
            }
            if expanded {
                if let args = tool.arguments, !args.isEmpty {
                    detailBlock(title: "Arguments", body: args, color: Theme.muted)
                }
                if let result = tool.result, !result.isEmpty {
                    detailBlock(title: "Result", body: result, color: Theme.text)
                }
                if let err = tool.error, !err.isEmpty {
                    detailBlock(title: "Error", body: err, color: Theme.error)
                }
            }
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
        .contentShape(Rectangle())
        .onTapGesture {
            if hasDetail { expanded.toggle() }
        }
    }

    private func detailBlock(title: String, body: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.muted)
            Text(body)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(color)
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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

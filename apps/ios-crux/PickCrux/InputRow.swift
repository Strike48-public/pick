import SwiftUI
import PickShared

/// Bottom chat input: rounded 12px text field + 44px sage pill Send button.
struct InputRow: View {
    @ObservedObject var core: CoreBridge
    @State private var text: String = ""

    var body: some View {
        HStack(spacing: 8) {
            TextField("Message", text: $text, axis: .vertical)
                .font(.system(size: 15))
                .foregroundStyle(Theme.text)
                .tint(Theme.brand)
                .padding(.vertical, 10)
                .padding(.horizontal, 14)
                .frame(minHeight: 44)
                .background(
                    RoundedRectangle(cornerRadius: Theme.radiusControl).fill(Theme.subtleFill)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: Theme.radiusControl).stroke(Theme.hairline, lineWidth: 1)
                )

            Button {
                send()
            } label: {
                Image(systemName: "arrow.up")
                    .font(.system(size: 18, weight: .semibold))
                    .frame(width: 44, height: 44)
            }
            .buttonStyle(SagePillButtonStyle(enabled: !trimmed.isEmpty))
            .disabled(trimmed.isEmpty)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    private var trimmed: String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func send() {
        let msg = trimmed
        guard !msg.isEmpty else { return }
        core.send(.sendMessage(msg))
        text = ""
    }
}

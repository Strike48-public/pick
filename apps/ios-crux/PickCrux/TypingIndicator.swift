import SwiftUI

/// An AI-chat style "agent is working" status line: three pulsing dots + a
/// label ("Thinking...", "Running tools...", etc). Replaces the spinner — chat
/// UIs never show a determinate/indeterminate spinner for agent activity.
struct TypingIndicator: View {
    /// The activity label (already localized/pre-formatted by the core).
    let label: String
    @State private var phase = 0

    private let timer = Timer.publish(every: 0.35, on: .main, in: .common).autoconnect()

    var body: some View {
        HStack(spacing: 8) {
            HStack(spacing: 4) {
                ForEach(0..<3, id: \.self) { i in
                    Circle()
                        .fill(Theme.brand)
                        .frame(width: 6, height: 6)
                        .opacity(phase == i ? 1.0 : 0.3)
                }
            }
            if !label.isEmpty {
                Text(label)
                    .font(.system(size: 14))
                    .foregroundStyle(Theme.muted)
            }
        }
        .onReceive(timer) { _ in
            phase = (phase + 1) % 3
        }
    }
}

import SwiftUI
import PickShared

/// Inline notice surfaced when the agent backend errored (token/rate-limit
/// exhaustion or a generic upstream failure) instead of producing a reply.
/// Distinct from the generic `ErrorCard`: it carries a specific title/detail
/// built from `tokenUsageStats` and an optional "Open Studio" link.
struct NoticeCard: View {
    let notice: NoticeView

    /// Accent color: token-limit warns (amber), a generic upstream blip errors.
    private var accent: Color {
        switch notice.kind {
        case .tokenLimit: return Theme.warning
        default: return Theme.error
        }
    }

    /// SF Symbol matching the Dioxus glyphs (clock for limit, warning otherwise).
    private var symbol: String {
        switch notice.kind {
        case .tokenLimit: return "clock.fill"
        default: return "exclamationmark.triangle.fill"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: symbol)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(accent)
                Text(notice.title)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(accent)
                Spacer()
            }
            Text(notice.detail)
                .font(.system(size: 14))
                .foregroundStyle(Theme.text)
                .frame(maxWidth: .infinity, alignment: .leading)
            if let urlString = notice.studioUrl, let url = URL(string: urlString) {
                Link(destination: url) {
                    HStack(spacing: 4) {
                        Text("Open Studio")
                        Image(systemName: "arrow.up.right.square")
                    }
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Theme.brand)
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: Theme.radiusCard).fill(Theme.surface)
        )
        .overlay(
            RoundedRectangle(cornerRadius: Theme.radiusCard).stroke(accent.opacity(0.4), lineWidth: 1)
        )
        .padding(.horizontal, 16)
    }
}

import SwiftUI
import PickShared

/// Full-screen document viewer for `openDocument`. Left chevron closes; body
/// renders markdown.
///
/// Once a share link exists (`doc.shareUrl`), a share row exposes the full set
/// of actions (matching the Dioxus app): Copy link, Share (native sheet), Open
/// in browser (opens the preview URL), and one button per social network
/// (X/LinkedIn/Facebook) opening the pre-built compose URL. Every share URL is
/// computed in Rust (`doc.previewUrl` / `doc.socialLinks`); the shell just
/// copies or opens the given string.
struct DocViewer: View {
    @ObservedObject var core: CoreBridge
    let doc: DocView
    @State private var showShareSheet = false

    var body: some View {
        ZStack {
            Theme.background.ignoresSafeArea()
            VStack(spacing: 0) {
                // Top bar
                HStack(spacing: 8) {
                    Button {
                        core.send(.closeDocument)
                    } label: {
                        Image(systemName: "chevron.left")
                            .font(.system(size: 20, weight: .semibold))
                            .foregroundStyle(Theme.text)
                            .frame(width: 40, height: 40)
                            .contentShape(Rectangle())
                    }
                    Text(doc.title)
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(Theme.text)
                        .lineLimit(1)
                    Spacer()
                    if doc.shareUrl == nil {
                        Button {
                            core.send(.createShareLink(doc.id))
                        } label: {
                            Text("Create link")
                                .font(.system(size: 14, weight: .semibold))
                                .foregroundStyle(Theme.onBrand)
                                .padding(.vertical, 6)
                                .padding(.horizontal, 12)
                        }
                        .buttonStyle(SagePillButtonStyle())
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .overlay(Rectangle().frame(height: 1).foregroundStyle(Theme.hairline), alignment: .bottom)

                if let url = doc.shareUrl {
                    shareRow(shareUrl: url)
                }

                ScrollView {
                    MarkdownText(blocks: doc.blocks)
                        .padding(16)
                }
            }
        }
        .sheet(isPresented: $showShareSheet) {
            if let url = doc.shareUrl, let link = URL(string: url) {
                ShareSheet(items: [link])
            }
        }
    }

    /// Horizontally scrollable pill row: Copy / Share / Open in browser / socials.
    @ViewBuilder private func shareRow(shareUrl: String) -> some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                sharePill("Copy link") { UIPasteboard.general.string = shareUrl }
                sharePill("Share") { showShareSheet = true }
                sharePill("Open in browser") { open(doc.previewUrl ?? shareUrl) }
                ForEach(Array(doc.socialLinks.enumerated()), id: \.offset) { _, link in
                    sharePill(link.label) { open(link.url) }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
        .overlay(Rectangle().frame(height: 1).foregroundStyle(Theme.hairline), alignment: .bottom)
    }

    private func sharePill(_ label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(Theme.text)
                .padding(.vertical, 8)
                .padding(.horizontal, 14)
                .background(Capsule().fill(Theme.faintWash))
                .overlay(Capsule().stroke(Theme.brand.opacity(0.4), lineWidth: 1))
        }
        .buttonStyle(.plain)
    }

    private func open(_ urlString: String) {
        guard let url = URL(string: urlString) else { return }
        UIApplication.shared.open(url)
    }
}

/// UIKit share sheet bridge.
struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}

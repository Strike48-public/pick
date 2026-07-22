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
    // Set when the user taps Share before a link exists; once the link arrives
    // we auto-present the OS share sheet so it behaves like a normal share button.
    @State private var pendingShare = false

    /// The link we actually hand out. The raw `/s/:token` URL redirects to the
    /// Studio login/SPA; the `preview=1` variant renders the report standalone,
    /// so it's the one that works when opened or shared. Falls back to the raw
    /// URL only if no preview URL was computed.
    private var shareableURL: String? { doc.previewUrl ?? doc.shareUrl }

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
                    // A normal share button. If the public link isn't created
                    // yet, tapping creates it and then auto-opens the OS share
                    // sheet once it arrives.
                    Button {
                        if shareableURL != nil {
                            showShareSheet = true
                        } else {
                            pendingShare = true
                            core.send(.createShareLink(doc.id))
                        }
                    } label: {
                        Image(systemName: "square.and.arrow.up")
                            .font(.system(size: 18, weight: .semibold))
                            .foregroundStyle(Theme.text)
                            .frame(width: 40, height: 40)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
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
            if let url = shareableURL, let link = URL(string: url) {
                ShareSheet(items: [link])
            }
        }
        // When Share was tapped before the link existed, present the sheet as
        // soon as the created link (and its preview URL) lands in the model.
        .onChange(of: doc.shareUrl) { _ in
            if pendingShare, shareableURL != nil {
                pendingShare = false
                showShareSheet = true
            }
        }
    }

    /// Horizontally scrollable pill row: Copy / Share / Open in browser / socials.
    @ViewBuilder private func shareRow(shareUrl: String) -> some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                // Copy/Open the preview link (renders standalone); the raw
                // share URL redirects to the Studio login.
                sharePill("Copy link") { UIPasteboard.general.string = doc.previewUrl ?? shareUrl }
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

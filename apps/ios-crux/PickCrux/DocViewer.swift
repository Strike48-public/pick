import SwiftUI
import PickShared

/// Full-screen document viewer for `openDocument`. Left chevron closes; body
/// renders markdown; Share offers a native share sheet or creates a link.
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
                    shareControl
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .overlay(Rectangle().frame(height: 1).foregroundStyle(Theme.hairline), alignment: .bottom)

                ScrollView {
                    MarkdownText(markdown: doc.markdownBody)
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

    @ViewBuilder private var shareControl: some View {
        if doc.shareUrl != nil {
            Button {
                showShareSheet = true
            } label: {
                Image(systemName: "square.and.arrow.up")
                    .font(.system(size: 18, weight: .medium))
                    .foregroundStyle(Theme.brand)
                    .frame(width: 40, height: 40)
                    .contentShape(Rectangle())
            }
        } else {
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
}

/// UIKit share sheet bridge.
struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}

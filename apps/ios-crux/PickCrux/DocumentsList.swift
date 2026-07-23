import SwiftUI
import PickShared

/// Reports list: all documents; tap -> openDocument(id).
struct DocumentsList: View {
    @ObservedObject var core: CoreBridge
    @Binding var isPresented: Bool

    var body: some View {
        ZStack {
            Theme.background.ignoresSafeArea()
            VStack(spacing: 0) {
                // Leading chevron-back header, matching DocViewer / Settings.
                HStack(spacing: 8) {
                    Button { isPresented = false } label: {
                        Image(systemName: "chevron.left")
                            .font(.system(size: 20, weight: .semibold))
                            .foregroundStyle(Theme.text)
                            .frame(width: 40, height: 40)
                            .contentShape(Rectangle())
                    }
                    Text("Reports")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(Theme.text)
                    Spacer()
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .overlay(Rectangle().frame(height: 1).foregroundStyle(Theme.hairline), alignment: .bottom)

                if core.vm.allDocuments.isEmpty {
                    Spacer()
                    Text("No reports yet")
                        .font(.system(size: 15))
                        .foregroundStyle(Theme.muted)
                    Spacer()
                } else {
                    ScrollView {
                        VStack(spacing: 0) {
                            ForEach(Array(core.vm.allDocuments.enumerated()), id: \.offset) { _, doc in
                                Button {
                                    core.send(.openDocument(doc.id))
                                    isPresented = false
                                } label: {
                                    HStack(spacing: 10) {
                                        Image(systemName: "doc.text")
                                            .foregroundStyle(Theme.muted)
                                        Text(doc.title)
                                            .font(.system(size: 16))
                                            .foregroundStyle(Theme.text)
                                        Spacer()
                                    }
                                    .padding(.vertical, 12)
                                    .padding(.horizontal, 16)
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                                Divider().overlay(Theme.rowSeparator)
                            }
                        }
                    }
                }
            }
        }
    }
}

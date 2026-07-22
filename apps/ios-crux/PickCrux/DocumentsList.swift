import SwiftUI
import PickShared

/// Reports list: all documents; tap -> openDocument(id).
struct DocumentsList: View {
    @ObservedObject var core: CoreBridge
    @Binding var isPresented: Bool

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.background.ignoresSafeArea()
                Group {
                    if core.vm.allDocuments.isEmpty {
                        Text("No reports yet")
                            .font(.system(size: 15))
                            .foregroundStyle(Theme.muted)
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
            .navigationTitle("Reports")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { isPresented = false }
                        .foregroundStyle(Theme.brand)
                }
            }
            .toolbarBackground(Theme.background, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
        }
    }
}

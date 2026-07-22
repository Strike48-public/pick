import SwiftUI
import PickShared

struct ContentView: View {
    @ObservedObject var core: CoreBridge

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                Text("Pick - Easy Mode")
                    .font(.title2)
                    .fontWeight(.bold)

                Text("screen=\(String(describing: core.vm.screen)) - \(core.vm.connection.label)")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if core.vm.showScanCard {
                    scanCard
                }

                if core.vm.scanInProgress {
                    ProgressView()
                    Text("Scan in progress")
                        .font(.body)
                }

                if let err = core.vm.error {
                    errorCard(err)
                }

                if !core.vm.messages.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(Array(core.vm.messages.enumerated()), id: \.offset) { _, msg in
                            Text("[\(prefix(for: msg.kind))] \(msg.markdown)")
                                .font(.caption)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
            }
            .onAppear {
                // Test hook: when launched with -autoScan the shell fires the
                // same code path as the Scan button so the FFI->view re-render
                // can be exercised headlessly (no GUI tap available over SSH).
                if ProcessInfo.processInfo.arguments.contains("-autoScan") {
                    core.send(.startScan)
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity)
        }
    }

    private var scanCard: some View {
        VStack(spacing: 12) {
            Text("Scan your network")
                .font(.headline)
            Text("Discover hosts and services on the local network.")
                .font(.body)
                .multilineTextAlignment(.center)
            Button {
                core.send(.startScan)
            } label: {
                Text(core.vm.scanInProgress ? "Scanning..." : "Scan My Network")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(core.vm.scanInProgress)
        }
        .padding(20)
        .frame(maxWidth: .infinity)
        .background(Color(.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func errorCard(_ err: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Error")
                .font(.subheadline)
                .foregroundStyle(.red)
            Text(err)
                .font(.caption)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func prefix(for kind: MessageKind) -> String {
        switch kind {
        case .user: return "you"
        case .agentText: return "agent"
        case .toolCall: return "tool"
        }
    }
}

import SwiftUI
import PickShared

/// The sage pill CTA card shown on the Scan screen (`showScanCard`).
struct ScanCard: View {
    @ObservedObject var core: CoreBridge

    var body: some View {
        VStack(spacing: 12) {
            Text("Scan your network")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(Theme.text)

            Text("Discover hosts and services on the local network.")
                .font(.system(size: 15))
                .foregroundStyle(Theme.muted)
                .multilineTextAlignment(.center)

            Button {
                core.send(.startScan)
            } label: {
                HStack(spacing: 8) {
                    if core.vm.scanInProgress {
                        ProgressView()
                            .progressViewStyle(.circular)
                            .tint(Theme.onBrand)
                    }
                    Text(core.vm.scanInProgress ? "Scanning..." : "Scan My Network")
                }
                .frame(maxWidth: .infinity, minHeight: 44)
            }
            .buttonStyle(SagePillButtonStyle(enabled: !core.vm.scanInProgress))
            .disabled(core.vm.scanInProgress)
        }
        .padding(.vertical, 18)
        .padding(.horizontal, 20)
        .frame(maxWidth: .infinity, minHeight: 64)
        .background(
            RoundedRectangle(cornerRadius: Theme.radiusCard).fill(Theme.surface)
        )
        .overlay(
            RoundedRectangle(cornerRadius: Theme.radiusCard).stroke(Theme.hairline, lineWidth: 1)
        )
    }
}

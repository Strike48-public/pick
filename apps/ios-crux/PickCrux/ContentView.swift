import SwiftUI
import PickShared

/// Thin shell: renders the sage-dark Easy Mode UI as a pure function of the
/// core `ViewModel`, switching on `screen` and overlay fields. All interaction
/// is emitted back through `CoreBridge.send(Event)`.
///
/// History and Reports are transient overlays that the ViewModel does not model
/// with a dedicated visibility flag, so their presentation is a local flag that
/// mirrors the corresponding open/close Events to the core.
struct ContentView: View {
    @ObservedObject var core: CoreBridge
    @State private var showHistory = false
    @State private var showDocuments = false

    var body: some View {
        ZStack {
            Theme.background.ignoresSafeArea()

            if core.vm.needsSignIn || core.vm.screen == .needsSignIn {
                SignInView(core: core)
            } else {
                VStack(spacing: 0) {
                    TopBar(core: core, showHistory: $showHistory, showDocuments: $showDocuments)

                    if let err = core.vm.error {
                        ErrorCard(core: core, message: err)
                            .padding(.bottom, 8)
                    }

                    mainContent
                }
            }
        }
        .preferredColorScheme(.dark)
        .tint(Theme.brand)
        .sheet(isPresented: $showHistory, onDismiss: { core.send(.closeHistory) }) {
            HistorySheet(core: core, isPresented: $showHistory)
        }
        .sheet(isPresented: $showDocuments) {
            DocumentsList(core: core, isPresented: $showDocuments)
        }
        .fullScreenCover(isPresented: docBinding) {
            if let doc = core.vm.openDocument {
                DocViewer(core: core, doc: doc)
            }
        }
        .onAppear {
            // Test hook: -autoScan fires the Scan button code path headlessly so
            // the FFI -> view round-trip can be exercised over SSH (no GUI tap).
            if ProcessInfo.processInfo.arguments.contains("-autoScan") {
                core.send(.startScan)
            }
        }
    }

    @ViewBuilder private var mainContent: some View {
        if core.vm.showScanCard {
            ScrollView {
                VStack(spacing: 16) {
                    ScanCard(core: core)
                }
                .padding(16)
            }
        } else {
            ChatList(core: core)
        }
    }

    private var docBinding: Binding<Bool> {
        Binding(
            get: { core.vm.openDocument != nil },
            set: { newValue in if !newValue { core.send(.closeDocument) } }
        )
    }
}

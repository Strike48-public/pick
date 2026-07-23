import SwiftUI
import PickShared

/// Thin shell: renders the sage-dark Easy Mode UI as a pure function of the
/// core `ViewModel`, switching on `screen` and overlay fields. All interaction
/// is emitted back through `CoreBridge.send(Event)`.
///
/// History and Reports are transient overlays that the ViewModel does not model
/// with a dedicated visibility flag, so their presentation is a local flag that
/// mirrors the corresponding open/close Events to the core.
///
/// Sign-in is a native-shell capability: until the shell has adopted an OAuth
/// token (`hasToken`) or the core reports `needsSignIn`, the `SignInView` is
/// shown and its button drives `ASWebAuthenticationSession`.
struct ContentView: View {
    @ObservedObject var core: CoreBridge
    @StateObject private var oauth = OAuthManager()
    /// True once the shell has handed a workspace-scoped token to the core.
    @State private var hasToken = false
    @State private var showDocuments = false
    @State private var showSettings = false
    /// Drives the slide-over navigation drawer overlay.
    @State private var drawerOpen = false

    var body: some View {
        Group {
            // Once the shell has adopted a workspace-scoped OAuth token, show the
            // app. `hasToken` takes precedence over the model's `needsSignIn`,
            // which can be stale: the in-core SignIn effect is a stub in this
            // build and is not what authenticates the shell.
            if !hasToken {
                ZStack {
                    Theme.background.ignoresSafeArea()
                    SignInView(core: core, oauth: oauth, onToken: adoptToken)
                }
            } else {
                signedInApp
            }
        }
        .preferredColorScheme(.dark)
        .tint(Theme.brand)
        .fullScreenCover(isPresented: $showDocuments) {
            DocumentsList(core: core, isPresented: $showDocuments)
        }
        .fullScreenCover(isPresented: $showSettings) {
            SettingsScreen(
                core: core,
                onClose: { showSettings = false },
                onTelemetryChange: { enabled in
                    core.send(.setTelemetryEnabled(enabled)) // apply in core (Sentry)
                    SettingsStore.telemetryEnabled = enabled // persist natively
                }
            )
        }
        .fullScreenCover(isPresented: docBinding) {
            if let doc = core.vm.openDocument {
                DocViewer(core: core, doc: doc)
            }
        }
        .onAppear {
            // Seed the persisted telemetry choice so the Sentry client reflects
            // the opt-out from the first launch, before any UI interaction.
            core.send(.seedSettings(telemetryEnabled: SettingsStore.telemetryEnabled))
            // Restore a persisted token (Keychain) so a relaunch skips sign-in.
            restorePersistedToken()
            // Test hook: -autoScan fires the Scan button code path headlessly so
            // the FFI -> view round-trip can be exercised over SSH (no GUI tap).
            if ProcessInfo.processInfo.arguments.contains("-autoScan") {
                hasToken = true
                core.send(.startScan)
            }
            // Test hook: -autoSignIn fires the Sign In button code path so the
            // ASWebAuthenticationSession start can be exercised over SSH (the
            // sim runs windowless, so a real tap cannot be injected).
            if ProcessInfo.processInfo.arguments.contains("-autoSignIn") {
                // Delay so the window scene reaches .foregroundActive before the
                // auth session resolves its presentation anchor (a real user tap
                // already happens after the screen is active).
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    oauth.signIn(onToken: adoptToken)
                }
            }
        }
    }

    /// The signed-in app: the chat/scan surface with the top bar, plus a
    /// slide-over drawer overlay. `NavigationSplitView` is an iPad/Mac
    /// master-detail control and doesn't behave as a hamburger drawer on iPhone
    /// (its column visibility leaks under sheets and swallows taps), so the
    /// drawer is a hand-rolled slide-over: a dimming scrim + an offset panel.
    @ViewBuilder private var signedInApp: some View {
        ZStack(alignment: .leading) {
            ZStack {
                Theme.background.ignoresSafeArea()
                VStack(spacing: 0) {
                    TopBar(core: core, onMenu: { openDrawer() })

                    if let err = core.vm.error {
                        ErrorCard(core: core, message: err)
                            .padding(.bottom, 8)
                    }
                    if let notice = core.vm.notice {
                        NoticeCard(notice: notice)
                            .padding(.bottom, 8)
                    }
                    mainContent
                }
            }

            // Scrim: tap outside the panel to dismiss.
            if drawerOpen {
                Color.black.opacity(0.4)
                    .ignoresSafeArea()
                    .transition(.opacity)
                    .onTapGesture { closeDrawer() }
            }

            // Slide-over panel (~82% width), anchored to the leading edge.
            GeometryReader { geo in
                let width = min(geo.size.width * 0.82, 340)
                DrawerView(
                    core: core,
                    onNewChat: { closeDrawer(); core.send(.newChat) },
                    onOpenReports: { closeDrawer(); core.send(.openDocuments); showDocuments = true },
                    onOpenSettings: { closeDrawer(); showSettings = true },
                    onSelectChat: { id in closeDrawer(); core.send(.selectConversation(id)) },
                    onLogout: { logout() }
                )
                .frame(width: width)
                .frame(maxHeight: .infinity)
                .offset(x: drawerOpen ? 0 : -width - 8)
            }
        }
        .animation(.easeInOut(duration: 0.22), value: drawerOpen)
    }

    private func openDrawer() {
        core.send(.openHistory) // refresh recent-chats list when the drawer opens
        drawerOpen = true
    }
    private func closeDrawer() { drawerOpen = false }

    /// Sign out: clear the persisted token and reset the in-core session, then
    /// return to the sign-in screen.
    private func logout() {
        closeDrawer()
        KeychainStore.clear()
        core.setToken("")
        core.send(.logout)
        hasToken = false
    }

    /// Adopt the workspace-scoped token from the browser flow and advance to
    /// the Scan screen. Persists the token to the Keychain so a relaunch can
    /// skip sign-in (mirrors the Dioxus `persist_matrix_token` flow).
    private func adoptToken(_ token: String) {
        NSLog("[PickCrux] adoptToken: got token len=\(token.count), advancing past Sign In")
        core.setToken(token)
        KeychainStore.save(token)
        hasToken = true
    }

    /// On launch, restore a previously-persisted token from the Keychain and
    /// skip sign-in if it isn't expired. An expired token is cleared so we fall
    /// through to a fresh sign-in.
    private func restorePersistedToken() {
        guard !hasToken, let token = KeychainStore.load() else { return }
        if KeychainStore.isTokenExpired(token) {
            NSLog("[PickCrux] restore: persisted token expired, clearing")
            KeychainStore.clear()
            return
        }
        NSLog("[PickCrux] restore: adopting persisted token len=\(token.count)")
        core.setToken(token)
        hasToken = true
    }

    @ViewBuilder private var mainContent: some View {
        if core.vm.showScanCard {
            // Start screen: the Scan CTA plus a message box, so the user can
            // either run the network scan or start a freeform chat. Sending a
            // message here creates a conversation just like the chat screen.
            VStack(spacing: 0) {
                ScrollView {
                    VStack(spacing: 16) {
                        ScanCard(core: core)
                    }
                    .padding(16)
                }
                InputRow(core: core)
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

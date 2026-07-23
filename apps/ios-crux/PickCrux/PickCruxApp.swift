import SwiftUI
import Sentry

@main
struct PickCruxApp: App {
    // Placeholder api_url/token: real Matrix/OAuth wiring is a later task.
    // Network calls may error into ViewModel.error, which the UI renders.
    @StateObject private var core = CoreBridge(
        apiUrl: "https://plg.strike48.test",
        token: "placeholder-token"
    )!

    init() {
        Self.initNativeCrashReporting()
    }

    var body: some Scene {
        WindowGroup {
            ContentView(core: core)
        }
    }

    /// Initialise sentry-cocoa for native (SwiftUI/Obj-C) crash + app-hang
    /// capture — the layer the Rust SDK can't see. DSN/env come from Info.plist
    /// (substituted from the SENTRY_DSN / SENTRY_ENV build settings, which come
    /// from the build env). Empty/unsubstituted DSN => not initialised. Respects
    /// the persisted telemetry opt-out (the Rust core enforces the same flag for
    /// its own client); a mid-session toggle takes effect on next launch.
    private static func initNativeCrashReporting() {
        let info = Bundle.main.infoDictionary
        guard let dsn = info?["SentryDSN"] as? String,
              !dsn.isEmpty,
              !dsn.hasPrefix("$(") // unsubstituted placeholder = no DSN set
        else { return }
        guard SettingsStore.telemetryEnabled else { return }

        let env = (info?["SentryEnv"] as? String).flatMap { $0.hasPrefix("$(") ? nil : $0 }
            ?? "production"
        let release = "pick-crux@\(info?["CFBundleShortVersionString"] as? String ?? "0")"
        SentrySDK.start { options in
            options.dsn = dsn
            options.environment = env
            options.releaseName = release
            options.enableAppHangTracking = true
            // Native performance: app-start timing + slow/frozen frames are
            // attached to the SDK's auto-generated UI transactions, so they only
            // flow when tracing is sampled. Enable auto perf tracing at a modest
            // rate to get those mobile vitals. These native screen-load traces
            // are complementary to (not duplicates of) the Rust core's UI-action
            // traces, which use different span names.
            options.enableAutoPerformanceTracing = true
            options.tracesSampleRate = 1.0
            // Auto breadcrumbs (view lifecycle / UI / network) are on by default
            // and give a crash report its leadup; left enabled.
            options.sendDefaultPii = false
            options.beforeSend = { event in
                event.tags = (event.tags ?? [:]).merging(["app.layer": "native_view"]) { _, new in new }
                return event
            }
        }
    }
}

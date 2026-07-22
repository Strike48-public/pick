import SwiftUI

@main
struct PickCruxApp: App {
    // Placeholder api_url/token: real Matrix/OAuth wiring is a later task.
    // Network calls may error into ViewModel.error, which the UI renders.
    @StateObject private var core = CoreBridge(
        apiUrl: "https://plg.strike48.test",
        token: "placeholder-token"
    )!

    var body: some Scene {
        WindowGroup {
            ContentView(core: core)
        }
    }
}

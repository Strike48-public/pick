import Foundation
import PickShared

/// Swift wrapper over the crux FFI C ABI (libpick_crux_ffi.a). The shell is a
/// pure view of `ViewModel`; it only encodes `Event`s and decodes the returned
/// ViewModel bytes.
///
/// Pentest effects resolve in-core (Design A). The core is built with a
/// placeholder token; the shell performs native OAuth and adopts the
/// workspace-scoped session token via `setToken` before scanning.
final class CoreBridge: ObservableObject {
    private var handle: OpaquePointer!

    @Published var vm: ViewModel

    init?(apiUrl: String, token: String) {
        let apiUrlBytes = Array(apiUrl.utf8)
        let tokenBytes = Array(token.utf8)

        // Build with a null notify user-data; we register the real callback via
        // pick_set_notify once `self` is fully initialized (Swift forbids
        // capturing `self` before all stored properties are set).
        let handle: OpaquePointer? = apiUrlBytes.withUnsafeBufferPointer { urlBuf in
            tokenBytes.withUnsafeBufferPointer { tokBuf in
                pick_core_new(
                    urlBuf.baseAddress, UInt(urlBuf.count),
                    tokBuf.baseAddress, UInt(tokBuf.count),
                    CoreBridge.notifyThunk,
                    nil
                )
            }
        }
        guard let handle, let initial = CoreBridge.decodeView(handle) else { return nil }
        self.handle = handle
        self.vm = initial

        // Now `self` is fully initialized: register it as the notify user-data.
        let selfPtr = Unmanaged.passUnretained(self).toOpaque()
        pick_set_notify(handle, CoreBridge.notifyThunk, selfPtr)
    }

    /// C notify thunk: called (possibly off-main) when an async effect resolves
    /// and the view may have changed. Hops to main and re-reads the view — the
    /// streaming path. `userData` is the `CoreBridge` pointer registered above.
    private static let notifyThunk: NotifyFn = { userData in
        guard let userData else { return }
        let bridge = Unmanaged<CoreBridge>.fromOpaque(userData).takeUnretainedValue()
        DispatchQueue.main.async { bridge.refresh() }
    }

    deinit {
        if let handle { pick_core_free(handle) }
    }

    /// Re-read the current view from the core and publish it. Called from the
    /// notify callback (on the main thread) as async effects resolve.
    func refresh() {
        if let next = CoreBridge.decodeView(handle) {
            vm = next
        }
    }

    /// Feed an `Event`. Returns immediately — `Pentest` effects resolve on a
    /// background thread in the core and stream back via the notify callback,
    /// which calls `refresh()`. We refresh once here for any synchronous
    /// (Render) state change too.
    func send(_ event: Event) {
        guard let eventBytes = try? event.bincodeSerialize() else { return }
        eventBytes.withUnsafeBufferPointer { buf in
            let out = pick_update(handle, buf.baseAddress, UInt(buf.count))
            pick_buf_free(out)
        }
        refresh()
    }

    /// Adopt a token obtained via native OAuth (`ASWebAuthenticationSession`).
    /// Calls `pick_set_token`, then refreshes the view so subsequent scans use
    /// the workspace-scoped session token.
    func setToken(_ token: String) {
        let tokenBytes = Array(token.utf8)
        tokenBytes.withUnsafeBufferPointer { buf in
            pick_set_token(handle, buf.baseAddress, UInt(buf.count))
        }
        if let next = CoreBridge.decodeView(handle) {
            vm = next
        }
    }

    private static func decodeView(_ handle: OpaquePointer) -> ViewModel? {
        let buf = pick_view(handle)
        defer { pick_buf_free(buf) }
        guard let ptr = buf.ptr, buf.len > 0 else { return nil }
        let bytes = Array(UnsafeBufferPointer(start: ptr, count: Int(buf.len)))
        return try? ViewModel.bincodeDeserialize(input: bytes)
    }
}

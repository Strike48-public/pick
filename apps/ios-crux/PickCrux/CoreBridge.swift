import Foundation
import PickShared

/// Swift wrapper over the crux FFI C ABI (libpick_crux_ffi.a). The shell is a
/// pure view of `ViewModel`; it only encodes `Event`s and decodes the returned
/// ViewModel bytes.
///
/// Pentest effects resolve in-core (Design A). For this task the core is built
/// with a placeholder api_url/token, so network calls may populate
/// `ViewModel.error`, which the UI renders.
final class CoreBridge: ObservableObject {
    private let handle: OpaquePointer

    @Published var vm: ViewModel

    init?(apiUrl: String, token: String) {
        let apiUrlBytes = Array(apiUrl.utf8)
        let tokenBytes = Array(token.utf8)

        let handle: OpaquePointer? = apiUrlBytes.withUnsafeBufferPointer { urlBuf in
            tokenBytes.withUnsafeBufferPointer { tokBuf in
                pick_core_new(urlBuf.baseAddress, UInt(urlBuf.count), tokBuf.baseAddress, UInt(tokBuf.count))
            }
        }
        guard let handle else { return nil }
        self.handle = handle

        // Initial view. If decoding fails we cannot proceed.
        guard let initial = CoreBridge.decodeView(handle) else { return nil }
        self.vm = initial
    }

    deinit {
        pick_core_free(handle)
    }

    /// Feed an `Event`, drain in-core Pentest effects, then refresh the view.
    /// The update return (remaining Render request bytes) is ignored here; a
    /// fresh view reflects the new state.
    func send(_ event: Event) {
        guard let eventBytes = try? event.bincodeSerialize() else { return }
        eventBytes.withUnsafeBufferPointer { buf in
            let out = pick_update(handle, buf.baseAddress, UInt(buf.count))
            pick_buf_free(out)
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

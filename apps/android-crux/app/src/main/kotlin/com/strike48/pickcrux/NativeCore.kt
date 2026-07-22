package com.strike48.pickcrux

import com.strike48.pick.shared.Event
import com.strike48.pick.shared.ViewModel

/**
 * Kotlin wrapper over the crux FFI C ABI (libpick_crux_ffi.so, reached through
 * the libpickcrux_jni.so shim). The shell is a pure view of [ViewModel]; it
 * only encodes [Event]s and decodes the returned ViewModel bytes.
 *
 * Pentest effects resolve in-core (Design A). For this task the core is built
 * with a placeholder api_url/token, so network calls may populate
 * ViewModel.error, which the UI renders.
 */
class NativeCore private constructor(private val handle: Long) {

    fun view(): ViewModel {
        val bytes = nativeView(handle)
        return ViewModel.bincodeDeserialize(bytes)
    }

    /**
     * Feed an [Event], drain in-core Pentest effects, then read the new view.
     * The update return (remaining Render request bytes) is ignored here; a
     * fresh [view] call reflects the new state.
     */
    fun update(event: Event): ViewModel {
        nativeUpdate(handle, event.bincodeSerialize())
        return view()
    }

    fun free() {
        nativeFree(handle)
    }

    companion object {
        init {
            System.loadLibrary("pickcrux_jni")
        }

        fun create(apiUrl: String, token: String): NativeCore {
            val handle = nativeNew(
                apiUrl.toByteArray(Charsets.UTF_8),
                token.toByteArray(Charsets.UTF_8),
            )
            check(handle != 0L) { "pick_core_new returned null" }
            return NativeCore(handle)
        }

        @JvmStatic private external fun nativeNew(apiUrl: ByteArray, token: ByteArray): Long
        @JvmStatic private external fun nativeFree(handle: Long)
        @JvmStatic private external fun nativeView(handle: Long): ByteArray
        @JvmStatic private external fun nativeUpdate(handle: Long, event: ByteArray): ByteArray
    }
}

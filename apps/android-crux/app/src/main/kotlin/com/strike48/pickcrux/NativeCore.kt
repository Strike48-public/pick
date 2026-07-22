package com.strike48.pickcrux

import android.os.Handler
import android.os.Looper
import com.strike48.pick.shared.Event
import com.strike48.pick.shared.ViewModel
import java.util.concurrent.ConcurrentHashMap

/**
 * Kotlin wrapper over the crux FFI C ABI (libpick_crux_ffi.so, reached through
 * the libpickcrux_jni.so shim). The shell is a pure view of [ViewModel]; it
 * only encodes [Event]s and decodes the returned ViewModel bytes.
 *
 * Streaming is push-based: `Pentest` effects resolve on a background thread in
 * the core, and the core pings us via a JNI notify. [onNotify] maps the native
 * handle back to the live instance and re-reads the view on the main thread,
 * invoking [onViewChanged] so Compose can re-render as the scan streams.
 */
class NativeCore private constructor(private val handle: Long) {

    /** Set by the UI to observe streamed view updates (invoked on the main thread). */
    var onViewChanged: ((ViewModel) -> Unit)? = null

    init {
        INSTANCES[handle] = this
    }

    fun view(): ViewModel {
        return ViewModel.bincodeDeserialize(nativeView(handle))
    }

    /**
     * Feed an [Event]. Returns the view immediately after the (non-blocking)
     * update; further changes stream in via [onViewChanged] as async effects
     * resolve.
     */
    fun update(event: Event): ViewModel {
        nativeUpdate(handle, event.bincodeSerialize())
        return view()
    }

    /**
     * Adopt a workspace-scoped Studio session token obtained by the shell via
     * native OAuth. Subsequent [view]/[update] calls use the new credential.
     */
    fun setToken(token: String) {
        nativeSetToken(handle, token.toByteArray(Charsets.UTF_8))
    }

    fun free() {
        INSTANCES.remove(handle)
        nativeFree(handle)
    }

    companion object {
        private val INSTANCES = ConcurrentHashMap<Long, NativeCore>()
        private val MAIN = Handler(Looper.getMainLooper())

        init {
            System.loadLibrary("pickcrux_jni")
        }

        /**
         * Build a core against [apiUrl] with an optional bootstrap [token]. The
         * tenant scope for a scan is derived in-core from the session token's
         * realm once OAuth provides it via [setToken], so the shell passes no
         * tenant here.
         */
        fun create(apiUrl: String, token: String): NativeCore {
            val handle = nativeNew(
                apiUrl.toByteArray(Charsets.UTF_8),
                token.toByteArray(Charsets.UTF_8),
            )
            check(handle != 0L) { "pick_core_new returned null" }
            return NativeCore(handle)
        }

        /**
         * Called from the JNI notify thunk (on the core's background thread) when
         * an async effect resolves. Hops to the main thread, re-reads the view,
         * and notifies the observer so Compose re-renders. This is the streaming
         * signal — no polling.
         */
        @JvmStatic
        fun onNotify(handle: Long) {
            MAIN.post {
                val core = INSTANCES[handle] ?: return@post
                core.onViewChanged?.invoke(core.view())
            }
        }

        @JvmStatic private external fun nativeNew(apiUrl: ByteArray, token: ByteArray): Long
        @JvmStatic private external fun nativeSetToken(handle: Long, token: ByteArray)
        @JvmStatic private external fun nativeFree(handle: Long)
        @JvmStatic private external fun nativeView(handle: Long): ByteArray
        @JvmStatic private external fun nativeUpdate(handle: Long, event: ByteArray): ByteArray
    }
}

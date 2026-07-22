// JNI bridge from Kotlin (com.strike48.pickcrux.NativeCore) to the crux FFI
// C ABI exposed by libpick_crux_ffi.so. Owns no state beyond the opaque
// PickCore* handle, which Kotlin holds as a jlong. Every PickBuf returned by
// the core is copied into a jbyteArray and freed here before returning.

#include <jni.h>
#include <stdint.h>
#include <string.h>

// ---- Mirror of crates/crux-ffi/include/pick_crux_ffi.h ----
typedef struct PickCore PickCore;

typedef struct PickBuf {
    uint8_t *ptr;
    uintptr_t len;
    uintptr_t cap;
} PickBuf;

// The Rust notify callback type: extern "C" fn(user_data: *mut c_void).
typedef void (*NotifyFn)(void *user_data);

extern PickCore *pick_core_new(const uint8_t *api_url_ptr, uintptr_t api_url_len,
                               const uint8_t *token_ptr, uintptr_t token_len,
                               NotifyFn notify, void *user_data);
extern void pick_set_notify(PickCore *core, NotifyFn notify, void *user_data);
extern void pick_set_token(PickCore *core, const uint8_t *token_ptr, uintptr_t token_len);
extern void pick_core_free(PickCore *core);
extern void pick_buf_free(PickBuf buf);
extern PickBuf pick_view(PickCore *core);
extern PickBuf pick_update(PickCore *core, const uint8_t *event_ptr, uintptr_t event_len);

// ---- Notify bridge: Rust (bg thread) -> JVM -> Kotlin NativeCore.onNotify ----
// Cached JavaVM (from JNI_OnLoad) so the notify callback, which fires on Rust's
// background thread, can attach and call back into Kotlin.
static JavaVM *g_vm = NULL;
static jclass g_native_core_cls = NULL;   // global ref to NativeCore
static jmethodID g_on_notify = NULL;      // static void onNotify(long handle)

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_vm = vm;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass local = (*env)->FindClass(env, "com/strike48/pickcrux/NativeCore");
    if (local != NULL) {
        g_native_core_cls = (jclass)(*env)->NewGlobalRef(env, local);
        g_on_notify = (*env)->GetStaticMethodID(env, g_native_core_cls, "onNotify", "(J)V");
        (*env)->DeleteLocalRef(env, local);
    }
    return JNI_VERSION_1_6;
}

// Invoked by the crux bridge on a Rust background thread when an async effect
// resolves. user_data is the PickCore* handle (as void*). Attaches to the JVM
// and calls NativeCore.onNotify(handle), which hops to the UI thread.
static void notify_thunk(void *user_data) {
    if (g_vm == NULL || g_native_core_cls == NULL || g_on_notify == NULL) return;
    JNIEnv *env = NULL;
    int attached = 0;
    jint st = (*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6);
    if (st == JNI_EDETACHED) {
        if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) return;
        attached = 1;
    } else if (st != JNI_OK) {
        return;
    }
    (*env)->CallStaticVoidMethod(env, g_native_core_cls, g_on_notify, (jlong)(uintptr_t)user_data);
    if (attached) (*g_vm)->DetachCurrentThread(g_vm);
}

// Copy a PickBuf into a freshly-allocated jbyteArray, then free the PickBuf.
static jbyteArray buf_to_java(JNIEnv *env, PickBuf buf) {
    jbyteArray out = (*env)->NewByteArray(env, (jsize)buf.len);
    if (out != NULL && buf.ptr != NULL && buf.len > 0) {
        (*env)->SetByteArrayRegion(env, out, 0, (jsize)buf.len, (const jbyte *)buf.ptr);
    }
    pick_buf_free(buf);
    return out;
}

JNIEXPORT jlong JNICALL
Java_com_strike48_pickcrux_NativeCore_nativeNew(JNIEnv *env, jclass clazz,
                                                jbyteArray apiUrl, jbyteArray token) {
    jsize url_len = (*env)->GetArrayLength(env, apiUrl);
    jsize tok_len = (*env)->GetArrayLength(env, token);
    jbyte *url_bytes = (*env)->GetByteArrayElements(env, apiUrl, NULL);
    jbyte *tok_bytes = (*env)->GetByteArrayElements(env, token, NULL);

    // Build with a null user_data first, then set user_data = the handle itself
    // so notify_thunk can pass it to NativeCore.onNotify (which maps handle ->
    // the live instance and refreshes on the UI thread).
    PickCore *core = pick_core_new((const uint8_t *)url_bytes, (uintptr_t)url_len,
                                   (const uint8_t *)tok_bytes, (uintptr_t)tok_len,
                                   notify_thunk, NULL);

    (*env)->ReleaseByteArrayElements(env, apiUrl, url_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, token, tok_bytes, JNI_ABORT);

    // user_data = the handle, delivered back to onNotify(long).
    if (core != NULL) {
        pick_set_notify(core, notify_thunk, (void *)core);
    }
    return (jlong)(uintptr_t)core;
}

JNIEXPORT void JNICALL
Java_com_strike48_pickcrux_NativeCore_nativeSetToken(JNIEnv *env, jclass clazz, jlong handle,
                                                     jbyteArray token) {
    jsize tok_len = (*env)->GetArrayLength(env, token);
    jbyte *tok_bytes = (*env)->GetByteArrayElements(env, token, NULL);
    pick_set_token((PickCore *)(uintptr_t)handle,
                   (const uint8_t *)tok_bytes, (uintptr_t)tok_len);
    (*env)->ReleaseByteArrayElements(env, token, tok_bytes, JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_com_strike48_pickcrux_NativeCore_nativeFree(JNIEnv *env, jclass clazz, jlong handle) {
    pick_core_free((PickCore *)(uintptr_t)handle);
}

JNIEXPORT jbyteArray JNICALL
Java_com_strike48_pickcrux_NativeCore_nativeView(JNIEnv *env, jclass clazz, jlong handle) {
    PickBuf buf = pick_view((PickCore *)(uintptr_t)handle);
    return buf_to_java(env, buf);
}

JNIEXPORT jbyteArray JNICALL
Java_com_strike48_pickcrux_NativeCore_nativeUpdate(JNIEnv *env, jclass clazz, jlong handle,
                                                   jbyteArray event) {
    jsize ev_len = (*env)->GetArrayLength(env, event);
    jbyte *ev_bytes = (*env)->GetByteArrayElements(env, event, NULL);
    PickBuf buf = pick_update((PickCore *)(uintptr_t)handle,
                              (const uint8_t *)ev_bytes, (uintptr_t)ev_len);
    (*env)->ReleaseByteArrayElements(env, event, ev_bytes, JNI_ABORT);
    return buf_to_java(env, buf);
}

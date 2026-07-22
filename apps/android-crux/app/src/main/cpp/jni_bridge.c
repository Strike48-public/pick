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

extern PickCore *pick_core_new(const uint8_t *api_url_ptr, uintptr_t api_url_len,
                               const uint8_t *token_ptr, uintptr_t token_len);
extern void pick_set_token(PickCore *core, const uint8_t *token_ptr, uintptr_t token_len);
extern void pick_core_free(PickCore *core);
extern void pick_buf_free(PickBuf buf);
extern PickBuf pick_view(PickCore *core);
extern PickBuf pick_update(PickCore *core, const uint8_t *event_ptr, uintptr_t event_len);

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

    PickCore *core = pick_core_new((const uint8_t *)url_bytes, (uintptr_t)url_len,
                                   (const uint8_t *)tok_bytes, (uintptr_t)tok_len);

    (*env)->ReleaseByteArrayElements(env, apiUrl, url_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, token, tok_bytes, JNI_ABORT);
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

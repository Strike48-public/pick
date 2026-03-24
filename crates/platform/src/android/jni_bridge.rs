//! JNI bridge infrastructure for Android platform calls (bd-18)
//!
//! Provides safe wrappers around JNI access via ndk-context.
//! - `with_jni`: attach current thread, get Context, run closure (works from any thread)
//! - `with_activity`: same as with_jni but loads custom classes via stored classloader
//! - `jstring_to_string`: null-safe JObject -> String conversion
//! - `check_permission`: runtime permission check

use jni::objects::{GlobalRef, JObject, JString, JValue};
use jni::{JNIEnv, JavaVM};
use pentest_core::error::{Error, Result};
use std::sync::OnceLock;

static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();
static CLASS_LOADER: OnceLock<GlobalRef> = OnceLock::new();

fn init_vm() -> Result<()> {
    if JAVA_VM.get().is_some() {
        return Ok(());
    }
    let ctx = ndk_context::android_context();
    let vm_ptr = ctx.vm();
    // SAFETY: ndk-context guarantees a valid JavaVM pointer while the app is alive
    let vm = unsafe { JavaVM::from_raw(vm_ptr as *mut jni::sys::JavaVM) }
        .map_err(|e| Error::ToolExecution(format!("Failed to get JavaVM: {e}")))?;
    let _ = JAVA_VM.set(vm);
    Ok(())
}

/// Get the cached JavaVM
pub fn get_vm() -> Result<&'static JavaVM> {
    init_vm()?;
    JAVA_VM
        .get()
        .ok_or_else(|| Error::ToolExecution("JavaVM not initialized".into()))
}

/// Attach current thread to JVM, obtain the application Context, and run `f`.
///
/// Works from any Rust thread — uses ndk-context directly so the system
/// classloader is available (sufficient for standard SDK classes like
/// WifiManager, Build, PackageManager, etc.).
pub fn with_jni<F, R>(f: F) -> Result<R>
where
    F: FnOnce(&mut JNIEnv, &JObject) -> Result<R>,
{
    let vm = get_vm()?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|e| Error::ToolExecution(format!("JNI attach failed: {e}")))?;

    let ctx = ndk_context::android_context();
    let context_ptr = ctx.context();
    // SAFETY: ndk-context guarantees a valid android.content.Context jobject
    let context = unsafe { JObject::from_raw(context_ptr as jni::sys::jobject) };

    f(&mut env, &context)
}

/// Run a closure with JNI access and the Activity's classloader available.
///
/// On first call, caches the classloader from the Context so that subsequent
/// calls from any thread can find custom Kotlin classes in the APK.
/// This avoids needing wry::prelude::dispatch to run on the UI thread.
pub fn with_activity<F, R>(f: F) -> Result<R>
where
    F: FnOnce(&mut JNIEnv, &JObject) -> Result<R> + Send + 'static,
    R: Send + 'static,
{
    // Just delegate to with_jni — on Android/Dioxus, ndk_context().context()
    // IS the Activity, and its classloader can find our custom Kotlin classes.
    // We cache the classloader on first call for potential future use.
    with_jni(|env, ctx| {
        // Ensure classloader is cached
        if CLASS_LOADER.get().is_none() {
            if let Ok(cl) = env
                .call_method(ctx, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
                .and_then(|v| v.l())
            {
                if let Ok(global) = env.new_global_ref(&cl) {
                    let _ = CLASS_LOADER.set(global);
                }
            }
        }
        f(env, ctx)
    })
}

/// Convert a JNI JString (or null JObject) to a Rust String.
/// Returns an empty string for null references.
pub fn jstring_to_string(env: &mut JNIEnv, obj: &JObject) -> String {
    if obj.is_null() {
        return String::new();
    }
    // SAFETY: we checked for null above; the caller ensures obj is a java.lang.String
    let jstr: &JString = unsafe { std::mem::transmute(obj) };
    env.get_string(jstr).map(|s| s.into()).unwrap_or_default()
}

/// Find a class using the app's classloader (cached from the Activity context).
///
/// Unlike `env.find_class()` which uses the current thread's classloader (system
/// classloader on Rust-spawned threads), this uses the Activity's classloader
/// which can see custom Kotlin classes compiled into the APK.
pub fn find_app_class<'a>(env: &mut JNIEnv<'a>, name: &str) -> Result<jni::objects::JClass<'a>> {
    let class_loader = CLASS_LOADER.get().ok_or_else(|| {
        Error::ToolExecution("App classloader not cached — call with_activity first".into())
    })?;

    let class_name = env
        .new_string(name.replace('/', "."))
        .map_err(|e| Error::ToolExecution(format!("JNI string error: {e}")))?;

    let cls = env
        .call_method(
            class_loader.as_obj(),
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&class_name.into())],
        )
        .and_then(|v| v.l())
        .map_err(|e| Error::ToolExecution(format!("Class not found '{name}': {e}")))?;

    Ok(cls.into())
}

/// Request all required runtime permissions via the PermissionRequester Kotlin helper.
/// Should be called once at app startup from the main thread.
pub fn request_permissions() {
    let _ = with_activity(|env, activity| {
        let cls = find_app_class(env, "com/strike48/pentest_connector/PermissionRequester")?;
        env.call_static_method(
            &cls,
            "requestAll",
            "(Landroid/app/Activity;)V",
            &[JValue::Object(activity)],
        )
        .map_err(|e| Error::ToolExecution(format!("requestAll: {e}")))?;
        Ok(())
    });
}

/// Start the foreground service to keep the connector alive in the background.
///
/// Calls `ConnectorService.start(context)` which acquires wake locks and WiFi locks,
/// and displays a persistent notification as required by Android foreground service rules.
pub fn start_foreground_service() {
    let result = with_activity(|env, activity| {
        let cls = find_app_class(env, "com/strike48/pentest_connector/ConnectorService")?;
        env.call_static_method(
            &cls,
            "start",
            "(Landroid/content/Context;)V",
            &[JValue::Object(activity)],
        )
        .map_err(|e| Error::ToolExecution(format!("ConnectorService.start: {e}")))?;
        Ok(())
    });
    match result {
        Ok(()) => tracing::info!("[Android] Foreground service started"),
        Err(e) => tracing::warn!("[Android] Failed to start foreground service: {}", e),
    }
}

/// Launch the screen capture consent dialog (MediaProjection).
/// This must be called before `capture_screenshot` will work.
/// The consent dialog is an OS-level Activity that returns a MediaProjection token.
pub fn request_screen_capture() {
    let _ = with_activity(|env, activity| {
        let ctx = env
            .call_method(
                activity,
                "getApplicationContext",
                "()Landroid/content/Context;",
                &[],
            )
            .and_then(|v| v.l())
            .map_err(|e| Error::ToolExecution(format!("getApplicationContext: {e}")))?;

        let bridge_cls = find_app_class(env, "com/strike48/pentest_connector/ConnectorBridge")?;
        env.call_static_method(
            &bridge_cls,
            "requestScreenCapture",
            "(Landroid/content/Context;)V",
            &[JValue::Object(&ctx)],
        )
        .map_err(|e| Error::ToolExecution(format!("requestScreenCapture: {e}")))?;
        Ok(())
    });
}

/// Check whether a runtime permission is granted.
/// Returns true if `Context.checkSelfPermission(permission) == PERMISSION_GRANTED (0)`.
pub fn check_permission(env: &mut JNIEnv, ctx: &JObject, permission: &str) -> bool {
    let Ok(perm_jstr) = env.new_string(permission) else {
        return false;
    };
    let result = env.call_method(
        ctx,
        "checkSelfPermission",
        "(Ljava/lang/String;)I",
        &[JValue::Object(&perm_jstr.into())],
    );
    match result {
        Ok(val) => val.i().unwrap_or(-1) == 0,
        Err(_) => false,
    }
}

/// Tell the Android OAuthCallbackActivity which port the local callback server is on.
///
/// Called before opening the browser for OAuth so the Activity knows where to
/// forward the access token it receives via the custom URI scheme intent.
pub fn set_oauth_callback_port(port: u16) -> Result<()> {
    with_activity(move |env, _activity| {
        let bridge_cls = find_app_class(env, "com/strike48/pentest_connector/ConnectorBridge")?;
        env.call_static_method(
            &bridge_cls,
            "setOAuthCallbackPort",
            "(I)V",
            &[JValue::Int(port as i32)],
        )
        .map_err(|e| Error::ToolExecution(format!("setOAuthCallbackPort: {e}")))?;
        Ok(())
    })
}

/// Open a URL in the system browser via Android Intent.
///
/// Uses ConnectorBridge.invoke(context, "open_browser", {"url": "..."})
pub fn open_browser(url: &str) -> Result<()> {
    let params = serde_json::json!({ "url": url }).to_string();

    with_activity(move |env, activity| {
        let ctx = env
            .call_method(
                activity,
                "getApplicationContext",
                "()Landroid/content/Context;",
                &[],
            )
            .and_then(|v| v.l())
            .map_err(|e| Error::ToolExecution(format!("getApplicationContext: {e}")))?;

        let bridge_cls = find_app_class(env, "com/strike48/pentest_connector/ConnectorBridge")?;

        let method_str = env
            .new_string("open_browser")
            .map_err(|e| Error::ToolExecution(format!("JNI string: {e}")))?;
        let params_str = env
            .new_string(&params)
            .map_err(|e| Error::ToolExecution(format!("JNI string: {e}")))?;

        let result = env
            .call_static_method(
                &bridge_cls,
                "invoke",
                "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                &[
                    JValue::Object(&ctx),
                    JValue::Object(&method_str.into()),
                    JValue::Object(&params_str.into()),
                ],
            )
            .and_then(|v| v.l())
            .map_err(|e| Error::ToolExecution(format!("ConnectorBridge.invoke: {e}")))?;

        let result_str = jstring_to_string(env, &result);

        // Check for error response
        if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&result_str) {
            if let Some(err) = obj.get("error").and_then(|e| e.as_str()) {
                return Err(Error::ToolExecution(format!("open_browser error: {err}")));
            }
        }

        Ok(())
    })
}

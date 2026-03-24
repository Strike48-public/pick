//! Android screenshot capture via Kotlin bridge (bd-21)
//!
//! Uses `with_activity` to invoke `ConnectorBridge.invoke(context, "capture_screenshot", "{}")`
//! which uses MediaProjection + VirtualDisplay + ImageReader on the Kotlin side.

use super::jni_bridge::{find_app_class, jstring_to_string, with_activity};
use jni::objects::JValue;
use pentest_core::error::{Error, Result};

/// Capture a screenshot via the Kotlin ConnectorBridge.
/// Returns raw PNG bytes.
pub async fn capture_screenshot() -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(capture_screenshot_blocking)
        .await
        .map_err(|e| Error::ToolExecution(format!("Screenshot join error: {e}")))?
}

fn capture_screenshot_blocking() -> Result<Vec<u8>> {
    let json_str = with_activity(|env, activity| {
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
            .new_string("capture_screenshot")
            .map_err(|e| Error::ToolExecution(format!("JNI string: {e}")))?;
        let params_str = env
            .new_string("{}")
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

        Ok(jstring_to_string(env, &result))
    })?;

    // Parse the JSON response — either base64 data or an error
    let resp: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| Error::ToolExecution(format!("Screenshot JSON parse: {e}")))?;

    if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
        // If MediaProjection isn't available, request consent and tell user to retry.
        if err.contains("MediaProjection") {
            super::jni_bridge::request_screen_capture();
            return Err(Error::ToolExecution(
                "Screen capture permission requested. Please grant the permission in the dialog and retry.".into(),
            ));
        }
        return Err(Error::ToolExecution(format!("Screenshot error: {err}")));
    }

    let b64 = resp
        .get("data")
        .and_then(|d| d.as_str())
        .ok_or_else(|| Error::ToolExecution("Screenshot response missing 'data' field".into()))?;

    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| Error::ToolExecution(format!("Screenshot base64 decode: {e}")))
}

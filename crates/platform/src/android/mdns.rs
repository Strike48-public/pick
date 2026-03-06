//! Android mDNS discovery via Kotlin bridge (bd-24)
//!
//! Uses `with_activity` to invoke `ConnectorBridge.invoke(context, "mdns_discover", paramsJson)`
//! on the UI thread where the APK classloader is available.

use super::jni_bridge::{find_app_class, jstring_to_string, with_activity};
use crate::traits::MdnsService;
use jni::objects::JValue;
use pentest_core::error::{Error, Result};
use std::collections::HashMap;

/// Discover mDNS services via the Kotlin ConnectorBridge.
pub async fn mdns_discover(service_type: &str, timeout_ms: u64) -> Result<Vec<MdnsService>> {
    let service_type = service_type.to_string();
    tokio::task::spawn_blocking(move || mdns_discover_blocking(&service_type, timeout_ms))
        .await
        .map_err(|e| Error::ToolExecution(format!("mDNS join error: {e}")))?
}

fn mdns_discover_blocking(service_type: &str, timeout_ms: u64) -> Result<Vec<MdnsService>> {
    let params = serde_json::json!({
        "service_type": service_type,
        "timeout_ms": timeout_ms,
    })
    .to_string();

    let json_str = with_activity(move |env, activity| {
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
            .new_string("mdns_discover")
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

        Ok(jstring_to_string(env, &result))
    })?;

    parse_mdns_json(&json_str)
}

fn parse_mdns_json(json_str: &str) -> Result<Vec<MdnsService>> {
    // Check for error response
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(json_str) {
        if let Some(err) = obj.get("error").and_then(|e| e.as_str()) {
            return Err(Error::ToolExecution(format!("mDNS bridge error: {err}")));
        }
    }

    let items: Vec<serde_json::Value> = serde_json::from_str(json_str)
        .map_err(|e| Error::ToolExecution(format!("mDNS JSON parse: {e}")))?;

    Ok(items
        .into_iter()
        .filter_map(|v| {
            Some(MdnsService {
                name: v.get("name")?.as_str()?.to_string(),
                service_type: v.get("service_type")?.as_str()?.to_string(),
                host: v
                    .get("host")
                    .and_then(|h| h.as_str())
                    .unwrap_or("")
                    .to_string(),
                port: v.get("port").and_then(|p| p.as_u64()).unwrap_or(0) as u16,
                txt_records: v
                    .get("txt_records")
                    .and_then(|t| serde_json::from_value::<HashMap<String, String>>(t.clone()).ok())
                    .unwrap_or_default(),
            })
        })
        .collect())
}

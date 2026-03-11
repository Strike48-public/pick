//! Android WiFi scanning via WifiManager JNI (bd-20)
//!
//! Uses pure Rust JNI to call WifiManager.getScanResults() — no Kotlin needed.
//! Requires ACCESS_FINE_LOCATION permission at runtime.

use super::jni_bridge::{check_permission, jstring_to_string, with_jni};
use crate::traits::WifiNetwork;
use jni::objects::{JObject, JValue};
use pentest_core::error::{Error, Result};

/// Retrieve visible WiFi networks via WifiManager.getScanResults().
pub async fn get_wifi_networks() -> Result<Vec<WifiNetwork>> {
    tokio::task::spawn_blocking(get_wifi_networks_blocking)
        .await
        .map_err(|e| Error::ToolExecution(format!("WiFi scan join error: {e}")))?
}

fn get_wifi_networks_blocking() -> Result<Vec<WifiNetwork>> {
    with_jni(|env, ctx| {
        // Check runtime permission
        if !check_permission(env, ctx, "android.permission.ACCESS_FINE_LOCATION") {
            return Err(Error::PermissionDenied(
                "ACCESS_FINE_LOCATION permission required for WiFi scanning".into(),
            ));
        }

        // ctx.getSystemService("wifi") -> WifiManager
        let service_name = env
            .new_string("wifi")
            .map_err(|e| Error::ToolExecution(format!("JNI new_string: {e}")))?;
        let wifi_mgr = env
            .call_method(
                ctx,
                "getSystemService",
                "(Ljava/lang/String;)Ljava/lang/Object;",
                &[JValue::Object(&service_name.into())],
            )
            .and_then(|v| v.l())
            .map_err(|e| Error::ToolExecution(format!("getSystemService(wifi): {e}")))?;

        if wifi_mgr.is_null() {
            return Err(Error::ToolExecution("WifiManager is null".into()));
        }

        // wifiManager.getScanResults() -> List<ScanResult>
        let scan_results = env
            .call_method(&wifi_mgr, "getScanResults", "()Ljava/util/List;", &[])
            .and_then(|v| v.l())
            .map_err(|e| Error::ToolExecution(format!("getScanResults: {e}")))?;

        if scan_results.is_null() {
            return Ok(vec![]);
        }

        let count = env
            .call_method(&scan_results, "size", "()I", &[])
            .and_then(|v| v.i())
            .unwrap_or(0);

        let mut networks = Vec::with_capacity(count as usize);

        for i in 0..count {
            let item = env
                .call_method(
                    &scan_results,
                    "get",
                    "(I)Ljava/lang/Object;",
                    &[JValue::Int(i)],
                )
                .and_then(|v| v.l());

            let Ok(sr) = item else { continue };
            if sr.is_null() {
                continue;
            }

            let ssid = read_string_field(env, &sr, "SSID");
            let bssid = read_string_field(env, &sr, "BSSID");
            let level = read_int_field(env, &sr, "level");
            let frequency = read_int_field(env, &sr, "frequency") as u32;
            let capabilities = read_string_field(env, &sr, "capabilities");

            let channel = freq_to_channel(frequency);
            let security = parse_security(&capabilities);

            networks.push(WifiNetwork {
                ssid,
                bssid,
                signal_strength: level,
                frequency,
                channel,
                security,
                clients: None, // Not available on Android
            });
        }

        Ok(networks)
    })
}

fn read_string_field(env: &mut jni::JNIEnv, obj: &JObject, field: &str) -> String {
    env.get_field(obj, field, "Ljava/lang/String;")
        .and_then(|v| v.l())
        .map(|o| jstring_to_string(env, &o))
        .unwrap_or_default()
}

fn read_int_field(env: &mut jni::JNIEnv, obj: &JObject, field: &str) -> i32 {
    env.get_field(obj, field, "I")
        .and_then(|v| v.i())
        .unwrap_or(0)
}

/// Convert frequency (MHz) to WiFi channel number.
fn freq_to_channel(freq: u32) -> u32 {
    match freq {
        2412..=2484 => (freq - 2407) / 5,
        5170..=5825 => (freq - 5000) / 5,
        // 6 GHz band (WiFi 6E)
        5955..=7115 => (freq - 5950) / 5,
        _ => 0,
    }
}

/// Extract security type from ScanResult capabilities string.
/// e.g. "[WPA2-PSK-CCMP][ESS]" -> "WPA2-PSK"
fn parse_security(capabilities: &str) -> String {
    if capabilities.contains("WPA3") {
        "WPA3".to_string()
    } else if capabilities.contains("WPA2") {
        if capabilities.contains("EAP") {
            "WPA2-Enterprise".to_string()
        } else {
            "WPA2-PSK".to_string()
        }
    } else if capabilities.contains("WPA") {
        "WPA-PSK".to_string()
    } else if capabilities.contains("WEP") {
        "WEP".to_string()
    } else if capabilities.contains("ESS") {
        "Open".to_string()
    } else {
        "Unknown".to_string()
    }
}

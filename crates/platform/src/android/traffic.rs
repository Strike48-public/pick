//! Android traffic capture via VPN service bridge (bd-25)
//!
//! Maps the CaptureOps trait to Kotlin PacketCaptureVpnService static methods.

use super::jni_bridge::{find_app_class, jstring_to_string, with_activity};
use crate::traits::{CaptureHandle, PacketInfo};
use jni::objects::JValue;
use pentest_core::error::{Error, Result};
use std::time::Instant;

/// Start traffic capture via the VPN service.
pub async fn start_traffic_capture() -> Result<CaptureHandle> {
    tokio::task::spawn_blocking(|| {
        with_activity(|env, activity| {
            let ctx = env
                .call_method(
                    activity,
                    "getApplicationContext",
                    "()Landroid/content/Context;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(|e| Error::ToolExecution(format!("getApplicationContext: {e}")))?;

            let vpn_cls = find_app_class(
                env,
                "com/strike48/pentest_connector/PacketCaptureVpnService",
            )?;

            let started = env
                .call_static_method(
                    &vpn_cls,
                    "startCapture",
                    "(Landroid/content/Context;)Z",
                    &[JValue::Object(&ctx)],
                )
                .and_then(|v| v.z())
                .map_err(|e| Error::ToolExecution(format!("startCapture: {e}")))?;

            if !started {
                return Err(Error::ToolExecution(
                    "VPN capture failed to start (user may need to grant VPN permission)".into(),
                ));
            }

            Ok(CaptureHandle {
                id: "android-vpn-capture".to_string(),
                started_at: Instant::now(),
            })
        })
    })
    .await
    .map_err(|e| Error::ToolExecution(format!("Traffic capture join error: {e}")))?
}

/// Retrieve captured packets from the VPN service ring buffer.
pub async fn get_captured_packets(
    _handle: &CaptureHandle,
    limit: usize,
) -> Result<Vec<PacketInfo>> {
    let limit = limit as i32;
    tokio::task::spawn_blocking(move || {
        with_activity(move |env, _activity| {
            let vpn_cls = find_app_class(
                env,
                "com/strike48/pentest_connector/PacketCaptureVpnService",
            )?;

            let result = env
                .call_static_method(
                    &vpn_cls,
                    "getPacketsJson",
                    "(I)Ljava/lang/String;",
                    &[JValue::Int(limit)],
                )
                .and_then(|v| v.l())
                .map_err(|e| Error::ToolExecution(format!("getPacketsJson: {e}")))?;

            let json_str = jstring_to_string(env, &result);
            parse_packets_json(&json_str)
        })
    })
    .await
    .map_err(|e| Error::ToolExecution(format!("Get packets join error: {e}")))?
}

/// Stop traffic capture.
pub async fn stop_traffic_capture(_handle: CaptureHandle) -> Result<()> {
    tokio::task::spawn_blocking(|| {
        with_activity(|env, activity| {
            let ctx = env
                .call_method(
                    activity,
                    "getApplicationContext",
                    "()Landroid/content/Context;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(|e| Error::ToolExecution(format!("getApplicationContext: {e}")))?;

            let vpn_cls = find_app_class(
                env,
                "com/strike48/pentest_connector/PacketCaptureVpnService",
            )?;

            env.call_static_method(
                &vpn_cls,
                "stopCapture",
                "(Landroid/content/Context;)Z",
                &[JValue::Object(&ctx)],
            )
            .map_err(|e| Error::ToolExecution(format!("stopCapture: {e}")))?;

            Ok(())
        })
    })
    .await
    .map_err(|e| Error::ToolExecution(format!("Stop capture join error: {e}")))?
}

fn parse_packets_json(json_str: &str) -> Result<Vec<PacketInfo>> {
    let items: Vec<serde_json::Value> = serde_json::from_str(json_str)
        .map_err(|e| Error::ToolExecution(format!("Packets JSON parse: {e}")))?;

    Ok(items
        .into_iter()
        .filter_map(|v| {
            Some(PacketInfo {
                timestamp: v.get("timestamp")?.as_u64()?,
                protocol: v.get("protocol")?.as_str()?.to_string(),
                src_ip: v.get("src_ip")?.as_str()?.to_string(),
                dst_ip: v.get("dst_ip")?.as_str()?.to_string(),
                src_port: v.get("src_port").and_then(|p| p.as_u64()).map(|p| p as u16),
                dst_port: v.get("dst_port").and_then(|p| p.as_u64()).map(|p| p as u16),
                size: v.get("size").and_then(|s| s.as_u64()).unwrap_or(0) as usize,
                tcp_flags: v
                    .get("tcp_flags")
                    .and_then(|f| f.as_str())
                    .map(String::from),
            })
        })
        .collect())
}

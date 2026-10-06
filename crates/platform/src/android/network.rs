//! Android network operations

use super::jni_bridge::{check_permission, jstring_to_string, with_jni};
use crate::traits::*;
use jni::objects::JValue;
use pentest_core::error::{Error, Result};
use std::time::Duration;

/// The active network's own link facts, read from Android's ConnectivityManager.
///
/// This is the reliable source of the device's local IPv4, prefix and gateway
/// on an unprivileged app, where `ip addr` / `ip route` and the `default_net`
/// routing-table lookup are blocked (#549). Empty fields mean the query found
/// nothing (no active network, IPv6-only, or a JNI error) - callers must treat
/// that as "unknown", never substitute a guessed subnet.
#[derive(Debug, Default, Clone)]
pub struct LinkInfo {
    /// Interface name the active network is bound to (e.g. "wlan0"), if known.
    pub interface: Option<String>,
    /// IPv4 addresses with their prefix length.
    pub addresses: Vec<InterfaceAddr>,
    /// IPv4 default-route gateway, if one is present.
    pub gateway: Option<String>,
}

/// Read the active network's interface name, IPv4 link addresses and default
/// gateway via ConnectivityManager. Best-effort: any failure yields an empty
/// `LinkInfo` rather than erroring, mirroring `get_arp_table`'s degrade.
pub fn active_link_info() -> LinkInfo {
    with_jni(|env, ctx| {
        // getActiveNetwork / getLinkProperties throw SecurityException without
        // ACCESS_NETWORK_STATE, which would crash the app (a JNI-pending Java
        // exception is not catchable in Rust). Check it first and degrade to
        // empty, exactly as WiFi scanning guards ACCESS_FINE_LOCATION.
        if !check_permission(env, ctx, "android.permission.ACCESS_NETWORK_STATE") {
            tracing::warn!("active_link_info: ACCESS_NETWORK_STATE not granted");
            return Ok(LinkInfo::default());
        }

        let service = env
            .new_string("connectivity")
            .map_err(|e| Error::ToolExecution(format!("JNI new_string: {e}")))?;
        let cm = env
            .call_method(
                ctx,
                "getSystemService",
                "(Ljava/lang/String;)Ljava/lang/Object;",
                &[JValue::Object(&service.into())],
            )
            .and_then(|v| v.l())
            .map_err(|e| Error::ToolExecution(format!("getSystemService(connectivity): {e}")))?;
        if cm.is_null() {
            return Ok(LinkInfo::default());
        }

        let network = env
            .call_method(&cm, "getActiveNetwork", "()Landroid/net/Network;", &[])
            .and_then(|v| v.l())
            .map_err(|e| Error::ToolExecution(format!("getActiveNetwork: {e}")))?;
        if network.is_null() {
            return Ok(LinkInfo::default());
        }

        let lp = env
            .call_method(
                &cm,
                "getLinkProperties",
                "(Landroid/net/Network;)Landroid/net/LinkProperties;",
                &[JValue::Object(&network)],
            )
            .and_then(|v| v.l())
            .map_err(|e| Error::ToolExecution(format!("getLinkProperties: {e}")))?;
        if lp.is_null() {
            return Ok(LinkInfo::default());
        }

        let interface = env
            .call_method(&lp, "getInterfaceName", "()Ljava/lang/String;", &[])
            .and_then(|v| v.l())
            .ok()
            .map(|o| jstring_to_string(env, &o))
            .filter(|s| !s.is_empty());

        let addresses = read_link_addresses(env, &lp);
        let gateway = read_default_gateway(env, &lp);

        Ok(LinkInfo {
            interface,
            addresses,
            gateway,
        })
    })
    .unwrap_or_default()
}

/// Extract IPv4 addresses (with prefix) from LinkProperties.getLinkAddresses().
fn read_link_addresses(env: &mut jni::JNIEnv, lp: &jni::objects::JObject) -> Vec<InterfaceAddr> {
    let Ok(list) = env
        .call_method(lp, "getLinkAddresses", "()Ljava/util/List;", &[])
        .and_then(|v| v.l())
    else {
        return vec![];
    };
    let count = env
        .call_method(&list, "size", "()I", &[])
        .and_then(|v| v.i())
        .unwrap_or(0);

    let mut out = Vec::new();
    for i in 0..count {
        let Ok(la) = env
            .call_method(&list, "get", "(I)Ljava/lang/Object;", &[JValue::Int(i)])
            .and_then(|v| v.l())
        else {
            continue;
        };
        let prefix = env
            .call_method(&la, "getPrefixLength", "()I", &[])
            .and_then(|v| v.i())
            .unwrap_or(-1);
        let addr = env
            .call_method(&la, "getAddress", "()Ljava/net/InetAddress;", &[])
            .and_then(|v| v.l());
        let Ok(inet) = addr else { continue };
        if let Some(a) = inet_to_ipv4_addr(env, &inet, prefix) {
            out.push(a);
        }
    }
    out
}

/// Find the IPv4 default-route gateway from LinkProperties.getRoutes().
fn read_default_gateway(env: &mut jni::JNIEnv, lp: &jni::objects::JObject) -> Option<String> {
    let list = env
        .call_method(lp, "getRoutes", "()Ljava/util/List;", &[])
        .and_then(|v| v.l())
        .ok()?;
    let count = env
        .call_method(&list, "size", "()I", &[])
        .and_then(|v| v.i())
        .unwrap_or(0);

    for i in 0..count {
        let Ok(route) = env
            .call_method(&list, "get", "(I)Ljava/lang/Object;", &[JValue::Int(i)])
            .and_then(|v| v.l())
        else {
            continue;
        };
        let is_default = env
            .call_method(&route, "isDefaultRoute", "()Z", &[])
            .and_then(|v| v.z())
            .unwrap_or(false);
        if !is_default {
            continue;
        }
        let Ok(gw) = env
            .call_method(&route, "getGateway", "()Ljava/net/InetAddress;", &[])
            .and_then(|v| v.l())
        else {
            continue;
        };
        if gw.is_null() {
            continue;
        }
        if let Some(addr) = inet_to_ipv4_addr(env, &gw, 32) {
            return Some(addr.ip);
        }
    }
    None
}

/// Turn an InetAddress into an IPv4 `InterfaceAddr`, or `None` for IPv6/invalid.
/// Delegates prefix+address parsing to the shared, tested `interface_addr_from_token`.
fn inet_to_ipv4_addr(
    env: &mut jni::JNIEnv,
    inet: &jni::objects::JObject,
    prefix: i32,
) -> Option<InterfaceAddr> {
    let host = env
        .call_method(inet, "getHostAddress", "()Ljava/lang/String;", &[])
        .and_then(|v| v.l())
        .ok()
        .map(|o| jstring_to_string(env, &o))?;
    ipv4_interface_addr(&host, prefix)
}

/// Perform a port scan
pub async fn port_scan(config: ScanConfig) -> Result<ScanResult> {
    let timeout = Duration::from_millis(config.timeout_ms);

    Ok(crate::common::tcp_port_scan(&config.host, &config.ports, timeout, 0).await)
}

/// Get the ARP table with layered fallback (bd-23):
/// 1. Try /proc/net/arp
/// 2. If empty, try `ip neigh show`
/// 3. If that fails, warn and return empty
pub async fn get_arp_table() -> Result<Vec<ArpEntry>> {
    // Layer 1: /proc/net/arp
    let entries = arp_from_proc().await;
    if !entries.is_empty() {
        return Ok(entries);
    }

    // Layer 2: `ip neigh show`
    let entries = arp_from_ip_neigh().await;
    if !entries.is_empty() {
        return Ok(entries);
    }

    tracing::warn!("ARP table: both /proc/net/arp and ip neigh returned empty");
    Ok(vec![])
}

async fn arp_from_proc() -> Vec<ArpEntry> {
    let content = match tokio::fs::read_to_string("/proc/net/arp").await {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    crate::common::parse_proc_arp(&content)
}

/// Run `ip neigh show` and parse the output via [`crate::common::parse_ip_neigh`].
async fn arp_from_ip_neigh() -> Vec<ArpEntry> {
    let output = match tokio::process::Command::new("ip")
        .args(["neigh", "show"])
        .output()
        .await
    {
        Ok(o) => o,
        Err(_) => return vec![],
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    crate::common::parse_ip_neigh(&stdout)
}

/// Discover SSDP devices.
///
/// Delegates to the shared, platform-agnostic implementation in
/// [`crate::common::ssdp`] (behavior-identical to the previous inline copy).
pub async fn ssdp_discover(timeout_ms: u64) -> Result<Vec<SsdpDevice>> {
    crate::common::ssdp::discover(timeout_ms).await
}

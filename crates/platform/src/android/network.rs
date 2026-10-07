//! Android network operations

use super::jni_bridge::{check_permission, with_jni};
use crate::traits::*;
use jni::objects::{JObject, JString, JValue, JValueOwned};
use jni::JNIEnv;
use pentest_core::error::Result;
use std::time::Duration;

/// `NetworkCapabilities.TRANSPORT_*` values (public, stable since API 21).
const TRANSPORT_WIFI: i32 = 1;
const TRANSPORT_ETHERNET: i32 = 3;
const TRANSPORT_VPN: i32 = 4;

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
/// gateway via ConnectivityManager. Best-effort: any failure, including a
/// thrown Java exception, yields an empty `LinkInfo` rather than erroring,
/// mirroring `get_arp_table`'s degrade.
///
/// Only a Wi-Fi or Ethernet network that is not a VPN is read. On cellular the
/// "local subnet" is the carrier's network, and through a VPN it is the remote
/// side's; neither is the operator's LAN, so both report "unknown" rather than
/// hand the agent a subnet it must not sweep.
pub fn active_link_info() -> LinkInfo {
    with_jni(|env, ctx| Ok(read_active_link(env, ctx).unwrap_or_default())).unwrap_or_default()
}

fn read_active_link(env: &mut JNIEnv, ctx: &JObject) -> Option<LinkInfo> {
    // getActiveNetwork / getLinkProperties throw SecurityException without
    // ACCESS_NETWORK_STATE. `call` would clear that and degrade, but checking
    // first keeps the expected case quiet, as WiFi scanning guards
    // ACCESS_FINE_LOCATION.
    if !check_permission(env, ctx, "android.permission.ACCESS_NETWORK_STATE") {
        tracing::warn!("active_link_info: ACCESS_NETWORK_STATE not granted");
        return None;
    }

    let service = env.new_string("connectivity").ok()?;
    let cm = object(call(
        env,
        ctx,
        "getSystemService",
        "(Ljava/lang/String;)Ljava/lang/Object;",
        &[JValue::Object(&service.into())],
    ))?;
    let network = object(call(
        env,
        &cm,
        "getActiveNetwork",
        "()Landroid/net/Network;",
        &[],
    ))?;
    if !is_lan_network(env, &cm, &network) {
        tracing::info!(
            "active_link_info: active network is not Wi-Fi/Ethernet, or is a VPN; subnet unknown"
        );
        return None;
    }
    let lp = object(call(
        env,
        &cm,
        "getLinkProperties",
        "(Landroid/net/Network;)Landroid/net/LinkProperties;",
        &[JValue::Object(&network)],
    ))?;

    let interface = object(call(
        env,
        &lp,
        "getInterfaceName",
        "()Ljava/lang/String;",
        &[],
    ))
    .and_then(|o| string(env, o))
    .filter(|s| !s.is_empty());

    Some(LinkInfo {
        interface,
        addresses: read_link_addresses(env, &lp),
        gateway: read_default_gateway(env, &lp),
    })
}

/// Whether `network` is Wi-Fi or Ethernet and not a VPN, per its
/// NetworkCapabilities. Unknown capabilities count as "not a LAN".
fn is_lan_network(env: &mut JNIEnv, cm: &JObject, network: &JObject) -> bool {
    let Some(caps) = object(call(
        env,
        cm,
        "getNetworkCapabilities",
        "(Landroid/net/Network;)Landroid/net/NetworkCapabilities;",
        &[JValue::Object(network)],
    )) else {
        return false;
    };
    let mut has = |transport: i32| {
        call(
            env,
            &caps,
            "hasTransport",
            "(I)Z",
            &[JValue::Int(transport)],
        )
        .and_then(|v| v.z().ok())
        .unwrap_or(false)
    };
    (has(TRANSPORT_WIFI) || has(TRANSPORT_ETHERNET)) && !has(TRANSPORT_VPN)
}

/// `env.call_method` that never leaves a Java exception pending. jni-rs reports
/// a thrown exception as an `Err` but leaves it pending, and the next JNI call
/// (or the return to the JVM) with one pending aborts the app, so clear it and
/// degrade to `None`.
fn call<'local>(
    env: &mut JNIEnv<'local>,
    obj: &JObject,
    name: &str,
    sig: &str,
    args: &[JValue],
) -> Option<JValueOwned<'local>> {
    match env.call_method(obj, name, sig, args) {
        Ok(v) => Some(v),
        Err(e) => {
            clear_exception(env);
            tracing::debug!("JNI {name}{sig} failed: {e}");
            None
        }
    }
}

/// Clear a pending Java exception, if any; see [`call`].
fn clear_exception(env: &mut JNIEnv) {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
}

/// The non-null object a JNI call returned, if any.
fn object<'local>(value: Option<JValueOwned<'local>>) -> Option<JObject<'local>> {
    value?.l().ok().filter(|o| !o.is_null())
}

/// A returned `java.lang.String` as a Rust string, without leaving a Java
/// exception pending. `jstring_to_string` swallows a `get_string` error but
/// does not clear the exception, which aborts the app on the next JNI call.
fn string(env: &mut JNIEnv, obj: JObject) -> Option<String> {
    match env.get_string(&JString::from(obj)) {
        Ok(s) => Some(s.into()),
        Err(e) => {
            clear_exception(env);
            tracing::debug!("JNI get_string failed: {e}");
            None
        }
    }
}

/// Extract IPv4 addresses (with prefix) from LinkProperties.getLinkAddresses().
fn read_link_addresses(env: &mut JNIEnv, lp: &JObject) -> Vec<InterfaceAddr> {
    let Some(list) = object(call(env, lp, "getLinkAddresses", "()Ljava/util/List;", &[])) else {
        return vec![];
    };
    (0..list_size(env, &list))
        .filter_map(|i| {
            let la = list_item(env, &list, i)?;
            let prefix = call(env, &la, "getPrefixLength", "()I", &[]).and_then(|v| v.i().ok())?;
            let inet = object(call(
                env,
                &la,
                "getAddress",
                "()Ljava/net/InetAddress;",
                &[],
            ))?;
            ipv4_interface_addr(&host_address(env, &inet)?, prefix)
        })
        .collect()
}

/// Find the IPv4 default-route gateway from LinkProperties.getRoutes(). A
/// default route with no next hop (`0.0.0.0`) is not a gateway; see
/// [`ipv4_gateway`].
fn read_default_gateway(env: &mut JNIEnv, lp: &JObject) -> Option<String> {
    let list = object(call(env, lp, "getRoutes", "()Ljava/util/List;", &[]))?;
    (0..list_size(env, &list)).find_map(|i| {
        let route = list_item(env, &list, i)?;
        let is_default =
            call(env, &route, "isDefaultRoute", "()Z", &[]).and_then(|v| v.z().ok())?;
        if !is_default {
            return None;
        }
        let gw = object(call(
            env,
            &route,
            "getGateway",
            "()Ljava/net/InetAddress;",
            &[],
        ))?;
        ipv4_gateway(&host_address(env, &gw)?)
    })
}

fn list_size(env: &mut JNIEnv, list: &JObject) -> i32 {
    call(env, list, "size", "()I", &[])
        .and_then(|v| v.i().ok())
        .unwrap_or(0)
}

fn list_item<'local>(env: &mut JNIEnv<'local>, list: &JObject, i: i32) -> Option<JObject<'local>> {
    object(call(
        env,
        list,
        "get",
        "(I)Ljava/lang/Object;",
        &[JValue::Int(i)],
    ))
}

/// `InetAddress.getHostAddress()`, or `None` if the call failed.
fn host_address(env: &mut JNIEnv, inet: &JObject) -> Option<String> {
    let host = object(call(
        env,
        inet,
        "getHostAddress",
        "()Ljava/lang/String;",
        &[],
    ))?;
    string(env, host)
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

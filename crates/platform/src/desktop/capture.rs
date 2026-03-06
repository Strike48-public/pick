//! Desktop capture operations implementation
//!
//! This module is the single source of truth for traffic capture state.
//! It owns both the per-capture packet buffers (`CAPTURES`) and the
//! "currently active capture" handle (`CURRENT_CAPTURE`).  Higher-level
//! code (e.g. the traffic-capture tool) should use the convenience
//! functions [`start_current_capture`], [`stop_current_capture`],
//! [`get_current_packets`], and [`is_capture_active`] instead of
//! managing their own handle storage.

// Imports used regardless of feature
use crate::traits::*;
use pentest_core::error::{Error, Result};

// Imports only used with pcap feature
#[cfg(feature = "pcap")]
use std::collections::HashMap;
#[cfg(feature = "pcap")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "pcap")]
use std::sync::Arc;
#[cfg(feature = "pcap")]
use tokio::sync::RwLock;
#[cfg(feature = "pcap")]
use uuid::Uuid;

/// Maximum number of bytes to capture per packet (snapshot length).
///
/// 65535 bytes is the maximum possible IP packet size, ensuring no
/// packet data is truncated during capture.
#[cfg(feature = "pcap")]
const MAX_SNAPSHOT_LEN: i32 = 65535;

/// Maximum number of packets retained in the in-memory capture buffer.
///
/// When this limit is reached, the oldest packet is evicted to make room
/// for the newest one (FIFO).
#[cfg(feature = "pcap")]
const MAX_PACKET_BUFFER_SIZE: usize = 10_000;

// Global capture state: per-capture packet buffers keyed by capture id.
#[cfg(feature = "pcap")]
lazy_static::lazy_static! {
    static ref CAPTURES: RwLock<HashMap<String, CaptureState>> = RwLock::new(HashMap::new());
}

// The currently active capture handle (at most one at a time).
#[cfg(feature = "pcap")]
lazy_static::lazy_static! {
    static ref CURRENT_CAPTURE: RwLock<Option<CaptureHandle>> = RwLock::new(None);
}

#[cfg(feature = "pcap")]
struct CaptureState {
    running: Arc<AtomicBool>,
    packets: Arc<RwLock<Vec<PacketInfo>>>,
}

/// Check whether pcap (packet capture) is available at runtime.
///
/// On Windows this probes for `wpcap.dll` (requires Npcap to be installed).
/// On Unix this always returns `true` when compiled with the `pcap` feature.
#[cfg(feature = "pcap")]
pub fn is_pcap_available() -> bool {
    #[cfg(windows)]
    {
        extern "system" {
            fn LoadLibraryW(name: *const u16) -> *mut core::ffi::c_void;
            fn FreeLibrary(handle: *mut core::ffi::c_void) -> i32;
        }
        let name: Vec<u16> = "wpcap.dll".encode_utf16().chain(Some(0)).collect();
        unsafe {
            let handle = LoadLibraryW(name.as_ptr());
            if !handle.is_null() {
                FreeLibrary(handle);
                true
            } else {
                false
            }
        }
    }
    #[cfg(not(windows))]
    {
        true
    }
}

#[cfg(not(feature = "pcap"))]
pub fn is_pcap_available() -> bool {
    false
}

/// Capture a screenshot
pub async fn capture_screenshot() -> Result<Vec<u8>> {
    #[cfg(feature = "screenshots")]
    {
        use screenshots::Screen;

        let screens =
            Screen::all().map_err(|e| Error::Capture(format!("Failed to get screens: {}", e)))?;

        if screens.is_empty() {
            return Err(Error::Capture("No screens found".into()));
        }

        // Capture the primary screen
        let screen = &screens[0];
        let image = screen
            .capture()
            .map_err(|e| Error::Capture(format!("Failed to capture screen: {}", e)))?;

        // Encode as PNG
        let mut buffer = Vec::new();
        let encoder = image::codecs::png::PngEncoder::new(&mut buffer);
        image::ImageEncoder::write_image(
            encoder,
            image.as_raw(),
            image.width(),
            image.height(),
            image::ExtendedColorType::Rgba8,
        )
        .map_err(|e| Error::Capture(format!("Failed to encode PNG: {}", e)))?;

        Ok(buffer)
    }

    #[cfg(not(feature = "screenshots"))]
    {
        Err(Error::PlatformNotSupported(
            "Screenshot capture requires 'screenshots' feature".into(),
        ))
    }
}

/// Start traffic capture
#[cfg(feature = "pcap")]
pub async fn start_traffic_capture() -> Result<CaptureHandle> {
    let id = Uuid::new_v4().to_string();
    let running = Arc::new(AtomicBool::new(true));
    let packets = Arc::new(RwLock::new(Vec::new()));

    let state = CaptureState {
        running: running.clone(),
        packets: packets.clone(),
    };

    CAPTURES.write().await.insert(id.clone(), state);

    // Start capture in background task
    let capture_id = id.clone();
    let capture_id_for_clear = id.clone();
    let capture_running = running.clone();
    let capture_packets = packets.clone();

    tokio::spawn(async move {
        if let Err(e) = run_capture(capture_running, capture_packets).await {
            tracing::error!("Capture error: {}", e);
        }
        CAPTURES.write().await.remove(&capture_id);
        // If the background task ends on its own (error or device EOF),
        // clear the current-capture handle so higher-level code sees it
        // as stopped.
        let mut current = CURRENT_CAPTURE.write().await;
        if current.as_ref().map(|h| h.id.as_str()) == Some(capture_id_for_clear.as_str()) {
            *current = None;
        }
    });

    Ok(CaptureHandle {
        id,
        started_at: std::time::Instant::now(),
    })
}

#[cfg(not(feature = "pcap"))]
pub async fn start_traffic_capture() -> Result<CaptureHandle> {
    Err(Error::PlatformNotSupported(
        "Traffic capture requires 'pcap' feature and libpcap".into(),
    ))
}

#[cfg(feature = "pcap")]
async fn run_capture(
    running: Arc<AtomicBool>,
    packets: Arc<RwLock<Vec<PacketInfo>>>,
) -> Result<()> {
    use pcap::{Capture, Device};

    // Find the default device
    let device = Device::lookup()
        .map_err(|e| Error::Capture(format!("Failed to find device: {}", e)))?
        .ok_or_else(|| Error::Capture("No capture device found".into()))?;

    let mut cap = Capture::from_device(device)
        .map_err(|e| Error::Capture(format!("Failed to open device: {}", e)))?
        .promisc(true)
        .snaplen(MAX_SNAPSHOT_LEN)
        .timeout(1000)
        .open()
        .map_err(|e| Error::Capture(format!("Failed to activate capture: {}", e)))?;

    while running.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(info) = parse_packet(packet.data) {
                    let mut pkts = packets.write().await;
                    pkts.push(info);
                    // Keep only the most recent packets
                    if pkts.len() > MAX_PACKET_BUFFER_SIZE {
                        pkts.remove(0);
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                tracing::warn!("Capture error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(feature = "pcap")]
fn parse_packet(data: &[u8]) -> Option<PacketInfo> {
    // Basic Ethernet + IP parsing
    if data.len() < 34 {
        return None;
    }

    // Skip Ethernet header (14 bytes)
    let ip_data = &data[14..];

    // Check IP version
    let version = (ip_data[0] >> 4) & 0x0F;
    if version != 4 {
        return None; // Only handle IPv4 for now
    }

    let ihl = (ip_data[0] & 0x0F) as usize * 4;
    if ip_data.len() < ihl {
        return None;
    }

    let protocol = ip_data[9];
    let src_ip = format!(
        "{}.{}.{}.{}",
        ip_data[12], ip_data[13], ip_data[14], ip_data[15]
    );
    let dst_ip = format!(
        "{}.{}.{}.{}",
        ip_data[16], ip_data[17], ip_data[18], ip_data[19]
    );

    let (protocol_name, src_port, dst_port, tcp_flags) = match protocol {
        6 => {
            // TCP
            if ip_data.len() >= ihl + 20 {
                let tcp_data = &ip_data[ihl..];
                let src = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);
                let dst = u16::from_be_bytes([tcp_data[2], tcp_data[3]]);
                let flags = tcp_data[13];
                let flags_str = format_tcp_flags(flags);
                ("TCP", Some(src), Some(dst), Some(flags_str))
            } else {
                ("TCP", None, None, None)
            }
        }
        17 => {
            // UDP
            if ip_data.len() >= ihl + 8 {
                let udp_data = &ip_data[ihl..];
                let src = u16::from_be_bytes([udp_data[0], udp_data[1]]);
                let dst = u16::from_be_bytes([udp_data[2], udp_data[3]]);
                ("UDP", Some(src), Some(dst), None)
            } else {
                ("UDP", None, None, None)
            }
        }
        1 => ("ICMP", None, None, None),
        _ => ("OTHER", None, None, None),
    };

    Some(PacketInfo {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        protocol: protocol_name.to_string(),
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        size: data.len(),
        tcp_flags,
    })
}

#[cfg(feature = "pcap")]
fn format_tcp_flags(flags: u8) -> String {
    let mut result = Vec::new();
    if flags & 0x01 != 0 {
        result.push("FIN");
    }
    if flags & 0x02 != 0 {
        result.push("SYN");
    }
    if flags & 0x04 != 0 {
        result.push("RST");
    }
    if flags & 0x08 != 0 {
        result.push("PSH");
    }
    if flags & 0x10 != 0 {
        result.push("ACK");
    }
    if flags & 0x20 != 0 {
        result.push("URG");
    }
    result.join(",")
}

/// Get captured packets
#[cfg(feature = "pcap")]
pub async fn get_captured_packets(handle: &CaptureHandle, limit: usize) -> Result<Vec<PacketInfo>> {
    let captures = CAPTURES.read().await;

    match captures.get(&handle.id) {
        Some(state) => {
            let packets = state.packets.read().await;
            let start = if packets.len() > limit {
                packets.len() - limit
            } else {
                0
            };
            Ok(packets[start..].to_vec())
        }
        None => Ok(Vec::new()),
    }
}

#[cfg(not(feature = "pcap"))]
pub async fn get_captured_packets(
    _handle: &CaptureHandle,
    _limit: usize,
) -> Result<Vec<PacketInfo>> {
    Ok(Vec::new())
}

/// Stop traffic capture
#[cfg(feature = "pcap")]
pub async fn stop_traffic_capture(handle: CaptureHandle) -> Result<()> {
    let mut captures = CAPTURES.write().await;

    if let Some(state) = captures.remove(&handle.id) {
        state.running.store(false, Ordering::Relaxed);
    }

    Ok(())
}

#[cfg(not(feature = "pcap"))]
pub async fn stop_traffic_capture(_handle: CaptureHandle) -> Result<()> {
    Ok(())
}

// ============ Convenience API (single-capture session management) ============
//
// These functions manage the `CURRENT_CAPTURE` handle so that callers do not
// need their own global state.  They are the intended public API for tools.

/// Start a new traffic capture session.
///
/// Returns an error if a capture is already in progress.
#[cfg(feature = "pcap")]
pub async fn start_current_capture() -> Result<()> {
    let mut current = CURRENT_CAPTURE.write().await;
    if current.is_some() {
        return Err(Error::Capture("Capture already in progress".into()));
    }
    let handle = start_traffic_capture().await?;
    *current = Some(handle);
    Ok(())
}

#[cfg(not(feature = "pcap"))]
pub async fn start_current_capture() -> Result<()> {
    Err(Error::PlatformNotSupported(
        "Traffic capture requires 'pcap' feature and libpcap".into(),
    ))
}

/// Stop the current traffic capture session.
///
/// Returns an error if no capture is in progress.
#[cfg(feature = "pcap")]
pub async fn stop_current_capture() -> Result<()> {
    let mut current = CURRENT_CAPTURE.write().await;
    match current.take() {
        Some(handle) => stop_traffic_capture(handle).await,
        None => Err(Error::Capture("No capture in progress".into())),
    }
}

#[cfg(not(feature = "pcap"))]
pub async fn stop_current_capture() -> Result<()> {
    Err(Error::PlatformNotSupported(
        "Traffic capture requires 'pcap' feature and libpcap".into(),
    ))
}

/// Retrieve packets from the current traffic capture session.
///
/// Returns an error if no capture is in progress.
#[cfg(feature = "pcap")]
pub async fn get_current_packets(limit: usize) -> Result<Vec<PacketInfo>> {
    let current = CURRENT_CAPTURE.read().await;
    match current.as_ref() {
        Some(handle) => get_captured_packets(handle, limit).await,
        None => Err(Error::Capture("No capture in progress".into())),
    }
}

#[cfg(not(feature = "pcap"))]
pub async fn get_current_packets(_limit: usize) -> Result<Vec<PacketInfo>> {
    Err(Error::PlatformNotSupported(
        "Traffic capture requires 'pcap' feature and libpcap".into(),
    ))
}

/// Check whether a traffic capture session is currently active.
#[cfg(feature = "pcap")]
pub async fn is_capture_active() -> bool {
    CURRENT_CAPTURE.read().await.is_some()
}

#[cfg(not(feature = "pcap"))]
pub async fn is_capture_active() -> bool {
    false
}

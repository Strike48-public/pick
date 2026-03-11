//! Parameter extraction helpers for tool implementations.
//!
//! Every tool repeats the same `params.get("key").and_then(|v| v.as_str())…`
//! boilerplate.  These tiny helpers eliminate that noise while keeping the
//! call-sites readable.

use serde_json::Value;

/// Extract a string parameter, returning an empty string if missing.
pub fn param_str(params: &Value, key: &str) -> String {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Extract an optional string parameter.
pub fn param_str_opt(params: &Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract a `u64` parameter with a default value.
pub fn param_u64(params: &Value, key: &str, default: u64) -> u64 {
    params.get(key).and_then(|v| v.as_u64()).unwrap_or(default)
}

/// Extract a `bool` parameter with a default value.
pub fn param_bool(params: &Value, key: &str, default: bool) -> bool {
    params.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

/// Convert dBm signal strength to signal quality percentage (0-100)
///
/// # Arguments
/// * `dbm` - Signal strength in dBm (e.g., -45, -67, -80)
///
/// # Returns
/// Signal quality percentage from 0 (worst) to 100 (best)
pub fn dbm_to_quality(dbm: i32) -> u8 {
    let quality = if dbm >= -50 {
        100
    } else if dbm <= -100 {
        0
    } else {
        // Linear scale between -50 dBm (100%) and -100 dBm (0%)
        2 * (dbm + 100)
    };

    quality.clamp(0, 100) as u8
}

/// Convert signal quality percentage to visual bar representation
///
/// # Arguments
/// * `quality` - Signal quality percentage (0-100)
///
/// # Returns
/// Unicode bar visualization string
///
/// # Examples
/// ```
/// use pentest_tools::util::quality_to_bars;
/// assert_eq!(quality_to_bars(100), "▂▄▆█");  // 4 bars (excellent)
/// assert_eq!(quality_to_bars(75), "▂▄▆_");   // 3 bars (good)
/// assert_eq!(quality_to_bars(55), "▂▄__");   // 2 bars (fair)
/// assert_eq!(quality_to_bars(35), "▂___");   // 1 bar (poor)
/// assert_eq!(quality_to_bars(10), "____");   // 0 bars (very poor)
/// ```
pub fn quality_to_bars(quality: u8) -> &'static str {
    match quality {
        90..=100 => "▂▄▆█", // 4 bars - excellent
        70..=89 => "▂▄▆_",  // 3 bars - good
        50..=69 => "▂▄__",  // 2 bars - fair
        30..=49 => "▂___",  // 1 bar - poor
        _ => "____",        // 0 bars - very poor
    }
}

/// Convert dBm signal strength directly to visual bars
///
/// # Arguments
/// * `dbm` - Signal strength in dBm
///
/// # Returns
/// Unicode bar visualization string
pub fn dbm_to_bars(dbm: i32) -> &'static str {
    quality_to_bars(dbm_to_quality(dbm))
}

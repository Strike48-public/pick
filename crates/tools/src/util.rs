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
/// Accepts integer, float, or string JSON values (e.g. `300`, `300.0`, `"300"`).
pub fn param_u64(params: &Value, key: &str, default: u64) -> u64 {
    params
        .get(key)
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_f64().map(|f| f as u64))
                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .unwrap_or(default)
}

/// Extract an optional `u16` parameter (e.g. a network port).
///
/// Accepts integer, float, or string JSON values and clamps to the valid u16
/// range: `22`, `22.0`, and `"22"` all yield `Some(22)`. LLM tool callers
/// frequently emit numeric args as floats (`22.0`), so a raw `as_u64()` here
/// silently rejected valid ports — this coerces them the same way `param_u64`
/// does. Out-of-range or non-numeric values yield `None`.
pub fn param_u16_opt(params: &Value, key: &str) -> Option<u16> {
    params.get(key).and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_f64().map(|f| f as u64))
            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            .filter(|n| *n >= 1 && *n <= u16::MAX as u64)
            .map(|n| n as u16)
    })
}

/// Extract a `bool` parameter with a default value.
///
/// Accepts real JSON booleans, plus the string forms LLM tool callers emit
/// (`"true"`/`"false"`/`"yes"`/`"no"`/`"1"`/`"0"`, case-insensitive) and numbers
/// (`1`, `1.0`, `0`, `0.0`; non-zero is true) — mirroring the loose coercion
/// `param_u64` does for numbers. Unparseable or missing values yield `default`.
pub fn param_bool(params: &Value, key: &str, default: bool) -> bool {
    match params.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => true,
            "false" | "no" | "0" => false,
            _ => default,
        },
        // `as_f64` (not `as_i64`) so float-valued flags like `1.0` coerce the way
        // `param_u64`/`param_u16_opt` handle numeric args — `as_i64` returns `None`
        // for a JSON float, silently dropping it to `default`. LLM callers emit both.
        Some(Value::Number(n)) => match n.as_f64() {
            Some(f) => f != 0.0,
            None => default,
        },
        _ => default,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn param_u16_opt_accepts_int_float_and_string() {
        // The bug this guards: LLM tool callers send ports as JSON floats
        // (`22.0`), which `as_u64()` rejects. All three forms must coerce.
        assert_eq!(param_u16_opt(&json!({"port": 22}), "port"), Some(22));
        assert_eq!(param_u16_opt(&json!({"port": 22.0}), "port"), Some(22));
        assert_eq!(param_u16_opt(&json!({"port": 5432.0}), "port"), Some(5432));
        assert_eq!(param_u16_opt(&json!({"port": "22"}), "port"), Some(22));
        assert_eq!(param_u16_opt(&json!({"port": 65535}), "port"), Some(65535));
    }

    #[test]
    fn param_u16_opt_rejects_missing_and_out_of_range() {
        assert_eq!(param_u16_opt(&json!({}), "port"), None);
        assert_eq!(param_u16_opt(&json!({"port": 0}), "port"), None);
        assert_eq!(param_u16_opt(&json!({"port": 70000}), "port"), None);
        assert_eq!(param_u16_opt(&json!({"port": -1}), "port"), None);
        assert_eq!(param_u16_opt(&json!({"port": "nope"}), "port"), None);
    }

    #[test]
    fn param_bool_coerces_bool_string_and_int() {
        assert!(param_bool(&json!({"append": true}), "append", false));
        assert!(param_bool(&json!({"append": "true"}), "append", false));
        assert!(param_bool(&json!({"append": "TRUE"}), "append", false));
        assert!(param_bool(&json!({"recursive": 1}), "recursive", false));
        assert!(param_bool(&json!({"recursive": "yes"}), "recursive", false));
        assert!(!param_bool(&json!({"append": "false"}), "append", true));
        assert!(!param_bool(&json!({"append": "0"}), "append", true));
        assert!(!param_bool(&json!({"append": 0}), "append", true));
    }

    #[test]
    fn param_bool_coerces_float_numbers() {
        // JSON floats like `1.0` return `None` from `as_i64`, so the earlier
        // int-only arm silently dropped them to the default. `as_f64` coerces
        // them the way `param_u64` handles numeric args. Guards that regression.
        assert!(param_bool(&json!({"append": 1.0}), "append", false));
        assert!(param_bool(&json!({"append": 0.5}), "append", false));
        assert!(param_bool(&json!({"append": 2.0}), "append", false));
        assert!(!param_bool(&json!({"append": 0.0}), "append", true));
        // Negative ints/floats are non-zero -> true.
        assert!(param_bool(&json!({"append": -1}), "append", false));
    }

    #[test]
    fn param_bool_falls_back_to_default_when_missing_or_unparseable() {
        assert!(param_bool(&json!({}), "append", true));
        assert!(!param_bool(&json!({}), "append", false));
        assert!(param_bool(&json!({"append": "maybe"}), "append", true));
        // Empty string and null are unrecognized -> default, not silent false.
        assert!(param_bool(&json!({"append": ""}), "append", true));
        assert!(param_bool(&json!({"append": null}), "append", true));
        assert!(!param_bool(&json!({"append": null}), "append", false));
    }
}

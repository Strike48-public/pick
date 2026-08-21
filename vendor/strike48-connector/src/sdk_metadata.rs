//! Auto-populated SDK instance metadata.
//!
//! Injects `sdk.*` prefixed keys into `InstanceMetadata.metadata` at
//! registration time so the server knows what runtime environment
//! each connector instance is running on.

use std::collections::HashMap;

const SDK_PREFIX: &str = "sdk.";

/// Collect SDK-level metadata about the current runtime environment.
///
/// Returns a map with `sdk.*` prefixed keys that describe the SDK
/// version, language, OS, architecture, and other operational context.
/// These are merged into `InstanceMetadata.metadata` during registration
/// without overwriting operator-supplied keys.
pub(crate) fn collect() -> HashMap<String, String> {
    let mut m = HashMap::new();

    m.insert(key("version"), env!("CARGO_PKG_VERSION").to_string());
    m.insert(key("language"), "rust".to_string());
    m.insert(key("os"), std::env::consts::OS.to_string());
    m.insert(key("arch"), std::env::consts::ARCH.to_string());
    m.insert(key("os_family"), std::env::consts::FAMILY.to_string());
    m.insert(key("rust_version"), env!("SDK_RUSTC_VERSION").to_string());
    m.insert(key("target"), env!("SDK_TARGET").to_string());
    m.insert(key("debug"), cfg!(debug_assertions).to_string());
    m.insert(key("pid"), std::process::id().to_string());

    if let Ok(host) = hostname::get() {
        m.insert(key("hostname"), host.to_string_lossy().to_string());
    }

    m
}

/// Merge SDK metadata into an existing operator-supplied metadata map.
///
/// `transport` and `tls` are connection-level values that only the
/// caller knows, so they are passed in rather than detected here.
///
/// Operator keys take precedence — if a user explicitly set a key
/// that collides with an `sdk.*` key, the user's value is preserved.
pub(crate) fn merge_into(operator: &mut HashMap<String, String>, transport: &str, tls: bool) {
    let mut sdk = collect();
    sdk.insert(key("transport"), transport.to_string());
    sdk.insert(key("tls"), tls.to_string());

    for (k, v) in sdk {
        operator.entry(k).or_insert(v);
    }
}

fn key(suffix: &str) -> String {
    format!("{SDK_PREFIX}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_contains_required_keys() {
        let m = collect();

        let required = [
            "sdk.version",
            "sdk.language",
            "sdk.os",
            "sdk.arch",
            "sdk.os_family",
            "sdk.rust_version",
            "sdk.target",
            "sdk.debug",
            "sdk.pid",
        ];

        for key in required {
            assert!(m.contains_key(key), "missing required key: {key}");
            assert!(!m[key].is_empty(), "key {key} must not be empty");
        }
    }

    #[test]
    fn test_collect_version_matches_cargo_pkg() {
        let m = collect();
        assert_eq!(m["sdk.version"], env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_collect_language_is_rust() {
        let m = collect();
        assert_eq!(m["sdk.language"], "rust");
    }

    #[test]
    fn test_collect_os_is_nonempty() {
        let m = collect();
        assert!(!m["sdk.os"].is_empty());
        assert!(!m["sdk.arch"].is_empty());
    }

    #[test]
    fn test_collect_pid_is_current_process() {
        let m = collect();
        let pid: u32 = m["sdk.pid"].parse().expect("pid should be a valid u32");
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn test_collect_debug_is_bool_string() {
        let m = collect();
        let val = &m["sdk.debug"];
        assert!(val == "true" || val == "false");
    }

    #[test]
    fn test_collect_hostname_present() {
        let m = collect();
        if let Ok(_host) = hostname::get() {
            assert!(
                m.contains_key("sdk.hostname"),
                "hostname should be present when hostname::get() succeeds"
            );
        }
    }

    #[test]
    fn test_merge_preserves_operator_keys() {
        let mut operator = HashMap::new();
        operator.insert("location".to_string(), "us-east-1".to_string());
        operator.insert("owner".to_string(), "platform".to_string());

        merge_into(&mut operator, "gRPC", false);

        assert_eq!(operator["location"], "us-east-1");
        assert_eq!(operator["owner"], "platform");
        assert!(operator.contains_key("sdk.version"));
    }

    #[test]
    fn test_merge_does_not_overwrite_operator_sdk_keys() {
        let mut operator = HashMap::new();
        operator.insert("sdk.version".to_string(), "custom-override".to_string());

        merge_into(&mut operator, "gRPC", false);

        assert_eq!(
            operator["sdk.version"], "custom-override",
            "operator-supplied sdk.* keys must not be overwritten"
        );
    }

    #[test]
    fn test_merge_into_empty_map() {
        let mut operator = HashMap::new();
        merge_into(&mut operator, "gRPC", true);

        assert!(operator.len() >= 11, "should have at least 11 sdk.* keys");
        assert!(
            operator.keys().all(|k| k.starts_with("sdk.")),
            "all keys should be sdk.* prefixed"
        );
    }

    #[test]
    fn test_merge_includes_transport_and_tls() {
        let mut operator = HashMap::new();
        merge_into(&mut operator, "WebSocket", true);

        assert_eq!(operator["sdk.transport"], "WebSocket");
        assert_eq!(operator["sdk.tls"], "true");
    }

    #[test]
    fn test_merge_transport_not_overwritten_by_operator() {
        let mut operator = HashMap::new();
        operator.insert("sdk.transport".to_string(), "custom".to_string());

        merge_into(&mut operator, "gRPC", false);

        assert_eq!(
            operator["sdk.transport"], "custom",
            "operator-supplied sdk.transport must not be overwritten"
        );
    }

    #[test]
    fn test_all_keys_have_sdk_prefix() {
        let m = collect();
        for key in m.keys() {
            assert!(
                key.starts_with("sdk."),
                "key {key} must start with 'sdk.' prefix"
            );
        }
    }

    #[test]
    fn test_rust_version_looks_like_semver() {
        let m = collect();
        let ver = &m["sdk.rust_version"];
        let parts: Vec<&str> = ver.split('.').collect();
        assert!(
            parts.len() >= 2,
            "rust_version '{ver}' should look like a semver (x.y.z)"
        );
    }
}

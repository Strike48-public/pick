//! Vendor intelligence database for known vulnerabilities and default patterns

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;

/// Vendor-specific intelligence
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct VendorIntel {
    pub vendor: &'static str,
    pub default_ssid_patterns: Vec<Regex>,
    pub default_password_patterns: Vec<&'static str>,
    pub notes: &'static str,
}

lazy_static! {
    /// Database of known vendor patterns
    pub static ref VENDOR_DATABASE: HashMap<&'static str, VendorIntel> = {
        let mut db = HashMap::new();

        // Netgear routers
        db.insert("netgear", VendorIntel {
            vendor: "Netgear",
            default_ssid_patterns: vec![
                Regex::new(r"^NETGEAR\d+$").unwrap(),
            ],
            default_password_patterns: vec![
                "?u?l?l?l?l?l?l?d?d?d",     // Wordword123
                "?u?l?l?l?l?l?l?l?d?d?d",   // Wordword1234
                "?l?l?l?l?l?l?l?d?d?d",     // password123
            ],
            notes: "Netgear often uses adjective+noun+numbers format",
        });

        // TP-Link routers
        db.insert("tp-link", VendorIntel {
            vendor: "TP-Link",
            default_ssid_patterns: vec![
                Regex::new(r"^TP-LINK_[0-9A-F]{4}$").unwrap(),
            ],
            default_password_patterns: vec![
                "?d?d?d?d?d?d?d?d",         // 8 digits
            ],
            notes: "TP-Link defaults often 8-digit passwords",
        });

        // Linksys routers
        db.insert("linksys", VendorIntel {
            vendor: "Linksys",
            default_ssid_patterns: vec![
                Regex::new(r"^Linksys\d+$").unwrap(),
            ],
            default_password_patterns: vec![
                "?l?l?l?l?l?l?l?l?l?l",     // 10 lowercase
            ],
            notes: "Linksys often uses 10 random lowercase letters",
        });

        // Belkin routers
        db.insert("belkin", VendorIntel {
            vendor: "Belkin",
            default_ssid_patterns: vec![
                Regex::new(r"^belkin\.\w+$").unwrap(),
            ],
            default_password_patterns: vec![
                "?d?d?d?d?d?d?d?d",         // 8 digits
            ],
            notes: "Belkin.XXX format with 8-digit password",
        });

        // D-Link routers
        db.insert("d-link", VendorIntel {
            vendor: "D-Link",
            default_ssid_patterns: vec![
                Regex::new(r"^dlink-[0-9A-F]{4}$").unwrap(),
            ],
            default_password_patterns: vec![
                "?l?l?l?l?l?l?l?l?l?l",     // 10 lowercase
            ],
            notes: "D-Link uses random lowercase letters",
        });

        db
    };
}

/// Try to identify vendor from SSID
pub fn identify_vendor(ssid: &str) -> Option<&'static VendorIntel> {
    for intel in VENDOR_DATABASE.values() {
        for pattern in &intel.default_ssid_patterns {
            if pattern.is_match(ssid) {
                return Some(intel);
            }
        }
    }
    None
}

/// Check if SSID matches known default pattern
pub fn is_default_ssid(ssid: &str) -> bool {
    identify_vendor(ssid).is_some()
}

/// Get recommended mask patterns for a vendor
pub fn get_mask_patterns(ssid: &str) -> Vec<&'static str> {
    if let Some(intel) = identify_vendor(ssid) {
        intel.default_password_patterns.clone()
    } else {
        // Generic patterns for unknown vendors
        vec![
            "?d?d?d?d?d?d?d?d", // 8 digits
            "?l?l?l?l?l?l?l?l", // 8 lowercase
            "?u?l?l?l?l?l?l?d?d?d", // Common word+number format
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netgear_detection() {
        assert!(is_default_ssid("NETGEAR42"));
        assert!(is_default_ssid("NETGEAR123"));
        assert!(!is_default_ssid("MyNetwork"));
    }

    #[test]
    fn test_tp_link_detection() {
        assert!(is_default_ssid("TP-LINK_A1B2"));
        assert!(!is_default_ssid("TP-LINK"));
    }

    #[test]
    fn test_vendor_identification() {
        let intel = identify_vendor("NETGEAR42");
        assert!(intel.is_some());
        assert_eq!(intel.unwrap().vendor, "Netgear");
    }
}

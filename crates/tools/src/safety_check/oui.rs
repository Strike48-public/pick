//! MAC address OUI (Organizationally Unique Identifier) vendor lookup.
//!
//! Maps the first three octets of a MAC address to a hardware vendor. This is a
//! curated subset of the IEEE OUI registry covering common consumer, router,
//! mobile, and IoT vendors - enough to make the network map readable for the
//! "am I safe?" use case without embedding the full ~35k-entry registry (which
//! would bloat the binary for little practical gain here). Unknown prefixes
//! return `None` and the map simply shows the MAC.

/// Look up the vendor for a MAC address by its OUI prefix.
///
/// Accepts MACs in common formats (`aa:bb:cc:...`, `aa-bb-cc-...`,
/// `aabb.cccc.dddd`, or contiguous hex). Returns the vendor name if the
/// 24-bit prefix is recognized.
pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    let prefix = normalize_oui(mac)?;
    OUI_TABLE
        .iter()
        .find(|(oui, _)| *oui == prefix)
        .map(|(_, vendor)| *vendor)
}

/// Normalize a MAC address to its 6-hex-digit uppercase OUI prefix.
///
/// Strips common separators and takes the first three octets. Returns `None`
/// if fewer than 6 hex digits are present.
fn normalize_oui(mac: &str) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect();

    if hex.len() < 6 {
        return None;
    }

    Some(hex.to_ascii_uppercase())
}

/// Curated OUI prefix -> vendor table. Prefixes are uppercase, no separators.
///
/// Sourced from the public IEEE registry. Intentionally a small, high-value
/// subset; expand as real-world demo gaps appear.
const OUI_TABLE: &[(&str, &str)] = &[
    // Apple
    ("F0989D", "Apple"),
    ("A85C2C", "Apple"),
    ("3C0754", "Apple"),
    ("AC87A3", "Apple"),
    ("F4F15A", "Apple"),
    // Google / Nest
    ("F4F5D8", "Google"),
    ("3C5AB4", "Google"),
    ("9C3DCF", "Google Nest"),
    // Amazon (Echo, Fire, Ring)
    ("FCA183", "Amazon"),
    ("44650D", "Amazon"),
    ("68DBF5", "Amazon"),
    ("0C47C9", "Amazon"),
    // Samsung
    ("5492BE", "Samsung"),
    ("8425DB", "Samsung"),
    ("BC8385", "Samsung"),
    // Intel (NICs)
    ("001B21", "Intel"),
    ("3C9709", "Intel"),
    ("A0A8CD", "Intel"),
    // Raspberry Pi
    ("B827EB", "Raspberry Pi"),
    ("DCA632", "Raspberry Pi"),
    ("E45F01", "Raspberry Pi"),
    // Router / network vendors
    ("C0FFD4", "Netgear"),
    ("2C3033", "Netgear"),
    ("A04F85", "TP-Link"),
    ("50C7BF", "TP-Link"),
    ("6466B3", "TP-Link"),
    ("EC086B", "TP-Link"),
    ("B0487A", "Cisco"),
    ("00000C", "Cisco"),
    ("F87394", "Cisco"),
    ("F81A67", "ASUS"),
    ("2C56DC", "ASUS"),
    ("1C872C", "ASUS"),
    ("9C5C8E", "ASUS"),
    ("4CE676", "Linksys"),
    ("C8D719", "Ubiquiti"),
    ("245A4C", "Ubiquiti"),
    ("E063DA", "Ubiquiti"),
    ("00156D", "Ubiquiti"),
    ("44D9E7", "Ubiquiti"),
    ("18E829", "Ubiquiti"),
    ("802AA8", "Ubiquiti"),
    // Mobile / misc
    ("D4619D", "Huawei"),
    ("48DB50", "Huawei"),
    ("2C5BB8", "Xiaomi"),
    ("64B473", "Xiaomi"),
    // Virtualization (useful to flag VMs on a network)
    ("000569", "VMware"),
    ("005056", "VMware"),
    ("000C29", "VMware"),
    ("080027", "VirtualBox"),
    ("525400", "QEMU/KVM"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_colon_format() {
        assert_eq!(lookup_vendor("b8:27:eb:12:34:56"), Some("Raspberry Pi"));
    }

    #[test]
    fn test_lookup_dash_format() {
        assert_eq!(lookup_vendor("00-15-6D-aa-bb-cc"), Some("Ubiquiti"));
    }

    #[test]
    fn test_lookup_uppercase_and_contiguous() {
        assert_eq!(lookup_vendor("005056AABBCC"), Some("VMware"));
    }

    #[test]
    fn test_unknown_prefix_returns_none() {
        assert_eq!(lookup_vendor("12:34:56:78:9a:bc"), None);
    }

    #[test]
    fn test_too_short_returns_none() {
        assert_eq!(lookup_vendor("00:15"), None);
    }

    #[test]
    fn test_empty_returns_none() {
        assert_eq!(lookup_vendor(""), None);
    }
}

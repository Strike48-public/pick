//! Attack strategy selection logic

use super::types::*;
use super::vendor_intel::{get_mask_patterns, is_default_ssid};
use pentest_core::error::Result;

/// Select the best attack strategy for a target
pub fn select_strategy(
    ssid: &str,
    bssid: &str,
    security: &str,
    signal: i32,
    clients: u32,
) -> Result<AttackStrategy> {
    let sec_type = SecurityType::parse(security);

    // Check if attackable
    if !sec_type.is_attackable() {
        return Ok(AttackStrategy::Unsupported {
            reason: format!(
                "{} networks are not supported for automated attacks",
                sec_type.as_str()
            ),
        });
    }

    // Check signal strength
    if signal < -85 {
        return Ok(AttackStrategy::Unsupported {
            reason: format!(
                "Signal too weak ({} dBm) - move closer to target",
                signal
            ),
        });
    }

    match sec_type {
        SecurityType::Wep => Ok(select_wep_strategy(signal)),
        SecurityType::Wpa | SecurityType::Wpa2 => {
            Ok(select_wpa_strategy(ssid, bssid, signal, clients))
        }
        _ => Ok(AttackStrategy::Unsupported {
            reason: "Unsupported security type".to_string(),
        }),
    }
}

/// Select WEP attack strategy
fn select_wep_strategy(signal: i32) -> AttackStrategy {
    // WEP is always feasible - just a matter of time
    let target_ivs = 40000;

    // Estimate time based on signal (better signal = faster IV capture)
    let estimated_time_sec = if signal > -50 {
        300 // 5 minutes with good signal
    } else if signal > -70 {
        600 // 10 minutes with ok signal
    } else {
        900 // 15 minutes with weak signal
    };

    // WEP attacks are very reliable
    let confidence = 0.95;

    AttackStrategy::Wep {
        estimated_time_sec,
        confidence,
        target_ivs,
    }
}

/// Select WPA attack strategy
fn select_wpa_strategy(ssid: &str, _bssid: &str, signal: i32, clients: u32) -> AttackStrategy {
    // Determine capture mode based on clients
    let capture_mode = if clients > 0 {
        // Active clients - can deauth to force handshake
        CaptureMode::ActiveDeauth {
            target_client: None, // Will deauth all
        }
    } else {
        // No clients - must wait passively
        CaptureMode::Passive
    };

    // Determine crack method based on SSID
    let crack_method = if is_default_ssid(ssid) {
        // Known vendor default pattern - use mask attack
        let patterns = get_mask_patterns(ssid);
        CrackMethod::MaskAttack {
            pattern: patterns.first().unwrap_or(&"?l?l?l?l?l?l?l?l").to_string(),
        }
    } else {
        // Unknown SSID - try dictionary first
        CrackMethod::Dictionary {
            wordlists: vec!["rockyou.txt".to_string()],
        }
    };

    // Estimate capture time
    let capture_time = if clients > 0 {
        60 // 1 minute with active deauth
    } else {
        600 // 10 minutes passive (could be hours in reality)
    };

    // Estimate crack time (very rough)
    let crack_time = match &crack_method {
        CrackMethod::MaskAttack { .. } => 3600, // 1 hour mask attack
        CrackMethod::Dictionary { .. } => 7200, // 2 hours dictionary
        _ => 1800,
    };

    let estimated_time_sec = capture_time + crack_time;

    // Confidence depends on several factors
    let mut confidence: f32 = 0.5; // Base confidence

    if clients > 0 {
        confidence += 0.2; // Easier to capture handshake
    }

    if signal > -60 {
        confidence += 0.1; // Good signal
    }

    if is_default_ssid(ssid) {
        confidence += 0.2; // Known vendor pattern
    }

    confidence = confidence.min(0.95); // Cap at 95%

    AttackStrategy::Wpa {
        capture_mode,
        crack_method,
        estimated_time_sec,
        confidence,
    }
}

/// Estimate time for a strategy
#[allow(dead_code)]
pub fn estimate_duration(strategy: &AttackStrategy) -> u64 {
    match strategy {
        AttackStrategy::Wep { estimated_time_sec, .. } => *estimated_time_sec,
        AttackStrategy::Wpa { estimated_time_sec, .. } => *estimated_time_sec,
        AttackStrategy::Unsupported { .. } => 0,
    }
}

/// Calculate attack feasibility score (0.0-1.0)
pub fn calculate_feasibility(
    security: &str,
    signal: i32,
    clients: u32,
    is_default: bool,
) -> f32 {
    let sec_type = SecurityType::parse(security);

    if !sec_type.is_attackable() {
        return 0.0;
    }

    let mut score: f32 = 0.0;

    // Security type factor
    score += match sec_type {
        SecurityType::Wep => 0.4,        // WEP is easy
        SecurityType::Wpa => 0.25,       // WPA is harder
        SecurityType::Wpa2 => 0.2,       // WPA2 is hardest
        _ => 0.0,
    };

    // Signal strength factor (0.0-0.3)
    let signal_factor = if signal > -50 {
        0.3
    } else if signal > -65 {
        0.2
    } else if signal > -75 {
        0.1
    } else {
        0.05
    };
    score += signal_factor;

    // Client factor (0.0-0.2)
    let client_factor = if clients > 3 {
        0.2
    } else if clients > 0 {
        0.15
    } else {
        0.0
    };
    score += client_factor;

    // Default SSID factor (0.0-0.1)
    if is_default {
        score += 0.1;
    }

    score.min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wep_always_attackable() {
        let strategy = select_strategy("TestNet", "00:11:22:33:44:55", "WEP", -60, 0).unwrap();
        assert!(strategy.is_supported());
        assert!(matches!(strategy, AttackStrategy::Wep { .. }));
    }

    #[test]
    fn test_wpa_with_clients() {
        let strategy = select_strategy("TestNet", "00:11:22:33:44:55", "WPA2-PSK", -55, 3).unwrap();
        assert!(strategy.is_supported());

        if let AttackStrategy::Wpa { capture_mode, confidence, .. } = strategy {
            assert!(matches!(capture_mode, CaptureMode::ActiveDeauth { .. }));
            assert!(confidence > 0.7); // Should have high confidence with clients
        } else {
            panic!("Expected WPA strategy");
        }
    }

    #[test]
    fn test_wpa_no_clients() {
        let strategy = select_strategy("TestNet", "00:11:22:33:44:55", "WPA2-PSK", -55, 0).unwrap();

        if let AttackStrategy::Wpa { capture_mode, .. } = strategy {
            assert!(matches!(capture_mode, CaptureMode::Passive));
        } else {
            panic!("Expected WPA strategy");
        }
    }

    #[test]
    fn test_default_ssid_uses_mask() {
        let strategy = select_strategy("NETGEAR42", "00:11:22:33:44:55", "WPA2-PSK", -55, 2).unwrap();

        if let AttackStrategy::Wpa { crack_method, .. } = strategy {
            assert!(matches!(crack_method, CrackMethod::MaskAttack { .. }));
        }
    }

    #[test]
    fn test_weak_signal_rejected() {
        let strategy = select_strategy("TestNet", "00:11:22:33:44:55", "WPA2-PSK", -90, 5).unwrap();
        assert!(!strategy.is_supported());
    }

    #[test]
    fn test_wpa3_unsupported() {
        let strategy = select_strategy("TestNet", "00:11:22:33:44:55", "WPA3", -50, 5).unwrap();
        assert!(!strategy.is_supported());
    }
}

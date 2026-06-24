//! Safety Check module for validating local network security.
//!
//! Performs comprehensive security checks to help operators determine if their
//! local network environment is safe for penetration testing work. Especially
//! useful when working from public WiFi (airports, coffee shops).
//!
//! # Checks Performed
//!
//! - DNS Integrity: Validates DNS responses aren't hijacked
//! - Router Threat Intelligence: Checks gateway against threat databases
//! - Network Device Discovery: Maps local network and flags suspicious devices
//!
//! # Usage
//!
//! ```no_run
//! use pentest_tools::safety_check::run_safety_check;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let result = run_safety_check().await?;
//!     println!("Status: {:?}", result.status);
//!     Ok(())
//! }
//! ```

mod dns_check;
mod network_map;
mod oui;
mod report;
mod threat_intel;
mod types;

pub use report::format_report;
pub use types::{
    CheckResult, CheckStatus, Device, NetworkMap, Recommendation, SafetyCheckResult, SafetyStatus,
    Severity, ThreatLevel,
};

/// Run a comprehensive safety check on the local network environment.
///
/// This function orchestrates all safety checks and aggregates results.
/// Uses best-effort error handling - shows results for checks that succeed,
/// marks failed checks as UNKNOWN.
///
/// # Errors
///
/// Returns error only if ALL checks fail catastrophically. Individual check
/// failures are captured in the result.
pub async fn run_safety_check() -> anyhow::Result<SafetyCheckResult> {
    tracing::info!("Starting safety check");

    let mut checks = Vec::new();
    let timestamp = chrono::Utc::now();

    // Run DNS integrity check
    match dns_check::check_dns_integrity().await {
        Ok(result) => {
            tracing::info!("DNS check completed: {:?}", result.status);
            checks.push(result);
        }
        Err(e) => {
            tracing::warn!("DNS check failed: {}", e);
            checks.push(CheckResult {
                name: "DNS Integrity".to_string(),
                status: CheckStatus::Unknown,
                details: format!("Check failed: {}", e),
                severity: Severity::Medium,
            });
        }
    }

    // Run router threat intelligence check
    match threat_intel::check_router_threat_intel().await {
        Ok(result) => {
            tracing::info!("Router threat intel check completed: {:?}", result.status);
            checks.push(result);
        }
        Err(e) => {
            tracing::warn!("Router threat intel check failed: {}", e);
            checks.push(CheckResult {
                name: "Router Threat Intelligence".to_string(),
                status: CheckStatus::Unknown,
                details: format!("Check unavailable: {}", e),
                severity: Severity::Low,
            });
        }
    }

    // Run network device discovery
    let network_map = match network_map::discover_network().await {
        Ok(map) => {
            tracing::info!(
                "Network discovery completed: {} devices found",
                map.other_devices.len()
            );
            checks.push(CheckResult {
                name: "Network Device Discovery".to_string(),
                status: CheckStatus::Passed,
                details: format!("Found {} devices on local network", map.other_devices.len()),
                severity: Severity::Info,
            });
            Some(map)
        }
        Err(e) => {
            tracing::warn!("Network discovery failed: {}", e);
            checks.push(CheckResult {
                name: "Network Device Discovery".to_string(),
                status: CheckStatus::Unknown,
                details: format!("Discovery failed: {}", e),
                severity: Severity::Low,
            });
            None
        }
    };

    // Determine overall status based on check results
    let status = determine_overall_status(&checks);

    // Generate recommendations based on findings
    let recommendations = report::generate_recommendations(&checks, &network_map);

    Ok(SafetyCheckResult {
        status,
        checks,
        network_map,
        recommendations,
        timestamp,
    })
}

/// Determine overall safety status based on individual check results.
///
/// Precedence (worst wins):
/// - Unsafe: any failed check (Critical/High severity = active threat).
/// - Caution: any warning, any check that could not run (Unknown), or a
///   lower-severity failure - normal public-network unknowns.
/// - Mostly Safe: nothing wrong, but a remote verification is still pending
///   (e.g. gateway reputation enrichment the agent will perform).
/// - Safe: everything passed and was fully verified.
fn determine_overall_status(checks: &[CheckResult]) -> SafetyStatus {
    let has_serious_failure = checks.iter().any(|c| {
        c.status == CheckStatus::Failed
            && (c.severity == Severity::Critical || c.severity == Severity::High)
    });

    let has_minor_failure = checks.iter().any(|c| c.status == CheckStatus::Failed);

    let has_warning = checks.iter().any(|c| c.status == CheckStatus::Warning);

    let has_unknown = checks.iter().any(|c| c.status == CheckStatus::Unknown);

    let has_pending = checks
        .iter()
        .any(|c| c.status == CheckStatus::NeedsEnrichment);

    if has_serious_failure {
        SafetyStatus::Unsafe
    } else if has_minor_failure || has_warning || has_unknown {
        SafetyStatus::Caution
    } else if has_pending {
        SafetyStatus::MostlySafe
    } else {
        SafetyStatus::Safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_overall_status_safe() {
        let checks = vec![
            CheckResult {
                name: "Test 1".to_string(),
                status: CheckStatus::Passed,
                details: "OK".to_string(),
                severity: Severity::Info,
            },
            CheckResult {
                name: "Test 2".to_string(),
                status: CheckStatus::Passed,
                details: "OK".to_string(),
                severity: Severity::Info,
            },
        ];

        assert_eq!(determine_overall_status(&checks), SafetyStatus::Safe);
    }

    #[test]
    fn test_determine_overall_status_caution_on_warning() {
        let checks = vec![
            CheckResult {
                name: "Test 1".to_string(),
                status: CheckStatus::Passed,
                details: "OK".to_string(),
                severity: Severity::Info,
            },
            CheckResult {
                name: "Test 2".to_string(),
                status: CheckStatus::Warning,
                details: "Medium issue".to_string(),
                severity: Severity::Medium,
            },
        ];

        assert_eq!(determine_overall_status(&checks), SafetyStatus::Caution);
    }

    #[test]
    fn test_determine_overall_status_unsafe_on_critical() {
        let checks = vec![
            CheckResult {
                name: "Test 1".to_string(),
                status: CheckStatus::Passed,
                details: "OK".to_string(),
                severity: Severity::Info,
            },
            CheckResult {
                name: "Test 2".to_string(),
                status: CheckStatus::Failed,
                details: "Critical issue".to_string(),
                severity: Severity::Critical,
            },
        ];

        assert_eq!(determine_overall_status(&checks), SafetyStatus::Unsafe);
    }

    #[test]
    fn test_determine_overall_status_mostly_safe_on_pending() {
        // All checks clean, but one is pending remote enrichment -> Mostly Safe.
        let checks = vec![
            CheckResult {
                name: "DNS Integrity".to_string(),
                status: CheckStatus::Passed,
                details: "OK".to_string(),
                severity: Severity::Info,
            },
            CheckResult {
                name: "Router Threat Intelligence".to_string(),
                status: CheckStatus::NeedsEnrichment,
                details: "Public IP pending reputation lookup".to_string(),
                severity: Severity::Low,
            },
        ];

        assert_eq!(determine_overall_status(&checks), SafetyStatus::MostlySafe);
    }

    #[test]
    fn test_pending_does_not_override_warning() {
        // A real warning outranks a pending enrichment -> Caution, not Mostly Safe.
        let checks = vec![
            CheckResult {
                name: "Router Threat Intelligence".to_string(),
                status: CheckStatus::NeedsEnrichment,
                details: "pending".to_string(),
                severity: Severity::Low,
            },
            CheckResult {
                name: "DNS Integrity".to_string(),
                status: CheckStatus::Warning,
                details: "partial".to_string(),
                severity: Severity::Medium,
            },
        ];

        assert_eq!(determine_overall_status(&checks), SafetyStatus::Caution);
    }

    #[test]
    fn test_minor_failure_is_caution_not_safe() {
        // A low-severity failure must not fall through to Safe.
        let checks = vec![CheckResult {
            name: "Test".to_string(),
            status: CheckStatus::Failed,
            details: "minor".to_string(),
            severity: Severity::Low,
        }];

        assert_eq!(determine_overall_status(&checks), SafetyStatus::Caution);
    }
}

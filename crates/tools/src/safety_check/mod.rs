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

// --- Stage wall-clock budgets (#495) ---------------------------------
// Every stage below used to be an unbounded `.await`: one wedged OS resolver,
// gateway probe or nmap sweep pinned the WHOLE tool until the caller's 520s
// connector timeout fired and the tool errored — 4/4 live invocations on
// 2026-09-24 died at exactly the 530s ceiling (520s budget + 10s grace), never
// returning a result, while every other Pick tool answered in <10s.
//
// A budget converts "never returns" into `Err(.. timed out ..)`, which the
// existing per-stage `Err` arms in `run_safety_check` already degrade into
// `CheckStatus::Unknown` — a structured, honest "could not check" instead of
// a nine-minute hang (#495).
//
// Worst-case SEQUENTIAL sum is asserted in tests to stay under the ~30s a
// metadata-class tool is allotted on the consuming side — that matching
// per-tool budget lands separately (pending), so today each side bounds the
// call on its own and neither PR needs the other to be safe.
//
// Note: `tokio::time::timeout` abandons the future; blocking work keeps
// running until the OS returns — the spawn_blocking'd OS resolver and gateway
// probe ride tokio's blocking pool (one call per stage per run), and two
// further probes (network_context's inline default-interface lookup,
// `NI::show()`) run synchronously inside their async fns and are not
// interruptible at all. All are local interface/resolver reads measured in
// µs–ms, so they cannot reintroduce the nine-minute hang — but they are
// strictly outside these budgets. The nmap CHILD is explicitly
// `kill_on_drop(true)` so no orphan scan survives a budget (network_map.rs).
pub(crate) const STAGE_BUDGET_MARKER: &str = "safety-check stage budget";
pub(crate) const DNS_CHECK_BUDGET_SECS: u64 = 5;
pub(crate) const THREAT_INTEL_BUDGET_SECS: u64 = 5;
/// Covers the 15s nmap inner budget plus gateway/ARP/interface probes.
pub(crate) const NETWORK_DISCOVERY_BUDGET_SECS: u64 = 17;
pub(crate) const NMAP_SWEEP_BUDGET_SECS: u64 = 15;
pub(crate) const NETWORK_CONTEXT_BUDGET_SECS: u64 = 2;

/// Run one safety-check stage under a hard wall-clock budget (#495).
///
/// Returns the stage's own `Ok`/`Err` untouched when it finishes inside the
/// budget; converts an over-budget (wedged) stage into an `Err` naming the
/// stage and its budget, so callers' existing error arms degrade gracefully.
pub(crate) async fn with_budget<T>(
    stage: &str,
    budget_secs: u64,
    fut: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    match tokio::time::timeout(std::time::Duration::from_secs(budget_secs), fut).await {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "{} timed out after {}s ({})",
            stage,
            budget_secs,
            STAGE_BUDGET_MARKER
        )),
    }
}

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
    match with_budget(
        "DNS integrity check",
        DNS_CHECK_BUDGET_SECS,
        dns_check::check_dns_integrity(),
    )
    .await
    {
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
    match with_budget(
        "router threat intel",
        THREAT_INTEL_BUDGET_SECS,
        threat_intel::check_router_threat_intel(),
    )
    .await
    {
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
    let network_map = match with_budget(
        "network discovery",
        NETWORK_DISCOVERY_BUDGET_SECS,
        network_map::discover_network(),
    )
    .await
    {
        Ok(map) => {
            tracing::info!(
                "Network discovery completed: {} devices found{}",
                map.other_devices.len(),
                if map.sweep_truncated.is_some() {
                    " (sweep truncated)"
                } else {
                    ""
                }
            );
            // #495 review: a sweep that hit its budget is a PARTIAL view —
            // reporting it as a clean pass hid the truncation entirely. Flag
            // it in `details` and downgrade to Warning, which the overall
            // status then maps to Caution instead of a confident green.
            let (status, details, severity) = match &map.sweep_truncated {
                Some(reason) => (
                    CheckStatus::Warning,
                    format!(
                        "Found {} devices on local network — PARTIAL: {}",
                        map.other_devices.len(),
                        reason
                    ),
                    Severity::Medium,
                ),
                None => (
                    CheckStatus::Passed,
                    format!("Found {} devices on local network", map.other_devices.len()),
                    Severity::Info,
                ),
            };
            checks.push(CheckResult {
                name: "Network Device Discovery".to_string(),
                status,
                details,
                severity,
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

    // Derive the host's active subnets scan-free (interface netmasks only, no
    // nmap/ARP). This is the reusable "what network am I on" source of truth,
    // independent of whether the discovery sweep above succeeded. Best-effort:
    // an enumeration failure yields an empty list, never a failed check.
    let active_subnets = match with_budget("network context", NETWORK_CONTEXT_BUDGET_SECS, async {
        crate::network_context::network_context()
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))
    })
    .await
    {
        Ok(subnets) => {
            tracing::info!(
                "Active subnets (scan-free): {}",
                if subnets.is_empty() {
                    "none derived".to_string()
                } else {
                    subnets
                        .iter()
                        .map(|s| s.cidr.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
            subnets.into_iter().map(|s| s.cidr).collect()
        }
        Err(e) => {
            tracing::warn!("Could not derive active subnets: {}", e);
            Vec::new()
        }
    };

    // Determine overall status based on check results, then cap it for the
    // realities of a large/shared network (busy networks never read a
    // confident green "Safe").
    let status = cap_for_network_size(determine_overall_status(&checks), &network_map);

    // Generate recommendations based on findings
    let recommendations = report::generate_recommendations(&checks, &network_map);

    Ok(SafetyCheckResult {
        status,
        checks,
        network_map,
        active_subnets,
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

/// Device count above which a network is treated as "busy" - large enough that
/// a confident green "Safe" would be misleading even when nothing is wrong.
const BUSY_NETWORK_DEVICE_THRESHOLD: usize = 20;

/// Cap a verdict for the realities of a large or shared network.
///
/// A network with many devices, or one spanning multiple subnets, is very
/// likely a public/corporate network. Nothing may be wrong, but a non-technical
/// user should not see a confident green "Safe" there - so we cap a `Safe`
/// result down to `MostlySafe` (with the reason surfaced via recommendations).
/// Worse verdicts (Caution/Unsafe) are never softened.
fn cap_for_network_size(status: SafetyStatus, network_map: &Option<NetworkMap>) -> SafetyStatus {
    // Only ever downgrade a clean "Safe"; never touch worse verdicts.
    if status != SafetyStatus::Safe {
        return status;
    }

    let Some(map) = network_map else {
        return status;
    };

    let is_busy = map.other_devices.len() >= BUSY_NETWORK_DEVICE_THRESHOLD;
    let is_multi_subnet = spans_multiple_subnets(map);

    if is_busy || is_multi_subnet {
        tracing::info!(
            "Capping Safe -> MostlySafe (devices={}, multi_subnet={})",
            map.other_devices.len(),
            is_multi_subnet
        );
        SafetyStatus::MostlySafe
    } else {
        status
    }
}

/// True if discovered devices span more than one /24, a strong signal of a
/// larger managed network rather than a small home/cafe LAN.
fn spans_multiple_subnets(map: &NetworkMap) -> bool {
    use std::net::IpAddr;

    fn slash24(ip: &IpAddr) -> Option<[u8; 3]> {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Some([o[0], o[1], o[2]])
            }
            // IPv6 is not part of the /24 heuristic; ignore for this signal.
            IpAddr::V6(_) => None,
        }
    }

    let mut seen: Option<[u8; 3]> = None;
    for dev in &map.other_devices {
        if let Some(prefix) = slash24(&dev.ip) {
            match seen {
                Some(p) if p != prefix => return true,
                Some(_) => {}
                None => seen = Some(prefix),
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // --- #495: stage wall-clock budgets -----------------------------
    #[tokio::test]
    async fn with_budget_returns_the_stages_own_result_when_under_budget() {
        let ok = with_budget("fast", 5, async { Ok::<_, anyhow::Error>(7) }).await;
        assert_eq!(ok.unwrap(), 7);

        let err = with_budget("failing", 5, async {
            Err::<i32, _>(anyhow::anyhow!("boom"))
        })
        .await;
        assert_eq!(err.unwrap_err().to_string(), "boom");
    }

    #[tokio::test]
    async fn with_budget_converts_a_wedged_stage_into_a_named_timeout_error() {
        // Zero budget = the stage can never finish in time; the future sleeps
        // an hour, so the timeout path is deterministic AND instant — this is
        // exactly the 4/4-hang shape from #495 (a stage that never
        // returns), reduced to a test that cannot flake.
        let started = std::time::Instant::now();
        let result = with_budget("wedged stage", 0, async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok::<_, anyhow::Error>(())
        })
        .await;

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("wedged stage"),
            "stage name must surface: {err}"
        );
        assert!(err.contains("timed out"), "budget must surface: {err}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the timeout must not wait for the wedged future"
        );
    }

    #[test]
    fn worst_case_stage_sum_stays_under_the_metadata_tool_budget() {
        // #495: a fully-degraded run (every stage hits its budget) must
        // still finish under ~30s — the whole point is never again approaching
        // the 520s ceiling (the caller-side per-tool budget lands separately).
        // Inline const so the assertion is checked at compile time (clippy's
        // `assertions_on_constants` applies to runtime-evaluated const sums).
        const {
            assert!(
                DNS_CHECK_BUDGET_SECS
                    + THREAT_INTEL_BUDGET_SECS
                    + NETWORK_DISCOVERY_BUDGET_SECS
                    + NETWORK_CONTEXT_BUDGET_SECS
                    <= 30,
                "stage budgets must sum to <= 30s (metadata-class tool budget, #495)"
            );
            assert!(NMAP_SWEEP_BUDGET_SECS <= NETWORK_DISCOVERY_BUDGET_SECS);
        }
    }

    // --- #495 review: wiring guard --------------------------------------
    //
    // The tests above prove the MECHANISM (with_budget) and the budget SUM;
    // this one proves it is WIRED into the real tool: a run_safety_check()
    // whose nmap wedge stalls must (a) return inside the stage budgets and
    // (b) report the truncated sweep as a Warning/PARTIAL check. Raising or
    // removing a budget trips the 40s watchdog as a clean failure (not a
    // hang).

    /// Restores PATH on drop so a failing assert cannot leak the shim.
    #[cfg(unix)]
    struct PathGuard(Option<std::ffi::OsString>);

    #[cfg(unix)]
    impl Drop for PathGuard {
        fn drop(&mut self) {
            if let Some(old) = self.0.take() {
                std::env::set_var("PATH", old);
            }
        }
    }

    /// Install a fake `nmap` at the FRONT of PATH: passes the presence probe
    /// (`--version`), then wedges (`exec sleep 37173`) in place of the sweep.
    /// Returns the temp dir (keep alive) plus a guard that restores PATH.
    #[cfg(unix)]
    fn install_fake_wedged_nmap() -> (tempfile::TempDir, PathGuard) {
        let dir = tempfile::tempdir().expect("tempdir");
        let shim = dir.path().join("nmap");
        std::fs::write(
            &shim,
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo 'Nmap 0.0-test (fake)'\n  exit 0\nfi\nexec sleep 37173\n",
        )
        .expect("write fake nmap");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
            .expect("chmod +x fake nmap");

        let old_path = std::env::var_os("PATH");
        let mut new_path = dir.path().as_os_str().to_os_string();
        new_path.push(":");
        new_path.push(old_path.clone().unwrap_or_default());
        std::env::set_var("PATH", &new_path);
        (dir, PathGuard(old_path))
    }

    #[cfg(unix)]
    fn count_fake_sleepers_once() -> usize {
        // pgrep: exit 0 = matched, 1 = no match, anything else = unavailable
        // (fail-open on THIS leg only; the budget/watchdog legs still guard).
        match std::process::Command::new("pgrep")
            .args(["-f", "sleep 37173"])
            .output()
        {
            Ok(out) if out.status.code() == Some(1) => 0,
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count(),
            _ => 0,
        }
    }

    /// Sweep ANY wedged fake-nmap child out of the suite's way. Housekeeping
    /// only — never asserted in the default run (see the orphan test's note).
    #[cfg(unix)]
    fn reap_fake_nmap_children() {
        let _ = std::process::Command::new("pkill")
            .args(["-f", "sleep 37173"])
            .status();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wedged_nmap_is_bounded_and_reported_as_truncated() {
        let mutex = tokio::sync::Mutex::const_new(());
        let _lock = mutex.lock().await;
        let (_dir, _path_guard) = install_fake_wedged_nmap();
        // Needs what the real check needs: a default gateway (any normal
        // network iface) — same prerequisite as `live_report`.

        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(Duration::from_secs(40), run_safety_check()).await;

        // Housekeeping regardless of outcome, so a failure here can never
        // leak a six-minute sleeper into the rest of the suite.
        reap_fake_nmap_children();

        let result = outcome.unwrap_or_else(|_| {
            panic!(
                "wiring failure: run_safety_check exceeded 40s — a stage budget \
                 was removed or enlarged"
            )
        });
        let elapsed = started.elapsed();
        let report = result.expect("a degraded report is still an Ok result");

        assert!(
            elapsed <= Duration::from_secs(35),
            "stage budgets must bound the run: took {elapsed:?}"
        );

        let discovery = report
            .checks
            .iter()
            .find(|c| c.name == "Network Device Discovery")
            .expect("discovery check must be present");
        assert_eq!(
            discovery.status,
            CheckStatus::Warning,
            "a wedged sweep must be reported as truncated (Warning), got {:?}: {}",
            discovery.status,
            discovery.details
        );
        assert!(
            discovery.details.contains("PARTIAL"),
            "truncation must be visible in details: {}",
            discovery.details
        );
        assert!(
            !matches!(report.status, SafetyStatus::Safe | SafetyStatus::MostlySafe),
            "a truncated sweep must not read as a confident green verdict: {:?}",
            report.status
        );
    }

    /// Opt-in `kill_on_drop` verification (#495 review):
    ///
    /// ```text
    /// cargo test -p pentest-tools --lib wedged_nmap_leaves_no_orphan -- --ignored --nocapture
    /// ```
    ///
    /// Isolated runs: clean on every attempt (child gone before sampling).
    /// Under the FULL parallel suite the kill can be observed not-yet-issued
    /// even after a 10s window — tokio 1.50's ChildDropGuard kill issues
    /// synchronously on drop, so that divergence is a runtime/environment
    /// interaction outside this crate, and a default-on assertion here would
    /// make the repository's suite racy. Kept opt-in (and CI-off) rather than
    /// pretending the observation is deterministic; the caller's own live
    /// `pgrep` check post-run covers it in staging.
    #[cfg(unix)]
    #[ignore = "timing/environment sensitive under full-suite parallelism — run isolated"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wedged_nmap_leaves_no_orphan() {
        let mutex = tokio::sync::Mutex::const_new(());
        let _lock = mutex.lock().await;
        let (_dir, _path_guard) = install_fake_wedged_nmap();

        let outcome = tokio::time::timeout(Duration::from_secs(40), run_safety_check()).await;

        // Await-driven grace: keep the runtime ticking so tokio's process
        // driver can deliver the kill before we look.
        let mut orphans = usize::MAX;
        for i in 0..30 {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            orphans = count_fake_sleepers_once();
            if orphans == 0 {
                break;
            }
        }
        reap_fake_nmap_children();

        outcome
            .unwrap_or_else(|_| panic!("run_safety_check exceeded 40s"))
            .expect("a degraded report is still an Ok result");
        assert_eq!(
            orphans, 0,
            "kill_on_drop must reap the wedged nmap child — found {orphans} sleeper(s)"
        );
    }

    /// Manual smoke test: runs the real safety check against the live network
    /// and prints the actual Markdown report. Ignored by default (needs network
    /// + nmap). Run with:
    ///   cargo test -p pentest-tools safety_check::tests::live_report -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn live_report() {
        let result = run_safety_check().await.expect("safety check should run");
        println!("\n===== LIVE SAFETY CHECK REPORT =====\n");
        println!("{}", report::format_report(&result));
        println!("\n===== END =====\n");
    }

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

    fn device_at(ip: &str) -> Device {
        Device {
            ip: ip.parse().unwrap(),
            mac: None,
            hostname: None,
            vendor: None,
            open_ports: Vec::new(),
            threat_level: ThreatLevel::Safe,
        }
    }

    fn map_with(devices: Vec<Device>) -> NetworkMap {
        NetworkMap {
            gateway: device_at("192.168.1.1"),
            your_device: device_at("192.168.1.100"),
            other_devices: devices,
            sweep_truncated: None,
        }
    }

    #[test]
    fn test_small_single_subnet_stays_safe() {
        // A handful of same-subnet devices is a normal home LAN - stays Safe.
        let map = Some(map_with(vec![
            device_at("192.168.1.2"),
            device_at("192.168.1.3"),
        ]));
        assert_eq!(
            cap_for_network_size(SafetyStatus::Safe, &map),
            SafetyStatus::Safe
        );
    }

    #[test]
    fn test_busy_network_caps_safe_to_mostly_safe() {
        let devices: Vec<Device> = (0..25)
            .map(|i| device_at(&format!("192.168.1.{}", 2 + i)))
            .collect();
        let map = Some(map_with(devices));
        assert_eq!(
            cap_for_network_size(SafetyStatus::Safe, &map),
            SafetyStatus::MostlySafe
        );
    }

    #[test]
    fn test_multi_subnet_caps_safe_to_mostly_safe() {
        // Only two devices, but on different /24s -> managed network -> capped.
        let map = Some(map_with(vec![
            device_at("172.16.26.10"),
            device_at("172.16.3.11"),
        ]));
        assert_eq!(
            cap_for_network_size(SafetyStatus::Safe, &map),
            SafetyStatus::MostlySafe
        );
    }

    #[test]
    fn test_cap_never_softens_worse_verdicts() {
        // A busy network must not soften Caution/Unsafe up to MostlySafe.
        let devices: Vec<Device> = (0..30)
            .map(|i| device_at(&format!("172.16.26.{}", 2 + i)))
            .collect();
        let map = Some(map_with(devices));
        assert_eq!(
            cap_for_network_size(SafetyStatus::Unsafe, &map),
            SafetyStatus::Unsafe
        );
        assert_eq!(
            cap_for_network_size(SafetyStatus::Caution, &map),
            SafetyStatus::Caution
        );
    }
}

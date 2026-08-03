//! Network-based autopwn planning for when WiFi pentesting is unavailable
//!
//! This module provides automated attack planning for network-based penetration testing,
//! serving as a fallback when WiFi pentest adapters are not available.

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::*;
use pentest_platform::{get_platform, SystemInfo};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Derive the sweep CIDR and the local IPv4 to plan around, from an interface's
/// addresses.
///
/// Selects the first usable IPv4 address (like `network_context`), never the
/// first address of any family — a garbage CIDR such as `"fe80::1.0/24"` must
/// never reach the attack plan → nmap. Resolution:
///
/// * IPv4 + known prefix → real netmask math (`subnet_cidr_v4`).
/// * IPv4 + missing prefix → `warn!` (matching the module's clamp-logging
///   observability) then a `/24` derived **via `subnet_cidr_v4`** (correct
///   network base, not a string-sliced guess). The prefix is unknown, not the
///   family, so a bounded /24 keeps planning moving while staying observable.
/// * No IPv4 at all → `Error::InvalidParams`, rather than fabricating a CIDR
///   from an IPv6/other-family string.
fn derive_scan_cidr(
    addresses: &[pentest_platform::InterfaceAddr],
    iface_name: &str,
) -> Result<(String, String)> {
    let (v4, prefix, ip) = addresses
        .iter()
        .find_map(|a| match a.parse_ip() {
            Some(std::net::IpAddr::V4(v4)) => Some((v4, a.prefix_len, a.ip.clone())),
            _ => None,
        })
        .ok_or_else(|| {
            Error::InvalidParams(format!(
                "interface {iface_name} has no IPv4 address to plan a network scan around"
            ))
        })?;

    let cidr = match prefix {
        Some(p) => crate::network_context::subnet_cidr_v4(v4, p),
        None => {
            tracing::warn!(
                "interface {} address {} has no known prefix; assuming /24 for the scan CIDR",
                iface_name,
                ip
            );
            crate::network_context::subnet_cidr_v4(v4, 24)
        }
    };
    Ok((cidr, ip))
}

/// Network-based attack plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAttackPlan {
    pub attack_type: NetworkAttackType,
    pub phases: Vec<AttackPhase>,
    pub estimated_duration_min: u32,
    pub target_network: String,
    pub notes: Vec<String>,
}

/// Type of network attack to perform
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NetworkAttackType {
    /// Full network penetration test (discovery -> scanning -> exploitation)
    FullPentest,
    /// Focused on specific host
    TargetedHost { host: String },
    /// Internal network mapping only
    Reconnaissance,
}

/// Individual phase in the attack sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPhase {
    pub phase_number: u8,
    pub name: String,
    pub description: String,
    pub tools: Vec<String>,
    pub estimated_duration_min: u32,
    pub depends_on: Option<u8>, // Phase number this depends on
}

/// Analyze network attack surface and recommend strategy
pub struct AutoPwnNetworkPlanTool;

#[async_trait]
impl PentestTool for AutoPwnNetworkPlanTool {
    fn name(&self) -> &str {
        "autopwn_network_plan"
    }

    fn description(&self) -> &str {
        "Plan a network-based penetration test attack sequence (discovery, scanning, exploitation)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::optional(
                "target_host",
                ParamType::String,
                "Specific target host to focus on (optional, for targeted attacks)",
                json!(null),
            ))
            .param(ToolParam::optional(
                "scan_type",
                ParamType::String,
                "Type of scan: 'full_pentest', 'targeted', or 'recon_only'",
                json!("full_pentest"),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![
            Platform::Desktop,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let target_host = params["target_host"].as_str();
            let scan_type = params["scan_type"]
                .as_str()
                .unwrap_or("full_pentest")
                .to_string();

            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("🎯 Network AutoPwn Planning");
            tracing::info!("═══════════════════════════════════════════════════");

            // Get network information
            let platform = get_platform();
            let interfaces = platform.get_network_interfaces().await?;

            // Find active network interface
            let active_iface = interfaces
                .iter()
                .find(|i| i.is_up && i.has_addresses())
                .ok_or_else(|| Error::InvalidParams("No active network interface found".into()))?;

            // Derive the scan CIDR + the local IPv4 to plan around. Picks the
            // first usable IPv4 (mirroring network_context) rather than the first
            // address of any family, so an IPv6-first interface can't produce a
            // garbage CIDR fed into the attack plan.
            let (network_cidr, local_ip) =
                derive_scan_cidr(&active_iface.addresses, &active_iface.name)?;

            tracing::info!("  Network:    {}", network_cidr);
            tracing::info!("  Local IP:   {}", local_ip);
            tracing::info!("  Interface:  {}", active_iface.name);
            tracing::info!("  Scan Type:  {}", scan_type);
            if let Some(host) = target_host {
                tracing::info!("  Target:     {}", host);
            }
            tracing::info!("───────────────────────────────────────────────────");

            // Build attack plan based on scan type
            let attack_plan = match scan_type.as_str() {
                "targeted" if target_host.is_some() => {
                    build_targeted_attack_plan(target_host.unwrap(), &network_cidr)
                }
                "recon_only" => build_recon_plan(&network_cidr),
                _ => build_full_pentest_plan(&network_cidr),
            };

            // Log the plan
            tracing::info!("");
            tracing::info!("📋 Attack Plan: {}", attack_plan.attack_type_str());
            tracing::info!(
                "⏱️  Estimated Duration: {} minutes",
                attack_plan.estimated_duration_min
            );
            tracing::info!("");
            tracing::info!("Attack Phases:");

            for phase in &attack_plan.phases {
                tracing::info!("");
                tracing::info!("Phase {}: {}", phase.phase_number, phase.name);
                tracing::info!("  Description: {}", phase.description);
                tracing::info!("  Tools: {}", phase.tools.join(", "));
                tracing::info!("  Duration: ~{} min", phase.estimated_duration_min);
                if let Some(dep) = phase.depends_on {
                    tracing::info!("  Depends on: Phase {}", dep);
                }
            }

            if !attack_plan.notes.is_empty() {
                tracing::info!("");
                tracing::info!("📝 Notes:");
                for note in &attack_plan.notes {
                    tracing::info!("  • {}", note);
                }
            }

            tracing::info!("");
            tracing::info!("═══════════════════════════════════════════════════");

            Ok(json!(attack_plan))
        })
        .await
    }
}

impl NetworkAttackPlan {
    fn attack_type_str(&self) -> &'static str {
        match self.attack_type {
            NetworkAttackType::FullPentest => "Full Network Penetration Test",
            NetworkAttackType::TargetedHost { .. } => "Targeted Host Attack",
            NetworkAttackType::Reconnaissance => "Network Reconnaissance",
        }
    }
}

/// Build a full penetration test plan
fn build_full_pentest_plan(network: &str) -> NetworkAttackPlan {
    let phases = vec![
        // Phase 1: Network Discovery
        AttackPhase {
            phase_number: 1,
            name: "Network Discovery".to_string(),
            description: "Discover live hosts on the network using ARP, mDNS, and SSDP".to_string(),
            tools: vec![
                "arp_table".to_string(),
                "ssdp_discover".to_string(),
                "network_discover".to_string(),
            ],
            estimated_duration_min: 2,
            depends_on: None,
        },
        // Phase 2: Port Scanning
        AttackPhase {
            phase_number: 2,
            name: "Port Scanning".to_string(),
            description: "Scan common ports on discovered hosts to identify services".to_string(),
            tools: vec!["port_scan".to_string()],
            estimated_duration_min: 5,
            depends_on: Some(1),
        },
        // Phase 3: Service Enumeration
        AttackPhase {
            phase_number: 3,
            name: "Service Enumeration".to_string(),
            description: "Grab service banners and enumerate protocols (SMB, HTTP, etc.)"
                .to_string(),
            tools: vec![
                "service_banner".to_string(),
                "smb_enum".to_string(),
                "web_vuln_scan".to_string(),
            ],
            estimated_duration_min: 10,
            depends_on: Some(2),
        },
        // Phase 4: Vulnerability Assessment
        AttackPhase {
            phase_number: 4,
            name: "Vulnerability Assessment".to_string(),
            description: "Search for known vulnerabilities and default credentials".to_string(),
            tools: vec!["cve_lookup".to_string(), "default_creds".to_string()],
            estimated_duration_min: 5,
            depends_on: Some(3),
        },
        // Phase 5: Exploitation Planning
        AttackPhase {
            phase_number: 5,
            name: "Exploitation Planning".to_string(),
            description: "Analyze findings and recommend exploitation strategies".to_string(),
            tools: vec!["Manual analysis required".to_string()],
            estimated_duration_min: 10,
            depends_on: Some(4),
        },
    ];

    let total_duration: u32 = phases.iter().map(|p| p.estimated_duration_min).sum();

    NetworkAttackPlan {
        attack_type: NetworkAttackType::FullPentest,
        phases,
        estimated_duration_min: total_duration,
        target_network: network.to_string(),
        notes: vec![
            "This is an automated attack sequence - monitor progress and adjust as needed"
                .to_string(),
            "Exploitation phase requires manual intervention based on discovered vulnerabilities"
                .to_string(),
            "Ensure you have proper authorization before running this attack sequence".to_string(),
        ],
    }
}

/// Build a targeted host attack plan
fn build_targeted_attack_plan(target: &str, network: &str) -> NetworkAttackPlan {
    let phases = vec![
        // Phase 1: Port Scanning
        AttackPhase {
            phase_number: 1,
            name: "Port Scanning".to_string(),
            description: format!("Scan all common ports on {}", target),
            tools: vec!["port_scan".to_string()],
            estimated_duration_min: 3,
            depends_on: None,
        },
        // Phase 2: Service Enumeration
        AttackPhase {
            phase_number: 2,
            name: "Service Enumeration".to_string(),
            description: "Identify services and versions on open ports".to_string(),
            tools: vec![
                "service_banner".to_string(),
                "smb_enum".to_string(),
                "web_vuln_scan".to_string(),
            ],
            estimated_duration_min: 8,
            depends_on: Some(1),
        },
        // Phase 3: Vulnerability Search
        AttackPhase {
            phase_number: 3,
            name: "Vulnerability Search".to_string(),
            description: "Search for CVEs and test default credentials".to_string(),
            tools: vec!["cve_lookup".to_string(), "default_creds".to_string()],
            estimated_duration_min: 5,
            depends_on: Some(2),
        },
        // Phase 4: Exploitation
        AttackPhase {
            phase_number: 4,
            name: "Exploitation".to_string(),
            description: "Attempt to exploit discovered vulnerabilities".to_string(),
            tools: vec!["Manual exploitation".to_string()],
            estimated_duration_min: 15,
            depends_on: Some(3),
        },
    ];

    let total_duration: u32 = phases.iter().map(|p| p.estimated_duration_min).sum();

    NetworkAttackPlan {
        attack_type: NetworkAttackType::TargetedHost {
            host: target.to_string(),
        },
        phases,
        estimated_duration_min: total_duration,
        target_network: network.to_string(),
        notes: vec![
            format!("Focused attack on target host: {}", target),
            "Exploitation requires manual intervention based on discovered vulnerabilities"
                .to_string(),
        ],
    }
}

/// Build a reconnaissance-only plan
fn build_recon_plan(network: &str) -> NetworkAttackPlan {
    let phases = vec![
        // Phase 1: Passive Discovery
        AttackPhase {
            phase_number: 1,
            name: "Passive Discovery".to_string(),
            description: "Discover hosts using ARP table and passive methods".to_string(),
            tools: vec!["arp_table".to_string()],
            estimated_duration_min: 1,
            depends_on: None,
        },
        // Phase 2: Service Discovery
        AttackPhase {
            phase_number: 2,
            name: "Service Discovery".to_string(),
            description: "Discover advertised services via mDNS and SSDP".to_string(),
            tools: vec!["network_discover".to_string(), "ssdp_discover".to_string()],
            estimated_duration_min: 2,
            depends_on: None,
        },
        // Phase 3: Light Port Scan
        AttackPhase {
            phase_number: 3,
            name: "Light Port Scan".to_string(),
            description: "Quick scan of common ports on discovered hosts".to_string(),
            tools: vec!["port_scan".to_string()],
            estimated_duration_min: 3,
            depends_on: Some(1),
        },
    ];

    let total_duration: u32 = phases.iter().map(|p| p.estimated_duration_min).sum();

    NetworkAttackPlan {
        attack_type: NetworkAttackType::Reconnaissance,
        phases,
        estimated_duration_min: total_duration,
        target_network: network.to_string(),
        notes: vec![
            "Reconnaissance-only - no active exploitation".to_string(),
            "Safe to run on production networks (minimal noise)".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_pentest_plan() {
        let plan = build_full_pentest_plan("192.168.1.0/24");
        assert_eq!(plan.phases.len(), 5);
        assert_eq!(plan.phases[0].name, "Network Discovery");
        assert_eq!(plan.phases[4].name, "Exploitation Planning");
        assert!(plan.estimated_duration_min > 0);
    }

    #[test]
    fn test_targeted_plan() {
        let plan = build_targeted_attack_plan("192.168.1.50", "192.168.1.0/24");
        assert_eq!(plan.phases.len(), 4);
        assert!(matches!(
            plan.attack_type,
            NetworkAttackType::TargetedHost { .. }
        ));
    }

    #[test]
    fn test_recon_plan() {
        let plan = build_recon_plan("192.168.1.0/24");
        assert_eq!(plan.phases.len(), 3);
        assert!(matches!(
            plan.attack_type,
            NetworkAttackType::Reconnaissance
        ));
        assert!(plan.estimated_duration_min < 10);
    }

    use pentest_platform::InterfaceAddr;

    #[test]
    fn derive_cidr_uses_real_prefix_for_ipv4() {
        // The core fix: a /22 host resolves to its real /22 base via netmask math.
        let addrs = vec![InterfaceAddr::new("10.0.11.5", Some(22))];
        let (cidr, ip) = derive_scan_cidr(&addrs, "eth0").unwrap();
        assert_eq!(cidr, "10.0.8.0/22");
        assert_eq!(ip, "10.0.11.5");
    }

    #[test]
    fn derive_cidr_skips_ipv6_and_picks_ipv4() {
        // An IPv6-first interface must NOT yield a garbage CIDR like
        // "fe80::1.0/24"; the IPv4 address is selected instead.
        let addrs = vec![
            InterfaceAddr::new("fe80::1", Some(64)),
            InterfaceAddr::new("192.168.40.130", Some(24)),
        ];
        let (cidr, ip) = derive_scan_cidr(&addrs, "wlan0").unwrap();
        assert_eq!(cidr, "192.168.40.0/24");
        assert_eq!(ip, "192.168.40.130");
        // Never fabricates from the IPv6 string.
        assert!(!cidr.contains("fe80"));
    }

    #[test]
    fn derive_cidr_ipv4_missing_prefix_assumes_24_via_netmask() {
        // Missing prefix (not family) -> bounded /24, computed by subnet_cidr_v4
        // (real network base), never a string-sliced "10.0.11.0/24" that could
        // mangle a non-.0 host or an IPv6 string.
        let addrs = vec![InterfaceAddr::new("10.0.11.5", None)];
        let (cidr, _) = derive_scan_cidr(&addrs, "eth0").unwrap();
        assert_eq!(cidr, "10.0.11.0/24");
    }

    #[test]
    fn derive_cidr_no_ipv4_is_an_error_not_a_garbage_cidr() {
        // IPv6-only interface: refuse rather than fabricate a CIDR. This is the
        // reachability half the PR widened (Android now enumerates inet6).
        let addrs = vec![InterfaceAddr::new("2001:db8::5", Some(64))];
        let err = derive_scan_cidr(&addrs, "tun0").unwrap_err();
        assert!(matches!(err, Error::InvalidParams(_)));
    }
}

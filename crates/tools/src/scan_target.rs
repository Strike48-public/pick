//! Resolve scan-target sentinels (`auto`/`current`/`all`) against the host's
//! real subnets, and flag out-of-subnet targets.
//!
//! The operational failure this addresses: an agent hallucinates a range
//! (`192.168.1.0/24`) instead of scanning the network it is actually on. Making
//! `auto`/`current` first-class targets (resolved from
//! [`crate::network_context`]) lets the safe target be the default instead of a
//! discipline the model must remember.
//!
//! Two layers: a pure core ([`resolve_against_subnets`]) that takes the subnet
//! list as input (unit-testable, no I/O), and an async wrapper
//! ([`resolve_scan_target`]) that fetches the live context.

use crate::network_context::{network_context, Subnet};
use pentest_core::error::Error;
use pentest_core::validation::validate_target;
use std::net::Ipv4Addr;

/// Sentinel target values, matched case-insensitively.
const SENTINEL_CURRENT: &str = "current";
const SENTINEL_AUTO: &str = "auto";
const SENTINEL_ALL: &str = "all";

/// Outcome of resolving a raw target argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTargets {
    /// Concrete targets to hand to the scanner (CIDRs and/or the original
    /// literal). Never empty on `Ok`.
    pub targets: Vec<String>,
    /// Non-blocking advisory: the raw target is a literal outside every known
    /// local subnet (possible typo, or an intentional routed/pivot scan). The
    /// scan still proceeds - this is surfaced, not enforced.
    pub out_of_subnet_warning: Option<String>,
}

/// Error resolving a sentinel target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// A sentinel (`auto`/`current`/`all`) was requested but no local subnet
    /// could be derived (interface enumeration failed or found nothing usable).
    NoSubnets(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::NoSubnets(s) => write!(
                f,
                "target '{s}' requires knowing this host's subnets, but none could be \
                 determined (interface enumeration failed or found no usable IPv4 subnet); \
                 specify an explicit CIDR instead"
            ),
        }
    }
}

impl std::error::Error for ResolveError {}

/// True if `ip` falls inside the IPv4 `cidr` (e.g. `10.0.8.0/22`).
///
/// Hand-rolled v4 containment (no external CIDR crate): parse base + prefix,
/// mask both, compare. Non-IPv4 or malformed inputs yield `false` (a v6 target
/// is simply never "in" a v4 subnet for this advisory check).
fn ipv4_in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let Some((base, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(base_addr) = base.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix_len) = prefix.parse::<u8>() else {
        return false;
    };
    if prefix_len > 32 {
        return false;
    }
    // /0 contains everything; guard the shift (<<32 is UB-adjacent).
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len as u32)
    };
    (u32::from(ip) & mask) == (u32::from(base_addr) & mask)
}

/// Extract the bare IPv4 address a raw target refers to, if any.
///
/// Handles a plain IP (`10.0.8.5`) and a CIDR (`10.0.8.0/22` -> its base). A
/// hostname or IPv6 target yields `None` (the out-of-subnet check only applies
/// to concrete v4 addresses).
fn target_ipv4(raw: &str) -> Option<Ipv4Addr> {
    let bare = raw.split('/').next().unwrap_or(raw);
    bare.parse::<Ipv4Addr>().ok()
}

/// Resolve a raw target against a known subnet list (pure).
///
/// * `current` -> the primary (default-route) subnet, or the first subnet if
///   none is flagged primary (best-effort when primary detection failed).
/// * `auto` / `all` -> every known subnet.
/// * anything else -> passed through unchanged, with an out-of-subnet advisory
///   attached when it is a concrete v4 address/CIDR outside every known subnet.
///
/// Sentinel matching is case-insensitive. Returns [`ResolveError::NoSubnets`]
/// only when a sentinel is requested and `subnets` is empty.
pub fn resolve_against_subnets(
    raw: &str,
    subnets: &[Subnet],
) -> Result<ResolvedTargets, ResolveError> {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();

    match lower.as_str() {
        SENTINEL_CURRENT => {
            let chosen = subnets
                .iter()
                .find(|s| s.is_primary)
                .or_else(|| subnets.first())
                .ok_or_else(|| ResolveError::NoSubnets(trimmed.to_string()))?;
            Ok(ResolvedTargets {
                targets: vec![chosen.cidr.clone()],
                out_of_subnet_warning: None,
            })
        }
        SENTINEL_AUTO | SENTINEL_ALL => {
            if subnets.is_empty() {
                return Err(ResolveError::NoSubnets(trimmed.to_string()));
            }
            Ok(ResolvedTargets {
                targets: subnets.iter().map(|s| s.cidr.clone()).collect(),
                out_of_subnet_warning: None,
            })
        }
        _ => {
            // Literal target: pass through, but advise if it's a concrete v4
            // address outside every known local subnet. Only warn when we
            // actually know our subnets (empty list -> no basis to judge).
            let warning = match target_ipv4(trimmed) {
                Some(ip) if !subnets.is_empty() => {
                    let inside = subnets.iter().any(|s| ipv4_in_cidr(ip, &s.cidr));
                    if inside {
                        None
                    } else {
                        let known = subnets
                            .iter()
                            .map(|s| s.cidr.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        Some(format!(
                            "target {trimmed} is outside your active subnet(s) [{known}]; \
                             scanning anyway (intentional if this is a routed/pivot target, \
                             but check for a typo if not)"
                        ))
                    }
                }
                _ => None,
            };
            Ok(ResolvedTargets {
                targets: vec![trimmed.to_string()],
                out_of_subnet_warning: warning,
            })
        }
    }
}

/// True if a raw target is one of the recognized sentinels (case-insensitive).
pub fn is_sentinel(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        SENTINEL_CURRENT | SENTINEL_AUTO | SENTINEL_ALL
    )
}

/// Resolve a raw target against the host's live network context.
///
/// Fetches [`network_context`] (scan-free) and delegates to
/// [`resolve_against_subnets`]. Only performs the interface enumeration when the
/// target is actually a sentinel *or* a concrete address worth range-checking -
/// a hostname passes straight through without touching the network.
pub async fn resolve_scan_target(raw: &str) -> Result<ResolvedTargets, ResolveError> {
    let subnets: Vec<Subnet> = network_context().await.unwrap_or_else(|e| {
        tracing::warn!("network_context unavailable while resolving target: {}", e);
        Vec::new()
    });
    resolve_against_subnets(raw, &subnets)
}

/// Validated, ready-to-scan targets plus any advisory to surface.
#[derive(Debug, Clone)]
pub struct PreparedTargets {
    /// Concrete targets, each already through `validate_target`. Never empty.
    pub targets: Vec<String>,
    /// Non-blocking out-of-subnet advisory, if any (for inclusion in the tool
    /// result so the agent sees it).
    pub warning: Option<String>,
}

/// Full target pipeline for a discovery scanner: **resolve sentinel -> validate
/// -> warn**, in that fixed order.
///
/// This is the single choke point the network scanners share so the ordering
/// (and the previously-missing validation on the bypass tools) lives in one
/// place rather than being re-implemented per tool:
///
/// 1. Resolve `auto`/`current`/`all` against the host's live subnets.
/// 2. Validate every resolved target with [`validate_target`] (format /
///    command-injection guard) - this closes the gap where `arp_scan`,
///    `netdiscover`, `masscan_fast`, and `nmap_vuln` shelled a raw string.
/// 3. Log any out-of-subnet advisory and return it for the tool result. The
///    advisory never blocks the scan (routed/pivot targets are legitimate).
///
/// # Errors
///
/// - [`Error::InvalidParams`] if a sentinel can't be resolved (no known subnets)
///   or if any resolved/literal target fails validation.
pub async fn prepare_scan_targets(raw: &str) -> pentest_core::error::Result<PreparedTargets> {
    let resolved = resolve_scan_target(raw)
        .await
        .map_err(|e| Error::InvalidParams(e.to_string()))?;

    // Validate every concrete target (closes the bypass-tool gap).
    let mut validated = Vec::with_capacity(resolved.targets.len());
    for t in &resolved.targets {
        validated.push(validate_target(t)?);
    }

    if let Some(ref w) = resolved.out_of_subnet_warning {
        tracing::warn!("{}", w);
    }

    Ok(PreparedTargets {
        targets: validated,
        warning: resolved.out_of_subnet_warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sn(cidr: &str, primary: bool) -> Subnet {
        Subnet {
            cidr: cidr.to_string(),
            interface: "test".to_string(),
            is_primary: primary,
        }
    }

    #[test]
    fn current_resolves_to_primary_subnet() {
        let subnets = vec![sn("10.0.8.0/22", false), sn("10.0.40.0/24", true)];
        let r = resolve_against_subnets("current", &subnets).unwrap();
        assert_eq!(r.targets, vec!["10.0.40.0/24"]);
        assert!(r.out_of_subnet_warning.is_none());
    }

    #[test]
    fn current_falls_back_to_first_when_no_primary_flagged() {
        let subnets = vec![sn("10.0.8.0/22", false), sn("10.0.40.0/24", false)];
        let r = resolve_against_subnets("current", &subnets).unwrap();
        assert_eq!(r.targets, vec!["10.0.8.0/22"]);
    }

    #[test]
    fn auto_and_all_resolve_to_every_subnet() {
        let subnets = vec![sn("10.0.8.0/22", true), sn("10.0.40.0/24", false)];
        for sentinel in ["auto", "all", "AUTO", "All"] {
            let r = resolve_against_subnets(sentinel, &subnets).unwrap();
            assert_eq!(
                r.targets,
                vec!["10.0.8.0/22", "10.0.40.0/24"],
                "sentinel {sentinel} should fan out to all subnets"
            );
        }
    }

    #[test]
    fn sentinel_with_no_subnets_is_an_error() {
        for sentinel in ["auto", "current", "all"] {
            assert!(
                matches!(
                    resolve_against_subnets(sentinel, &[]),
                    Err(ResolveError::NoSubnets(_))
                ),
                "sentinel {sentinel} with no subnets must error, not silently pass through"
            );
        }
    }

    #[test]
    fn literal_target_passes_through_unchanged() {
        let subnets = vec![sn("10.0.8.0/22", true)];
        let r = resolve_against_subnets("10.0.8.50", &subnets).unwrap();
        assert_eq!(r.targets, vec!["10.0.8.50"]);
        assert!(
            r.out_of_subnet_warning.is_none(),
            "an in-subnet literal must not warn"
        );
    }

    #[test]
    fn in_subnet_cidr_literal_does_not_warn() {
        let subnets = vec![sn("10.0.8.0/22", true)];
        let r = resolve_against_subnets("10.0.9.0/24", &subnets).unwrap();
        assert_eq!(r.targets, vec!["10.0.9.0/24"]);
        assert!(r.out_of_subnet_warning.is_none());
    }

    #[test]
    fn out_of_subnet_literal_warns_but_still_scans() {
        // The motivating bug: 192.168.1.0/24 while actually on 10.0.x.
        let subnets = vec![sn("10.0.8.0/22", true), sn("10.0.40.0/24", false)];
        let r = resolve_against_subnets("192.168.1.0/24", &subnets).unwrap();
        // Still scans the requested target (non-blocking).
        assert_eq!(r.targets, vec!["192.168.1.0/24"]);
        let warning = r.out_of_subnet_warning.expect("should warn");
        assert!(warning.contains("192.168.1.0/24"));
        assert!(warning.contains("10.0.8.0/22"));
        assert!(warning.contains("10.0.40.0/24"));
    }

    #[test]
    fn out_of_subnet_never_warns_when_subnets_unknown() {
        // No basis to judge -> no false warning.
        let r = resolve_against_subnets("192.168.1.5", &[]).unwrap();
        assert_eq!(r.targets, vec!["192.168.1.5"]);
        assert!(r.out_of_subnet_warning.is_none());
    }

    #[test]
    fn hostname_target_passes_through_without_warning() {
        let subnets = vec![sn("10.0.8.0/22", true)];
        let r = resolve_against_subnets("scanme.nmap.org", &subnets).unwrap();
        assert_eq!(r.targets, vec!["scanme.nmap.org"]);
        assert!(r.out_of_subnet_warning.is_none());
    }

    #[test]
    fn ipv4_in_cidr_boundaries() {
        // /22 spans 10.0.8.0 - 10.0.11.255.
        assert!(ipv4_in_cidr("10.0.8.0".parse().unwrap(), "10.0.8.0/22"));
        assert!(ipv4_in_cidr("10.0.11.255".parse().unwrap(), "10.0.8.0/22"));
        assert!(!ipv4_in_cidr("10.0.12.0".parse().unwrap(), "10.0.8.0/22"));
        // /32 host route.
        assert!(ipv4_in_cidr("1.2.3.4".parse().unwrap(), "1.2.3.4/32"));
        assert!(!ipv4_in_cidr("1.2.3.5".parse().unwrap(), "1.2.3.4/32"));
        // /0 contains everything.
        assert!(ipv4_in_cidr("8.8.8.8".parse().unwrap(), "0.0.0.0/0"));
        // Malformed cidr -> false, no panic.
        assert!(!ipv4_in_cidr("10.0.8.5".parse().unwrap(), "not-a-cidr"));
    }

    #[test]
    fn is_sentinel_matches_case_insensitively() {
        assert!(is_sentinel("auto"));
        assert!(is_sentinel("  Current "));
        assert!(is_sentinel("ALL"));
        assert!(!is_sentinel("10.0.8.0/22"));
        assert!(!is_sentinel("scanme.nmap.org"));
    }
}

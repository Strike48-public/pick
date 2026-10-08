//! Container network awareness: is this connector running in a container that
//! can only see a Docker bridge network?
//!
//! The failure mode (#510): the connector runs in Docker on the default bridge
//! network, comes up online in Studio, scans Docker's private subnet
//! (typically inside `172.16.0.0/12`), finds nothing, and reports an empty
//! network - with nothing telling the operator or the agent why. Every "what
//! network am I on" source (interface enumeration, `/proc/net/arp`, multicast
//! discovery) then reflects the bridge, not the host's LAN.
//!
//! Detection is **advisory only**: it produces one startup log warning and a
//! caveat in the agent persona. It never blocks or redirects scans, never
//! relaxes `PENTEST_ALLOW_PRIVATE_IPS`, and never switches networking modes.
//!
//! ## Classification rule
//!
//! Two inputs decide:
//!
//! 1. A container marker: `/.dockerenv` (Docker creates it for every
//!    container), `/run/.containerenv` (Podman), or a docker/containerd/
//!    kubepods entry in `/proc/self/cgroup`. On cgroup-v2-only hosts the
//!    cgroup file reports `0::/` inside the container, so the marker files are
//!    the primary signal and the cgroup scan is best effort.
//! 2. The default-route interface's identity. Docker bridge veth interfaces
//!    carry a `02:42:` MAC prefix (Docker derives the rest from the assigned
//!    IP); under `network_mode: host` the container instead sees the host
//!    NIC's real MAC.
//!
//! The rule is deliberately asymmetric: a *false negative* (missed warning)
//! is acceptable - the connector just behaves as it did before #510 - while a
//! *false positive* would cry wolf on healthy installs. Concretely:
//!
//! * No container marker -> bare metal, silent.
//! * Default interface unknown -> inconclusive, silent. We do NOT fall back
//!   to "first active interface": a host-mode container also sees the host's
//!   own `docker0`, which carries a Docker bridge MAC, so that fallback would
//!   classify a healthy host-mode install as bridged.
//! * Default interface MAC has the `02:42:` prefix -> bridged; the warning
//!   names the interface's derived subnet.
//! * Default interface MAC unknown and the interface is literally `eth0` with
//!   a subnet inside `172.16.0.0/12` -> bridged (covers enumerators that fail
//!   to report a MAC). `192.168.0.0/16` is also a Docker default pool, but it
//!   is deliberately excluded from this fallback: with host networking on a
//!   `192.168.x` LAN the pool check alone would flag the host's real subnet.
//! * Anything else -> host networking or a custom setup, silent.
//!
//! Kubernetes/podified connectors stay silent too: CNI veths do not use the
//! Docker MAC scheme, and pod subnets sit outside `172.16.0.0/12`.

use crate::network_context::{subnet_for_ipv4, subnets_from_interfaces, Subnet};
use pentest_platform::{get_platform, NetworkInterface, SystemInfo};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::OnceLock;

/// MAC prefix Docker derives bridge veth addresses from (e.g.
/// `02:42:ac:11:00:02` for 172.17.0.2).
const DOCKER_BRIDGE_MAC_PREFIX: &str = "02:42:";

/// Outcome of container-network classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerNetworking {
    /// No container marker: bare-metal install, nothing to warn about.
    NotContainer,
    /// Container on a Docker bridge network: the visible subnet is Docker's
    /// private network, not the host's LAN. `subnet` is the derived CIDR base
    /// of the default-route interface (e.g. `"172.18.0.0/16"`).
    Bridged { subnet: String },
    /// Container detected but networking is not a Docker bridge (host
    /// networking, custom network, or an inconclusive enumeration). The
    /// visible subnets are the host's real ones - stay silent.
    Other,
}

/// True if this process appears to run inside a container.
///
/// Checks the marker files Docker (`/.dockerenv`) and Podman
/// (`/run/.containerenv`) create, then falls back to a best-effort scan of
/// `/proc/self/cgroup` for docker/containerd/kubepods entries. The result is
/// cached: a process cannot leave its container, so re-reading is pure waste.
pub fn in_container() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        if Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists() {
            return true;
        }
        // Best effort: on cgroup-v2-only hosts this reports `0::/` inside the
        // container, so absence of these markers is not evidence of bare metal.
        std::fs::read_to_string("/proc/self/cgroup")
            .map(|cgroups| {
                cgroups.contains("docker")
                    || cgroups.contains("containerd")
                    || cgroups.contains("kubepods")
            })
            .unwrap_or(false)
    })
}

/// True if `subnet` (e.g. `"172.20.0.0/16"`) lies inside Docker's
/// `172.16.0.0/12` default address pool (pure).
///
/// A subnet is inside the pool when its prefix is at least /12 and its base
/// address masked to /12 equals the pool base.
fn subnet_within_docker_172_pool(subnet: &str) -> bool {
    let Some((base, prefix)) = subnet.split_once('/') else {
        return false;
    };
    let Ok(base) = base.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    // A /12 is the widest subnet that can sit inside the pool, and anything
    // above /32 is malformed input that must be rejected, not classified.
    if !(12..=32).contains(&prefix) {
        return false;
    }
    // 12 < 32, so the shift is well-defined.
    let mask: u32 = u32::MAX << (32 - 12);
    (u32::from(base) & mask) == (u32::from(Ipv4Addr::new(172, 16, 0, 0)) & mask)
}

/// Classify the container networking situation (pure; no I/O).
///
/// `interfaces` and `primary_iface` come from one interface enumeration; the
/// caller passes whether a container marker was found. See the module docs
/// for the rule and its false-positive/false-negative rationale.
pub fn classify_container_networking(
    in_container: bool,
    interfaces: &[NetworkInterface],
    primary_iface: Option<&str>,
) -> ContainerNetworking {
    if !in_container {
        return ContainerNetworking::NotContainer;
    }

    // The default-route interface decides. If it cannot be pinned down, stay
    // silent (see module docs: no "first interface" fallback).
    let Some(primary) = primary_iface.and_then(|name| {
        interfaces
            .iter()
            .find(|i| i.name == name && i.is_up && !i.is_loopback)
    }) else {
        return ContainerNetworking::Other;
    };
    // First derivable IPv4 subnet of the default interface - the same math the
    // scan-target resolution uses, so the warning names what scans would see.
    let Some(subnet) = primary
        .addresses
        .iter()
        .find_map(|a| subnet_for_ipv4(&a.ip, a.prefix_len))
    else {
        return ContainerNetworking::Other;
    };

    let mac_is_docker_bridge = primary
        .mac_address
        .as_deref()
        .map(|mac| {
            mac.to_ascii_lowercase()
                .starts_with(DOCKER_BRIDGE_MAC_PREFIX)
        })
        .unwrap_or(false);

    // The subnet-pool branch is a fallback for enumerators that fail to report
    // a MAC; it is restricted to `eth0` + the 172.16/12 pool precisely so a
    // host-mode container on a 192.168.x or 10.x LAN cannot trip it.
    if mac_is_docker_bridge || (primary.name == "eth0" && subnet_within_docker_172_pool(&subnet)) {
        ContainerNetworking::Bridged { subnet }
    } else {
        ContainerNetworking::Other
    }
}

/// Enumerate the host's interfaces and default route once.
///
/// `None` on enumeration failure - callers degrade silently (an inconclusive
/// detection must not produce a warning).
async fn host_network_snapshot() -> Option<(Vec<NetworkInterface>, Option<String>)> {
    let interfaces = get_platform().get_network_interfaces().await.ok()?;
    let primary = default_net::get_default_interface().ok().map(|i| i.name);
    Some((interfaces, primary))
}

/// Enumerate the host and classify its container networking.
///
/// I/O wrapper over [`classify_container_networking`]; enumeration failure
/// yields `Other` (silent).
pub async fn classify_current_host() -> ContainerNetworking {
    let Some((interfaces, primary)) = host_network_snapshot().await else {
        tracing::debug!("container network check: interface enumeration failed");
        return ContainerNetworking::Other;
    };
    classify_container_networking(in_container(), &interfaces, primary.as_deref())
}

/// At startup, log one warning if this connector is confined to a Docker
/// bridge network (#510).
///
/// Logs at most once per process regardless of how many startup paths call
/// it. The warning names the visible subnet and points at the host-networking
/// section of `docs/DOCKER_INSTALL.md`. Host-networking and bare-metal
/// installs are silent.
pub async fn warn_if_bridged_container() {
    static WARNED: OnceLock<()> = OnceLock::new();
    if WARNED.get().is_some() {
        return;
    }
    if let ContainerNetworking::Bridged { subnet } = classify_current_host().await {
        // set() wins exactly once even if two startup paths race here.
        if WARNED.set(()).is_ok() {
            tracing::warn!(
                "This connector runs in a container on a Docker bridge network: scans and \
                 discovery can only see the container's private subnet {subnet}, not the \
                 host's LAN. Multicast discovery (mDNS/SSDP) returns nothing and ARP sees \
                 only the bridge. To scan the host's network, enable host networking \
                 (network_mode: host in docker-compose.override.yml) - see the 'Scanning \
                 your local network (host networking)' section of docs/DOCKER_INSTALL.md."
            );
        }
    }
}

/// Persona-ready caveat for the agent's host-network facts (#510).
///
/// `Some` only for [`ContainerNetworking::Bridged`]: the agent gets told its
/// subnets are the container's private bridge network so it reports "I can
/// only see the container's private network" instead of an empty LAN. All
/// other classifications yield `None` - no caveat on healthy installs.
pub fn bridged_network_advisory(classification: &ContainerNetworking) -> Option<String> {
    match classification {
        ContainerNetworking::Bridged { subnet } => Some(format!(
            "IMPORTANT: these subnets are this connector's private Docker bridge network \
             ({subnet}), NOT the operator's LAN. You can reach little beyond the Docker \
             host itself: hosts on the real network, and multicast discovery of them \
             (mDNS/SSDP), are not reachable from here. When describing network scope, say \
             that you can only see the container's private network - never report an empty \
             scan as 'no hosts on the network' without that caveat - and tell the operator \
             to enable host networking (docs/DOCKER_INSTALL.md, 'Scanning your local \
             network (host networking)') if they need the LAN scanned."
        )),
        _ => None,
    }
}

/// Enumerate this host's subnets and the container-bridge advisory in one
/// pass, for injection into the agent persona (#347, #510).
///
/// One interface enumeration serves both outputs. Subnets degrade to an empty
/// list on enumeration failure (the persona then steers the agent to
/// `target="auto"`); the advisory degrades to `None` (inconclusive detection
/// stays silent).
pub async fn persona_network_facts() -> (Vec<Subnet>, Option<String>) {
    let Some((interfaces, primary)) = host_network_snapshot().await else {
        tracing::warn!("could not enumerate host subnets for agent context");
        return (Vec::new(), None);
    };
    let subnets = subnets_from_interfaces(&interfaces, primary.as_deref());
    let classification =
        classify_container_networking(in_container(), &interfaces, primary.as_deref());
    (subnets, bridged_network_advisory(&classification))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_context::subnet_cidr_v4;
    use pentest_platform::InterfaceAddr;

    fn iface(name: &str, mac: Option<&str>, addrs: &[(&str, Option<u8>)]) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            addresses: addrs
                .iter()
                .map(|(ip, p)| InterfaceAddr::new(*ip, *p))
                .collect(),
            mac_address: mac.map(String::from),
            is_up: true,
            is_loopback: false,
        }
    }

    #[test]
    fn bare_metal_is_never_flagged() {
        // Even a Docker-MAC interface on a Docker-pool subnet is silent without
        // a container marker: the marker is the gate for every warning.
        let ifaces = vec![iface(
            "eth0",
            Some("02:42:ac:11:00:02"),
            &[("172.17.0.2", Some(16))],
        )];
        assert_eq!(
            classify_container_networking(false, &ifaces, Some("eth0")),
            ContainerNetworking::NotContainer
        );
    }

    #[test]
    fn bridged_container_on_default_bridge_is_flagged_with_its_subnet() {
        // Classic `docker run` default bridge: 02:42 MAC + 172.17.0.0/16.
        let ifaces = vec![iface(
            "eth0",
            Some("02:42:AC:11:00:02"),
            &[("172.17.0.2", Some(16))],
        )];
        assert_eq!(
            classify_container_networking(true, &ifaces, Some("eth0")),
            ContainerNetworking::Bridged {
                subnet: "172.17.0.0/16".to_string()
            }
        );
    }

    #[test]
    fn compose_bridge_outside_172_pool_is_flagged_via_mac() {
        // Compose networks often land in 192.168.x (a Docker default pool the
        // fallback deliberately ignores); the 02:42 MAC still catches them.
        let ifaces = vec![iface(
            "eth0",
            Some("02:42:c0:a8:10:03"),
            &[("192.168.16.3", Some(20))],
        )];
        assert_eq!(
            classify_container_networking(true, &ifaces, Some("eth0")),
            ContainerNetworking::Bridged {
                subnet: "192.168.16.0/20".to_string()
            }
        );
    }

    #[test]
    fn custom_pool_bridge_is_flagged_via_mac() {
        // An operator-configured default-address-pool (e.g. 10.200.0.0/16) is
        // still a Docker bridge: the MAC prefix is the decisive signal.
        let ifaces = vec![iface(
            "eth0",
            Some("02:42:0a:c8:00:04"),
            &[("10.200.0.4", Some(16))],
        )];
        assert_eq!(
            classify_container_networking(true, &ifaces, Some("eth0")),
            ContainerNetworking::Bridged {
                subnet: "10.200.0.0/16".to_string()
            }
        );
    }

    #[test]
    fn host_mode_container_on_lan_is_silent() {
        // #510 acceptance: `network_mode: host` must NOT warn. The container
        // sees the host's real NIC (physical MAC, real LAN subnet).
        let ifaces = vec![iface(
            "enp3s0",
            Some("de:ad:be:ef:00:01"),
            &[("192.168.8.10", Some(24))],
        )];
        assert_eq!(
            classify_container_networking(true, &ifaces, Some("enp3s0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn host_mode_container_with_eth0_naming_is_silent() {
        // Hosts with legacy NIC naming (eth0) on a 192.168.x LAN: the pool
        // fallback must NOT fire, or host-mode installs would get false
        // warnings. 192.168.0.0/16 is excluded from the fallback on purpose.
        let ifaces = vec![iface(
            "eth0",
            Some("b8:27:eb:12:34:56"),
            &[("192.168.8.10", Some(24))],
        )];
        assert_eq!(
            classify_container_networking(true, &ifaces, Some("eth0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn host_mode_container_with_eth0_outside_172_pool_is_silent() {
        // Even a literal eth0 stays silent when the subnet is outside the
        // 172.16/12 fallback pool (here a 10.x LAN).
        let ifaces = vec![iface("eth0", None, &[("10.0.8.10", Some(24))])];
        assert_eq!(
            classify_container_networking(true, &ifaces, Some("eth0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn mac_less_eth0_inside_172_pool_is_flagged() {
        // The intended fallback: no MAC reported, but eth0 + 172.16/12 subnet
        // under an active container marker. Also covers a base that only masks
        // into the pool (172.20) and the /12-clamp edge (prefix 12 clamps to
        // /16, which still sits inside the pool).
        for (addr, prefix) in [("172.17.0.2", 16u8), ("172.20.0.5", 16), ("172.16.0.1", 12)] {
            let ifaces = vec![iface("eth0", None, &[(addr, Some(prefix))])];
            // Derive the expected base the same way production does.
            let expected = subnet_cidr_v4(addr.parse().unwrap(), prefix);
            assert_eq!(
                classify_container_networking(true, &ifaces, Some("eth0")),
                ContainerNetworking::Bridged { subnet: expected },
                "case {addr}"
            );
        }
    }

    #[test]
    fn mac_less_non_eth0_inside_172_pool_is_silent() {
        // The pool fallback requires the literal eth0 name: an interface named
        // anything else with no MAC is inconclusive, not bridged.
        let ifaces = vec![iface("ens18", None, &[("172.20.0.5", Some(16))])];
        assert_eq!(
            classify_container_networking(true, &ifaces, Some("ens18")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn unknown_primary_interface_is_silent() {
        // No default route determinable: inconclusive, and inconclusive must
        // not warn. In particular a host-mode container's docker0 (02:42 MAC,
        // 172.17.0.0/16) present in the list must not trigger anything.
        let ifaces = vec![
            iface(
                "docker0",
                Some("02:42:ac:11:00:01"),
                &[("172.17.0.1", Some(16))],
            ),
            iface(
                "enp3s0",
                Some("de:ad:be:ef:00:01"),
                &[("192.168.8.10", Some(24))],
            ),
        ];
        assert_eq!(
            classify_container_networking(true, &ifaces, None),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn no_usable_interfaces_is_silent() {
        // Adversarial: loopback only, or nothing at all - stay silent.
        let lo = NetworkInterface {
            name: "lo".to_string(),
            addresses: vec![InterfaceAddr::new("127.0.0.1", Some(8))],
            mac_address: None,
            is_up: true,
            is_loopback: true,
        };
        assert_eq!(
            classify_container_networking(true, &[lo], Some("lo")),
            ContainerNetworking::Other
        );
        assert_eq!(
            classify_container_networking(true, &[], Some("eth0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn primary_with_no_derivable_subnet_is_silent() {
        // Adversarial: the default interface has no usable IPv4 address (no
        // prefix / IPv6-only) - cannot name a subnet, so no warning.
        let ifaces = vec![iface(
            "eth0",
            Some("02:42:ac:11:00:02"),
            &[("fd00::2", None)],
        )];
        assert_eq!(
            classify_container_networking(true, &ifaces, Some("eth0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn down_or_loopback_primary_is_ignored() {
        // The named primary exists but is down/loopback: do not classify by
        // it (an inactive docker0 must not look like a bridge).
        let mut docker0 = iface(
            "docker0",
            Some("02:42:ac:11:00:01"),
            &[("172.17.0.1", Some(16))],
        );
        docker0.is_up = false;
        assert_eq!(
            classify_container_networking(true, &[docker0], Some("docker0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn advisory_only_for_bridged() {
        let bridged = ContainerNetworking::Bridged {
            subnet: "172.18.0.0/16".to_string(),
        };
        let advisory = bridged_network_advisory(&bridged).expect("bridged gets an advisory");
        assert!(advisory.contains("172.18.0.0/16"), "names the subnet");
        assert!(
            advisory.to_lowercase().contains("docker bridge"),
            "says the network is the container's bridge"
        );
        assert!(
            advisory.contains("DOCKER_INSTALL.md"),
            "points at the runbook"
        );
        // Silent classifications carry no caveat.
        assert_eq!(
            bridged_network_advisory(&ContainerNetworking::NotContainer),
            None
        );
        assert_eq!(bridged_network_advisory(&ContainerNetworking::Other), None);
    }

    #[test]
    fn pool_membership_math() {
        // Inside the pool at various prefixes; outside cases rejected.
        assert!(subnet_within_docker_172_pool("172.17.0.0/16"));
        assert!(subnet_within_docker_172_pool("172.31.255.0/24"));
        assert!(subnet_within_docker_172_pool("172.20.0.0/14"));
        assert!(subnet_within_docker_172_pool("172.16.0.0/12"));
        assert!(!subnet_within_docker_172_pool("192.168.16.0/20"));
        assert!(!subnet_within_docker_172_pool("10.200.0.0/16"));
        assert!(!subnet_within_docker_172_pool("172.32.0.0/16"));
        assert!(!subnet_within_docker_172_pool("172.16.0.0/8"));
        // Malformed input never panics, only rejects.
        assert!(!subnet_within_docker_172_pool("not-a-cidr"));
        assert!(!subnet_within_docker_172_pool("172.17.0.0"));
        assert!(!subnet_within_docker_172_pool("172.17.0.0/99"));
    }
}

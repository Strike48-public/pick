//! Container network awareness: is this connector running in a container that
//! can only see a container bridge network?
//!
//! The failure mode (pick#510): the connector runs in Docker on the default bridge
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
//! 1. Which container runtime the process runs under (best effort):
//!    `/.dockerenv` (Docker), `/run/.containerenv` (Podman), or
//!    docker/containerd/kubepods entries in `/proc/self/cgroup`. A kubepods
//!    entry wins over `/.dockerenv`, because docker-shim pods (k8s <= 1.23)
//!    carry both and a pod's networking is CNI, not a user-managed bridge. On
//!    cgroup-v2-only hosts the cgroup file reports `0::/` inside the
//!    container, so there the marker files are the primary signal and the
//!    cgroup scan is best effort.
//! 2. What the container can see. This has to be the decisive discriminator:
//!    Docker Engine 28.0.0 switched bridge and macvlan container interfaces
//!    to randomly generated MACs (moby/moby#48808), so the historical
//!    `02:42:` prefix no longer exists on current Engines and subnet pools
//!    alone cannot separate a bridge from a host-mode container (host-mode on
//!    stock EC2 is `eth0` inside AWS's `172.31.0.0/16` default VPC). A
//!    *bridged* container's network namespace holds only `lo` and its `eth0`;
//!    a *host-networked* container shares the host's namespace and sees the
//!    host-side bridge machinery: `docker0`, the `br-<12 hex>` bridges of
//!    user-defined networks, `veth*` pairs, and Podman's `podman*`/`cni*`
//!    bridges. Concretely, for a Docker/Podman container:
//!
//!    * default interface up with a derivable IPv4 subnet, named `eth0`, and
//!      no host bridge visible -> bridged, whatever the pool (Docker's
//!      `172.16.0.0/12` and `192.168.0.0/16` defaults and custom
//!      `default-address-pool`s alike);
//!    * `02:42:` MAC on the default interface -> bridged (supporting signal
//!      for pre-28 Engines, and for enumerations that under-report the
//!      interface list);
//!    * a host bridge visible -> host networking or an equivalent custom
//!      setup, silent;
//!    * default interface unknown, down, or without a usable IPv4 subnet ->
//!      inconclusive, silent. No "first active interface" fallback: a
//!      host-mode container also sees the host's own `docker0`, and
//!      classifying by some other interface would be a guess.
//!
//! Kubernetes pods stay silent regardless of what their interfaces look
//! like: CNI networking is not a user-managed bridge, and the
//! docker-compose host-networking advice does not apply to a pod.
//!
//! Known limitation, accepted on purpose: macvlan/ipvlan containers also see
//! no host bridge, so they can be flagged even though they attach to the
//! real LAN at layer 2. Neither docs/DOCKER_INSTALL.md nor the compose files
//! set those modes up; bridge and host networking are the supported shapes.
//!
//! The rule is deliberately asymmetric: a *false negative* (missed warning)
//! is acceptable - the connector just behaves as it did before pick#510 - while a
//! *false positive* would cry wolf on healthy installs, so anything
//! inconclusive stays silent.

use crate::network_context::{
    interface_snapshot, subnet_for_ipv4, subnets_from_interfaces, Subnet,
};
use pentest_platform::NetworkInterface;
use std::path::Path;
use std::sync::OnceLock;

/// MAC prefix Docker derives bridge veth addresses from (e.g.
/// `02:42:ac:11:00:02` for 172.17.0.2).
///
/// Supporting signal only: Docker Engine 28.0.0 switched container veths to
/// randomly generated MACs (moby/moby#48808), so current Engines are detected
/// by what the container can see, not by this prefix.
const DOCKER_BRIDGE_MAC_PREFIX: &str = "02:42:";

/// Which container runtime this process appears to run in, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerRuntime {
    /// No container marker found: bare metal, or a runtime this check does
    /// not recognize. Nothing to warn about.
    None,
    /// Docker: `/.dockerenv`, or a docker/containerd cgroup entry.
    Docker,
    /// Podman: `/run/.containerenv`.
    Podman,
    /// Kubernetes: a kubepods cgroup entry. Pod networking is CNI, not a
    /// user-managed bridge, so podified connectors stay silent.
    Kubernetes,
}

/// Combine the container markers into a runtime (pure; unit-testable).
///
/// Order matters: a kubepods cgroup entry wins over `/.dockerenv`, because
/// docker-shim pods (k8s <= 1.23) carry both and their networking is CNI.
fn runtime_from_markers(dockerenv: bool, containerenv: bool, cgroups: &str) -> ContainerRuntime {
    if cgroups.contains("kubepods") {
        return ContainerRuntime::Kubernetes;
    }
    if dockerenv {
        return ContainerRuntime::Docker;
    }
    if containerenv {
        return ContainerRuntime::Podman;
    }
    // Best effort: on cgroup-v2-only hosts this reports `0::/` inside the
    // container, so absence of these markers is not evidence of bare metal.
    if cgroups.contains("docker") || cgroups.contains("containerd") {
        return ContainerRuntime::Docker;
    }
    ContainerRuntime::None
}

/// Best-effort container-runtime detection.
///
/// Checks the marker files Docker (`/.dockerenv`) and Podman
/// (`/run/.containerenv`) create, then falls back to a best-effort scan of
/// `/proc/self/cgroup` for docker/containerd/kubepods entries. The result is
/// cached: a process cannot leave its container, so re-reading is pure waste.
pub fn detect_container_runtime() -> ContainerRuntime {
    static CACHE: OnceLock<ContainerRuntime> = OnceLock::new();
    *CACHE.get_or_init(|| {
        let cgroups = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        runtime_from_markers(
            Path::new("/.dockerenv").exists(),
            Path::new("/run/.containerenv").exists(),
            &cgroups,
        )
    })
}

/// Outcome of container-network classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerNetworking {
    /// No container marker: bare-metal install, nothing to warn about.
    NotContainer,
    /// Container on a container bridge network (Docker or Podman): the
    /// visible subnet is the container's private network, not the host's
    /// LAN. `subnet` is the derived CIDR base of the default-route interface
    /// (e.g. `"172.18.0.0/16"`).
    Bridged { subnet: String },
    /// Container detected but networking is not a user-managed bridge (host
    /// networking, a Kubernetes pod, a custom network, or an inconclusive
    /// enumeration). The visible subnets are the host's real ones - stay
    /// silent.
    Other,
}

/// True if `name` is a host-side container-bridge interface: `docker0`, a
/// Docker user-network bridge (`br-` + 12 hex chars), a `veth*` host-side
/// pair, or a Podman bridge (`podman*`, `cni*`).
///
/// These live in the host's network namespace. A bridged container never sees
/// them (its namespace holds only `lo` and `eth0`); a host-networked container
/// shares the host namespace and does. Names that merely resemble the pattern
/// (`bracket`, `br-x`) do not count.
fn is_host_bridge_iface(name: &str) -> bool {
    name == "docker0"
        || (name.len() == 15
            && name.starts_with("br-")
            && name[3..].bytes().all(|b| b.is_ascii_hexdigit()))
        || name.starts_with("veth")
        || name.starts_with("podman")
        || name.starts_with("cni")
}

/// Classify the container networking situation (pure; no I/O).
///
/// `interfaces` and `primary_iface` come from one interface enumeration; the
/// caller passes the detected container runtime. See the module docs for the
/// rule and its false-positive/false-negative rationale.
pub fn classify_container_networking(
    runtime: ContainerRuntime,
    interfaces: &[NetworkInterface],
    primary_iface: Option<&str>,
) -> ContainerNetworking {
    match runtime {
        ContainerRuntime::None => return ContainerNetworking::NotContainer,
        // Pod networking is CNI, not a user-managed bridge, and the
        // docker-compose host-networking advice does not apply to a pod.
        ContainerRuntime::Kubernetes => return ContainerNetworking::Other,
        ContainerRuntime::Docker | ContainerRuntime::Podman => {}
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

    // What the container can see decides (module docs): a bridged container's
    // namespace holds only `lo` and `eth0`, so a visible host bridge means
    // host networking. The interface name is part of the signal because
    // Docker and Podman always name the container-side interface `eth0` - a
    // non-`eth0` default interface looks like host networking whose bridge
    // list the enumeration under-reported, which stays silent (asymmetric
    // rule). The MAC prefix stays as a supporting signal for pre-28 Engines.
    let host_bridge_visible = interfaces
        .iter()
        .any(|i| i.is_up && !i.is_loopback && is_host_bridge_iface(&i.name));
    if mac_is_docker_bridge || (primary.name == "eth0" && !host_bridge_visible) {
        ContainerNetworking::Bridged { subnet }
    } else {
        ContainerNetworking::Other
    }
}

/// Enumerate the host and classify its container networking.
///
/// I/O wrapper over [`classify_container_networking`]; enumeration failure
/// yields `Other` (silent).
pub async fn classify_current_host() -> ContainerNetworking {
    // Marker check first (optional note d): a bare-metal install should not
    // pay for an interface enumeration, and Kubernetes is decided without
    // one too.
    let runtime = detect_container_runtime();
    match runtime {
        ContainerRuntime::None => return ContainerNetworking::NotContainer,
        ContainerRuntime::Kubernetes => return ContainerNetworking::Other,
        ContainerRuntime::Docker | ContainerRuntime::Podman => {}
    }
    let (interfaces, primary) = match interface_snapshot().await {
        Ok(pair) => pair,
        Err(e) => {
            // Headless logs at info: an enumeration failure that silently
            // disables detection must still leave a trace (optional note b).
            tracing::warn!("container network check: interface enumeration failed: {e}");
            return ContainerNetworking::Other;
        }
    };
    classify_container_networking(runtime, &interfaces, primary.as_deref())
}

/// At startup, log one warning if this connector is confined to a container
/// bridge network (pick#510).
///
/// Logs at most once per process regardless of how many startup paths call
/// it. The warning names the visible subnet and points at the host-networking
/// section of `docs/DOCKER_INSTALL.md`. Host-networking, Kubernetes and
/// bare-metal installs are silent.
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

/// Persona-ready caveat for the agent's host-network facts (pick#510).
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
/// pass, for injection into the agent persona (pick#347, pick#510).
///
/// One interface enumeration serves both outputs. Subnets degrade to an empty
/// list on enumeration failure (the persona then steers the agent to
/// `target="auto"`); the advisory degrades to `None` (inconclusive detection
/// stays silent).
pub async fn persona_network_facts() -> (Vec<Subnet>, Option<String>) {
    let runtime = detect_container_runtime();
    let (interfaces, primary) = match interface_snapshot().await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!("could not enumerate host subnets for agent context: {e}");
            return (Vec::new(), None);
        }
    };
    let subnets = subnets_from_interfaces(&interfaces, primary.as_deref());
    let classification = classify_container_networking(runtime, &interfaces, primary.as_deref());
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

    fn lo() -> NetworkInterface {
        NetworkInterface {
            name: "lo".to_string(),
            addresses: vec![InterfaceAddr::new("127.0.0.1", Some(8))],
            mac_address: None,
            is_up: true,
            is_loopback: true,
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
            classify_container_networking(ContainerRuntime::None, &ifaces, Some("eth0")),
            ContainerNetworking::NotContainer
        );
    }

    #[test]
    fn bridged_container_on_default_bridge_is_flagged_with_its_subnet() {
        // Classic `docker run` default bridge: 02:42 MAC + 172.17.0.0/16. The
        // MAC decides here (supporting signal); on Engine 28+ the visibility
        // rule below takes over.
        let ifaces = vec![
            lo(),
            iface(
                "eth0",
                Some("02:42:AC:11:00:02"),
                &[("172.17.0.2", Some(16))],
            ),
        ];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("eth0")),
            ContainerNetworking::Bridged {
                subnet: "172.17.0.0/16".to_string()
            }
        );
    }

    #[test]
    fn compose_bridge_outside_172_pool_is_flagged_via_mac() {
        // Compose networks often land in 192.168.x; the 02:42 MAC catches
        // them on pre-28 Engines (the engine28 probe test covers current
        // Engines, whose MACs are random).
        let ifaces = vec![iface(
            "eth0",
            Some("02:42:c0:a8:10:03"),
            &[("192.168.16.3", Some(20))],
        )];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("eth0")),
            ContainerNetworking::Bridged {
                subnet: "192.168.16.0/20".to_string()
            }
        );
    }

    #[test]
    fn custom_pool_bridge_is_flagged_via_mac() {
        // An operator-configured default-address-pool (e.g. 10.200.0.0/16) is
        // still a Docker bridge: the MAC prefix is the pre-28 signal.
        let ifaces = vec![iface(
            "eth0",
            Some("02:42:0a:c8:00:04"),
            &[("10.200.0.4", Some(16))],
        )];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("eth0")),
            ContainerNetworking::Bridged {
                subnet: "10.200.0.0/16".to_string()
            }
        );
    }

    #[test]
    fn engine28_random_mac_bridge_in_192_pool_is_flagged() {
        // Docker Engine 28+ gives container veths random MACs
        // (moby/moby#48808), so the 02:42 prefix is gone. Detection must rest
        // on what the container can see: only lo and eth0, no host bridge.
        // This is the reviewer's item-2 probe (previously classified Other).
        let ifaces = vec![
            lo(),
            iface(
                "eth0",
                Some("6e:1f:9a:42:07:c3"),
                &[("192.168.16.3", Some(20))],
            ),
        ];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("eth0")),
            ContainerNetworking::Bridged {
                subnet: "192.168.16.0/20".to_string()
            }
        );
    }

    #[test]
    fn engine28_random_mac_custom_pool_bridge_is_flagged() {
        // Custom default-address-pool on Engine 28+: random MAC, no host
        // bridge visible -> still bridged. The old pool fallback missed this
        // shape entirely.
        let ifaces = vec![iface(
            "eth0",
            Some("9a:3c:71:aa:19:e2"),
            &[("10.200.0.4", Some(16))],
        )];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("eth0")),
            ContainerNetworking::Bridged {
                subnet: "10.200.0.0/16".to_string()
            }
        );
    }

    #[test]
    fn host_networked_container_on_ec2_stays_silent() {
        // Reviewer's item-1 probe: host-networked container on stock EC2.
        // Amazon Linux names its NIC eth0 and the AWS default VPC is
        // 172.31.0.0/16, so the old MAC-agnostic pool fallback flagged it.
        // The container shares the host namespace and sees the host's docker0
        // -> host networking, silent.
        let ifaces = vec![
            iface(
                "eth0",
                Some("0a:5e:3c:11:22:33"),
                &[("172.31.10.5", Some(20))],
            ),
            iface(
                "docker0",
                Some("02:42:ac:11:00:01"),
                &[("172.17.0.1", Some(16))],
            ),
        ];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("eth0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn host_networked_container_with_user_network_bridge_stays_silent() {
        // Host networking next to compose's user-defined networks: the
        // br-<12hex> bridge is visible from the host namespace -> silent.
        let ifaces = vec![
            iface(
                "eth0",
                Some("0a:5e:3c:11:22:33"),
                &[("172.31.10.5", Some(20))],
            ),
            iface(
                "br-1a2b3c4d5e6f",
                Some("02:42:2a:aa:bb:01"),
                &[("172.18.0.1", Some(16))],
            ),
        ];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("eth0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn host_networked_container_with_veths_stays_silent() {
        // The host-side veth pairs are equally visible under host networking.
        let ifaces = vec![
            iface(
                "eth0",
                Some("b8:27:eb:12:34:56"),
                &[("192.168.8.10", Some(24))],
            ),
            iface("veth1a2b3c4", None, &[]),
        ];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("eth0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn host_mode_container_on_lan_is_silent() {
        // pick#510 acceptance: `network_mode: host` must NOT warn. The
        // container shares the host namespace and sees the host's docker0
        // next to the real NIC (physical MAC, real LAN subnet).
        let ifaces = vec![
            iface(
                "enp3s0",
                Some("de:ad:be:ef:00:01"),
                &[("192.168.8.10", Some(24))],
            ),
            iface(
                "docker0",
                Some("02:42:ac:11:00:01"),
                &[("172.17.0.1", Some(16))],
            ),
        ];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("enp3s0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn host_mode_container_with_eth0_naming_is_silent() {
        // Hosts with legacy NIC naming (eth0): host networking still sees the
        // host's docker0, which keeps the classification silent. Without a
        // visible host bridge an eth0 interface is indistinguishable from a
        // bridged container (see the engine28 probe tests).
        let ifaces = vec![
            iface(
                "eth0",
                Some("b8:27:eb:12:34:56"),
                &[("192.168.8.10", Some(24))],
            ),
            iface(
                "docker0",
                Some("02:42:ac:11:00:01"),
                &[("172.17.0.1", Some(16))],
            ),
        ];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("eth0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn host_mode_container_with_eth0_outside_any_pool_is_silent() {
        // A 10.x LAN under host networking: docker0 in the namespace keeps
        // this silent regardless of the subnet pool.
        let ifaces = vec![
            iface("eth0", None, &[("10.0.8.10", Some(24))]),
            iface(
                "docker0",
                Some("02:42:ac:11:00:01"),
                &[("172.17.0.1", Some(16))],
            ),
        ];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("eth0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn kubernetes_pod_is_silent() {
        // Pod networking is CNI, not a user-managed bridge, and the
        // docker-compose host-networking advice does not apply to a pod: a
        // kubepods marker stays silent even with a Docker-looking interface.
        let ifaces = vec![iface(
            "eth0",
            Some("02:42:ac:11:00:02"),
            &[("172.17.0.2", Some(16))],
        )];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Kubernetes, &ifaces, Some("eth0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn podman_bridge_is_flagged() {
        // Podman's default rootful network is 10.88.0.0/16 with random MACs;
        // the container sees only lo + eth0 -> bridged.
        let ifaces = vec![iface(
            "eth0",
            Some("5a:94:0e:33:6b:10"),
            &[("10.88.0.2", Some(16))],
        )];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Podman, &ifaces, Some("eth0")),
            ContainerNetworking::Bridged {
                subnet: "10.88.0.0/16".to_string()
            }
        );
    }

    #[test]
    fn podman_host_networking_sees_podman0_and_stays_silent() {
        // Host-networked Podman container: the host's podman0 bridge is in
        // the shared namespace -> silent.
        let ifaces = vec![
            iface(
                "eth0",
                Some("de:ad:be:ef:00:01"),
                &[("192.168.8.10", Some(24))],
            ),
            iface(
                "podman0",
                Some("5a:94:0e:33:6b:01"),
                &[("10.88.0.1", Some(16))],
            ),
        ];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Podman, &ifaces, Some("eth0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn docker_mac_on_non_eth0_primary_still_flags() {
        // The 02:42 MAC alone is decisive regardless of the interface name:
        // this covers enumerators that under-report names, and keeps the
        // supporting signal testable now that the visibility rule catches the
        // common shapes.
        let ifaces = vec![iface(
            "ens192",
            Some("02:42:ac:11:00:02"),
            &[("172.17.0.2", Some(16))],
        )];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("ens192")),
            ContainerNetworking::Bridged {
                subnet: "172.17.0.0/16".to_string()
            }
        );
    }

    #[test]
    fn mac_less_eth0_inside_172_pool_is_flagged() {
        // A MAC-less enumeration of a bridged container: eth0 and no host
        // bridge visible is bridged whatever the pool. Also covers a base
        // that only masks into the old 172.16/12 pool (172.20) and the
        // /12-clamp edge (prefix 12 clamps to /16, which still sits inside).
        for (addr, prefix) in [("172.17.0.2", 16u8), ("172.20.0.5", 16), ("172.16.0.1", 12)] {
            let ifaces = vec![iface("eth0", None, &[(addr, Some(prefix))])];
            // Derive the expected base the same way production does.
            let expected = subnet_cidr_v4(addr.parse().unwrap(), prefix);
            assert_eq!(
                classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("eth0")),
                ContainerNetworking::Bridged { subnet: expected },
                "case {addr}"
            );
        }
    }

    #[test]
    fn mac_less_non_eth0_inside_172_pool_is_silent() {
        // Docker and Podman name the container-side interface eth0: a
        // non-eth0 default interface looks like host networking whose bridge
        // list the enumeration under-reported - inconclusive, silent.
        let ifaces = vec![iface("ens18", None, &[("172.20.0.5", Some(16))])];
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("ens18")),
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
            classify_container_networking(ContainerRuntime::Docker, &ifaces, None),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn no_usable_interfaces_is_silent() {
        // Adversarial: loopback only, or nothing at all - stay silent.
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &[lo()], Some("lo")),
            ContainerNetworking::Other
        );
        assert_eq!(
            classify_container_networking(ContainerRuntime::Docker, &[], Some("eth0")),
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
            classify_container_networking(ContainerRuntime::Docker, &ifaces, Some("eth0")),
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
            classify_container_networking(ContainerRuntime::Docker, &[docker0], Some("docker0")),
            ContainerNetworking::Other
        );
    }

    #[test]
    fn host_bridge_iface_names() {
        // docker0 and Docker's user-network bridges (br- + 12 hex) count, as
        // do host-side veth pairs and Podman's bridges.
        assert!(is_host_bridge_iface("docker0"));
        assert!(is_host_bridge_iface("br-1a2b3c4d5e6f"));
        assert!(is_host_bridge_iface("veth1a2b3c4"));
        assert!(is_host_bridge_iface("podman0"));
        assert!(is_host_bridge_iface("cni-podman0"));
        // Lookalikes must not count: a container's own eth0, a human-named
        // bridge (br0, br-lan), or a malformed br- name.
        assert!(!is_host_bridge_iface("eth0"));
        assert!(!is_host_bridge_iface("lo"));
        assert!(!is_host_bridge_iface("br0"));
        assert!(!is_host_bridge_iface("br-lan"));
        assert!(!is_host_bridge_iface("br-1a2b3c4d5e6")); // 11 hex
        assert!(!is_host_bridge_iface("br-zz1a2b3c4d5"));
        assert!(!is_host_bridge_iface("br-1a2b3c4d5e6ff")); // 13 hex
    }

    #[test]
    fn runtime_marker_precedence() {
        use ContainerRuntime as R;
        // docker-shim pods (k8s <= 1.23) carry /.dockerenv AND a kubepods
        // cgroup entry: the pod wins, its networking is CNI.
        assert_eq!(
            runtime_from_markers(
                true,
                false,
                "12:perf_event:/kubepods/burstable/podabc123\n1:name=systemd:/docker/def456"
            ),
            R::Kubernetes
        );
        assert_eq!(
            runtime_from_markers(true, false, ""),
            R::Docker,
            "/.dockerenv means Docker"
        );
        assert_eq!(
            runtime_from_markers(false, true, ""),
            R::Podman,
            "/run/.containerenv means Podman"
        );
        // cgroup-v1-style entries without marker files.
        assert_eq!(
            runtime_from_markers(false, false, "9:devices:/docker/def456"),
            R::Docker
        );
        assert_eq!(
            runtime_from_markers(false, false, "0::/system.slice/containerd.service"),
            R::Docker
        );
        // Nothing matches: bare metal (or cgroup-v2 silence with no markers).
        assert_eq!(runtime_from_markers(false, false, ""), R::None);
        assert_eq!(runtime_from_markers(false, false, "0::/"), R::None);
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
}

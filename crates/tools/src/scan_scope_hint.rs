//! Zero-host / degraded-scan scope hints (#347).
//!
//! When a sweep returns no hosts, the Red Team agent tends to report "the
//! network is empty" when the real cause is almost always that it scanned the
//! wrong network (the `192.168.1.0/24`-on-a-`10.0.x` failure) or that raw-socket
//! host discovery was degraded inside the sandbox (#251). A scope hint turns
//! that silent zero into a teachable signal: it names the connector's actual
//! subnets and states any capability degradation, so the model re-targets
//! instead of concluding nothing is there.

use crate::network_context::Subnet;

/// Build the hint appended to a scan result that found zero hosts.
///
/// `target` is the range that was scanned; `active_subnets` are the connector's
/// live subnets (fact-first re-targeting); `raw_socket_available` is false when
/// privileged host discovery was unavailable in-sandbox (#251), which is stated
/// explicitly rather than masked as an empty network.
pub fn zero_host_scope_hint(
    target: &str,
    active_subnets: &[Subnet],
    raw_socket_available: bool,
) -> String {
    let mut parts = vec![format!(
        "The scan of `{target}` returned zero hosts. Before concluding the network is empty, \
         verify you scanned the right network."
    )];

    if active_subnets.is_empty() {
        parts.push(
            "No active host subnets could be enumerated; pass target=\"auto\" (or run a \
             discovery tool) to scan this connector's own network rather than guessing a range."
                .to_string(),
        );
    } else {
        let list = active_subnets
            .iter()
            .map(|s| s.cidr.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!(
            "This connector's active subnet(s) are: {list}. Re-target one of these (or use \
             target=\"auto\") if `{target}` is not among them."
        ));
    }

    if !raw_socket_available {
        parts.push(
            "Raw-socket capability was unavailable in this sandbox, so privileged host \
             discovery (SYN/ICMP sweeps) was degraded - a zero result here may reflect that \
             degradation, not an empty network."
                .to_string(),
        );
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subnet(cidr: &str) -> Subnet {
        Subnet {
            cidr: cidr.to_string(),
            interface: "eth0".to_string(),
            is_primary: false,
        }
    }

    #[test]
    fn hint_names_active_subnets_and_the_scanned_target() {
        let subnets = [subnet("10.0.8.0/22"), subnet("172.16.4.0/24")];
        let hint = zero_host_scope_hint("192.168.1.0/24", &subnets, true);
        assert!(hint.contains("192.168.1.0/24"), "names the scanned target");
        assert!(hint.contains("10.0.8.0/22") && hint.contains("172.16.4.0/24"));
        assert!(hint.contains("target=\"auto\""));
        // Raw sockets available -> no degradation clause.
        assert!(!hint.contains("degrad"));
    }

    #[test]
    fn hint_states_raw_socket_degradation_when_unavailable() {
        let hint = zero_host_scope_hint("10.0.8.0/22", &[subnet("10.0.8.0/22")], false);
        assert!(
            hint.to_lowercase().contains("raw-socket") && hint.contains("degrad"),
            "must state the sandbox degradation, not mask it (#251)"
        );
    }

    #[test]
    fn hint_falls_back_to_auto_when_no_subnets_known() {
        let hint = zero_host_scope_hint("192.168.1.0/24", &[], true);
        assert!(
            hint.contains("target=\"auto\""),
            "with no known subnets, steer to auto/discovery"
        );
    }
}

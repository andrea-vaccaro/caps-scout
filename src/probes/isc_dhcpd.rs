use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. The original candidate note assumed the
/// `isc` plugin family covered both BIND and ISC DHCP — wrong: checking
/// Checkmk's own plugin (`isc/agent_based/isc_dhcpd.py`, checkman: "Linux
/// ISC DHCP-Daemon DHCP Pools") shows it's ISC DHCP only, no BIND/`named`
/// component at all. ISC DHCP's server daemon is `dhcpd`.
pub fn detect_isc_dhcpd(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["dhcpd"]).then_some("caps/net/isc_dhcpd")
}

#[cfg(test)]
mod tests {
    use super::detect_isc_dhcpd;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_isc_dhcpd_when_process_present() {
        let system = FakeProcesses(vec!["dhcpd"]);
        assert_eq!(detect_isc_dhcpd(&system), Some("caps/net/isc_dhcpd"));
    }

    #[test]
    fn no_detection_without_a_dhcpd_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "nginx"]);
        assert_eq!(detect_isc_dhcpd(&system), None);
    }
}

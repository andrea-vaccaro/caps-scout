use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `keepalived` plugin is
/// SNMP-based (`keepalived/agent_based/keepalived.py` is an `SNMPSection`),
/// so there's no host-agent gating logic to check against — unlike
/// `corosync`/`veritas`, this isn't confirmed against a Checkmk-side
/// signal, just keepalived's own standard binary name.
///
/// keepalived's daemon process is named `keepalived`.
pub fn detect_keepalived(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["keepalived"]).then_some("caps/cluster/keepalived")
}

#[cfg(test)]
mod tests {
    use super::detect_keepalived;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_keepalived_when_process_present() {
        let system = FakeProcesses(vec!["keepalived"]);
        assert_eq!(
            detect_keepalived(&system),
            Some("caps/cluster/keepalived")
        );
    }

    #[test]
    fn no_detection_without_a_keepalived_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "corosync"]);
        assert_eq!(detect_keepalived(&system), None);
    }
}

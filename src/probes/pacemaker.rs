use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Pacemaker/Heartbeat's cluster resource
/// manager is bundled in the same Checkmk plugin family as `corosync`
/// (`corosync/agent_based/heartbeat_crm.py` etc.) but is a distinct
/// capability with its own detection signal — not covered by
/// `detect_corosync`.
///
/// Checkmk's own core agent (`agents/check_mk_agent.linux:1170`) gates its
/// `heartbeat_crm` section on:
/// `[ -S /var/run/heartbeat/crm/cib_ro ] || [ -S /var/run/crm/cib_ro ] ||
/// pgrep "^(crmd|pacemaker-contr)$"`. This mirrors the process half of that
/// check: `crmd` (legacy Heartbeat CRM daemon) or `pacemaker-contr` (the
/// Pacemaker controller daemon, `pacemaker-controld`, truncated to Linux's
/// 15-character process-name limit).
pub fn detect_pacemaker(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["crmd", "pacemaker-contr"]).then_some("caps/cluster/pacemaker")
}

#[cfg(test)]
mod tests {
    use super::detect_pacemaker;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_pacemaker_when_crmd_process_present() {
        let system = FakeProcesses(vec!["crmd"]);
        assert_eq!(detect_pacemaker(&system), Some("caps/cluster/pacemaker"));
    }

    #[test]
    fn detects_pacemaker_when_controld_process_present() {
        let system = FakeProcesses(vec!["pacemaker-contr"]);
        assert_eq!(detect_pacemaker(&system), Some("caps/cluster/pacemaker"));
    }

    #[test]
    fn no_detection_without_a_pacemaker_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "corosync"]);
        assert_eq!(detect_pacemaker(&system), None);
    }
}

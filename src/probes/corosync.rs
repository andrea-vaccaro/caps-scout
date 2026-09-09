use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `corosync` plugin never
/// detects presence itself — the core agent (`agents/check_mk_agent.linux`,
/// `section_corosync_latency`) gates its corosync section on `inpath
/// corosync-cmapctl` (a CLI tool check), not a process, so there's no exact
/// signal to copy from the Checkmk source.
///
/// Corosync's own engine daemon is named `corosync`.
pub fn detect_corosync(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["corosync"]).then_some("caps/cluster/corosync")
}

#[cfg(test)]
mod tests {
    use super::detect_corosync;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_corosync_when_process_present() {
        let system = FakeProcesses(vec!["corosync"]);
        assert_eq!(detect_corosync(&system), Some("caps/cluster/corosync"));
    }

    #[test]
    fn no_detection_without_a_corosync_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "dockerd"]);
        assert_eq!(detect_corosync(&system), None);
    }
}

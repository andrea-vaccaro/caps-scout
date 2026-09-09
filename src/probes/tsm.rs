use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `tsm` plugin family has no
/// host-agent gating logic to check against (data comes via `dsmadmc`
/// queries configured through `agent_config_tsm.py`), so this isn't
/// confirmed against a Checkmk-side signal — but `dsmserv` (the IBM
/// Tivoli Storage Manager / Storage Protect server engine) and `dsmcad`
/// (the client scheduler/acceptor daemon) are IBM's own standard process
/// names, documented across IBM's TSM administration docs.
pub fn detect_tsm(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["dsmserv", "dsmcad"]).then_some("caps/backup/tsm")
}

#[cfg(test)]
mod tests {
    use super::detect_tsm;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_tsm_when_server_process_present() {
        let system = FakeProcesses(vec!["dsmserv"]);
        assert_eq!(detect_tsm(&system), Some("caps/backup/tsm"));
    }

    #[test]
    fn detects_tsm_when_client_scheduler_process_present() {
        let system = FakeProcesses(vec!["dsmcad"]);
        assert_eq!(detect_tsm(&system), Some("caps/backup/tsm"));
    }

    #[test]
    fn no_detection_without_a_tsm_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "dockerd"]);
        assert_eq!(detect_tsm(&system), None);
    }
}

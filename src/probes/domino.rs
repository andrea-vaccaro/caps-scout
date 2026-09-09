use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `domino_info` plugin is
/// SNMP-based (queries the Notes-MIB), so there's no host-side signal to
/// copy from the Checkmk source. IBM Domino's core server process on
/// Linux is `nserver`, confirmed via SolarWinds' Domino process
/// documentation and general IBM references — one of several
/// `n`-prefixed Domino processes, but the main server engine itself.
pub fn detect_domino(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["nserver"]).then_some("caps/collab/domino")
}

#[cfg(test)]
mod tests {
    use super::detect_domino;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_domino_when_nserver_process_present() {
        let system = FakeProcesses(vec!["nserver"]);
        assert_eq!(detect_domino(&system), Some("caps/collab/domino"));
    }

    #[test]
    fn no_detection_without_an_nserver_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "nginx"]);
        assert_eq!(detect_domino(&system), None);
    }
}

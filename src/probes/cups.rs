use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own agent script
/// (`cups/agents/mk_cups_queues`) gates on `type lpstat` (the CLI tool
/// being available), not the daemon process. caps-scout wants "is CUPS
/// present", so this matches the daemon directly: `cupsd`.
pub fn detect_cups(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["cupsd"]).then_some("caps/print/cups")
}

#[cfg(test)]
mod tests {
    use super::detect_cups;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_cups_when_process_present() {
        let system = FakeProcesses(vec!["cupsd"]);
        assert_eq!(detect_cups(&system), Some("caps/print/cups"));
    }

    #[test]
    fn no_detection_without_a_cupsd_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "nginx"]);
        assert_eq!(detect_cups(&system), None);
    }
}

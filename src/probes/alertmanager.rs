use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `alertmanager` plugin never
/// detects presence itself — it's a special agent that queries
/// Alertmanager's HTTP API, so there's no host-side signal to copy from the
/// Checkmk source.
///
/// Alertmanager's official release binary is named `alertmanager`.
pub fn detect_alertmanager(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["alertmanager"]).then_some("caps/monitoring/alertmanager")
}

#[cfg(test)]
mod tests {
    use super::detect_alertmanager;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_alertmanager_when_process_present() {
        let system = FakeProcesses(vec!["alertmanager"]);
        assert_eq!(
            detect_alertmanager(&system),
            Some("caps/monitoring/alertmanager")
        );
    }

    #[test]
    fn no_detection_without_an_alertmanager_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "mysqld"]);
        assert_eq!(detect_alertmanager(&system), None);
    }
}

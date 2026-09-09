use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `prometheus` plugin never
/// detects presence itself — it's a special agent that scrapes Prometheus's
/// HTTP API, so there's no host-side signal to copy from the Checkmk source.
///
/// Prometheus's official release binary is named `prometheus`.
pub fn detect_prometheus(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["prometheus"]).then_some("caps/monitoring/prometheus")
}

#[cfg(test)]
mod tests {
    use super::detect_prometheus;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_prometheus_when_process_present() {
        let system = FakeProcesses(vec!["prometheus"]);
        assert_eq!(
            detect_prometheus(&system),
            Some("caps/monitoring/prometheus")
        );
    }

    #[test]
    fn no_detection_without_a_prometheus_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "mysqld"]);
        assert_eq!(detect_prometheus(&system), None);
    }
}

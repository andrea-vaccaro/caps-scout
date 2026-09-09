use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `docker` plugin never detects
/// presence itself — a host is manually configured as a Docker node, so
/// there's no host-side signal to copy from the Checkmk source.
///
/// Docker's daemon process is `dockerd`.
pub fn detect_docker(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["dockerd"]).then_some("caps/container/docker")
}

#[cfg(test)]
mod tests {
    use super::detect_docker;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_docker_when_dockerd_process_present() {
        let system = FakeProcesses(vec!["dockerd"]);
        assert_eq!(detect_docker(&system), Some("caps/container/docker"));
    }

    #[test]
    fn no_detection_without_a_dockerd_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "containerd"]);
        assert_eq!(detect_docker(&system), None);
    }
}

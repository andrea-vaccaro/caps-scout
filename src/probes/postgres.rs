use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md. In short:
/// no built-in Checkmk plugin currently detects *which* DB engines are present
/// on a host (each DB plugin only monitors an already-configured connection),
/// so this is a real gap, not duplicated work. Labels follow the
/// `caps/<capability>` convention and are emitted whenever the capability is
/// detected, whether or not a corresponding Checkmk plugin is deployed.
/// Detection is presence-only: does a process with a matching name exist?
pub fn detect_postgres(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["postgres", "postmaster"]).then_some("caps/db/postgres")
}

#[cfg(test)]
mod tests {
    use super::detect_postgres;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_postgres_when_postgres_process_present() {
        let system = FakeProcesses(vec!["postgres"]);
        assert_eq!(detect_postgres(&system), Some("caps/db/postgres"));
    }

    #[test]
    fn detects_postgres_when_postmaster_process_present() {
        let system = FakeProcesses(vec!["postmaster"]);
        assert_eq!(detect_postgres(&system), Some("caps/db/postgres"));
    }

    #[test]
    fn no_detection_without_a_postgres_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "mysqld"]);
        assert_eq!(detect_postgres(&system), None);
    }
}

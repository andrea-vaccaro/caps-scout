use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md. In short:
/// no built-in Checkmk plugin currently detects *which* DB engines are present
/// on a host (each DB plugin only monitors an already-configured connection),
/// so this is a real gap, not duplicated work. Labels follow the
/// `caps/<capability>` convention and are emitted whenever the capability is
/// detected, whether or not a corresponding Checkmk plugin is deployed.
/// Detection is presence-only: does a process with a matching name exist?
pub fn detect_mysql(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["mysqld"]).then_some("caps/db/mysql")
}

#[cfg(test)]
mod tests {
    use super::detect_mysql;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_mysql_when_mysqld_process_present() {
        let system = FakeProcesses(vec!["mysqld"]);
        assert_eq!(detect_mysql(&system), Some("caps/db/mysql"));
    }

    #[test]
    fn no_detection_without_a_mysqld_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "postgres"]);
        assert_eq!(detect_mysql(&system), None);
    }
}

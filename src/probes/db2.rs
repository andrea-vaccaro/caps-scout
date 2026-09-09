use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md. In short:
/// no built-in Checkmk plugin currently detects *which* DB engines are present
/// on a host (each DB plugin only monitors an already-configured connection),
/// so this is a real gap, not duplicated work. Labels follow the
/// `caps/<capability>` convention and are emitted whenever the capability is
/// detected, whether or not a corresponding Checkmk plugin is deployed.
/// Detection is presence-only: does a process with a matching name exist?

/// DB2's system controller process is `db2sysc`, the canonical process
/// present for any running instance.
pub fn detect_db2(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["db2sysc"]).then_some("caps/db/db2")
}

#[cfg(test)]
mod tests {
    use super::detect_db2;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_db2_when_db2sysc_process_present() {
        let system = FakeProcesses(vec!["db2sysc"]);
        assert_eq!(detect_db2(&system), Some("caps/db/db2"));
    }

    #[test]
    fn no_detection_without_a_db2sysc_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "mysqld"]);
        assert_eq!(detect_db2(&system), None);
    }
}

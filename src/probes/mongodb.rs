use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md. In short:
/// no built-in Checkmk plugin currently detects *which* DB engines are present
/// on a host (each DB plugin only monitors an already-configured connection),
/// so this is a real gap, not duplicated work. Labels follow the
/// `caps/<capability>` convention and are emitted whenever the capability is
/// detected, whether or not a corresponding Checkmk plugin is deployed.
/// Detection is presence-only: does a process with a matching name exist?

/// MongoDB's server process is `mongod`.
pub fn detect_mongodb(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["mongod"]).then_some("caps/db/mongodb")
}

#[cfg(test)]
mod tests {
    use super::detect_mongodb;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_mongodb_when_mongod_process_present() {
        let system = FakeProcesses(vec!["mongod"]);
        assert_eq!(detect_mongodb(&system), Some("caps/db/mongodb"));
    }

    #[test]
    fn no_detection_without_a_mongod_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "mysqld"]);
        assert_eq!(detect_mongodb(&system), None);
    }
}

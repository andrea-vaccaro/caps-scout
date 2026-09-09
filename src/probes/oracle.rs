use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md. In short:
/// no built-in Checkmk plugin currently detects *which* DB engines are present
/// on a host (each DB plugin only monitors an already-configured connection),
/// so this is a real gap, not duplicated work. Labels follow the
/// `caps/<capability>` convention and are emitted whenever the capability is
/// detected, whether or not a corresponding Checkmk plugin is deployed.
/// Detection is presence-only: does a process with a matching name exist?

/// Oracle background processes are named ora_<process>_<SID>, e.g.
/// ora_pmon_ORCL. ora_pmon_ is the canonical one to look for.
pub fn detect_oracle(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["ora_pmon_"]).then_some("caps/db/oracle")
}

#[cfg(test)]
mod tests {
    use super::detect_oracle;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_oracle_when_pmon_process_present() {
        let system = FakeProcesses(vec!["ora_pmon_ORCL"]);
        assert_eq!(detect_oracle(&system), Some("caps/db/oracle"));
    }

    #[test]
    fn no_detection_without_a_pmon_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "mysqld"]);
        assert_eq!(detect_oracle(&system), None);
    }
}

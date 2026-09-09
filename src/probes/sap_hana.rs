use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md. In short:
/// no built-in Checkmk plugin currently detects *which* DB engines are present
/// on a host (each DB plugin only monitors an already-configured connection),
/// so this is a real gap, not duplicated work. Labels follow the
/// `caps/<capability>` convention and are emitted whenever the capability is
/// detected, whether or not a corresponding Checkmk plugin is deployed.
/// Detection is presence-only: does a process with a matching name exist?

/// SAP HANA's instance watchdog process is `hdbdaemon`, present for any
/// running instance regardless of which other `hdb*` service processes it
/// has started.
pub fn detect_sap_hana(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["hdbdaemon"]).then_some("caps/db/sap_hana")
}

#[cfg(test)]
mod tests {
    use super::detect_sap_hana;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_sap_hana_when_hdbdaemon_process_present() {
        let system = FakeProcesses(vec!["hdbdaemon"]);
        assert_eq!(detect_sap_hana(&system), Some("caps/db/sap_hana"));
    }

    #[test]
    fn no_detection_without_a_hdbdaemon_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "mysqld"]);
        assert_eq!(detect_sap_hana(&system), None);
    }
}

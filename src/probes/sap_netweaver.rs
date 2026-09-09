use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. In short: no built-in Checkmk plugin
/// currently detects *which* web/app engines are present on a host (each
/// plugin only monitors an already-configured connection), so this is a real
/// gap, not duplicated work. Detection is presence-only: does a process with
/// a matching name exist?

/// SAP NetWeaver's ABAP dispatcher process is `disp+work`. This only
/// catches classic ABAP-stack instances; a Java-stack-only instance runs
/// `jlaunch`/`jcontrol` instead and won't be detected by this pattern.
pub fn detect_sap_netweaver(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["disp+work"]).then_some("caps/app/sap_netweaver")
}

#[cfg(test)]
mod tests {
    use super::detect_sap_netweaver;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_sap_netweaver_when_dispatcher_process_present() {
        let system = FakeProcesses(vec!["disp+work"]);
        assert_eq!(
            detect_sap_netweaver(&system),
            Some("caps/app/sap_netweaver")
        );
    }

    #[test]
    fn no_detection_without_a_dispatcher_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "mysqld"]);
        assert_eq!(detect_sap_netweaver(&system), None);
    }
}

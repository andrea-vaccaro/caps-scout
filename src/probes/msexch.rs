use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `msexch_*` plugins never
/// detect Exchange presence themselves — they're unconditionally deployed
/// by an admin-configured rule and read Windows Performance Counters, not a
/// process name, so there's no signal to copy from the Checkmk source.
///
/// Instead this uses `Microsoft.Exchange.Store.Service.exe` (internally
/// "MSExchangeIS"), which Microsoft's Managed Store architecture docs
/// describe as the single store-service-controller process running on any
/// Exchange Mailbox-role server, regardless of how many databases are
/// mounted — unlike the per-database `Microsoft.Exchange.Store.Worker.exe`
/// workers, which are absent if no database is mounted. This only detects
/// the Mailbox role; an Edge Transport-only server runs `EdgeTransport.exe`
/// instead and won't be detected here.
pub fn detect_msexch(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["Microsoft.Exchange.Store.Service"]).then_some("caps/app/exchange")
}

#[cfg(test)]
mod tests {
    use super::detect_msexch;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_msexch_when_store_service_process_present() {
        let system = FakeProcesses(vec!["Microsoft.Exchange.Store.Service.exe"]);
        assert_eq!(detect_msexch(&system), Some("caps/app/exchange"));
    }

    #[test]
    fn no_detection_without_a_store_service_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "mysqld"]);
        assert_eq!(detect_msexch(&system), None);
    }
}

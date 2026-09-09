use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `veeam_backup_status.ps1`
/// (`veeam/agents/veeam_backup_status.ps1`) checks for Veeam's presence the
/// same way: `Get-Process | where { $_.Name -like "*Veeam.Backup.Service*" }`.
/// This mirrors that exactly.
pub fn detect_veeam(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["Veeam.Backup.Service"]).then_some("caps/backup/veeam")
}

#[cfg(test)]
mod tests {
    use super::detect_veeam;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_veeam_when_backup_service_process_present() {
        let system = FakeProcesses(vec!["Veeam.Backup.Service.exe"]);
        assert_eq!(detect_veeam(&system), Some("caps/backup/veeam"));
    }

    #[test]
    fn no_detection_without_a_veeam_backup_service_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "dockerd"]);
        assert_eq!(detect_veeam(&system), None);
    }
}

use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `zerto` plugin is entirely
/// REST-API-based (`zerto/special_agent/agent_zerto.py`), and Zerto's VRA
/// (the per-protected-host replication appliance) is a separate thin Linux
/// VM, not a process on the protected host itself — so there's no way to
/// detect "this host is protected by Zerto" via a local process.
///
/// What *is* detectable is a host running the Zerto Virtual Manager (ZVM)
/// itself — the management server Checkmk's plugin actually queries. Its
/// service executable, `Zerto.Zvm.Service.exe`, is confirmed by a real
/// Windows Event Log crash entry from a Zerto support forum thread
/// (path `C:\Program Files\Zerto\Zerto Virtual Replication\Zerto.Zvm.Service.exe`).
/// This is the same scope as `detect_msexch` detecting the Mailbox role or
/// `detect_veeam` detecting the B&R server — a management/server
/// component, not every host the product happens to touch.
pub fn detect_zerto(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["Zerto.Zvm.Service"]).then_some("caps/backup/zerto")
}

#[cfg(test)]
mod tests {
    use super::detect_zerto;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_zerto_when_zvm_service_process_present() {
        let system = FakeProcesses(vec!["Zerto.Zvm.Service.exe"]);
        assert_eq!(detect_zerto(&system), Some("caps/backup/zerto"));
    }

    #[test]
    fn no_detection_without_a_zvm_service_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "dockerd"]);
        assert_eq!(detect_zerto(&system), None);
    }
}

use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `hyperv` plugins never detect
/// presence themselves — the agent scripts (`hyperv/agents/hyperv_vms.ps1`)
/// use the Hyper-V PowerShell module to list VMs unconditionally, so
/// there's no host-side signal to copy from the Checkmk source.
///
/// `vmms.exe` (Virtual Machine Management Service) runs whenever the
/// Hyper-V role is enabled on a Windows host, regardless of whether any VM
/// is currently running.
pub fn detect_hyperv(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["vmms.exe"]).then_some("caps/virt/hyperv")
}

#[cfg(test)]
mod tests {
    use super::detect_hyperv;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_hyperv_when_vmms_process_present() {
        let system = FakeProcesses(vec!["vmms.exe"]);
        assert_eq!(detect_hyperv(&system), Some("caps/virt/hyperv"));
    }

    #[test]
    fn no_detection_without_a_vmms_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "dockerd"]);
        assert_eq!(detect_hyperv(&system), None);
    }
}

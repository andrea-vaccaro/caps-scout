use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `vbox` plugin
/// (`vbox/agent_based/vbox_guest.py`) is entirely guest-side: it runs
/// `VBoxControl guestproperty enumerate` to check the VirtualBox Guest
/// Additions installed *inside* a VM, never detects a host running the
/// VirtualBox hypervisor itself. So the caps-scout-shaped gap here is the
/// same one: "is this host itself a VirtualBox guest VM", not "does this
/// host run VirtualBox as a hypervisor" (`caps/virt/virtualbox` isn't
/// something this probe can support — no signal for that was found here).
///
/// `VBoxService` is the Guest Additions root daemon on Linux guests,
/// confirmed via VirtualBox's own source
/// (https://www.virtualbox.org/svn/vbox/trunk/src/VBox/Additions/common/VBoxService/VBoxService.cpp).
pub fn detect_virtualbox_guest(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["VBoxService"]).then_some("caps/virt/virtualbox_guest")
}

#[cfg(test)]
mod tests {
    use super::detect_virtualbox_guest;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_virtualbox_guest_when_vboxservice_process_present() {
        let system = FakeProcesses(vec!["VBoxService"]);
        assert_eq!(
            detect_virtualbox_guest(&system),
            Some("caps/virt/virtualbox_guest")
        );
    }

    #[test]
    fn no_detection_without_a_vboxservice_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "dockerd"]);
        assert_eq!(detect_virtualbox_guest(&system), None);
    }
}

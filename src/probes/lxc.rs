use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `lxc` plugin
/// (`lxc/agent_based/lxc_container_cpu*.py`) is guest-side — it reads
/// cgroup CPU stats from inside a running LXC container — not a host-side
/// presence signal, so there's nothing to copy from the Checkmk source for
/// "this host runs LXC containers".
///
/// Instead this matches the `[lxc monitor]` process LXC spawns for each
/// running container, confirmed by the upstream LXC project
/// (https://github.com/lxc/lxc/issues/3254) as a distinctly-renamed,
/// persistent process for the container's lifetime. Caveat: unlike Docker's
/// always-running `dockerd`, this only detects LXC while at least one
/// container is actively running — an idle LXC install with no running
/// containers won't be detected.
pub fn detect_lxc(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["lxc monitor"]).then_some("caps/container/lxc")
}

#[cfg(test)]
mod tests {
    use super::detect_lxc;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_lxc_when_monitor_process_present() {
        let system = FakeProcesses(vec!["[lxc monitor] /var/lib/lxc mycontainer"]);
        assert_eq!(detect_lxc(&system), Some("caps/container/lxc"));
    }

    #[test]
    fn no_detection_without_a_monitor_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "dockerd"]);
        assert_eq!(detect_lxc(&system), None);
    }
}

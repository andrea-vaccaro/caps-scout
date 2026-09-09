use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. The NFS server daemon itself (`nfsd`)
/// usually runs as kernel threads, not a normal userspace process, so it
/// isn't something `any_process_named`'s substring match can reliably
/// catch. Checkmk's own agent script (`nfsexports/agents/nfsexports`)
/// instead gates its export-listing on `/etc/exports` having real entries
/// *and* `pgrep rpc.mountd` succeeding — `rpc.mountd` is a genuine
/// userspace daemon that only runs while the NFS server is actually
/// active, so it's used here as the presence signal (the `/etc/exports`
/// content check is about whether exports are *configured*, a narrower
/// question than whether the server capability is present at all).
pub fn detect_nfs_server(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["rpc.mountd"]).then_some("caps/file/nfs_server")
}

#[cfg(test)]
mod tests {
    use super::detect_nfs_server;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_nfs_server_when_mountd_process_present() {
        let system = FakeProcesses(vec!["rpc.mountd"]);
        assert_eq!(detect_nfs_server(&system), Some("caps/file/nfs_server"));
    }

    #[test]
    fn no_detection_without_a_mountd_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "nginx"]);
        assert_eq!(detect_nfs_server(&system), None);
    }
}

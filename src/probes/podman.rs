use super::util::filesystem::FileSystem;

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Unlike Docker, Podman is daemonless by
/// default, so there's no persistent process to match on. Checkmk's own
/// agent config (`podman/rulesets/agent_plugin_config.py`) documents its
/// socket auto-detection paths directly: the root socket at
/// `/run/podman/podman.sock`, and per-user sockets at
/// `/run/user/{user_id}/podman/podman.sock`. This only checks the root
/// socket — the one Checkmk itself offers as an "only root socket" option —
/// so a purely rootless Podman setup (no root socket, only user sockets)
/// won't be detected.
const ROOT_SOCKET_PATH: &str = "/run/podman/podman.sock";

pub fn detect_podman(fs: &impl FileSystem) -> Option<&'static str> {
    fs.exists(ROOT_SOCKET_PATH).then_some("caps/container/podman")
}

#[cfg(test)]
mod tests {
    use super::detect_podman;
    use crate::probes::util::filesystem::FakeFileSystem;

    #[test]
    fn detects_podman_when_root_socket_present() {
        let fs = FakeFileSystem(vec!["/run/podman/podman.sock"]);
        assert_eq!(detect_podman(&fs), Some("caps/container/podman"));
    }

    #[test]
    fn no_detection_without_the_root_socket() {
        let fs = FakeFileSystem(vec![]);
        assert_eq!(detect_podman(&fs), None);
    }
}

use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own core agent
/// (`agents/check_mk_agent.linux:1463`, `section_haproxy`) doesn't check
/// the daemon process at all — it looks for a readable stats socket (one
/// of `/run/haproxy/admin.sock`, `/var/lib/haproxy/stats`,
/// `/var/run/haproxy.sock`, or an enterprise-edition `hapee-lb.sock` path)
/// plus `socat` being available, since that's what it needs to actually
/// pull stats. That's a "can Checkmk monitor it" signal, not a "is it
/// present" one — an admin socket is opt-in config, so a running HAProxy
/// without one configured would still be missed. caps-scout wants the
/// latter, so this matches the daemon process directly instead: `haproxy`.
pub fn detect_haproxy(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["haproxy"]).then_some("caps/lb/haproxy")
}

#[cfg(test)]
mod tests {
    use super::detect_haproxy;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_haproxy_when_process_present() {
        let system = FakeProcesses(vec!["haproxy"]);
        assert_eq!(detect_haproxy(&system), Some("caps/lb/haproxy"));
    }

    #[test]
    fn no_detection_without_a_haproxy_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "nginx"]);
        assert_eq!(detect_haproxy(&system), None);
    }
}

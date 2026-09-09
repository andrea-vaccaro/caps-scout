use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own core agent
/// (`agents/check_mk_agent.linux:1447`, `section_http_accelerator`) gates
/// on `inpath varnishstat` — the CLI stats tool being available — not the
/// daemon process itself. caps-scout wants "is the cache engine present",
/// so this matches the daemon directly: `varnishd`.
pub fn detect_varnish(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["varnishd"]).then_some("caps/cache/varnish")
}

#[cfg(test)]
mod tests {
    use super::detect_varnish;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_varnish_when_process_present() {
        let system = FakeProcesses(vec!["varnishd"]);
        assert_eq!(detect_varnish(&system), Some("caps/cache/varnish"));
    }

    #[test]
    fn no_detection_without_a_varnishd_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "nginx"]);
        assert_eq!(detect_varnish(&system), None);
    }
}

use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. In short: no built-in Checkmk plugin
/// currently detects *which* web/app engines are present on a host (each
/// plugin only monitors an already-configured connection), so this is a real
/// gap, not duplicated work. Detection is presence-only: does a process with
/// a matching name exist?

/// nginx's master/worker processes are named `nginx`.
pub fn detect_nginx(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["nginx"]).then_some("caps/web/nginx")
}

#[cfg(test)]
mod tests {
    use super::detect_nginx;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_nginx_when_nginx_process_present() {
        let system = FakeProcesses(vec!["nginx"]);
        assert_eq!(detect_nginx(&system), Some("caps/web/nginx"));
    }

    #[test]
    fn no_detection_without_an_nginx_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "httpd"]);
        assert_eq!(detect_nginx(&system), None);
    }
}

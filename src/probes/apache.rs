use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. In short: no built-in Checkmk plugin
/// currently detects *which* web/app engines are present on a host (each
/// plugin only monitors an already-configured connection), so this is a real
/// gap, not duplicated work. Detection is presence-only: does a process with
/// a matching name exist?

/// Apache's httpd binary is named `httpd` on RHEL/CentOS-family
/// distributions and `apache2` on Debian/Ubuntu-family ones.
pub fn detect_apache(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["httpd", "apache2"]).then_some("caps/web/apache")
}

#[cfg(test)]
mod tests {
    use super::detect_apache;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_apache_when_httpd_process_present() {
        let system = FakeProcesses(vec!["httpd"]);
        assert_eq!(detect_apache(&system), Some("caps/web/apache"));
    }

    #[test]
    fn detects_apache_when_apache2_process_present() {
        let system = FakeProcesses(vec!["apache2"]);
        assert_eq!(detect_apache(&system), Some("caps/web/apache"));
    }

    #[test]
    fn no_detection_without_an_apache_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "nginx"]);
        assert_eq!(detect_apache(&system), None);
    }
}

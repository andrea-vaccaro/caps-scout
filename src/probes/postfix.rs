use super::util::process::{any_command_line_contains, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Postfix's master process is literally named
/// `master` — too generic to match on directly (Jenkins, gunicorn, and
/// other software also run a process just called `master`). Checkmk's own
/// core agent (`agents/check_mk_agent.linux:1231`) verifies Postfix is
/// actually running by checking that process's command line against the
/// regex `.*postfix/\(s\?bin/\)\?/\?master.*` — i.e. `postfix/master`,
/// `postfix/sbin/master`, or `postfix/bin/master` in the full command line,
/// which Postfix's master daemon includes to distinguish itself. This
/// mirrors that check across all three variants.
pub fn detect_postfix(system: &impl ProcessNames) -> Option<&'static str> {
    any_command_line_contains(
        system,
        &["postfix/master", "postfix/sbin/master", "postfix/bin/master"],
    )
    .then_some("caps/mail/postfix")
}

#[cfg(test)]
mod tests {
    use super::detect_postfix;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_postfix_when_master_command_line_present() {
        let system = FakeProcesses(vec!["/usr/lib/postfix/sbin/master"]);
        assert_eq!(detect_postfix(&system), Some("caps/mail/postfix"));
    }

    #[test]
    fn no_detection_from_an_unrelated_master_process() {
        let system = FakeProcesses(vec!["/usr/lib/jenkins/master"]);
        assert_eq!(detect_postfix(&system), None);
    }
}

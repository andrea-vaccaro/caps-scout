use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `skype` plugin reads Windows
/// perf counters via WMI, not a process name, so there's no host-side
/// signal to copy from the Checkmk source. Skype for Business Server's
/// Front End service process, `RtcSrv.exe`, is confirmed by multiple
/// Microsoft support KB articles naming it directly in crash reports
/// (e.g. "Event 1000 occurs and the Rtcsrv.exe process crashes ... Front
/// End server"). Casing varies across Microsoft's own docs, so both
/// variants are matched. This only detects the Front End role, matching
/// Checkmk's own check ("monitors ... a skype frontend server").
pub fn detect_skype(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["RtcSrv", "Rtcsrv"]).then_some("caps/collab/skype_for_business")
}

#[cfg(test)]
mod tests {
    use super::detect_skype;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_skype_when_rtcsrv_process_present() {
        let system = FakeProcesses(vec!["RtcSrv.exe"]);
        assert_eq!(
            detect_skype(&system),
            Some("caps/collab/skype_for_business")
        );
    }

    #[test]
    fn detects_skype_when_lowercase_rtcsrv_process_present() {
        let system = FakeProcesses(vec!["Rtcsrv.exe"]);
        assert_eq!(
            detect_skype(&system),
            Some("caps/collab/skype_for_business")
        );
    }

    #[test]
    fn no_detection_without_a_rtcsrv_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "nginx"]);
        assert_eq!(detect_skype(&system), None);
    }
}

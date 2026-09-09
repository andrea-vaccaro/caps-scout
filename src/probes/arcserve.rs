use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `arcserve_backup` plugin
/// targets "Arcserve Backup" specifically (per its checkman: connects to
/// the Arcserve Backup database over TCP/IP or named pipes) — a different,
/// older product line than "Arcserve UDP"/"D2D", whose service name
/// (`CASAD2DWebSvc`) doesn't apply here.
///
/// Arcserve's own documentation
/// (https://documentation.arcserve.com/Arcserve-Backup/Available/R16/ENU/Bookshelf_Files/HTML/impltgde/2966.html)
/// lists the primary server's core components: the DB Engine (`dbeng.exe`,
/// "Provides database services for Arcserve Backup products") and the Job
/// Engine (`jobeng.exe`, runs backup jobs) — both fundamental to any
/// primary server install, unlike optional components like the Tape Engine
/// (needs physical tape hardware) or Discovery Service (network discovery).
pub fn detect_arcserve(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["dbeng.exe", "jobeng.exe"]).then_some("caps/backup/arcserve")
}

#[cfg(test)]
mod tests {
    use super::detect_arcserve;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_arcserve_when_db_engine_process_present() {
        let system = FakeProcesses(vec!["dbeng.exe"]);
        assert_eq!(detect_arcserve(&system), Some("caps/backup/arcserve"));
    }

    #[test]
    fn detects_arcserve_when_job_engine_process_present() {
        let system = FakeProcesses(vec!["jobeng.exe"]);
        assert_eq!(detect_arcserve(&system), Some("caps/backup/arcserve"));
    }

    #[test]
    fn no_detection_without_an_arcserve_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "dockerd"]);
        assert_eq!(detect_arcserve(&system), None);
    }
}

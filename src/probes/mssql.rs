use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md. In short:
/// no built-in Checkmk plugin currently detects *which* DB engines are present
/// on a host (each DB plugin only monitors an already-configured connection),
/// so this is a real gap, not duplicated work. Labels follow the
/// `caps/<capability>` convention and are emitted whenever the capability is
/// detected, whether or not a corresponding Checkmk plugin is deployed.
/// Detection is presence-only: does a process with a matching name exist?

/// SQL Server's engine process is `sqlservr` on both Linux and Windows
/// (`sqlservr.exe`) — `any_process_named` matches by substring, so one
/// pattern covers both.
pub fn detect_mssql(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["sqlservr"]).then_some("caps/db/mssql")
}

#[cfg(test)]
mod tests {
    use super::detect_mssql;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_mssql_when_sqlservr_process_present() {
        let system = FakeProcesses(vec!["sqlservr"]);
        assert_eq!(detect_mssql(&system), Some("caps/db/mssql"));
    }

    #[test]
    fn no_detection_without_a_sqlservr_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "mysqld"]);
        assert_eq!(detect_mssql(&system), None);
    }
}

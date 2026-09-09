use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md. In short:
/// no built-in Checkmk plugin currently detects *which* DB engines are present
/// on a host (each DB plugin only monitors an already-configured connection),
/// so this is a real gap, not duplicated work. Labels follow the
/// `caps/<capability>` convention and are emitted whenever the capability is
/// detected, whether or not a corresponding Checkmk plugin is deployed.
/// Detection is presence-only: does a process with a matching name exist?

/// Redis's server process is `redis-server`.
pub fn detect_redis(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["redis-server"]).then_some("caps/db/redis")
}

#[cfg(test)]
mod tests {
    use super::detect_redis;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_redis_when_redis_server_process_present() {
        let system = FakeProcesses(vec!["redis-server"]);
        assert_eq!(detect_redis(&system), Some("caps/db/redis"));
    }

    #[test]
    fn no_detection_without_a_redis_server_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "mysqld"]);
        assert_eq!(detect_redis(&system), None);
    }
}

use super::util::process::{any_command_line_contains, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `activemq` plugin never
/// detects presence itself — it's a special agent that queries ActiveMQ's
/// admin HTTP endpoint, so there's no host-side signal to copy from the
/// Checkmk source.
///
/// ActiveMQ is a Java application, so its process name is just `java` —
/// too generic to match on. Its actual startup script (`bin/activemq`,
/// see https://github.com/apache/activemq/blob/main/assembly/src/release/bin/activemq)
/// launches with `-jar .../bin/activemq.jar`, which is distinctive and
/// shows up in the process's full command line.
pub fn detect_activemq(system: &impl ProcessNames) -> Option<&'static str> {
    any_command_line_contains(system, &["activemq.jar"]).then_some("caps/mq/activemq")
}

#[cfg(test)]
mod tests {
    use super::detect_activemq;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_activemq_when_jar_present_in_command_line() {
        let system = FakeProcesses(vec!["java -jar /opt/activemq/bin/activemq.jar start"]);
        assert_eq!(detect_activemq(&system), Some("caps/mq/activemq"));
    }

    #[test]
    fn no_detection_without_the_activemq_jar() {
        let system = FakeProcesses(vec!["java -jar /opt/app/other.jar"]);
        assert_eq!(detect_activemq(&system), None);
    }
}

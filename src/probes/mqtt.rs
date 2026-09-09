use super::util::process::{any_process_named, ProcessNames};

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `mqtt` plugin is
/// protocol-based, not tied to one broker implementation: it connects over
/// MQTT itself and reads `$SYS` topics
/// (https://github.com/mqtt/mqtt.org/wiki/SYS-Topics), which any
/// MQTT-compliant broker exposes — Mosquitto, HiveMQ, EMQX, VerneMQ, etc.
/// There's no single "MQTT broker" process to detect.
///
/// This only detects Mosquitto, the most common self-hosted broker, via its
/// `mosquitto` process. Other broker implementations (HiveMQ, EMQX,
/// VerneMQ, ...) won't be detected — this is a narrower signal than the
/// `mqtt` plugin family it maps to.
pub fn detect_mqtt(system: &impl ProcessNames) -> Option<&'static str> {
    any_process_named(system, &["mosquitto"]).then_some("caps/mq/mqtt")
}

#[cfg(test)]
mod tests {
    use super::detect_mqtt;
    use crate::probes::util::process::FakeProcesses;

    #[test]
    fn detects_mqtt_when_mosquitto_process_present() {
        let system = FakeProcesses(vec!["mosquitto"]);
        assert_eq!(detect_mqtt(&system), Some("caps/mq/mqtt"));
    }

    #[test]
    fn no_detection_without_a_mosquitto_process() {
        let system = FakeProcesses(vec!["sshd", "bash", "mysqld"]);
        assert_eq!(detect_mqtt(&system), None);
    }
}

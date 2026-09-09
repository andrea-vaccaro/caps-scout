//! Black-box tests against the compiled binary's stdout contract. These
//! assert the *shape* of the output, not what a given machine happens to
//! detect, so they hold regardless of what's installed on the test runner.

use std::process::{Command, Output};

fn run_caps_scout() -> Output {
    Command::new(env!("CARGO_BIN_EXE_caps-scout"))
        .output()
        .expect("failed to run the caps-scout binary")
}

#[test]
fn exits_successfully() {
    let output = run_caps_scout();
    assert!(
        output.status.success(),
        "caps-scout exited with {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn output_is_empty_or_a_well_formed_labels_section() {
    let output = run_caps_scout();
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    if stdout.is_empty() {
        return;
    }

    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some("<<<labels:sep(0)>>>"),
        "non-empty output must start with the labels section header"
    );

    let json_line = lines
        .next()
        .expect("labels section header with no JSON line following it");
    assert!(
        lines.next().is_none(),
        "labels section must be exactly one JSON line"
    );

    serde_json::from_str::<serde_json::Value>(json_line).expect("labels line was not valid JSON");
}

#[test]
fn labels_follow_the_caps_namespace_and_yes_value_convention() {
    let output = run_caps_scout();
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    let Some(json_line) = stdout.lines().nth(1) else {
        // No labels detected on this machine — nothing to check.
        return;
    };

    let labels: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(json_line).expect("labels line was not valid JSON");

    for (key, value) in &labels {
        assert!(
            key.starts_with("caps/"),
            "label key {key:?} does not start with caps/"
        );
        assert_eq!(
            value.as_str(),
            Some("yes"),
            "label {key:?} has value {value:?}, expected \"yes\""
        );
    }
}

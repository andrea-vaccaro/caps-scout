//! Component test: spawns a real Apache container and confirms caps-scout
//! actually detects it. Needs a working Docker daemon and network access to
//! pull the image — following the same pattern as mk-oracle's DB-dependent
//! tests (see ~/workspace/check_mk/packages/mk-oracle/tests/), this doesn't
//! use `#[ignore]`. It always runs under plain `cargo test`, and instead
//! detects at runtime whether its prerequisites are met, printing why and
//! returning early (counted as passed, not skipped) if they aren't — so the
//! reason is visible in normal test output instead of hidden behind a flag.

use std::process::Command;
use std::time::{Duration, Instant};

const CONTAINER_IMAGE: &str = "httpd:alpine";

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Owns the container's lifetime: `docker stop` (with `--rm` on the
/// container, that also removes it) runs on drop, including on panic, so a
/// failed assertion never leaks a running container.
struct ApacheContainer {
    name: String,
}

impl ApacheContainer {
    fn start(name: &str) -> Option<Self> {
        let output = Command::new("docker")
            .args(["run", "--detach", "--rm", "--name", name, CONTAINER_IMAGE])
            .output()
            .ok()?;
        output.status.success().then(|| Self {
            name: name.to_string(),
        })
    }
}

impl Drop for ApacheContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["stop", &self.name]).output();
    }
}

fn caps_scout_reports_apache() -> bool {
    let Ok(output) = Command::new(env!("CARGO_BIN_EXE_caps-scout")).output() else {
        return false;
    };
    let Ok(stdout) = String::from_utf8(output.stdout) else {
        return false;
    };
    let Some(json_line) = stdout.lines().nth(1) else {
        return false;
    };
    let Ok(labels) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(json_line)
    else {
        return false;
    };
    labels.get("caps/web/apache").and_then(|v| v.as_str()) == Some("yes")
}

fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

#[test]
fn detects_apache_running_in_a_docker_container() {
    if !docker_available() {
        eprintln!(
            "Skipping detects_apache_running_in_a_docker_container: docker is not available"
        );
        return;
    }

    let container_name = format!("caps-scout-test-apache-{}", std::process::id());
    let Some(_container) = ApacheContainer::start(&container_name) else {
        eprintln!(
            "Skipping detects_apache_running_in_a_docker_container: failed to start the \
             {CONTAINER_IMAGE} container (no network access to pull it?)"
        );
        return;
    };

    assert!(
        wait_until(Duration::from_secs(15), caps_scout_reports_apache),
        "caps-scout never reported caps/web/apache while the {CONTAINER_IMAGE} container was \
         running"
    );
}

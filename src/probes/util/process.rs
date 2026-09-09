use sysinfo::System;

/// Abstracts "the set of process names/command lines currently running" so
/// probes can be tested against fake process data instead of the real
/// OS-backed `sysinfo::System`, which has no public way to inject fake
/// processes.
pub trait ProcessNames {
    fn process_names(&self) -> Vec<String>;

    /// Full command line (argv, space-joined) per running process. Needed
    /// for probes where the short process name is too generic to match on
    /// (e.g. a Java app always shows up as `java`) but a distinctive marker
    /// — a jar name, a main class — appears in its arguments instead.
    fn command_lines(&self) -> Vec<String>;
}

impl ProcessNames for System {
    fn process_names(&self) -> Vec<String> {
        self.processes()
            .values()
            .map(|process| process.name().to_string_lossy().into_owned())
            .collect()
    }

    fn command_lines(&self) -> Vec<String> {
        self.processes()
            .values()
            .map(|process| {
                process
                    .cmd()
                    .iter()
                    .map(|arg| arg.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect()
    }
}

pub fn any_process_named(system: &impl ProcessNames, patterns: &[&str]) -> bool {
    any_name_matches(system.process_names(), patterns)
}

pub fn any_command_line_contains(system: &impl ProcessNames, patterns: &[&str]) -> bool {
    any_name_matches(system.command_lines(), patterns)
}

fn any_name_matches<S: AsRef<str>>(names: impl IntoIterator<Item = S>, patterns: &[&str]) -> bool {
    names
        .into_iter()
        .any(|name| patterns.iter().any(|pattern| name.as_ref().contains(pattern)))
}

/// A fake process list for testing `detect_*` probes without a real
/// `sysinfo::System`. Shared across the `probes` module tree, not just this
/// file's own tests. The same strings serve as both process names and
/// command lines — tests exercising `command_lines()` just pass
/// command-line-shaped strings.
#[cfg(test)]
pub struct FakeProcesses(pub Vec<&'static str>);

#[cfg(test)]
impl ProcessNames for FakeProcesses {
    fn process_names(&self) -> Vec<String> {
        self.0.iter().map(|name| name.to_string()).collect()
    }

    fn command_lines(&self) -> Vec<String> {
        self.process_names()
    }
}

#[cfg(test)]
mod tests {
    use super::any_name_matches;

    #[test]
    fn matches_oracle_pmon_process() {
        assert!(any_name_matches(["ora_pmon_ORCL"], &["ora_pmon_"]));
    }

    #[test]
    fn matches_mysqld_process() {
        assert!(any_name_matches(["mysqld"], &["mysqld"]));
    }

    #[test]
    fn matches_either_postgres_pattern() {
        assert!(any_name_matches(["postgres"], &["postgres", "postmaster"]));
        assert!(any_name_matches(["postmaster"], &["postgres", "postmaster"]));
    }

    #[test]
    fn matches_pattern_as_substring_anywhere_in_name() {
        assert!(any_name_matches(
            ["/usr/lib/postgresql/16/bin/postgres"],
            &["postgres"]
        ));
    }

    #[test]
    fn no_match_when_no_process_contains_any_pattern() {
        assert!(!any_name_matches(
            ["sshd", "bash", "systemd"],
            &["ora_pmon_", "mysqld"]
        ));
    }

    #[test]
    fn no_match_on_empty_process_list() {
        assert!(!any_name_matches(std::iter::empty::<&str>(), &["mysqld"]));
    }

    #[test]
    fn no_match_on_empty_pattern_list() {
        assert!(!any_name_matches(["mysqld"], &[]));
    }

    #[test]
    fn match_is_case_sensitive() {
        assert!(!any_name_matches(["MySQLd"], &["mysqld"]));
    }
}

/// Checkmk itself never *detects* the host OS at runtime: each platform gets
/// its own agent build, and that build hardcodes a single "AgentOS: <name>"
/// string, one per platform (see e.g. `agents/check_mk_agent.linux`,
/// `.aix`, `.solaris`, `.macosx` in the Checkmk source — `AgentOS: linux`,
/// `AgentOS: aix`, `AgentOS: solaris`, `AgentOS: macosx` respectively; Windows
/// is `AgentOS: windows`, hardcoded in the agent's C++ provider). The build
/// *is* the OS it targets. caps-scout mirrors that exactly: the OS is known
/// at compile time via `cfg!(target_os = ...)`, using the same name Checkmk's
/// own per-platform agents use, rather than probing for it at runtime.
pub fn detect_os() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        Some("caps/os_type/linux")
    } else if cfg!(target_os = "windows") {
        Some("caps/os_type/windows")
    } else if cfg!(target_os = "macos") {
        Some("caps/os_type/macosx")
    } else if cfg!(target_os = "solaris") {
        Some("caps/os_type/solaris")
    } else if cfg!(target_os = "aix") {
        Some("caps/os_type/aix")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::detect_os;

    #[test]
    fn detects_a_known_build_platform() {
        let expected = match std::env::consts::OS {
            "linux" => "caps/os_type/linux",
            "windows" => "caps/os_type/windows",
            "macos" => "caps/os_type/macosx",
            other => {
                eprintln!("skipping: no expected label wired up for target_os {other:?}");
                return;
            }
        };

        assert_eq!(detect_os(), Some(expected));
    }
}

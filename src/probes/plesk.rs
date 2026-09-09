use super::util::filesystem::FileSystem;

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Unlike the process-based probes, this one
/// checks for a file: Checkmk's own `plesk_domains.py`/`plesk_backups.py`
/// agent scripts (Linux-only) authenticate to Plesk's internal `psa` MySQL
/// database using credentials read from `/etc/psa/.psa.shadow`, which Plesk
/// creates on every install — the same marker Checkmk itself relies on.
/// Plesk's control-panel web server (`sw-cp-server`) can be stopped
/// independently of the rest of Plesk (hosting keeps running), so a
/// process-name probe would produce false negatives; this file isn't tied
/// to any one Plesk service being up.
const PSA_SHADOW_PATH: &str = "/etc/psa/.psa.shadow";

pub fn detect_plesk(fs: &impl FileSystem) -> Option<&'static str> {
    fs.exists(PSA_SHADOW_PATH).then_some("caps/app/plesk")
}

#[cfg(test)]
mod tests {
    use super::detect_plesk;
    use crate::probes::util::filesystem::FakeFileSystem;

    #[test]
    fn detects_plesk_when_psa_shadow_file_present() {
        let fs = FakeFileSystem(vec!["/etc/psa/.psa.shadow"]);
        assert_eq!(detect_plesk(&fs), Some("caps/app/plesk"));
    }

    #[test]
    fn no_detection_without_the_psa_shadow_file() {
        let fs = FakeFileSystem(vec![]);
        assert_eq!(detect_plesk(&fs), None);
    }
}

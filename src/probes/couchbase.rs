use super::util::filesystem::FileSystem;

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Checkmk's own `couchbase` plugin never
/// detects presence itself — it's a special agent that talks to Couchbase's
/// REST/management API over the network, so there's no host-side signal to
/// copy from the Checkmk source.
///
/// Couchbase's per-service binaries (`cbft`, `cbq-engine`, `indexer`,
/// `goxdcr`, `cbas`, `eventing-producer`/`eventing-consumer`) aren't
/// reliable: Couchbase is multi-service and a Data-only node runs none of
/// them. The processes present on every node (`beam.smp`, `memcached`) are
/// both generic and shared with unrelated software, so a process-name probe
/// risks false positives either way.
///
/// Instead this checks for `/opt/couchbase`, Couchbase's documented default
/// install path on every supported Linux RPM/DEB package. This only catches
/// the default install location — a custom `--install-dir` install won't be
/// detected.
const INSTALL_DIR: &str = "/opt/couchbase";

pub fn detect_couchbase(fs: &impl FileSystem) -> Option<&'static str> {
    fs.exists(INSTALL_DIR).then_some("caps/db/couchbase")
}

#[cfg(test)]
mod tests {
    use super::detect_couchbase;
    use crate::probes::util::filesystem::FakeFileSystem;

    #[test]
    fn detects_couchbase_when_install_dir_present() {
        let fs = FakeFileSystem(vec!["/opt/couchbase"]);
        assert_eq!(detect_couchbase(&fs), Some("caps/db/couchbase"));
    }

    #[test]
    fn no_detection_without_the_install_dir() {
        let fs = FakeFileSystem(vec![]);
        assert_eq!(detect_couchbase(&fs), None);
    }
}

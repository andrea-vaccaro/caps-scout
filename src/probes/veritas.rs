use super::util::filesystem::FileSystem;

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. Unlike a guess at the `had` cluster-engine
/// process (too short/generic — it substring-matches unrelated things like
/// `shadow`), this uses the exact signal Checkmk's own core agent relies
/// on: `agents/check_mk_agent.linux:1368` gates its Veritas Cluster Server
/// section on `[ -x /opt/VRTSvcs/bin/haclus ]`, i.e. that file existing and
/// being executable. This mirrors that check (existence only, not the
/// executable bit).
const HACLUS_PATH: &str = "/opt/VRTSvcs/bin/haclus";

pub fn detect_veritas(fs: &impl FileSystem) -> Option<&'static str> {
    fs.exists(HACLUS_PATH)
        .then_some("caps/cluster/veritas_cluster_server")
}

#[cfg(test)]
mod tests {
    use super::detect_veritas;
    use crate::probes::util::filesystem::FakeFileSystem;

    #[test]
    fn detects_veritas_when_haclus_present() {
        let fs = FakeFileSystem(vec!["/opt/VRTSvcs/bin/haclus"]);
        assert_eq!(
            detect_veritas(&fs),
            Some("caps/cluster/veritas_cluster_server")
        );
    }

    #[test]
    fn no_detection_without_haclus() {
        let fs = FakeFileSystem(vec![]);
        assert_eq!(detect_veritas(&fs), None);
    }
}

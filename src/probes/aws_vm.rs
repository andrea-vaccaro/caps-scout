use super::util::filesystem::FileSystem;

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. This detects "was this host provisioned by
/// AWS EC2" purely from local host state — no network call to the instance
/// metadata service, unlike Checkmk's own `aws` plugin family (which
/// requires API credentials and reports on AWS *resources*, not on the
/// underlying host itself).
///
/// Matches AWS's own documented, non-privileged detection method
/// (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/identify_ec2_instances.html):
/// on Nitro-based instances, `/sys/devices/virtual/dmi/id/board_asset_tag`
/// is populated with the instance ID (e.g. `i-0af01c0123456789a`), and is
/// world-readable — unlike `product_uuid`/`product_serial`, which are
/// root-only. This covers essentially all of today's EC2 fleet: AWS has
/// transparently migrated even legacy instance type names onto Nitro
/// hardware. The one documented, permanent exception is legacy GPU/FPGA
/// families (G2, G3, P2, P3, F1), which AWS states will never run on
/// Nitro and so won't be detected by this probe.
const BOARD_ASSET_TAG_PATH: &str = "/sys/devices/virtual/dmi/id/board_asset_tag";

pub fn detect_aws_vm(fs: &impl FileSystem) -> Option<&'static str> {
    let tag = fs.read_to_string(BOARD_ASSET_TAG_PATH)?;
    is_instance_id(tag.trim()).then_some("caps/cloud/aws-vm")
}

/// AWS instance IDs are `i-` followed by lowercase hex (8 hex digits in
/// legacy IDs, 17 in current ones) — matched loosely on shape rather than
/// a fixed length, since the exact length isn't guaranteed to stay fixed.
fn is_instance_id(value: &str) -> bool {
    value
        .strip_prefix("i-")
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::detect_aws_vm;
    use crate::probes::util::filesystem::FakeFileContents;

    const PATH: &str = "/sys/devices/virtual/dmi/id/board_asset_tag";

    #[test]
    fn detects_aws_vm_when_board_asset_tag_is_an_instance_id() {
        let fs = FakeFileContents(vec![(PATH, "i-0af01c0123456789a\n")]);
        assert_eq!(detect_aws_vm(&fs), Some("caps/cloud/aws-vm"));
    }

    #[test]
    fn detects_aws_vm_with_a_legacy_short_instance_id() {
        let fs = FakeFileContents(vec![(PATH, "i-1a2b3c4d")]);
        assert_eq!(detect_aws_vm(&fs), Some("caps/cloud/aws-vm"));
    }

    #[test]
    fn no_detection_when_board_asset_tag_is_not_specified() {
        let fs = FakeFileContents(vec![(PATH, "Not Specified")]);
        assert_eq!(detect_aws_vm(&fs), None);
    }

    #[test]
    fn no_detection_when_board_asset_tag_file_is_missing() {
        let fs = FakeFileContents(vec![]);
        assert_eq!(detect_aws_vm(&fs), None);
    }
}

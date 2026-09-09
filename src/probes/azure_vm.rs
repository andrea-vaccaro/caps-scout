use super::util::filesystem::FileSystem;

/// Scope and rationale are tracked in docs/checkmk-label-catalog.md and
/// docs/capability-coverage.md. This detects "was this host provisioned by
/// Azure" purely from local host state — no network call to the instance
/// metadata service, unlike Checkmk's own `azure`/`azure_v2` plugins
/// (which need API credentials and report on Azure-side resources, not on
/// the host itself). Same shape as `detect_aws_vm`.
///
/// Matches the exact check `cloud-init` itself uses
/// (`tools/ds-identify`, `is_azure_chassis()`, in
/// https://github.com/canonical/cloud-init): Azure hard-codes a fixed,
/// well-known value into every VM's DMI chassis asset tag (both Azure
/// public cloud and Azure Stack, the on-prem variant) —
/// `/sys/devices/virtual/dmi/id/chassis_asset_tag` equals exactly
/// `7783-7084-3265-9085-8269-3286-77`, unlike AWS's shape-matched (not
/// exact) instance ID. cloud-init also excludes containers here, since a
/// container inherits the host's DMI data rather than getting its own;
/// this probe doesn't — kept in parity with `detect_aws_vm`, which has the
/// same limitation.
const CHASSIS_ASSET_TAG_PATH: &str = "/sys/devices/virtual/dmi/id/chassis_asset_tag";
const AZURE_CHASSIS_ASSET_TAG: &str = "7783-7084-3265-9085-8269-3286-77";

pub fn detect_azure_vm(fs: &impl FileSystem) -> Option<&'static str> {
    let tag = fs.read_to_string(CHASSIS_ASSET_TAG_PATH)?;
    (tag.trim() == AZURE_CHASSIS_ASSET_TAG).then_some("caps/cloud/azure-vm")
}

#[cfg(test)]
mod tests {
    use super::detect_azure_vm;
    use crate::probes::util::filesystem::FakeFileContents;

    const PATH: &str = "/sys/devices/virtual/dmi/id/chassis_asset_tag";

    #[test]
    fn detects_azure_vm_when_chassis_asset_tag_matches() {
        let fs = FakeFileContents(vec![(PATH, "7783-7084-3265-9085-8269-3286-77\n")]);
        assert_eq!(detect_azure_vm(&fs), Some("caps/cloud/azure-vm"));
    }

    #[test]
    fn no_detection_when_chassis_asset_tag_differs() {
        let fs = FakeFileContents(vec![(PATH, "Not Specified")]);
        assert_eq!(detect_azure_vm(&fs), None);
    }

    #[test]
    fn no_detection_when_chassis_asset_tag_file_is_missing() {
        let fs = FakeFileContents(vec![]);
        assert_eq!(detect_azure_vm(&fs), None);
    }
}

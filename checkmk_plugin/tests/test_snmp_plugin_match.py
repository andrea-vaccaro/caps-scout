import sys
import unittest
from pathlib import Path

import _cmk_stub

_cmk_stub.install()

sys.path.insert(0, str(Path(__file__).parent.parent))

from cmk_addons.plugins.caps_scout.agent_based.snmp_plugin_match import (  # noqa: E402
    SysInfo,
    host_label_snmp_plugin_match,
    parse_snmp_plugin_match,
)


def _labels(sys_descr: str, sys_object_id: str) -> list[str]:
    section = SysInfo(sys_descr=sys_descr, sys_object_id=sys_object_id)
    return [label.name for label in host_label_snmp_plugin_match(section)]


class TestParseSnmpPluginMatch(unittest.TestCase):
    def test_none_for_empty_table(self):
        self.assertIsNone(parse_snmp_plugin_match([]))

    def test_parses_and_strips_the_single_row(self):
        result = parse_snmp_plugin_match([["  Cisco IOS  ", "  .1.3.6.1.4.1.9.1.516  "]])
        self.assertEqual(result, SysInfo(sys_descr="Cisco IOS", sys_object_id=".1.3.6.1.4.1.9.1.516"))


class TestHostLabelSnmpPluginMatch(unittest.TestCase):
    def test_no_labels_for_an_unmatched_device(self):
        self.assertEqual(_labels("Linux myhost 6.1.0", ".1.3.6.1.4.1.8072.3.2.10.99"), [])

    def test_cisco_matches_on_sysdescr_case_insensitively(self):
        self.assertEqual(
            _labels("CISCO IOS Software, C3560 Software", ".1.3.6.1.4.1.9.1.516"),
            ["caps/snmp_plugin/cisco"],
        )

    def test_juniper_matches_on_sysobjectid_prefix(self):
        self.assertEqual(
            _labels("Juniper Networks, Inc. ex2200", ".1.3.6.1.4.1.2636.1.1.1.2.57"),
            ["caps/snmp_plugin/juniper"],
        )

    def test_juniper_screenos_sub_line_is_not_covered(self):
        self.assertEqual(_labels("NetScreen", ".1.3.6.1.4.1.3224.1.1"), [])

    def test_fortigate_matches_on_sysobjectid_prefix(self):
        self.assertEqual(
            _labels("FortiGate-100E", ".1.3.6.1.4.1.12356.101.1.1"),
            ["caps/snmp_plugin/fortinet"],
        )

    def test_fortimail_matches_on_exact_sysobjectid(self):
        self.assertEqual(
            _labels("FortiMail-VM", ".1.3.6.1.4.1.12356.105"),
            ["caps/snmp_plugin/fortinet"],
        )

    def test_aruba_wlc_matches_on_sysobjectid_prefix(self):
        self.assertEqual(
            _labels("ArubaOS Mobility Controller", ".1.3.6.1.4.1.14823.1.1.3"),
            ["caps/snmp_plugin/aruba"],
        )

    def test_aruba_2930m_matches_on_sysdescr_pattern(self):
        self.assertEqual(
            _labels("Aruba JL256A 2930M-24G Switch", ".1.3.6.1.4.1.11.2.100"),
            ["caps/snmp_plugin/aruba"],
        )

    def test_aruba_other_switch_models_are_not_covered(self):
        self.assertEqual(_labels("Aruba 2540 24G Switch", ".1.3.6.1.4.1.11.2.100"), [])

    def test_hp_procurve_matches_either_enterprise_sub_branch(self):
        self.assertEqual(
            _labels("HP J9280A ProCurve Switch", ".1.3.6.1.4.1.11.2.3.7.11.13"),
            ["caps/snmp_plugin/hp_procurve"],
        )
        self.assertEqual(
            _labels("HP ProCurve Switch", ".1.3.6.1.4.1.11.2.3.7.8.1"),
            ["caps/snmp_plugin/hp_procurve"],
        )

    def test_checkpoint_matches_on_sysobjectid_prefix(self):
        self.assertEqual(
            _labels("Check Point Gaia", ".1.3.6.1.4.1.2620.1.1"),
            ["caps/snmp_plugin/checkpoint"],
        )

    def test_checkpoint_matches_ipso_sysdescr(self):
        self.assertEqual(
            _labels("IPSO some-model", ".1.3.6.1.4.1.99999"),
            ["caps/snmp_plugin/checkpoint"],
        )

    def test_palo_alto_matches_on_enterprise_number_anywhere_in_sysobjectid(self):
        self.assertEqual(
            _labels("Palo Alto Networks PA-220 series firewall", ".1.3.6.1.4.1.25461.2.3.1"),
            ["caps/snmp_plugin/palo_alto"],
        )

    def test_f5_bigip_matches_on_sysobjectid_prefix(self):
        self.assertEqual(
            _labels("BIG-IP 12.1.0", ".1.3.6.1.4.1.3375.2.1.3.4.20"),
            ["caps/snmp_plugin/f5_bigip"],
        )

    def test_multiple_families_can_match_simultaneously(self):
        # Not realistic for a real device, but the function shouldn't
        # short-circuit after the first match.
        labels = _labels("Aruba 2930M cisco", ".1.3.6.1.4.1.9.1.1")
        self.assertEqual(labels, ["caps/snmp_plugin/cisco", "caps/snmp_plugin/aruba"])


if __name__ == "__main__":
    unittest.main()

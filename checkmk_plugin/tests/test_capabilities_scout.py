import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import _cmk_stub

_cmk_stub.install()

sys.path.insert(0, str(Path(__file__).parent.parent))

from cmk.agent_based.v2 import State  # noqa: E402

from cmk_addons.plugins.caps_scout.agent_based.capabilities_scout import (  # noqa: E402
    DISPLAY_NAME_BY_LABEL,
    ICON_BY_LABEL,
    _TD_CAPABILITY_STYLE,
    _TD_RULES_STYLE,
    check_capabilities_scout,
    discover_capabilities_scout,
)
from cmk_addons.plugins.caps_scout.agent_based.snmp_plugin_match import (  # noqa: E402
    SysInfo,
    _FAMILY_DETECTORS,
)

CISCO_ASA_SYSINFO = SysInfo(
    sys_descr="Cisco Adaptive Security Appliance Version 9.9(2)61",
    sys_object_id=".1.3.6.1.4.1.9.1.1",
)


class TestDiscoverCapabilitiesScout(unittest.TestCase):
    def test_no_service_without_caps_labels(self):
        section = {"cmk/device_type": "vm"}
        self.assertEqual(list(discover_capabilities_scout(section, None)), [])

    def test_service_discovered_when_an_agent_caps_label_is_present(self):
        section = {"cmk/device_type": "vm", "caps/db/postgres": "yes"}
        services = list(discover_capabilities_scout(section, None))
        self.assertEqual(len(services), 1)

    def test_service_discovered_from_snmp_plugin_match_alone(self):
        services = list(discover_capabilities_scout(None, CISCO_ASA_SYSINFO))
        self.assertEqual(len(services), 1)

    def test_no_service_when_both_sections_are_absent(self):
        self.assertEqual(list(discover_capabilities_scout(None, None)), [])


class TestCheckCapabilitiesScout(unittest.TestCase):
    def test_ok_with_no_caps_labels(self):
        results = list(check_capabilities_scout({"cmk/device_type": "vm"}, None))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].state, State.OK)
        self.assertEqual(results[0].summary, "No caps-scout capabilities currently detected")

    def test_summary_lists_label_keys_sorted_and_ignores_non_caps_labels(self):
        section = {
            "cmk/device_type": "vm",
            "caps/web/apache": "yes",
            "caps/db/postgres": "yes",
        }
        [result] = check_capabilities_scout(section, None)
        self.assertEqual(result.state, State.OK)
        self.assertEqual(result.summary, "caps/db/postgres, caps/web/apache")

    def test_summary_includes_snmp_plugin_match_labels(self):
        section_labels = {"caps/db/oracle": "yes"}
        [result] = check_capabilities_scout(section_labels, CISCO_ASA_SYSINFO)
        self.assertEqual(result.summary, "caps/db/oracle, caps/snmp_plugin/cisco")

    def test_snmp_plugin_match_labels_alone_are_shown_without_an_agent_section(self):
        [result] = check_capabilities_scout(None, CISCO_ASA_SYSINFO)
        self.assertEqual(result.summary, "caps/snmp_plugin/cisco")

    def test_details_render_a_table_with_capability_and_rules_headers(self):
        section = {"caps/db/postgres": "yes"}
        [result] = check_capabilities_scout(section, None)
        self.assertIn("<table", result.details)
        self.assertIn(">Capability</th>", result.details)
        self.assertIn(">Rules</th>", result.details)

    def test_details_render_an_add_rule_chip_for_a_known_bakery_rule(self):
        section = {"caps/db/postgres": "yes"}
        [result] = check_capabilities_scout(section, None)
        self.assertIn("PostgreSQL", result.details)
        self.assertIn("<svg", result.details)
        self.assertIn(
            '<a href="wato.py?mode=new_rule&varname=agent_config:mk_postgres&_new_dflt_rule=1"',
            result.details,
        )
        self.assertIn("Add rule</a>", result.details)

    def test_details_show_the_confirmed_rule_title_next_to_its_chip(self):
        section = {"caps/db/postgres": "yes"}
        [result] = check_capabilities_scout(section, None)
        self.assertIn("PostgreSQL database and sessions (Linux, Windows)", result.details)
        # the raw varname should only appear inside the "Add rule" URL, not as a
        # separate visible label
        self.assertEqual(result.details.count("mk_postgres"), 1)

    def test_details_render_one_chip_per_rule_for_a_capability_with_two_rules(self):
        section = {"caps/db/oracle": "yes"}
        [result] = check_capabilities_scout(section, None)
        self.assertEqual(result.details.count("Add rule</a>"), 2)
        self.assertIn("Unified Oracle plug-in (beta)", result.details)
        self.assertIn("Oracle databases (Linux, Solaris, AIX, Windows)", result.details)
        self.assertIn(
            '<a href="wato.py?mode=new_rule&varname=agent_config:mk_oracle_unified&_new_dflt_rule=1"',
            result.details,
        )
        self.assertIn(
            '<a href="wato.py?mode=new_rule&varname=agent_config:mk_oracle&_new_dflt_rule=1"',
            result.details,
        )

    def test_details_fall_back_to_the_raw_varname_when_no_title_is_confirmed(self):
        section = {"caps/unmapped/widget": "yes"}
        with patch.dict(
            "cmk_addons.plugins.caps_scout.agent_based.capabilities_scout.BAKERY_RULES_BY_LABEL",
            {"caps/unmapped/widget": ("mk_not_yet_confirmed",)},
        ):
            [result] = check_capabilities_scout(section, None)
        self.assertIn("mk_not_yet_confirmed", result.details)
        self.assertIn("font-family:monospace", result.details)

    def test_details_separate_multiple_labels_into_their_own_rows(self):
        section = {"caps/web/apache": "yes", "caps/db/postgres": "yes"}
        [result] = check_capabilities_scout(section, None)
        # one header row plus one row per capability
        self.assertEqual(result.details.count("<tr"), 3)
        self.assertLess(
            result.details.index("PostgreSQL"), result.details.index("Apache HTTP Server")
        )

    def test_details_show_an_em_dash_for_a_label_without_a_known_bakery_rule(self):
        section = {"caps/unmapped/widget": "yes"}
        [result] = check_capabilities_scout(section, None)
        self.assertEqual(
            result.details,
            '<table style="border-collapse:collapse;width:100%;max-width:38em;">'
            '<tr><th style="border-bottom:1px solid rgba(128,128,128,0.35);text-align:left;'
            "padding:0 0 8px 0;font-size:0.8em;text-transform:uppercase;letter-spacing:0.04em;"
            'opacity:0.65;padding-right:1.5em;">Capability</th>'
            '<th style="border-bottom:1px solid rgba(128,128,128,0.35);text-align:left;'
            'padding:0 0 8px 0;font-size:0.8em;text-transform:uppercase;letter-spacing:0.04em;'
            'opacity:0.65;">Rules</th></tr>'
            f'<tr><td style="{_TD_CAPABILITY_STYLE}">caps/unmapped/widget</td>'
            f'<td style="{_TD_RULES_STYLE}"><span style="opacity:0.4;">&mdash;</span></td></tr>'
            "</table>",
        )

    def test_details_render_a_logo_and_em_dash_for_a_mapped_label_without_a_bakery_rule(self):
        section = {"caps/mq/mqtt": "yes"}
        [result] = check_capabilities_scout(section, None)
        self.assertIn("<svg", result.details)
        self.assertIn("MQTT (Mosquitto)", result.details)
        self.assertIn("&mdash;", result.details)
        self.assertNotIn("Add rule", result.details)

    def test_details_render_a_logo_for_an_snmp_plugin_match_label(self):
        [result] = check_capabilities_scout(None, CISCO_ASA_SYSINFO)
        self.assertIn("<svg", result.details)
        self.assertIn("Cisco", result.details)
        self.assertNotIn("caps/snmp_plugin/cisco", result.details)

    def test_details_show_an_em_dash_for_an_snmp_plugin_match_label(self):
        [result] = check_capabilities_scout(None, CISCO_ASA_SYSINFO)
        self.assertIn("&mdash;", result.details)
        self.assertNotIn("Add rule", result.details)

    def test_details_render_the_generic_network_glyph_for_snmp_families_with_no_brand_mark(self):
        section = {"caps/snmp_plugin/aruba": "yes", "caps/snmp_plugin/checkpoint": "yes"}
        [result] = check_capabilities_scout(section, None)
        self.assertIn("Aruba Networks", result.details)
        self.assertIn("Check Point", result.details)
        self.assertEqual(result.details.count("<svg"), 2)

    def test_details_show_the_raw_key_for_an_unrecognized_snmp_plugin_match_family(self):
        # aruba and checkpoint get the generic network glyph, not the raw key -
        # this guards the true no-icon-at-all fallback, using a label no ICON_BY_LABEL
        # entry will ever cover.
        section = {"caps/snmp_plugin/made_up_family": "yes"}
        [result] = check_capabilities_scout(section, None)
        self.assertIn("caps/snmp_plugin/made_up_family", result.details)
        self.assertNotIn("<svg", result.details)

    def test_details_render_a_real_brand_mark_for_huawei(self):
        section = {"caps/snmp_plugin/huawei": "yes"}
        [result] = check_capabilities_scout(section, None)
        self.assertIn("Huawei", result.details)
        self.assertIn("<svg", result.details)

    def test_details_render_a_company_mark_for_apc_via_schneider_electric(self):
        # APC (power/UPS/PDU vendor) was acquired by Schneider Electric in 2007 -
        # no dedicated APC mark exists in Simple Icons, so it reuses Schneider
        # Electric's, the same company-mark tier as Dell for EMC or NetApp for Decru.
        section = {"caps/snmp_plugin/apc": "yes"}
        [result] = check_capabilities_scout(section, None)
        self.assertIn("APC", result.details)
        self.assertIn("<svg", result.details)

    def test_details_render_a_generic_glyph_for_an_unbranded_sensor_vendor(self):
        section = {"caps/snmp_plugin/akcp": "yes"}
        [result] = check_capabilities_scout(section, None)
        self.assertIn("AKCP", result.details)
        self.assertIn("<svg", result.details)

    def test_every_snmp_plugin_match_family_has_a_display_name_and_icon(self):
        for family, _ in _FAMILY_DETECTORS:
            label = f"caps/snmp_plugin/{family}"
            self.assertIn(label, DISPLAY_NAME_BY_LABEL, f"missing display name for {family}")
            self.assertIn(label, ICON_BY_LABEL, f"missing icon for {family}")


if __name__ == "__main__":
    unittest.main()

import sys
import unittest
from pathlib import Path

import _cmk_stub

_cmk_stub.install()

sys.path.insert(0, str(Path(__file__).parent.parent))

from cmk.agent_based.v2 import State  # noqa: E402

from cmk_addons.plugins.caps_scout.agent_based.capabilities_scout import (  # noqa: E402
    check_capabilities_scout,
    discover_capabilities_scout,
)


class TestDiscoverCapabilitiesScout(unittest.TestCase):
    def test_no_service_without_caps_labels(self):
        section = {"cmk/device_type": "vm"}
        self.assertEqual(list(discover_capabilities_scout(section)), [])

    def test_service_discovered_when_a_caps_label_is_present(self):
        section = {"cmk/device_type": "vm", "caps/db/postgres": "yes"}
        services = list(discover_capabilities_scout(section))
        self.assertEqual(len(services), 1)


class TestCheckCapabilitiesScout(unittest.TestCase):
    def test_ok_with_no_caps_labels(self):
        results = list(check_capabilities_scout({"cmk/device_type": "vm"}))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].state, State.OK)
        self.assertEqual(results[0].summary, "No caps-scout capabilities currently detected")

    def test_summary_lists_label_keys_sorted_and_ignores_non_caps_labels(self):
        section = {
            "cmk/device_type": "vm",
            "caps/web/apache": "yes",
            "caps/db/postgres": "yes",
        }
        [result] = check_capabilities_scout(section)
        self.assertEqual(result.state, State.OK)
        self.assertEqual(result.summary, "caps/db/postgres, caps/web/apache")

    def test_details_render_an_add_rule_link_with_icon_for_a_known_bakery_rule(self):
        section = {"caps/db/postgres": "yes"}
        [result] = check_capabilities_scout(section)
        self.assertIn("• caps/db/postgres", result.details)
        self.assertIn(
            '<a href="wato.py?mode=new_rule&varname=agent_config:mk_postgres&_new_dflt_rule=1"',
            result.details,
        )
        self.assertIn("➕", result.details)
        self.assertIn("Add rule</a>", result.details)

    def test_details_separate_multiple_labels_into_their_own_rows(self):
        section = {"caps/web/apache": "yes", "caps/db/postgres": "yes"}
        [result] = check_capabilities_scout(section)
        self.assertEqual(result.details.count("<div"), 2)
        self.assertLess(
            result.details.index("caps/db/postgres"), result.details.index("caps/web/apache")
        )

    def test_details_have_a_plain_bullet_div_for_labels_without_a_known_bakery_rule(self):
        section = {"caps/mq/mqtt": "yes"}
        [result] = check_capabilities_scout(section)
        self.assertEqual(result.details, "<div>• caps/mq/mqtt</div>")


if __name__ == "__main__":
    unittest.main()

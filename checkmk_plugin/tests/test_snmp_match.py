import sys
import unittest
from pathlib import Path

import _cmk_stub

_cmk_stub.install()

sys.path.insert(0, str(Path(__file__).parent.parent))

from cmk_addons.plugins.caps_scout.agent_based.snmp_match import (  # noqa: E402
    SysInfo,
    host_label_snmp_match,
    parse_snmp_match,
)


def _labels(sys_descr: str, sys_object_id: str) -> list[str]:
    section = SysInfo(sys_descr=sys_descr, sys_object_id=sys_object_id)
    return [label.name for label in host_label_snmp_match(section)]


class TestParseSnmpMatch(unittest.TestCase):
    def test_none_for_empty_table(self):
        self.assertIsNone(parse_snmp_match([]))

    def test_parses_and_strips_the_single_row(self):
        result = parse_snmp_match([["  Cisco IOS  ", "  .1.3.6.1.4.1.9.1.516  "]])
        self.assertEqual(result, SysInfo(sys_descr="Cisco IOS", sys_object_id=".1.3.6.1.4.1.9.1.516"))


class TestHostLabelSnmpMatch(unittest.TestCase):
    def test_no_labels_for_an_unmatched_device(self):
        self.assertEqual(_labels("Linux myhost 6.1.0", ".1.3.6.1.4.1.8072.3.2.10.99"), [])

    def test_cisco_matches_on_sysdescr_case_insensitively(self):
        self.assertEqual(
            _labels("CISCO IOS Software, C3560 Software", ".1.3.6.1.4.1.9.1.516"),
            ["caps/snmp/cisco"],
        )

    def test_juniper_matches_on_sysobjectid_prefix(self):
        self.assertEqual(
            _labels("Juniper Networks, Inc. ex2200", ".1.3.6.1.4.1.2636.1.1.1.2.57"),
            ["caps/snmp/juniper"],
        )

    def test_juniper_screenos_sub_line_now_matches(self):
        # Previously an explicit gap (see the old docstring); the juniper
        # detector was extended to close it.
        self.assertEqual(
            _labels("NetScreen", ".1.3.6.1.4.1.3224.1.1"),
            ["caps/snmp/juniper"],
        )

    def test_juniper_trpz_sub_line_matches(self):
        self.assertEqual(
            _labels("Trapeze Networks MX-8", ".1.3.6.1.4.1.14525.3.1"),
            ["caps/snmp/juniper"],
        )

    def test_fortigate_matches_on_sysobjectid_prefix(self):
        self.assertEqual(
            _labels("FortiGate-100E", ".1.3.6.1.4.1.12356.101.1.1"),
            ["caps/snmp/fortinet"],
        )

    def test_fortimail_matches_on_exact_sysobjectid(self):
        self.assertEqual(
            _labels("FortiMail-VM", ".1.3.6.1.4.1.12356.105"),
            ["caps/snmp/fortinet"],
        )

    def test_aruba_wlc_matches_on_sysobjectid_prefix(self):
        self.assertEqual(
            _labels("ArubaOS Mobility Controller", ".1.3.6.1.4.1.14823.1.1.3"),
            ["caps/snmp/aruba"],
        )

    def test_aruba_2930m_matches_on_sysdescr_pattern(self):
        self.assertEqual(
            _labels("Aruba JL256A 2930M-24G Switch", ".1.3.6.1.4.1.11.2.100"),
            ["caps/snmp/aruba"],
        )

    def test_aruba_other_switch_models_are_not_covered(self):
        self.assertEqual(_labels("Aruba 2540 24G Switch", ".1.3.6.1.4.1.11.2.100"), [])

    def test_hp_procurve_matches_either_enterprise_sub_branch(self):
        self.assertEqual(
            _labels("HP J9280A ProCurve Switch", ".1.3.6.1.4.1.11.2.3.7.11.13"),
            ["caps/snmp/hp_procurve"],
        )
        self.assertEqual(
            _labels("HP ProCurve Switch", ".1.3.6.1.4.1.11.2.3.7.8.1"),
            ["caps/snmp/hp_procurve"],
        )

    def test_checkpoint_matches_on_sysobjectid_prefix(self):
        self.assertEqual(
            _labels("Check Point Gaia", ".1.3.6.1.4.1.2620.1.1"),
            ["caps/snmp/checkpoint"],
        )

    def test_checkpoint_matches_ipso_sysdescr(self):
        self.assertEqual(
            _labels("IPSO some-model", ".1.3.6.1.4.1.99999"),
            ["caps/snmp/checkpoint"],
        )

    def test_palo_alto_matches_on_enterprise_number_anywhere_in_sysobjectid(self):
        self.assertEqual(
            _labels("Palo Alto Networks PA-220 series firewall", ".1.3.6.1.4.1.25461.2.3.1"),
            ["caps/snmp/palo_alto"],
        )

    def test_f5_bigip_matches_on_sysobjectid_prefix(self):
        self.assertEqual(
            _labels("BIG-IP 12.1.0", ".1.3.6.1.4.1.3375.2.1.3.4.20"),
            ["caps/snmp/f5_bigip"],
        )

    def test_acme_matches(self):
        self.assertIn(
            "caps/snmp/acme",
            _labels('Generic Test Device', '.1.3.6.1.4.1.9148'),
        )

    def test_adva_matches(self):
        self.assertIn(
            "caps/snmp/adva",
            _labels('Fiber Service Platform F7', '.9.9.9.9.9.9'),
        )

    def test_akcp_matches(self):
        self.assertIn(
            "caps/snmp/akcp",
            _labels('Generic Test Device', '.1.3.6.1.4.1.3854.1'),
        )

    def test_alcatel_matches(self):
        self.assertIn(
            "caps/snmp/alcatel",
            _labels('Generic Test Device', '.1.3.6.1.4.1.6486.801'),
        )

    def test_apc_matches(self):
        self.assertIn(
            "caps/snmp/apc",
            _labels('apc', '.9.9.9.9.9.9'),
        )

    def test_arbor_matches(self):
        self.assertIn(
            "caps/snmp/arbor",
            _labels('Peakflow', '.9.9.9.9.9.9'),
        )

    def test_arris_matches(self):
        self.assertIn(
            "caps/snmp/arris",
            _labels('Generic Test Device', '.1.3.6.1.4.1.4998.2.1'),
        )

    def test_atto_matches(self):
        self.assertIn(
            "caps/snmp/atto",
            _labels('Generic Test Device', '.1.3.6.1.4.1.4547'),
        )

    def test_audiocodes_matches(self):
        self.assertIn(
            "caps/snmp/audiocodes",
            _labels('Generic Test Device', '.1.3.6.1.4.1.5003.8.1.1'),
        )

    def test_avaya_matches(self):
        self.assertIn(
            "caps/snmp/avaya",
            _labels('Generic Test Device', '.1.3.6.1.4.1.2272'),
        )

    def test_barracuda_matches(self):
        self.assertIn(
            "caps/snmp/barracuda",
            _labels('barracuda', '.1.3.6.1.4.1.8072.3.2.10'),
        )

    def test_bintec_matches(self):
        self.assertIn(
            "caps/snmp/bintec",
            _labels('Generic Test Device', '.1.3.6.1.4.1.272.4'),
        )

    def test_blade_matches(self):
        self.assertIn(
            "caps/snmp/blade",
            _labels('bx600', '.9.9.9.9.9.9'),
        )

    def test_bluecat_matches(self):
        self.assertIn(
            "caps/snmp/bluecat",
            _labels('Generic Test Device', '.1.3.6.1.4.1.13315.2.1'),
        )

    def test_bluecoat_matches(self):
        self.assertIn(
            "caps/snmp/bluecoat",
            _labels('Generic Test Device', '1.3.6.1.4.1.3417.1.1'),
        )

    def test_brocade_matches(self):
        self.assertIn(
            "caps/snmp/brocade",
            _labels('Generic Test Device', '.1.3.6.1.4.1.1588.2.1.1'),
        )

    def test_bvip_matches(self):
        self.assertIn(
            "caps/snmp/bvip",
            _labels('flexidome', '.9.9.9.9.9.9'),
        )

    def test_casa_matches(self):
        self.assertIn(
            "caps/snmp/casa",
            _labels('Generic Test Device', '.1.3.6.1.4.1.20858.2.'),
        )

    def test_ciena_ces_matches(self):
        self.assertIn(
            "caps/snmp/ciena_ces",
            _labels('Generic Test Device', '.1.3.6.1.4.1.1271.1.2.11'),
        )

    def test_datapower_matches(self):
        self.assertIn(
            "caps/snmp/datapower",
            _labels('Generic Test Device', '.1.3.6.1.4.1.14685.1.8'),
        )

    def test_decru_matches(self):
        self.assertIn(
            "caps/snmp/decru",
            _labels('datafort', '.9.9.9.9.9.9'),
        )

    def test_didactum_matches(self):
        self.assertIn(
            "caps/snmp/didactum",
            _labels('didactum', '.9.9.9.9.9.9'),
        )

    def test_docsis_matches(self):
        self.assertIn(
            "caps/snmp/docsis",
            _labels('Generic Test Device', '.1.3.6.1.4.1.4115.820.1.0.0.0.0.0'),
        )

    def test_eltek_matches(self):
        self.assertIn(
            "caps/snmp/eltek",
            _labels('Generic Test Device', '.1.3.6.1.4.1.12148.9'),
        )

    def test_emc_matches(self):
        self.assertIn(
            "caps/snmp/emc",
            _labels('isilon', '.9.9.9.9.9.9'),
        )

    def test_enterasys_matches(self):
        self.assertIn(
            "caps/snmp/enterasys",
            _labels('Generic Test Device', '.1.3.6.1.4.1.5624.2.1'),
        )

    def test_enviromux_matches(self):
        self.assertIn(
            "caps/snmp/enviromux",
            _labels('Generic Test Device', '.1.3.6.1.4.1.3699.1.1.11'),
        )

    def test_epson_matches(self):
        self.assertIn(
            "caps/snmp/epson",
            _labels('Generic Test Device', '1248'),
        )

    def test_fireeye_matches(self):
        self.assertIn(
            "caps/snmp/fireeye",
            _labels('Generic Test Device', '.1.3.6.1.4.1.25597.1'),
        )

    def test_fjdarye_matches(self):
        self.assertIn(
            "caps/snmp/fjdarye",
            _labels('Generic Test Device', '.1.3.6.1.4.1.211.1.21.1.60'),
        )

    def test_genua_matches(self):
        self.assertIn(
            "caps/snmp/genua",
            _labels('genuscreen', '.9.9.9.9.9.9'),
        )

    def test_gude_matches(self):
        self.assertIn(
            "caps/snmp/gude",
            _labels('Generic Test Device', '.1.3.6.1.4.1.28507'),
        )

    def test_h3c_matches(self):
        self.assertIn(
            "caps/snmp/h3c",
            _labels('3com s', '.9.9.9.9.9.9'),
        )

    def test_hitachi_matches(self):
        self.assertIn(
            "caps/snmp/hitachi",
            _labels('Generic Test Device', '.1.3.6.1.4.1.116'),
        )

    def test_hitachi_hnas_matches(self):
        self.assertIn(
            "caps/snmp/hitachi_hnas",
            _labels('Generic Test Device', '.1.3.6.1.4.1.11096.6'),
        )

    def test_hp_matches(self):
        self.assertIn(
            "caps/snmp/hp",
            _labels('Generic Test Device', '.1.3.6.1.4.1.11.10.2.1.3.20'),
        )

    def test_hp_blade_matches(self):
        self.assertIn(
            "caps/snmp/hp_blade",
            _labels('Generic Test Device', '.11.5.7.1.2'),
        )

    def test_hpux_matches(self):
        self.assertIn(
            "caps/snmp/hpux",
            _labels('HP-UX', '.9.9.9.9.9.9'),
        )

    def test_huawei_matches(self):
        self.assertIn(
            "caps/snmp/huawei",
            _labels('Generic Test Device', '.1.3.6.1.4.1.2011.2.23'),
        )

    def test_hwg_matches(self):
        self.assertIn(
            "caps/snmp/hwg",
            _labels('hwg', '.9.9.9.9.9.9'),
        )

    def test_icom_matches(self):
        self.assertIn(
            "caps/snmp/icom",
            _labels('fr5000', '.9.9.9.9.9.9'),
        )

    def test_infoblox_matches(self):
        self.assertIn(
            "caps/snmp/infoblox",
            _labels('infoblox', '.9.9.9.9.9.9'),
        )

    def test_innovaphone_matches(self):
        self.assertIn(
            "caps/snmp/innovaphone",
            _labels('Generic Test Device', '.1.3.6.1.4.1.6666'),
        )

    def test_intel_true_scale_matches(self):
        self.assertIn(
            "caps/snmp/intel_true_scale",
            _labels('Generic Test Device', '.1.3.6.1.4.1.10222'),
        )

    def test_ispro_matches(self):
        self.assertIn(
            "caps/snmp/ispro",
            _labels('Generic Test Device', '.1.3.6.1.4.1.19011.1.3.2'),
        )

    def test_janitza_matches(self):
        self.assertIn(
            "caps/snmp/janitza",
            _labels('Generic Test Device', '.1.3.6.1.4.1.34278.8.6'),
        )

    def test_kemp_loadmaster_matches(self):
        self.assertIn(
            "caps/snmp/kemp_loadmaster",
            _labels('Generic Test Device', '.1.3.6.1.4.1.12196.250.10'),
        )

    def test_kentix_matches(self):
        self.assertIn(
            "caps/snmp/kentix",
            _labels('Generic Test Device', '.1.3.6.1.4.1.332.11.6'),
        )

    def test_knuerr_matches(self):
        self.assertIn(
            "caps/snmp/knuerr",
            _labels('Generic Test Device', '.1.3.6.1.4.1.3711.15.1'),
        )

    def test_kyocera_matches(self):
        self.assertIn(
            "caps/snmp/kyocera",
            _labels('kyocera', '.9.9.9.9.9.9'),
        )

    def test_lgp_matches(self):
        self.assertIn(
            "caps/snmp/lgp",
            _labels('Generic Test Device', '.1.3.6.1.4.1.476.1.42'),
        )

    def test_liebert_matches(self):
        self.assertIn(
            "caps/snmp/liebert",
            _labels('Generic Test Device', '.1.3.6.1.4.1.476.1.42'),
        )

    def test_mcafee_matches(self):
        self.assertIn(
            "caps/snmp/mcafee",
            _labels('mcafee email gateway', '.9.9.9.9.9.9'),
        )

    def test_meinberg_matches(self):
        self.assertIn(
            "caps/snmp/meinberg",
            _labels('Generic Test Device', '.1.3.6.1.4.1.5597.3'),
        )

    def test_meraki_matches(self):
        self.assertIn(
            "caps/snmp/meraki",
            _labels('Generic Test Device', '.1.3.6.1.4.1.29671'),
        )

    def test_mikrotik_matches(self):
        self.assertIn(
            "caps/snmp/mikrotik",
            _labels('Generic Test Device', '.1.3.6.1.4.1.14988.1'),
        )

    def test_moxa_matches(self):
        self.assertIn(
            "caps/snmp/moxa",
            _labels('Generic Test Device', '.1.3.6.1.4.1.8691.'),
        )

    def test_netextreme_matches(self):
        self.assertIn(
            "caps/snmp/netextreme",
            _labels('Generic Test Device', '.1.3.6.1.4.1.1916.2'),
        )

    def test_netgear_matches(self):
        self.assertIn(
            "caps/snmp/netgear",
            _labels('Generic Test Device', '.1.3.6.1.4.1.4526.100'),
        )

    def test_netscaler_matches(self):
        self.assertIn(
            "caps/snmp/netscaler",
            _labels('Generic Test Device', '.1.3.6.1.4.1.5951.1'),
        )

    def test_nimble_matches(self):
        self.assertIn(
            "caps/snmp/nimble",
            _labels('Generic Test Device', '.1.3.6.1.4.1.37447.3.1'),
        )

    def test_pandacom_matches(self):
        self.assertIn(
            "caps/snmp/pandacom",
            _labels('Generic Test Device', '.1.3.6.1.4.1.3652.3'),
        )

    def test_papouch_matches(self):
        self.assertIn(
            "caps/snmp/papouch",
            _labels('th2e', '.0.10.43.6.1.4.1'),
        )

    def test_perle_matches(self):
        self.assertIn(
            "caps/snmp/perle",
            _labels('Generic Test Device', '.1.3.6.1.4.1.1966.20'),
        )

    def test_pfsense_matches(self):
        self.assertIn(
            "caps/snmp/pfsense",
            _labels('pfsense', '.9.9.9.9.9.9'),
        )

    def test_poseidon_matches(self):
        self.assertIn(
            "caps/snmp/poseidon",
            _labels('Generic Test Device', '.1.3.6.1.4.1.21796.3'),
        )

    def test_printer_matches(self):
        self.assertIn(
            "caps/snmp/printer",
            _labels('canon', '.9.9.9.9.9.9'),
        )

    def test_pulse_secure_matches(self):
        self.assertIn(
            "caps/snmp/pulse_secure",
            _labels('Generic Test Device', '.1.3.6.1.4.1.12532'),
        )

    def test_qlogic_matches(self):
        self.assertIn(
            "caps/snmp/qlogic",
            _labels('Generic Test Device', '.1.3.6.1.4.1.3873'),
        )

    def test_qnap_matches(self):
        self.assertIn(
            "caps/snmp/qnap",
            _labels('Linux TS-', '.9.9.9.9.9.9'),
        )

    def test_raritan_matches(self):
        self.assertIn(
            "caps/snmp/raritan",
            _labels('Generic Test Device', '.1.3.6.1.4.1.13742.6'),
        )

    def test_rittal_matches(self):
        self.assertIn(
            "caps/snmp/rittal",
            _labels('Rittal LCP', '.9.9.9.9.9.9'),
        )

    def test_roomalert_matches(self):
        self.assertIn(
            "caps/snmp/roomalert",
            _labels('Generic Test Device', '1.3.6.1.4.1.20916.1.8'),
        )

    def test_safenet_matches(self):
        self.assertIn(
            "caps/snmp/safenet",
            _labels('Generic Test Device', '.1.3.6.1.4.1.12383'),
        )

    def test_sentry_matches(self):
        self.assertIn(
            "caps/snmp/sentry",
            _labels('Generic Test Device', '.1.3.6.1.4.1.1718.3'),
        )

    def test_silverpeak_matches(self):
        self.assertIn(
            "caps/snmp/silverpeak",
            _labels('Generic Test Device', '.1.3.6.1.4.1.23867'),
        )

    def test_sni_octopuse_matches(self):
        self.assertIn(
            "caps/snmp/sni_octopuse",
            _labels('agent for hipath', '.9.9.9.9.9.9'),
        )

    def test_sophos_matches(self):
        self.assertIn(
            "caps/snmp/sophos",
            _labels('Generic Test Device', '.1.3.6.1.4.1.21067.2'),
        )

    def test_steelhead_matches(self):
        self.assertIn(
            "caps/snmp/steelhead",
            _labels('Generic Test Device', '.1.3.6.1.4.1.17163.'),
        )

    def test_teracom_matches(self):
        self.assertIn(
            "caps/snmp/teracom",
            _labels('teracom', '.9.9.9.9.9.9'),
        )

    def test_ups_matches(self):
        self.assertIn(
            "caps/snmp/ups",
            _labels('Generic Test Device', '.1.3.6.1.4.1.232.165.3'),
        )

    def test_vutlan_matches(self):
        self.assertIn(
            "caps/snmp/vutlan",
            _labels('vutlan ems', '.9.9.9.9.9.9'),
        )

    def test_wagner_matches(self):
        self.assertIn(
            "caps/snmp/wagner",
            _labels('Generic Test Device', '.1.3.6.1.4.1.34187.21501'),
        )

    def test_watchdog_matches(self):
        self.assertIn(
            "caps/snmp/watchdog",
            _labels('Generic Test Device', '.1.3.6.1.4.1.21239.5.1'),
        )

    def test_wut_matches(self):
        self.assertIn(
            "caps/snmp/wut",
            _labels('Generic Test Device', '.1.3.6.1.4.1.5040'),
        )

    def test_zebra_matches(self):
        self.assertIn(
            "caps/snmp/zebra",
            _labels('zebra', '.9.9.9.9.9.9'),
        )

    def test_bdt_tape_matches(self):
        self.assertIn(
            "caps/snmp/bdt_tape",
            _labels("BDT tape library", ".1.3.6.1.4.1.20884.77.83.1.2"),
        )

    def test_bluenet_matches(self):
        self.assertIn(
            "caps/snmp/bluenet",
            _labels("BlueNET PDU", ".1.3.6.1.4.1.21695.1.1"),
        )

    def test_cbl_matches(self):
        self.assertIn(
            "caps/snmp/cbl",
            _labels("CBL AirLaser device", ".1.3.6.1.4.1.2800.2.1.1"),
        )

    def test_cisco_sma_matches(self):
        self.assertIn(
            "caps/snmp/cisco_sma",
            _labels("Cisco Secure Email Manager", ".1.3.6.1.4.1.15497.1.1"),
        )

    def test_climaveneta_matches(self):
        self.assertIn(
            "caps/snmp/climaveneta",
            _labels("pCO Gateway", ".1.3.6.1.4.1.9839.1.1"),
        )

    def test_cpsecure_matches(self):
        self.assertIn(
            "caps/snmp/cpsecure",
            _labels("CoreProcess Secure appliance", ".1.3.6.1.4.1.26546.1.1.2"),
        )

    def test_netapp_matches(self):
        self.assertIn(
            "caps/snmp/netapp",
            _labels("NetApp Release ONTAP 9.10", ".1.3.6.1.4.1.789.1.1"),
        )

    def test_emka_matches(self):
        self.assertIn(
            "caps/snmp/emka",
            _labels("EMKA enclosure monitor", ".1.3.6.1.4.1.13595.1.1"),
        )

    def test_ewon_matches(self):
        self.assertIn(
            "caps/snmp/ewon",
            _labels("eWON industrial router", ".1.3.6.1.4.1.8284.2.1"),
        )

    def test_f5os_rseries_matches(self):
        self.assertIn(
            "caps/snmp/f5os_rseries",
            _labels("F5OS rSeries platform", ".1.3.6.1.4.1.12276.1.3.1"),
        )

    def test_hepta_matches(self):
        self.assertIn(
            "caps/snmp/hepta",
            _labels("Hepta power device", ".1.3.6.1.4.1.12527.1.1"),
        )

    def test_hp_hh3c_matches(self):
        self.assertIn(
            "caps/snmp/hp_hh3c",
            _labels("HPE H3C switch", ".1.3.6.1.4.1.25506.1.1"),
        )

    def test_hp_mcs_matches(self):
        self.assertIn(
            "caps/snmp/hp_mcs",
            _labels("HP Modular Cooling System", ".1.3.6.1.4.1.232.167.1"),
        )

    def test_infratec_plus_matches(self):
        self.assertIn(
            "caps/snmp/infratec_plus",
            _labels("Infratec Plus RMS200", ".1.3.6.1.4.1.1909.13"),
        )

    def test_ipr400_matches(self):
        self.assertIn(
            "caps/snmp/ipr400",
            _labels("IPR VoIP Device IPR400", ".1.3.6.1.4.1.10000.1.1"),
        )

    def test_orion_matches(self):
        self.assertIn(
            "caps/snmp/orion",
            _labels("Orion UPS system", ".1.3.6.1.4.1.20246.1.1"),
        )

    def test_packeteer_matches(self):
        self.assertIn(
            "caps/snmp/packeteer",
            _labels("Packeteer PacketShaper", ".1.3.6.1.4.1.2334.1.1"),
        )

    def test_seh_matches(self):
        self.assertIn(
            "caps/snmp/seh",
            _labels("SEH PSrv print server", ".1.3.6.1.4.1.1229.1.1.1"),
        )

    def test_sensatronics_matches(self):
        self.assertIn(
            "caps/snmp/sensatronics",
            _labels("Sensatronics sensor", ".1.3.6.1.4.1.16174.1.1.1"),
        )

    def test_strem1_matches(self):
        self.assertIn(
            "caps/snmp/strem1",
            _labels("Sensatronics EM1", ".1.3.6.1.4.1.99999.1.1"),
        )

    def test_superstack3_matches(self):
        self.assertIn(
            "caps/snmp/superstack3",
            _labels("3Com SuperStack 3 Switch", ".1.3.6.1.4.1.43.1.1"),
        )

    def test_sym_brightmail_matches(self):
        self.assertIn(
            "caps/snmp/sym_brightmail",
            _labels("Linux el6 brightmail gateway", ".1.3.6.1.4.1.99999.1.1"),
        )

    def test_arista_matches(self):
        self.assertIn(
            "caps/snmp/arista",
            _labels("Arista Networks EOS", ".1.3.6.1.4.1.30065.1.1"),
        )

    def test_multiple_families_can_match_simultaneously(self):
        # Not realistic for a real device, but the function shouldn't
        # short-circuit after the first match.
        labels = _labels("Aruba 2930M cisco", ".1.3.6.1.4.1.9.1.1")
        self.assertEqual(labels, ["caps/snmp/cisco", "caps/snmp/aruba"])


if __name__ == "__main__":
    unittest.main()

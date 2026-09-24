#!/usr/bin/env python3
# Part of caps-scout (https://github.com/andrea-vaccaro/caps-scout) - License: GNU General Public License v2

"""caps-scout SNMP plugin-match labels.

Like `checkmk_plugin`'s other half, this runs Checkmk-side as a regular
`agent_based` plugin: Checkmk's core fetches the data itself, using whatever
the host's own "SNMP credentials" rule already configures. No credentials
are entered or stored here.

Rather than dumping the device's raw SNMP capability table (an earlier
version of this plugin did that via sysORTable - too free-form to act on),
this answers a more directly useful question: *which of Checkmk's own
SNMP-monitored device plugin families would actually attach to this host*,
so the label points straight at a plugin the user might go activate.

Checkmk ships such families under `cmk/plugins/<family>/`, each deciding
whether one of its own check plugins applies to a scanned device via a
`detect=` scan spec - almost always built from `sysDescr`
(`.1.3.6.1.2.1.1.1.0`) and/or `sysObjectID` (`.1.3.6.1.2.1.1.2.0`), the same
two System-group scalars `cmk/plugins/network/agent_based/snmp_info.py`
already fetches for its own `cmk/device_type` label. An exhaustive pass over
every one of the 279 real directories under `cmk/plugins/` (a naive
`ls cmk/plugins | wc -l` gives 281, but two entries, `BUILD` and `OWNERS`,
are not plugin directories at all) settled the full picture:

- **117** are covered below (cisco, juniper, fortinet, aruba, hp_procurve,
  checkpoint, palo_alto, f5_bigip, and many more).
- **139** have no SNMP `detect=`/`DETECT_*` condition anywhere at all -
  special agents, agent-section-only plugins that parse the *agent's* own
  stdout, or shared library/support code - confirmed out of scope, not just
  unresearched.
- **22** were researched and deliberately excluded because their real
  Checkmk condition isn't meaningfully expressible via sysDescr/sysObjectID
  alone - either it depends entirely on a third, unrelated OID this plugin
  doesn't fetch (`hp_proliant`, `oracle_snmp`'s Oracle DIVA CSM check,
  `supermicro`, `etherbox2`, `emerson`, `hr`'s HOST-RESOURCES-MIB probe,
  `poe`'s POWER-ETHERNET-MIB probe, `openbsd`), or the only
  sysDescr/sysObjectID-only remainder left after dropping an `exists()` half
  is too generic to mean anything - a bare "contains linux"/"starts with
  Linux" (`keepalived`, `entersekt`, `synology`) or the shared generic
  net-snmp enterprise OID with no vendor narrowing at all (`quantum`,
  `fujitsu`, `primekey`, `quanta`, `stormshield`, `domino`, `fast_lta`,
  `artec` - the last one also ANDs in sysDescr containing "version" and
  "serial", still too common to mean anything), or it's redundant with/too
  broad next to an already-covered family (`rmon`, `carel` next to the
  `climaveneta` family below); shipping those would have this plugin claim a
  specific vendor's device on essentially any generic Linux/Windows/net-snmp
  host, which is worse than not labeling it at all. One more, `zertificon`,
  is excluded for a different reason: its cited condition is
  `exists(sysDescr) AND not_exists(sysDescr)` on the same OID - logically
  impossible, so there was nothing to replicate at all.
- **1** (`security_master`) is left unresolved: its cited source,
  `detect=startswith(".1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.35491")`, is missing
  the leading `.` every real sysObjectID value has, so as literally written
  it looks like an upstream Checkmk bug that can never match anything -
  faithfully copying it would add a family that silently never fires, and
  "fixing" it would mean deviating from the cited source, so it's deferred
  pending a decision either way.

For each family that *is* included, this plugin replicates the exact
condition that family's own `lib.py` (or, for some, an inline `detect=` in a
check file) uses, cited per function below. Where a family's real condition
also ANDs in a second, vendor-specific OID beyond sysDescr/sysObjectID, that
second condition is dropped here rather than adding a per-vendor SNMP fetch
tree just for it - noted per function, since it makes this plugin's match
slightly more permissive than the real one for those families.

Checkmk's own `contains`/`startswith`/`equals`/`matches` detect helpers
build a regex evaluated with
`re.fullmatch(pattern, value, re.IGNORECASE | re.DOTALL)`
(`packages/cmk-plugin-apis/cmk/agent_based/internal/_snmp.py`) - i.e.
case-insensitive substring/prefix/exact/regex matching. `_contains`/
`_startswith`/`_equals`/`_matches` below replicate that exactly, operating
directly on the two already-fetched strings instead of building a detect
spec for Checkmk's own scan phase to evaluate.

`detect` gates on the scalar `sysDescr` itself (any SNMP host has it); an
empty/missing System group means `parse_function` returns `None` and no
labels are emitted.
"""

import re
from collections.abc import Callable, Sequence
from typing import NamedTuple

from cmk.agent_based.v2 import (
    exists,
    HostLabel,
    HostLabelGenerator,
    SimpleSNMPSection,
    SNMPTree,
    StringTable,
)

HAS_SYSDESC = exists(".1.3.6.1.2.1.1.1.0")


class SysInfo(NamedTuple):
    sys_descr: str
    sys_object_id: str


def _contains(value: str, substring: str) -> bool:
    return substring.lower() in value.lower()


def _startswith(value: str, prefix: str) -> bool:
    return value.lower().startswith(prefix.lower())


def _equals(value: str, expected: str) -> bool:
    return value.lower() == expected.lower()


def _matches(value: str, pattern: str) -> bool:
    return re.fullmatch(pattern, value, re.IGNORECASE | re.DOTALL) is not None


def _is_cisco(sys: SysInfo) -> bool:
    """cmk/plugins/cisco/lib.py:8 - DETECT_CISCO."""
    return _contains(sys.sys_descr, "cisco")


def _is_juniper(sys: SysInfo) -> bool:
    """cmk/plugins/juniper/lib.py:8,10,12 - DETECT_JUNIPER (general Junos),
    DETECT_JUNIPER_TRPZ (legacy Trapeze wifi), DETECT_JUNIPER_SCREENOS
    (ScreenOS/NetScreen) - all three sub-lines, closing the gap the previous
    version of this function's docstring flagged as not included."""
    return (
        _startswith(sys.sys_object_id, ".1.3.6.1.4.1.2636.1.1.1")
        or _startswith(sys.sys_object_id, ".1.3.6.1.4.1.14525.3")
        or _startswith(sys.sys_object_id, ".1.3.6.1.4.1.3224.1")
    )


# ---- new families ----


def _is_fortinet(sys: SysInfo) -> bool:
    """cmk/plugins/fortinet/lib.py:8-14 - OR of every product-specific
    detect the family's own checks use: DETECT_FORTIGATE, DETECT_FORTIMAIL,
    DETECT_FORTISANDBOX, DETECT_FORTIAUTHENTICATOR."""
    return (
        _startswith(sys.sys_object_id, ".1.3.6.1.4.1.12356.101.1.")  # FortiGate
        or _equals(sys.sys_object_id, ".1.3.6.1.4.1.12356.105")  # FortiMail
        or _startswith(sys.sys_object_id, ".1.3.6.1.4.1.12356.118.1.")  # FortiSandbox
        or _equals(sys.sys_object_id, ".1.3.6.1.4.1.8072.3.2.10")  # FortiAuthenticator
        or _startswith(sys.sys_object_id, ".1.3.6.1.4.1.12356.113.")  # FortiAuthenticator
    )


def _is_aruba(sys: SysInfo) -> bool:
    """cmk/plugins/aruba/lib.py:8-9 - OR of DETECT_2930M (one specific
    switch model, via sysDescr) and DETECT_WLC (wireless LAN controllers,
    via sysObjectID). The family's checks only cover these two product
    lines, not Aruba's full catalog."""
    return _matches(sys.sys_descr, "Aruba.+2930M.*") or _startswith(
        sys.sys_object_id, ".1.3.6.1.4.1.14823.1.1"
    )


def _is_hp_procurve(sys: SysInfo) -> bool:
    """cmk/plugins/hp_procurve/agent_based/hp_procurve_cpu.py:53-56 (also
    used by hp_procurve_mem.py and hp_procurve_sensors.py) - sysObjectID
    under either of HP's two ProCurve-switch enterprise sub-branches."""
    return _contains(sys.sys_object_id, ".11.2.3.7.11") or _contains(
        sys.sys_object_id, ".11.2.3.7.8"
    )


def _is_checkpoint(sys: SysInfo) -> bool:
    """cmk/plugins/checkpoint/lib.py:10-20 - the first `any_of(...)` half
    of `DETECT` (sysObjectID/sysDescr only). The real spec ANDs in a second
    `any_of(...)` that requires two more Check Point-specific OIDs
    (firewall/Gaia markers); dropped here to keep this plugin to the
    universal System-group scalars only, at the cost of being slightly more
    permissive than the real plugin."""
    return (
        _startswith(sys.sys_object_id, ".1.3.6.1.4.1.2620")
        or _matches(sys.sys_descr, "[^ ]+ [^ ]+ [^ ]*cp( .*)?")
        or _startswith(sys.sys_descr, "IPSO ")
        or _matches(sys.sys_descr, "Linux.*cpx.*")
    )


def _is_palo_alto(sys: SysInfo) -> bool:
    """cmk/plugins/palo_alto/lib.py:8 - DETECT_PALO_ALTO."""
    return _contains(sys.sys_object_id, "25461")


def _is_f5_bigip(sys: SysInfo) -> bool:
    """cmk/plugins/f5_bigip/lib.py:20-23 - the sysObjectID half of
    F5_BIGIP. The real spec also ANDs a sysProductName OID containing
    "big-ip"; dropped here for the same reason as checkpoint above."""
    return _contains(sys.sys_object_id, ".1.3.6.1.4.1.3375.2")


def _is_acme(sys: SysInfo) -> bool:
    """cmk/plugins/acme/agent_based/lib.py:10 - DETECT_ACME."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.9148")


def _is_adva(sys: SysInfo) -> bool:
    """cmk/plugins/adva/agent_based/{adva_fsp_current.py:53, adva_fsp_if.py:74,
    adva_fsp_temp.py:76} - inline detect, identical across all three files."""
    return _equals(sys.sys_descr, "Fiber Service Platform F7")


def _is_arris(sys: SysInfo) -> bool:
    """cmk/plugins/arris/agent_based/{arris_cmts_temp.py:48, arris_cmts_cpu.py:58,
    arris_cmts_mem.py:69} - inline detect, identical across all three files
    (overlaps this plugin's own `docsis` family above, expected/harmless)."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.4998.2.1")


def _is_atto(sys: SysInfo) -> bool:
    """cmk/plugins/atto/agent_based/{atto_fibrebridge_fcport.py:38,
    atto_fibrebridge_chassis.py:52, atto_fibrebridge_sas.py:91} - inline
    detect, identical across all three files."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.4547")


def _is_akcp(sys: SysInfo) -> bool:
    """cmk/plugins/akcp/lib.py:8 - DETECT_AKCP_EXP. The real spec also ANDs
    `exists(".1.3.6.1.4.1.3854.2.*")`; dropped here, same reasoning as
    checkpoint/f5_bigip above."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.3854.1")


def _is_alcatel(sys: SysInfo) -> bool:
    """cmk/plugins/alcatel/lib.py:8,10 - DETECT_ALCATEL_AOS7 and DETECT_ALCATEL,
    two sibling enterprise sub-branches."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.6486.801") or _startswith(
        sys.sys_object_id, ".1.3.6.1.4.1.6486.800"
    )


def _is_apc(sys: SysInfo) -> bool:
    """cmk/plugins/apc/{lib_ats.py:10, agent_based/apc_powerswitch.py:59,
    agent_based/apc_mod_pdu_modules.py:91, agent_based/apc_netbotz_smoke.py:59,
    agent_based/apc_netbotz_fluid.py:59, agent_based/apc_netbotz_other_sensors.py:61,76,
    agent_based/apc_sts_inputs.py:65} - combined: APC's own enterprise branch
    (covers the ATS/powerswitch/PDU sub-OIDs), the NetBotz sensor lines'
    dedicated enterprise OIDs, a shared "apc" sysDescr substring, and the STS
    transfer-switch OID. apc_rackpdu_power.py's detect ANDs in an extra
    `exists(...)`, dropped here (same reasoning as checkpoint/f5_bigip)."""
    return (
        _startswith(sys.sys_object_id, ".1.3.6.1.4.1.318")
        or _contains(sys.sys_descr, "apc")
        or _startswith(sys.sys_object_id, ".1.3.6.1.4.1.5528.100.20.10")
        or _startswith(sys.sys_object_id, ".1.3.6.1.4.1.52674.500")
        or _contains(sys.sys_object_id, ".1.3.6.1.4.1.705.2.2")
    )


def _is_arbor(sys: SysInfo) -> bool:
    """cmk/plugins/arbor/agent_based/lib.py:8-10 - DETECT_PEAKFLOW_SP/_TMS
    (both covered by the broader "Peakflow" prefix) and DETECT_PRAVAIL."""
    return _startswith(sys.sys_descr, "Peakflow") or _startswith(sys.sys_descr, "Pravail")


def _is_audiocodes(sys: SysInfo) -> bool:
    """cmk/plugins/audiocodes/agent_based/lib.py:11 - DETECT_AUDIOCODES."""
    return _contains(sys.sys_object_id, ".1.3.6.1.4.1.5003.8.1.1")


def _is_avaya(sys: SysInfo) -> bool:
    """cmk/plugins/avaya/lib.py:8 - DETECT_AVAYA."""
    return _contains(sys.sys_object_id, ".1.3.6.1.4.1.2272")


def _is_barracuda(sys: SysInfo) -> bool:
    """cmk/plugins/barracuda/lib.py:8-11 - DETECT_BARRACUDA (fully expressible
    via sysDescr/sysObjectID, no dropped condition)."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.8072.3.2.10") and _contains(
        sys.sys_descr, "barracuda"
    )


def _is_bintec(sys: SysInfo) -> bool:
    """cmk/plugins/bintec/agent_based/{bintec_cpu.py:42, bintec_info.py:48-51} -
    simplified to Bintec/Teldat's whole enterprise sub-branch, which covers
    both the prefix and the two exact values found."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.272.4")


def _is_blade(sys: SysInfo) -> bool:
    """cmk/plugins/blade/agent_based/detection.py:8-19 - DETECT_BLADE and
    DETECT_BLADE_BX (IBM/Lenovo BladeCenter management modules)."""
    return (
        any(
            _contains(sys.sys_descr, needle)
            for needle in (
                "bladecenter management module",
                "bladecenter advanced management module",
                "ibm flex chassis management module",
                "lenovo flex chassis management module",
            )
        )
        or _contains(sys.sys_descr, "bx600")
        or _equals(sys.sys_object_id, ".1.3.6.1.4.1.7244.1.1.1")
    )


def _is_bluecat(sys: SysInfo) -> bool:
    """cmk/plugins/bluecat/lib.py:25 - DETECT_BLUECAT."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.13315.2.1")


def _is_bluecoat(sys: SysInfo) -> bool:
    """cmk/plugins/bluecoat/agent_based/{bluecoat_sensors.py:89-92,
    bluecoat_diskcpu.py:46} - inline detect, identical in both files."""
    return _contains(sys.sys_object_id, "1.3.6.1.4.1.3417.1.1")


def _is_brocade(sys: SysInfo) -> bool:
    """cmk/plugins/brocade/lib.py:24,29 - DETECT and DETECT_MLX. DETECT's real
    spec also ANDs `exists(".1.3.6.1.4.1.1588.2.1.1.1.6.2.1.*")`; dropped here,
    same reasoning as checkpoint/f5_bigip above."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.1588.2.1.1") or _startswith(
        sys.sys_object_id, ".1.3.6.1.4.1.1991.1."
    )


def _is_bvip(sys: SysInfo) -> bool:
    """cmk/plugins/bvip/lib.py:8-13 - DETECT_BVIP (Bosch video/IP camera
    line: FlexiDome, VIP-X, Dinion, AutoDome)."""
    return any(
        _contains(sys.sys_descr, needle)
        for needle in ("flexidome", "vip-x", "dinion", "autodome")
    )


def _is_casa(sys: SysInfo) -> bool:
    """cmk/plugins/casa/lib.py:8 - DETECT_CASA."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.20858.2.")


def _is_ciena_ces(sys: SysInfo) -> bool:
    """cmk/plugins/ciena_ces/lib.py:122-125 - DETECT_CIENA (the shared base
    condition the 5171/5142 sub-variants build on)."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.1271.1.2.11") or _startswith(
        sys.sys_object_id, ".1.3.6.1.4.1.6141.1.96"
    )


def _is_datapower(sys: SysInfo) -> bool:
    """cmk/plugins/datapower/lib.py:15-19 - DETECT."""
    return any(
        _equals(sys.sys_object_id, oid)
        for oid in (
            ".1.3.6.1.4.1.14685.1.8",
            ".1.3.6.1.4.1.14685.1.7",
            ".1.3.6.1.4.1.14685.1.3",
        )
    )


def _is_decru(sys: SysInfo) -> bool:
    """cmk/plugins/decru/lib.py:8 - DETECT_DECRU (NetApp DataFort)."""
    return _contains(sys.sys_descr, "datafort")


def _is_didactum(sys: SysInfo) -> bool:
    """cmk/plugins/didactum/lib.py:25 - DETECT_DIDACTUM."""
    return _contains(sys.sys_descr, "didactum")


def _is_docsis(sys: SysInfo) -> bool:
    """cmk/plugins/docsis/agent_based/docsis_channels_upstream.py:146-151 -
    inline detect (cable-modem/CMTS OIDs; the Arris one overlaps this
    plugin's own dedicated `arris` family below, expected/harmless overlap)."""
    return any(
        _equals(sys.sys_object_id, oid)
        for oid in (
            ".1.3.6.1.4.1.4115.820.1.0.0.0.0.0",
            ".1.3.6.1.4.1.4115.900.2.0.0.0.0.0",
            ".1.3.6.1.4.1.9.1.827",
            ".1.3.6.1.4.1.4998.2.1",
            ".1.3.6.1.4.1.20858.2.600",
        )
    )


def _is_eltek(sys: SysInfo) -> bool:
    """cmk/plugins/eltek/lib.py:8 - DETECT_ELTEK."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.12148.9")


def _is_emc(sys: SysInfo) -> bool:
    """cmk/plugins/emc/lib.py:13,15 - DETECT_ISILON and DETECT_DATADOMAIN.
    DETECT_VPLEX (line 8) is excluded - see the summary."""
    return _contains(sys.sys_descr, "isilon") or _startswith(sys.sys_descr, "Data Domain OS")


def _is_enterasys(sys: SysInfo) -> bool:
    """cmk/plugins/enterasys/lib.py:8-10 - DETECT_ENTERASYS."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.5624.2.1") or _startswith(
        sys.sys_object_id, ".1.3.6.1.4.1.5624.2.2"
    )


def _is_enviromux(sys: SysInfo) -> bool:
    """cmk/plugins/enviromux/lib.py:242-248 - DETECT_ENVIROMUX(5|_SEMS|_SEMS_E2D|_MICRO)."""
    return any(
        _startswith(sys.sys_object_id, oid)
        for oid in (
            ".1.3.6.1.4.1.3699.1.1.11",
            ".1.3.6.1.4.1.3699.1.1.10",
            ".1.3.6.1.4.1.3699.1.1.2",
            ".1.3.6.1.4.1.3699.1.1.9",
            ".1.3.6.1.4.1.3699.1.1.12",
        )
    )


def _is_epson(sys: SysInfo) -> bool:
    """cmk/plugins/epson/agent_based/epson_beamer_lamp.py:31 - inline detect."""
    return _contains(sys.sys_object_id, "1248")


def _is_fireeye(sys: SysInfo) -> bool:
    """cmk/plugins/fireeye/lib.py:10 - DETECT."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.25597.1")


def _is_fjdarye(sys: SysInfo) -> bool:
    """cmk/plugins/fjdarye/lib.py:31-39 - DETECT_FJDARYE (Fujitsu ETERNUS
    DX/AF disk arrays: fjdarye60/500/600)."""
    return any(
        _equals(sys.sys_object_id, oid)
        for oid in (
            ".1.3.6.1.4.1.211.1.21.1.60",
            ".1.3.6.1.4.1.211.1.21.1.150",
            ".1.3.6.1.4.1.211.1.21.1.153",
        )
    )


def _is_genua(sys: SysInfo) -> bool:
    """cmk/plugins/genua/lib.py:8-12 - DETECT_GENUA."""
    return any(
        _contains(sys.sys_descr, needle) for needle in ("genuscreen", "genubox", "genucrypt")
    )


def _is_gude(sys: SysInfo) -> bool:
    """cmk/plugins/gude/agent_based/{gude_powerbanks.py:84-87,
    gude_relayport.py:57} - simplified to Gude's whole enterprise branch,
    which covers both confirmed sub-OIDs."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.28507")


def _is_h3c(sys: SysInfo) -> bool:
    """cmk/plugins/h3c/agent_based/{h3c_lanswitch_sensors.py:53,
    h3c_lanswitch_cpu.py:97} - inline detect, identical in both files
    (legacy 3Com/H3C switch line)."""
    return _contains(sys.sys_descr, "3com s")


def _is_hwg(sys: SysInfo) -> bool:
    """cmk/plugins/hwg/agent_based/{hwg_humidity.py:51, hwg_temp.py:73,93} -
    inline detect."""
    return _contains(sys.sys_descr, "hwg") or _contains(sys.sys_descr, "STE2")


def _is_hitachi(sys: SysInfo) -> bool:
    """cmk/plugins/hitachi/agent_based/{hitachi_hus.py:55-60,
    hitachi_hus_status.py:65} - _DETECT_HUS (HUS 100-series model names) and
    the broader Hitachi enterprise-OID branch (distinct from hitachi_hnas
    above, a separate product line)."""
    return (
        any(_contains(sys.sys_descr, needle) for needle in ("hm700", "hm800", "hm850", "hm900"))
        or _startswith(sys.sys_object_id, ".1.3.6.1.4.1.116")
    )


def _is_hitachi_hnas(sys: SysInfo) -> bool:
    """cmk/plugins/hitachi_hnas/lib.py:15-22 - DETECT's first `any_of` branch
    only. The second branch (generic net-snmp + `exists` on a vendor OID) is
    dropped entirely rather than just its `exists` part, since generic
    net-snmp alone with nothing else is far too broad to keep - see summary."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.11096.6")


def _is_hp(sys: SysInfo) -> bool:
    """cmk/plugins/hp/agent_based/{hp_fan.py:55, hp_psu.py:45, hp_eml_sum.py:60} -
    the two ProCurve-switch-model detects (distinct from the hp_procurve
    family above, which is OID-based) and the EML tape-library OID.
    hp_webmgmt_status.py's detect (line 61) is excluded - its `startswith` on
    HP's entire top-level enterprise branch, minus the `exists` that narrows
    it, would be far too broad on its own."""
    return (
        (_contains(sys.sys_descr, "hp") and _contains(sys.sys_descr, "5406rzl2"))
        or (_contains(sys.sys_descr, "hp") and _contains(sys.sys_descr, "5412rzl2"))
        or _equals(sys.sys_object_id, ".1.3.6.1.4.1.11.10.2.1.3.20")
    )


def _is_hp_blade(sys: SysInfo) -> bool:
    """cmk/plugins/hp_blade/lib.py:8 - DETECT_HP_BLADE."""
    return _contains(sys.sys_object_id, ".11.5.7.1.2")


def _is_hpux(sys: SysInfo) -> bool:
    """cmk/plugins/hpux/agent_based/hpux_snmp_cs.py:95 - inline detect."""
    return _startswith(sys.sys_descr, "HP-UX")


def _is_huawei(sys: SysInfo) -> bool:
    """cmk/plugins/huawei/lib.py:11,13 - DETECT_HUAWEI_SWITCH and DETECT_HUAWEI_OSN."""
    return _contains(sys.sys_object_id, ".1.3.6.1.4.1.2011.2.23") or _contains(
        sys.sys_object_id, ".1.3.6.1.4.1.2011.2.25.1"
    )


def _is_icom(sys: SysInfo) -> bool:
    """cmk/plugins/icom/agent_based/icom_repeater.py:269 - inline detect."""
    return _contains(sys.sys_descr, "fr5000")


def _is_infoblox(sys: SysInfo) -> bool:
    """cmk/plugins/infoblox/lib.py:10-13 - DETECT_INFOBLOX."""
    return _contains(sys.sys_descr, "infoblox") or _startswith(
        sys.sys_object_id, ".1.3.6.1.4.1.7779.1"
    )


def _is_innovaphone(sys: SysInfo) -> bool:
    """cmk/plugins/innovaphone/agent_based/{innovaphone_priports_l1.py:97,
    innovaphone_priports_l2.py:85} - inline detect, identical in both files."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.6666")


def _is_intel_true_scale(sys: SysInfo) -> bool:
    """cmk/plugins/intel/lib.py:8 - DETECT_INTEL_TRUE_SCALE."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.10222")


def _is_ispro(sys: SysInfo) -> bool:
    """cmk/plugins/ispro/lib.py:8 - DETECT_ISPRO_SENSORS."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.19011.1.3.2")


def _is_janitza(sys: SysInfo) -> bool:
    """cmk/plugins/janitza/agent_based/janitza_umg.py:135-139 - inline detect."""
    return any(
        _equals(sys.sys_object_id, oid)
        for oid in (
            ".1.3.6.1.4.1.34278.8.6",
            ".1.3.6.1.4.1.34278.10.1",
            ".1.3.6.1.4.1.34278.10.4",
        )
    )


def _is_kemp_loadmaster(sys: SysInfo) -> bool:
    """cmk/plugins/kemp_loadmaster/lib.py:22-25 - DETECT_KEMP_LOADMASTER."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.12196.250.10") or _equals(
        sys.sys_object_id, ".1.3.6.1.4.1.2021.250.10"
    )


def _is_kentix(sys: SysInfo) -> bool:
    """cmk/plugins/kentix/lib.py:8 - DETECT_KENTIX."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.332.11.6")


def _is_knuerr(sys: SysInfo) -> bool:
    """cmk/plugins/knuerr/lib.py:8 - DETECT_KNUERR."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.3711.15.1")


def _is_kyocera(sys: SysInfo) -> bool:
    """cmk/plugins/kyocera/agent_based/inventory_kyocera_printer.py:55 - inline detect."""
    return _contains(sys.sys_descr, "kyocera")


def _is_lgp(sys: SysInfo) -> bool:
    """cmk/plugins/lgp/lib.py:8 - DETECT_LGP. Overlaps liebert's broader
    startswith on the same enterprise sub-branch below - both kept as
    separate labels, matching Checkmk's own separate plugin families."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.476.1.42")


def _is_liebert(sys: SysInfo) -> bool:
    """cmk/plugins/liebert/agent_based/lib.py:15 - DETECT_LIEBERT."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.476.1.42")


def _is_mcafee(sys: SysInfo) -> bool:
    """cmk/plugins/mcafee/libgateway.py:16-24 - DETECT_EMAIL_GATEWAY,
    DETECT_MCAFEE_WEBGATEWAY, DETECT_SKYHIGH_WEBGATEWAY (McAfee rebranded to
    Skyhigh Secure)."""
    return (
        _contains(sys.sys_descr, "mcafee email gateway")
        or _contains(sys.sys_descr, "mcafee web gateway")
        or _contains(sys.sys_object_id, "1.3.6.1.4.1.1230.2.7.1.1")
        or _contains(sys.sys_descr, "skyhigh secure web gateway")
        or _contains(sys.sys_object_id, "1.3.6.1.4.1.59732.2.7.1.1")
    )


def _is_meinberg(sys: SysInfo) -> bool:
    """cmk/plugins/meinberg/liblantime.py:10-13 - DETECT_MBG_LANTIME_NG.
    mbg_lantime_state.py's extra `not_exists(...)` refinement is dropped
    (same reasoning as checkpoint/f5_bigip)."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.5597.3") or _equals(
        sys.sys_object_id, ".1.3.6.1.4.1.5597.30"
    )


def _is_meraki(sys: SysInfo) -> bool:
    """cmk/plugins/network/agent_based/lib.py:10 - DETECT_MERAKI (Cisco Meraki,
    distinct enterprise OID from the main cisco family above)."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.29671")


def _is_mikrotik(sys: SysInfo) -> bool:
    """cmk/plugins/mikrotik/agent_based/mikrotik_signal.py:76 - inline detect."""
    return _contains(sys.sys_object_id, ".1.3.6.1.4.1.14988.1")


def _is_moxa(sys: SysInfo) -> bool:
    """cmk/plugins/moxa/agent_based/moxa_iologik_register.py:52-55 - its
    `startswith` half only; the second half (a `startswith` against a
    different, model-specific OID's *value*) is dropped, same reasoning as
    checkpoint/f5_bigip."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.8691.")


def _is_netextreme(sys: SysInfo) -> bool:
    """cmk/plugins/netextreme/lib.py:8-15 - DETECT_NETEXTREME (Avaya/Extreme
    VSP switch line, rebranded Avaya enterprise OID)."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.1916.2") or _startswith(
        sys.sys_object_id, ".1.3.6.1.4.1.2272.2"
    )


def _is_netgear(sys: SysInfo) -> bool:
    """cmk/plugins/netgear/lib.py:8 - DETECT_NETGEAR."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.4526.100")


def _is_netscaler(sys: SysInfo) -> bool:
    """cmk/plugins/netscaler/agent_based/lib.py:8 - SNMP_DETECT (Citrix
    NetScaler/ADC)."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.5951.1")


def _is_nimble(sys: SysInfo) -> bool:
    """cmk/plugins/nimble/agent_based/{nimble_volumes,nimble_latency}.py -
    inline detect, identical across both check files."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.37447.3.1")


def _is_pandacom(sys: SysInfo) -> bool:
    """cmk/plugins/pandacom/lib.py:8 - DETECT_PANDACOM."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.3652.3")


def _is_papouch(sys: SysInfo) -> bool:
    """cmk/plugins/papouch/agent_based/papouch_th2e_sensors.py:113-116 - inline detect."""
    return _contains(sys.sys_descr, "th2e") and _startswith(sys.sys_object_id, ".0.10.43.6.1.4.1")


def _is_perle(sys: SysInfo) -> bool:
    """cmk/plugins/perle/lib.py:8 - DETECT_PERLE."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.1966.20")


def _is_pfsense(sys: SysInfo) -> bool:
    """cmk/plugins/pfsense/agent_based/{pfsense_if,pfsense_status,pfsense_counter}.py -
    inline detect, identical across all three check files."""
    return _contains(sys.sys_descr, "pfsense")


def _is_poseidon(sys: SysInfo) -> bool:
    """cmk/plugins/poseidon/agent_based/{poseidon_inputs.py:81,
    poseidon_temp.py:76} - inline detect, identical in both files."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.21796.3")


def _is_printer(sys: SysInfo) -> bool:
    """cmk/plugins/printer/lib.py:108,113 - DETECT_RICOH and
    DETECT_CANON_HAS_TOTAL, both minus their `exists(...)` half (same
    reasoning as checkpoint/f5_bigip). DETECT_PRINTER_MANUFACTURER (line 98,
    a much longer manufacturer-OID allowlist) isn't included - see summary."""
    return _contains(sys.sys_object_id, ".1.3.6.1.4.1.367.1.1") or _contains(
        sys.sys_descr, "canon"
    )


def _is_pulse_secure(sys: SysInfo) -> bool:
    """cmk/plugins/pulse_secure/lib.py:11 - DETECT_PULSE_SECURE."""
    return _contains(sys.sys_object_id, ".1.3.6.1.4.1.12532")


def _is_qlogic(sys: SysInfo) -> bool:
    """cmk/plugins/qlogic/agent_based/qlogic_sanbox_fabric_element.py:56-59 -
    simplified to Qlogic's whole SANbox enterprise branch, which covers both
    confirmed sub-OIDs (other qlogic check files not individually verified)."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.3873")


def _is_qnap(sys: SysInfo) -> bool:
    """cmk/plugins/qnap/lib.py:8-10 - DETECT_QNAP."""
    return _startswith(sys.sys_descr, "Linux TS-") or _startswith(sys.sys_descr, "NAS Q")


def _is_raritan(sys: SysInfo) -> bool:
    """cmk/plugins/raritan/lib.py:25 - DETECT_RARITAN."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.13742.6")


def _is_rittal(sys: SysInfo) -> bool:
    """cmk/plugins/rittal/{lib/cmctc.py:9, lib/cmciii.py:24,
    agent_based/cmciii_lcp_waterflow.py:88, agent_based/cmc_temp.py:51} -
    DETECT_CMCTC, the `startswith` half of DETECT_CMCIII_LCP (its
    vendor-OID-string-value half is dropped, not expressible as a plain
    sysDescr/sysObjectID match), and the LCP-specific sysDescr prefix."""
    return (
        _contains(sys.sys_object_id, ".1.3.6.1.4.1.2606.4")
        or _contains(sys.sys_object_id, ".1.3.6.1.4.1.2606.7")
        or _contains(sys.sys_object_id, ".1.3.6.1.4.1.2606.1")
        or _startswith(sys.sys_descr, "Rittal LCP")
    )


def _is_roomalert(sys: SysInfo) -> bool:
    """cmk/plugins/roomalert/lib.py:7-10 - DETECT_RA32E and DETECT_RA3S."""
    return _contains(sys.sys_object_id, "1.3.6.1.4.1.20916.1.8") or (
        _contains(sys.sys_object_id, "1.3.6.1.4.1.20916") and _contains(sys.sys_descr, "3S")
    )


def _is_safenet(sys: SysInfo) -> bool:
    """cmk/plugins/safenet/agent_based/safenet_hsm.py:209-212 - its
    SafeNet-specific `startswith` branch only; the sibling
    `startswith(sysObjectID, ".1.3.6.1.4.1.8072")` branch (generic net-snmp)
    is dropped entirely - too broad to keep, see summary."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.12383")


def _is_sentry(sys: SysInfo) -> bool:
    """cmk/plugins/sentry/agent_based/{sentry_pdu_outlets.py:50,64,
    sentry_pdu_systempower.py:48, sentry_pdu.py:83} - inline detect (Sentry
    Server Technology PDUs)."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.1718.3") or _equals(
        sys.sys_object_id, ".1.3.6.1.4.1.1718.4"
    )


def _is_silverpeak(sys: SysInfo) -> bool:
    """cmk/plugins/silverpeak/agent_based/silverpeak_VX6000.py:89 - inline detect."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.23867")


def _is_sni_octopuse(sys: SysInfo) -> bool:
    """cmk/plugins/sni_octopuse/lib.py:8 - DETECT_SNI_OCTOPUSE (Siemens
    HiPath/OpenScape phone systems)."""
    return _contains(sys.sys_descr, "agent for hipath")


def _is_sophos(sys: SysInfo) -> bool:
    """cmk/plugins/sophos/lib.py:8 - DETECT_SOPHOS."""
    return _contains(sys.sys_object_id, ".1.3.6.1.4.1.21067.2")


def _is_steelhead(sys: SysInfo) -> bool:
    """cmk/plugins/steelhead/lib.py:8 - DETECT_STEELHEAD (Riverbed)."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.17163.")


def _is_teracom(sys: SysInfo) -> bool:
    """cmk/plugins/teracom/agent_based/{teracom_tcw241_analog.py:106,
    teracom_tcw241_digital.py:83} - inline detect, identical in both files."""
    return _contains(sys.sys_descr, "teracom")


def _is_ups(sys: SysInfo) -> bool:
    """cmk/plugins/ups/lib.py:28-48,50 - DETECT_UPS_GENERIC and DETECT_UPS_CPS,
    a broad allowlist of UPS-vendor enterprise OIDs (APC, Liebert/Emerson,
    Eaton/Powerware, MGE, Tripplite, Riello, SOCOMEC, Delta, Legrand,
    Cyberpower, and more) plus the RFC 1628 upsMIB branch."""
    return any(
        _equals(sys.sys_object_id, oid)
        for oid in (
            ".1.3.6.1.4.1.232.165.3",
            ".1.3.6.1.4.1.476.1.42",
            ".1.3.6.1.4.1.534.1",
            ".1.3.6.1.4.1.935",
            ".1.3.6.1.4.1.8072.3.2.10",
            ".1.3.6.1.4.1.2254.2.5",
            ".1.3.6.1.4.1.12551.4.0",
            ".1.3.6.1.4.1.43943",
            ".1.3.6.1.4.1.4555.1.1.7",
            ".1.3.6.1.4.1.42610.1.4.4",
        )
    ) or any(
        _startswith(sys.sys_object_id, oid)
        for oid in (
            ".1.3.6.1.4.1.850",
            ".1.3.6.1.2.1.33",
            ".1.3.6.1.4.1.534.2",
            ".1.3.6.1.4.1.5491",
            ".1.3.6.1.4.1.705.1",
            ".1.3.6.1.4.1.818.1.100.1",
            ".1.3.6.1.4.1.935",
            ".1.3.6.1.4.1.534.10",
            ".1.3.6.1.4.1.3808.1.1.1",
        )
    )


def _is_vutlan(sys: SysInfo) -> bool:
    """cmk/plugins/vutlan/lib.py:8 - DETECT_VUTLAN_EMS."""
    return _contains(sys.sys_descr, "vutlan ems")


def _is_wagner(sys: SysInfo) -> bool:
    """cmk/plugins/wagner/agent_based/wagner_titanus_topsense.py:42-45 - inline detect."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.34187.21501") or _equals(
        sys.sys_object_id, ".1.3.6.1.4.1.34187.74195"
    )


def _is_watchdog(sys: SysInfo) -> bool:
    """cmk/plugins/watchdog/agent_based/watchdog_sensors.py:153-156 - inline detect."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.21239.5.1") or _startswith(
        sys.sys_object_id, ".1.3.6.1.4.1.21239.42.1"
    )


def _is_wut(sys: SysInfo) -> bool:
    """cmk/plugins/wut/agent_based/wut_webtherm.py:111 - simplified to W&T's
    whole enterprise branch; wut_webio.py's detect (line 93) uses the same
    branch via named OID constants not resolved here."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.5040")


def _is_zebra(sys: SysInfo) -> bool:
    """cmk/plugins/zebra/agent_based/{zebra_printer_status,zebra_model}.py -
    inline detect, identical across both check files."""
    return _contains(sys.sys_descr, "zebra")


def _is_bdt_tape(sys: SysInfo) -> bool:
    """cmk/plugins/bdt_tape/agent_based/bdtms_tape_status.py:51 (also
    bdtms_tape_info.py, bdtms_tape_module.py) and bdt_tape_info.py:36 (also
    bdt_tape_status.py) - two BDT tape-library product generations, both
    pure sysObjectID contains checks."""
    return _contains(sys.sys_object_id, ".1.3.6.1.4.1.20884.77.83.1") or _contains(
        sys.sys_object_id, ".1.3.6.1.4.1.20884.10893.2.101"
    )


def _is_bluenet(sys: SysInfo) -> bool:
    """cmk/plugins/bluenet/agent_based/bluenet_sensor.py:50 (also
    bluenet_meter.py) and bluenet2_powerrail.py:272 - two BayTech/BlueNET PDU
    product generations."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.21695.1") or _contains(
        sys.sys_object_id, ".1.3.6.1.4.1.31770.2.1"
    )


def _is_cbl(sys: SysInfo) -> bool:
    """cmk/plugins/cbl/agent_based/cbl_airlaser.py:222 - CBL AirLaser wireless
    bridge. Real spec also ANDs exists(".1.3.6.1.4.1.2800.2.1.1.0"); dropped
    here since "airlaser" alone is already a specific product string, same
    reasoning as checkpoint/f5_bigip above."""
    return _contains(sys.sys_descr, "airlaser")


def _is_cisco_sma(sys: SysInfo) -> bool:
    """cmk/plugins/cisco_sma/agent_based/detect.py:8 - DETECT_CISCO_SMA (Cisco
    Secure Email/Web Manager appliances - distinct product line from the
    existing `cisco` network-gear family)."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.15497.1.1")


def _is_climaveneta(sys: SysInfo) -> bool:
    """cmk/plugins/climaveneta/agent_based/climaveneta_temp.py:51 (also
    climaveneta_fan.py, climaveneta_alarm.py) - exact sysDescr match, distinct
    from the broader/generic `carel` pCO-controller signal (excluded - see
    the module docstring)."""
    return _equals(sys.sys_descr, "pCO Gateway")


def _is_cpsecure(sys: SysInfo) -> bool:
    """cmk/plugins/cpsecure/agent_based/cpsecure_sessions.py:57 - CoreProcess
    Secure appliances."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.26546.1.1.2")


def _is_netapp(sys: SysInfo) -> bool:
    """cmk/plugins/df/agent_based/df_netapp.py:44 - IS_NETAPP_FILER, the
    vendor-identification half shared by df_netapp/df_netapp32 (their
    exists()/not_exists() split only decides which sub-check variant to run,
    not whether it's a NetApp filer at all - that part is fully
    sysDescr/sysObjectID already)."""
    return _contains(sys.sys_descr, "ontap") or _contains(sys.sys_object_id, ".1.3.6.1.4.1.789")


def _is_emka(sys: SysInfo) -> bool:
    """cmk/plugins/emka/agent_based/emka_modules.py:30 - DETECT_EMKA (EMKA
    ELM2-MIB enclosure monitoring)."""
    return _contains(sys.sys_descr, "emka") and _startswith(
        sys.sys_object_id, ".1.3.6.1.4.1.13595"
    )


def _is_ewon(sys: SysInfo) -> bool:
    """cmk/plugins/ewon/agent_based/ewon.py:213 - eWON industrial routers."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.8284.2.1")


def _is_f5os_rseries(sys: SysInfo) -> bool:
    """cmk/plugins/f5os_rseries/lib/detect.py:10 - DETECT_F5OS_RSERIES. F5's
    newer rSeries hardware platform - distinct OID branch from the existing
    `f5_bigip` (BIG-IP software) family."""
    return _contains(sys.sys_descr, "rSeries") and _startswith(
        sys.sys_object_id, ".1.3.6.1.4.1.12276.1.3."
    )


def _is_hepta(sys: SysInfo) -> bool:
    """cmk/plugins/hepta/agent_based/hepta.py:95 - Hepta UPS/power devices."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.12527")


def _is_hp_hh3c(sys: SysInfo) -> bool:
    """cmk/plugins/hp_hh3c/agent_based/hp_hh3c_fan.py:36 (also
    hp_hh3c_power.py) - HPE/H3C joint-venture switches, a different OID
    branch/era from the existing `h3c` (legacy 3Com-branded) family. The
    third file, hp_hh3c_ext.py, ANDs an extra exists() only that one
    sub-check needs; the fan/power detect used here needs no such clause."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.25506") and (
        _contains(sys.sys_descr, "H3C") or _contains(sys.sys_descr, "HPE")
    )


def _is_hp_mcs(sys: SysInfo) -> bool:
    """cmk/plugins/hp_mcs/agent_based/hp_mcs_sensors.py:59 (also
    hp_mcs_system.py) - HP Modular Cooling System."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.232.167")


def _is_infratec_plus(sys: SysInfo) -> bool:
    """cmk/plugins/infratec_plus/agent_based/rms200_temp.py:49 - Infratec Plus
    RMS200 environmental sensors."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.1909.13")


def _is_ipr400(sys: SysInfo) -> bool:
    """cmk/plugins/ipr400/agent_based/ipr400_temp.py:42 (also
    ipr400_in_voltage.py) - IPR400 VoIP intercom devices."""
    return _startswith(sys.sys_descr, "ipr voip device ipr400")


def _is_orion(sys: SysInfo) -> bool:
    """cmk/plugins/orion/agent_based/orion_system.py:104 (also orion_backup.py,
    orion_batterytest.py) - Orion (Merlin Gerin/Socomec-adjacent) UPS/power
    systems."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.20246")


def _is_packeteer(sys: SysInfo) -> bool:
    """cmk/plugins/packeteer/agent_based/packeteer_ps_status.py:28 (also
    packeteer_fan_status.py) - Packeteer/Blue Coat PacketShaper WAN
    appliances."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.2334")


def _is_seh(sys: SysInfo) -> bool:
    """cmk/plugins/seh/agent_based/seh_ports.py:41 - SEH PSrv USB/print
    servers."""
    return _contains(sys.sys_object_id, ".1.3.6.1.4.1.1229.1.1")


def _is_sensatronics(sys: SysInfo) -> bool:
    """cmk/plugins/sensatronics/agent_based/sensatronics_temp.py:40 -
    Sensatronics environmental sensors (newer product; see also `strem1`
    below, an older Sensatronics product identified via sysDescr instead)."""
    return _equals(sys.sys_object_id, ".1.3.6.1.4.1.16174.1.1.1")


def _is_strem1(sys: SysInfo) -> bool:
    """cmk/plugins/strem1/agent_based/strem1_sensors.py:86 - Sensatronics EM1,
    an older product from the same vendor as `sensatronics` above, identified
    via sysDescr instead of sysObjectID."""
    return _contains(sys.sys_descr, "Sensatronics EM1")


def _is_superstack3(sys: SysInfo) -> bool:
    """cmk/plugins/superstack3/agent_based/superstack3_sensors.py:45 - 3Com
    SuperStack 3 switches - distinct product line/sysDescr signal from the
    existing `h3c` family's "3com s" prefix match."""
    return _contains(sys.sys_descr, "3com superstack 3")


def _is_sym_brightmail(sys: SysInfo) -> bool:
    """cmk/plugins/sym_brightmail/agent_based/sym_brightmail_queues.py:113 -
    Symantec/Broadcom Brightmail (mail security) gateway appliances, detected
    via their underlying RHEL5/6 sysDescr build tags. Weaker signal than most
    (a generic-sounding OS build tag) but it's Checkmk's own real, chosen
    detect condition - not narrowed further here."""
    return _contains(sys.sys_descr, "el5_sms") or _contains(sys.sys_descr, "el6")


def _is_arista(sys: SysInfo) -> bool:
    """cmk/plugins/entity_sensors/agent_based/entity_sensors.py:61-65 - one
    arm of entity_sensors' detect (any_of palo-alto/cisco-asa/arista sysDescr
    prefixes, generic ENTITY-MIB sensor support) - the palo-alto and
    cisco-asa arms duplicate this plugin's existing `palo_alto`/`cisco`
    families; only the Arista Networks arm is new."""
    return _startswith(sys.sys_descr, "arista networks")


_FAMILY_DETECTORS: Sequence[tuple[str, Callable[[SysInfo], bool]]] = (
    ("cisco", _is_cisco),
    ("juniper", _is_juniper),
    ("fortinet", _is_fortinet),
    ("aruba", _is_aruba),
    ("hp_procurve", _is_hp_procurve),
    ("checkpoint", _is_checkpoint),
    ("palo_alto", _is_palo_alto),
    ("f5_bigip", _is_f5_bigip),
    ("acme", _is_acme),
    ("adva", _is_adva),
    ("akcp", _is_akcp),
    ("alcatel", _is_alcatel),
    ("apc", _is_apc),
    ("arbor", _is_arbor),
    ("arris", _is_arris),
    ("atto", _is_atto),
    ("audiocodes", _is_audiocodes),
    ("avaya", _is_avaya),
    ("barracuda", _is_barracuda),
    ("bintec", _is_bintec),
    ("blade", _is_blade),
    ("bluecat", _is_bluecat),
    ("bluecoat", _is_bluecoat),
    ("brocade", _is_brocade),
    ("bvip", _is_bvip),
    ("casa", _is_casa),
    ("ciena_ces", _is_ciena_ces),
    ("datapower", _is_datapower),
    ("decru", _is_decru),
    ("didactum", _is_didactum),
    ("docsis", _is_docsis),
    ("eltek", _is_eltek),
    ("emc", _is_emc),
    ("enterasys", _is_enterasys),
    ("enviromux", _is_enviromux),
    ("epson", _is_epson),
    ("fireeye", _is_fireeye),
    ("fjdarye", _is_fjdarye),
    ("genua", _is_genua),
    ("gude", _is_gude),
    ("h3c", _is_h3c),
    ("hitachi", _is_hitachi),
    ("hitachi_hnas", _is_hitachi_hnas),
    ("hp", _is_hp),
    ("hp_blade", _is_hp_blade),
    ("hpux", _is_hpux),
    ("huawei", _is_huawei),
    ("hwg", _is_hwg),
    ("icom", _is_icom),
    ("infoblox", _is_infoblox),
    ("innovaphone", _is_innovaphone),
    ("intel_true_scale", _is_intel_true_scale),
    ("ispro", _is_ispro),
    ("janitza", _is_janitza),
    ("kemp_loadmaster", _is_kemp_loadmaster),
    ("kentix", _is_kentix),
    ("knuerr", _is_knuerr),
    ("kyocera", _is_kyocera),
    ("lgp", _is_lgp),
    ("liebert", _is_liebert),
    ("mcafee", _is_mcafee),
    ("meinberg", _is_meinberg),
    ("meraki", _is_meraki),
    ("mikrotik", _is_mikrotik),
    ("moxa", _is_moxa),
    ("netextreme", _is_netextreme),
    ("netgear", _is_netgear),
    ("netscaler", _is_netscaler),
    ("nimble", _is_nimble),
    ("pandacom", _is_pandacom),
    ("papouch", _is_papouch),
    ("perle", _is_perle),
    ("pfsense", _is_pfsense),
    ("poseidon", _is_poseidon),
    ("printer", _is_printer),
    ("pulse_secure", _is_pulse_secure),
    ("qlogic", _is_qlogic),
    ("qnap", _is_qnap),
    ("raritan", _is_raritan),
    ("rittal", _is_rittal),
    ("roomalert", _is_roomalert),
    ("safenet", _is_safenet),
    ("sentry", _is_sentry),
    ("silverpeak", _is_silverpeak),
    ("sni_octopuse", _is_sni_octopuse),
    ("sophos", _is_sophos),
    ("steelhead", _is_steelhead),
    ("teracom", _is_teracom),
    ("ups", _is_ups),
    ("vutlan", _is_vutlan),
    ("wagner", _is_wagner),
    ("watchdog", _is_watchdog),
    ("wut", _is_wut),
    ("zebra", _is_zebra),
    ("bdt_tape", _is_bdt_tape),
    ("bluenet", _is_bluenet),
    ("cbl", _is_cbl),
    ("cisco_sma", _is_cisco_sma),
    ("climaveneta", _is_climaveneta),
    ("cpsecure", _is_cpsecure),
    ("netapp", _is_netapp),
    ("emka", _is_emka),
    ("ewon", _is_ewon),
    ("f5os_rseries", _is_f5os_rseries),
    ("hepta", _is_hepta),
    ("hp_hh3c", _is_hp_hh3c),
    ("hp_mcs", _is_hp_mcs),
    ("infratec_plus", _is_infratec_plus),
    ("ipr400", _is_ipr400),
    ("orion", _is_orion),
    ("packeteer", _is_packeteer),
    ("seh", _is_seh),
    ("sensatronics", _is_sensatronics),
    ("strem1", _is_strem1),
    ("superstack3", _is_superstack3),
    ("sym_brightmail", _is_sym_brightmail),
    ("arista", _is_arista),
)


def parse_snmp_match(string_table: StringTable) -> SysInfo | None:
    if not string_table:
        return None
    sys_descr, sys_object_id = string_table[0]
    return SysInfo(sys_descr=sys_descr.strip(), sys_object_id=sys_object_id.strip())


def host_label_snmp_match(section: SysInfo) -> HostLabelGenerator:
    """
    Labels:

        caps/snmp/<family>:
            One label per matching vendor family (117 covered - see
            `_FAMILY_DETECTORS` above) whose real Checkmk plugin would
            likely attach to this device - see the per-family functions
            above for the detection logic and its source.
    """
    for family, is_match in _FAMILY_DETECTORS:
        if is_match(section):
            yield HostLabel(f"caps/snmp/{family}", "yes")


snmp_section_caps_scout_snmp_match = SimpleSNMPSection(
    name="caps_scout_snmp_match",
    parse_function=parse_snmp_match,
    host_label_function=host_label_snmp_match,
    fetch=SNMPTree(
        base=".1.3.6.1.2.1.1",
        oids=["1", "2"],
    ),
    detect=HAS_SYSDESC,
)

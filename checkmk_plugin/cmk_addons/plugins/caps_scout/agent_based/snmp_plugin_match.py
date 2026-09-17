#!/usr/bin/env python3
# Part of caps-scout (https://github.com/andrea-vaccaro/caps-scout) - License: GNU General Public License v3

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

Checkmk ships ~150 such families under `cmk/plugins/<family>/` (cisco,
juniper, fortinet, aruba, hp_procurve, checkpoint, palo_alto, f5_bigip, and
many more), each deciding whether one of its own check plugins applies to a
scanned device via a `detect=` scan spec - almost always built from
`sysDescr` (`.1.3.6.1.2.1.1.1.0`) and/or `sysObjectID`
(`.1.3.6.1.2.1.1.2.0`), the same two System-group scalars
`cmk/plugins/network/agent_based/snmp_info.py` already fetches for its own
`cmk/device_type` label. This plugin covers a handful of common families
(a `git grep -rn "^DETECT" cmk/plugins/<family>` in the Checkmk source finds
the rest) - not the full catalog - and, for each one, replicates the exact
condition that family's own `lib.py` uses, cited per function below. Where a
family's real condition also ANDs in a second, vendor-specific OID beyond
sysDescr/sysObjectID (checkpoint, f5_bigip), that second condition is
dropped here rather than adding a per-vendor SNMP fetch tree just for it -
noted per function, since it makes this plugin's match slightly more
permissive than the real one in those two cases.

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
    """cmk/plugins/juniper/lib.py:8 - DETECT_JUNIPER, the general Junos
    signal most of the family's checks use. The family also covers the
    legacy Trapeze-wifi (DETECT_JUNIPER_TRPZ) and ScreenOS/NetScreen
    (DETECT_JUNIPER_SCREENOS) sub-lines under different enterprise OIDs,
    not included here."""
    return _startswith(sys.sys_object_id, ".1.3.6.1.4.1.2636.1.1.1")


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


_FAMILY_DETECTORS: Sequence[tuple[str, Callable[[SysInfo], bool]]] = (
    ("cisco", _is_cisco),
    ("juniper", _is_juniper),
    ("fortinet", _is_fortinet),
    ("aruba", _is_aruba),
    ("hp_procurve", _is_hp_procurve),
    ("checkpoint", _is_checkpoint),
    ("palo_alto", _is_palo_alto),
    ("f5_bigip", _is_f5_bigip),
)


def parse_snmp_plugin_match(string_table: StringTable) -> SysInfo | None:
    if not string_table:
        return None
    sys_descr, sys_object_id = string_table[0]
    return SysInfo(sys_descr=sys_descr.strip(), sys_object_id=sys_object_id.strip())


def host_label_snmp_plugin_match(section: SysInfo) -> HostLabelGenerator:
    """
    Labels:

        caps/snmp_plugin/<family>:
            One label per matching vendor family (cisco, juniper, fortinet,
            aruba, hp_procurve, checkpoint, palo_alto, f5_bigip) whose real
            Checkmk plugin would likely attach to this device - see the
            per-family functions above for the detection logic and its
            source.
    """
    for family, is_match in _FAMILY_DETECTORS:
        if is_match(section):
            yield HostLabel(f"caps/snmp_plugin/{family}", "yes")


snmp_section_caps_scout_snmp_plugin_match = SimpleSNMPSection(
    name="caps_scout_snmp_plugin_match",
    parse_function=parse_snmp_plugin_match,
    host_label_function=host_label_snmp_plugin_match,
    fetch=SNMPTree(
        base=".1.3.6.1.2.1.1",
        oids=["1", "2"],
    ),
    detect=HAS_SYSDESC,
)

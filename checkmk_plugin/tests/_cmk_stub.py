"""Test-only stand-in for the `cmk.agent_based.v2` names the plugin imports.

The real Checkmk agent-based plugin API isn't published as a standalone,
pip-installable package outside a Checkmk site/checkout, so it can't be a
test dependency here. These tests only exercise
`snmp_capabilities.py`'s own pure functions (`parse_snmp_capabilities`,
`host_label_snmp_capabilities`) - this fakes just the handful of names the
module imports at load time (mirroring their real shapes: `HostLabel` is a
`(name, value)` pair, `SimpleSNMPSection`/`SNMPTree` just capture their
constructor arguments) so the module can be imported without a real Checkmk
installation. It is not a reimplementation of the real API and proves
nothing about actual SNMP fetching - that only happens in a real site, per
the MKP install steps in ../README.md.
"""

import dataclasses
import enum
import sys
import types
from typing import NamedTuple


def install() -> None:
    if "cmk.agent_based.v2" in sys.modules:
        return

    class HostLabel(NamedTuple):
        name: str
        value: str

    class SNMPTree:
        def __init__(self, *, base: str, oids: list[str]) -> None:
            self.base = base
            self.oids = oids

    class SimpleSNMPSection:
        def __init__(self, *, name, parse_function, host_label_function, fetch, detect) -> None:
            self.name = name
            self.parse_function = parse_function
            self.host_label_function = host_label_function
            self.fetch = fetch
            self.detect = detect

    def exists(oid: str) -> tuple[str, str]:
        return ("exists", oid)

    class State(enum.Enum):
        OK = 0
        WARN = 1
        CRIT = 2
        UNKNOWN = 3

    class Service(NamedTuple):
        item: str | None = None

    class Result(NamedTuple):
        state: "State"
        summary: str | None = None
        details: str | None = None

    @dataclasses.dataclass
    class CheckPlugin:
        name: str
        service_name: str
        discovery_function: object
        check_function: object
        sections: list[str] | None = None

    v2 = types.ModuleType("cmk.agent_based.v2")
    v2.HostLabel = HostLabel
    v2.HostLabelGenerator = object
    v2.SimpleSNMPSection = SimpleSNMPSection
    v2.SNMPTree = SNMPTree
    v2.StringTable = list
    v2.exists = exists
    v2.State = State
    v2.Service = Service
    v2.Result = Result
    v2.CheckPlugin = CheckPlugin
    v2.CheckResult = object
    v2.DiscoveryResult = object

    cmk = sys.modules.setdefault("cmk", types.ModuleType("cmk"))
    agent_based = sys.modules.setdefault("cmk.agent_based", types.ModuleType("cmk.agent_based"))
    cmk.agent_based = agent_based
    agent_based.v2 = v2
    sys.modules["cmk.agent_based.v2"] = v2

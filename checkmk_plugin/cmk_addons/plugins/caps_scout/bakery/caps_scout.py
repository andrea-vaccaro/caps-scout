#!/usr/bin/env python3
# Part of caps-scout (https://github.com/andrea-vaccaro/caps-scout) - License: MIT

"""caps-scout agent-plugin bakery rule.

Bakes the caps-scout Rust binary (`cmk_addons/plugins/caps_scout/agents/caps-scout` /
`caps-scout.exe`, built from this repo's `src/`) onto monitored hosts as a regular
Checkmk agent plug-in, instead of requiring it to be copied into the plug-in directory
by hand (see "Installing as a Checkmk agent plugin" in the top-level README). The
binary itself takes no arguments and decides on its own, per host, which `caps/*`
labels to print - but deployment offers the standard sync-vs-cached choice
(`CapsScoutConfig.deployment`) most first-party bakery-deployed plug-ins expose (see
`cmk/plugins/collection/bakery/isc_dhcpd.py`/`cmk/plugins/hyperv/bakery/hyperv_vms.py`
for the same shape), since the binary walks the full process table on every
invocation - on a host with many short agent cycles, running it on a cache interval
rather than every single cycle can be worth it.

Deliberately targets `cmk.bakery.v2_unstable`, not the nominally-stable `v1`: v1's
`Plugin(source=...)` is resolved against the site's legacy global agent-source
directories, not this plugin family's own `cmk_addons/plugins/caps_scout/agents/`
folder, so a v1
plugin's source file is silently never found when packaged as an MKP this way. v2's
resolver looks up `source` relative to the bakery module's own family folder instead
- the same mechanism Checkmk's own shipped
`cmk/plugins/ceph/bakery/ceph.py` and `cmk/plugins/oracle/bakery/mk_oracle_unified.py`
rely on for this exact reason.
"""

from collections.abc import Iterable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from cmk.bakery.v2_unstable import BakeryPlugin, OS, Plugin


class CapsScoutConfig(BaseModel):
    deployment: tuple[Literal["do_not_deploy", "sync", "cached"], float | None]


def get_caps_scout_files(confm: CapsScoutConfig) -> Iterable[Plugin]:
    if confm.deployment[0] == "do_not_deploy":
        return

    interval = confm.deployment[1]
    yield Plugin(base_os=OS.LINUX, source=Path("caps-scout"), interval=interval)
    yield Plugin(base_os=OS.WINDOWS, source=Path("caps-scout.exe"), interval=interval)


bakery_plugin_caps_scout = BakeryPlugin(
    name="caps_scout",
    parameter_parser=CapsScoutConfig.model_validate,
    default_parameters=None,
    files_function=get_caps_scout_files,
)

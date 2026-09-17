#!/usr/bin/env python3
# Part of caps-scout (https://github.com/andrea-vaccaro/caps-scout) - License: GNU General Public License v3

"""caps-scout agent-plugin bakery rule.

Bakes the caps-scout Rust binary (`cmk_addons/plugins/caps_scout/agents/caps-scout` /
`caps-scout.exe`, built from this repo's `src/`) onto monitored hosts as a regular
Checkmk agent plug-in, instead of requiring it to be copied into the plug-in directory
by hand (see "Installing as a Checkmk agent plugin" in the top-level README). No
configuration is needed beyond whether to deploy it at all - the binary takes no
arguments and decides on its own, per host, which `caps/*` labels to print.

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

from pydantic import BaseModel

from cmk.bakery.v2_unstable import BakeryPlugin, OS, Plugin


class CapsScoutConfig(BaseModel):
    deploy: bool


def get_caps_scout_files(confm: CapsScoutConfig) -> Iterable[Plugin]:
    if not confm.deploy:
        return

    yield Plugin(base_os=OS.LINUX, source=Path("caps-scout"))
    yield Plugin(base_os=OS.WINDOWS, source=Path("caps-scout.exe"))


bakery_plugin_caps_scout = BakeryPlugin(
    name="caps_scout",
    parameter_parser=CapsScoutConfig.model_validate,
    default_parameters=None,
    files_function=get_caps_scout_files,
)

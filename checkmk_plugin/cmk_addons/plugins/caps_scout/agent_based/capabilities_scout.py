#!/usr/bin/env python3
# Part of caps-scout (https://github.com/checkmk/caps-scout) - License: GNU General Public License v2

"""caps-scout Capabilities Scout service.

Turns caps-scout's own `caps/*` host labels into a visible service, so the
detected capabilities show up in the service list rather than only in the
host's label set (WATO -> host properties, or the "Labels" table).

caps-scout's agent plugin (the Rust binary in this repo's `src/`) reports
what it finds via a standard `<<<labels:sep(0)>>>` agent section - the exact
same section Checkmk's own core agent uses for its own host labels (e.g.
`cmk/device_type`, see `agents/check_mk_agent.linux:section_labels`) and
that `cmk.plugins.collection.agent_based.labels` already parses and turns
into host labels for every agent that sends it. This plugin doesn't
re-parse that section - it subscribes to the same already-parsed `labels`
section (`sections=["labels"]`) and filters it down to the `caps/*` keys,
so it stays in sync with whatever `caps/*` labels caps-scout emits without
needing to know their exact set up front.

For labels with a known corresponding Checkmk agent-bakery rule (a rule that
would deploy/configure the plugin actually monitoring that engine - see
`BAKERY_RULE_BY_LABEL` below), the details view adds a small pill-shaped "Add rule"
link, right-aligned next to the label in its own row, straight to that rule's
"new rule" page (`wato.py?mode=new_rule&varname=agent_config:<rule>`) - so the
label points directly at the next action, same spirit as `snmp_plugin_match.py`'s
labels. The pill's border uses `currentColor` rather than a fixed color so it reads
correctly in both the light and dark GUI themes. `BAKERY_RULE_BY_LABEL` only covers
labels whose bakery rule name was confirmed against this Checkmk version's own
`cmk/gui/**/plugins/wato/agent_bakery/rulespecs/*.py` (or `cmk/plugins/*/rulesets/`
for newer unified ones) - labels without an entry (special-agent-only integrations,
Checkmk-Exchange-only plugins, or engines the core agent already covers with no
plugin to activate) get a plain bullet, not a broken link.

Rendering the link as clickable HTML - rather than literal `<a href=...>` text -
requires a rule in Setup -> Services -> Service monitoring rules ->
"Escape HTML in service output (dangerous to deactivate - read help)" (ruleset
`extra_service_conf:_ESCAPE_PLUGIN_OUTPUT`), set to "Don't escape HTML" and scoped
via a service condition to `Capabilities Scout` - then activate changes, since the
setting only takes effect on the core after that. Off by default because plugin
output is normally untrusted; safe to scope to this one service because every value
in it - the label keys, and the fixed rule-name table below - is produced by this
plugin's own code, never by data an attacker could influence.
"""

from collections.abc import Mapping

from cmk.agent_based.v2 import CheckPlugin, CheckResult, DiscoveryResult, Result, Service, State

Section = Mapping[str, str]

CAPS_LABEL_PREFIX = "caps/"

# Only labels with a bakery rule confirmed to exist in this Checkmk version - see
# the module docstring. Deliberately not exhaustive: many `caps/*` labels name
# engines with no first-party bakery rule at all (special-agent-only integrations,
# Checkmk-Exchange-only plugins, or core-agent-builtin checks with nothing to bake).
BAKERY_RULE_BY_LABEL: Mapping[str, str] = {
    "caps/db/oracle": "mk_oracle_unified",
    "caps/db/mysql": "mk_mysql",
    "caps/db/postgres": "mk_postgres",
    "caps/db/mssql": "mk_ms_sql",
    "caps/db/mongodb": "mk_mongodb",
    "caps/db/redis": "mk_redis",
    "caps/db/db2": "mk_db2",
    "caps/db/sap_hana": "mk_sap_hana",
    "caps/web/apache": "apache_status",
    "caps/web/nginx": "nginx_status",
    "caps/app/sap_netweaver": "mk_sap",
    "caps/app/exchange": "msexch_database",
    "caps/app/plesk": "plesk",
    "caps/container/docker": "mk_docker",
    "caps/container/podman": "mk_podman",
    "caps/virt/hyperv": "hyperv_vms",
    "caps/backup/veeam": "veeam_backup_status",
    "caps/backup/tsm": "mk_tsm",
    "caps/backup/arcserve": "arcserve_backup",
    "caps/print/cups": "mk_cups_queues",
    "caps/net/isc_dhcpd": "isc_dhcpd",
}


def _caps_labels(section: Section) -> list[str]:
    return sorted(key for key in section if key.startswith(CAPS_LABEL_PREFIX))


_ADD_RULE_LINK_STYLE = (
    "white-space:nowrap;border:1px solid currentColor;border-radius:12px;"
    "padding:1px 10px;text-decoration:none;font-size:0.9em;"
)


def _bullet(key: str) -> str:
    rule_name = BAKERY_RULE_BY_LABEL.get(key)
    if rule_name is None:
        return f"<div>• {key}</div>"
    url = f"wato.py?mode=new_rule&varname=agent_config:{rule_name}&_new_dflt_rule=1"
    return (
        '<div style="display:flex;justify-content:space-between;align-items:center;'
        'gap:1em;max-width:26em;">'
        f"<span>• {key}</span>"
        f'<a href="{url}" style="{_ADD_RULE_LINK_STYLE}">➕&nbsp;Add rule</a>'
        "</div>"
    )


def discover_capabilities_scout(section: Section) -> DiscoveryResult:
    if _caps_labels(section):
        yield Service()


def check_capabilities_scout(section: Section) -> CheckResult:
    caps = _caps_labels(section)
    if not caps:
        yield Result(state=State.OK, summary="No caps-scout capabilities currently detected")
        return

    yield Result(
        state=State.OK,
        summary=", ".join(caps),
        details="".join(_bullet(key) for key in caps),
    )


check_plugin_capabilities_scout = CheckPlugin(
    name="capabilities_scout",
    service_name="Capabilities Scout",
    sections=["labels"],
    discovery_function=discover_capabilities_scout,
    check_function=check_capabilities_scout,
)

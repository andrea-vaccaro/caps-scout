#!/usr/bin/env python3
# Part of caps-scout (https://github.com/andrea-vaccaro/caps-scout) - License: GNU General Public License v3

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
section (`sections=["labels", ...]`) and filters it down to the `caps/*` keys,
so it stays in sync with whatever `caps/*` labels caps-scout emits without
needing to know their exact set up front.

`snmp_plugin_match.py`'s `caps/snmp_plugin/<family>` labels are a second,
independent source of `caps/*` labels - but they're computed by an SNMP
section's `host_label_function`, not written into the `labels` agent section
at all, so they aren't visible through that subscription. To show them here
too, this plugin also subscribes to the raw `caps_scout_snmp_plugin_match`
SNMP section (the same `SysInfo` of `sysDescr`/`sysObjectID`) and calls
`host_label_snmp_plugin_match` on it directly, reusing the exact same
per-family detection logic rather than re-implementing it. Either section can
be absent for a given host (a pure-agent host has no SNMP section; a
pure-SNMP device has no agent `labels` section) - the check runs as soon as
at least one of them has data, with the other passed in as `None`.

The details render as a two-column table - Capability, Rules - rather than a flat
list, since a capability can have more than one applicable Checkmk agent-bakery rule
(a rule that would deploy/configure a plugin actually monitoring that engine - see
`BAKERY_RULES_BY_LABEL` below). Each applicable rule gets its own row in the Rules
cell: the same title Checkmk's own Setup GUI shows for that rule (`RULE_TITLE_BY_NAME`
- confirmed per rule against source, same rigor as `BAKERY_RULES_BY_LABEL` itself;
a rule added there without yet having a confirmed title here falls back to showing
its raw varname in monospace, never a guessed title) as a small label, plus a solid
"Add rule" chip straight to that rule's "new rule" page
(`wato.py?mode=new_rule&varname=agent_config:<rule>`) - so the row points directly at
the next action, same spirit as `snmp_plugin_match.py`'s labels. This deliberately
always links to "new rule", never to an existing rule or
the ruleset's overview: `cmk.agent_based.v2`'s `validate_function_arguments` only
allows a check function to declare `item`/`params`/`section*` parameters (see
`packages/cmk-check-engine/.../plugin_backend/utils.py` in Checkmk's source) - there
is no way for this plugin to learn the current host's name, so it can never know
whether an already-existing rule (in some WATO folder, scoped by tags/host list) is
even the one applicable to this host. Counting rule instances anywhere in the site's
config and guessing from that would be misleading, so this plugin doesn't try - "Add
rule" always takes you to WATO's normal rule list for that ruleset, where you can see
and manage whatever already exists. A capability with no known rule at all gets a
muted em dash in that cell instead of a broken link. `BAKERY_RULES_BY_LABEL` only
covers labels whose bakery rule names were confirmed against this Checkmk version's
own `cmk/gui/**/plugins/wato/agent_bakery/rulespecs/*.py` (or `cmk/plugins/*/rulesets/`
and `cmk/gui/plugins/legacy_bakery_rulesets/*.py` for older/superseded ones) - it is
deliberately not exhaustive. Most entries are a single rule, but the value is a tuple
because a few capabilities genuinely have two confirmed, mutually-exclusive rules for
the same engine - e.g. Oracle's legacy `mk_oracle` plugin and its newer
`mk_oracle_unified` replacement, which Checkmk's own rule help text says explicitly
not to configure together.

Only a row divider is drawn, never a column divider, between Capability and Rules -
both `<td>`s in every `<tr>` get the same `border-bottom` (with `border-collapse` on
the `<table>` so the two cells' borders merge into one line), including rows whose
Rules cell is just the em dash - so the divider always lines up with the row above
and below it, instead of a stray full-width rule under button-less rows.

Rendering the link as clickable HTML - rather than literal `<a href=...>` text -
requires a rule in Setup -> Services -> Service monitoring rules ->
"Escape HTML in service output (dangerous to deactivate - read help)" (ruleset
`extra_service_conf:_ESCAPE_PLUGIN_OUTPUT`), set to "Don't escape HTML" and scoped
via a service condition to `Capabilities Scout` - then activate changes, since the
setting only takes effect on the core after that. Off by default because plugin
output is normally untrusted; safe to scope to this one service because every value
in it - the label keys, and the fixed rule-name tables below - is produced by this
plugin's own code, never by data an attacker could influence.
"""

from collections.abc import Mapping

from cmk.agent_based.v2 import CheckPlugin, CheckResult, DiscoveryResult, Result, Service, State

from .snmp_plugin_match import SysInfo, host_label_snmp_plugin_match

Section = Mapping[str, str]

CAPS_LABEL_PREFIX = "caps/"

# Only labels with a bakery rule confirmed to exist in this Checkmk version - see
# the module docstring. Deliberately not exhaustive: many `caps/*` labels name
# engines with no first-party bakery rule at all (special-agent-only integrations,
# Checkmk-Exchange-only plugins, or core-agent-builtin checks with nothing to bake).
# Every entry is a tuple of rule varnames - today always one, but a capability with
# two confirmed applicable rules can list both.
BAKERY_RULES_BY_LABEL: Mapping[str, tuple[str, ...]] = {
    "caps/db/oracle": ("mk_oracle_unified", "mk_oracle"),
    "caps/db/mysql": ("mk_mysql",),
    "caps/db/postgres": ("mk_postgres",),
    "caps/db/mssql": ("mk_ms_sql",),
    "caps/db/mongodb": ("mk_mongodb",),
    "caps/db/redis": ("mk_redis",),
    "caps/db/db2": ("mk_db2",),
    "caps/db/sap_hana": ("mk_sap_hana",),
    "caps/web/apache": ("apache_status",),
    "caps/web/nginx": ("nginx_status",),
    "caps/app/sap_netweaver": ("mk_sap",),
    "caps/app/exchange": ("msexch_database",),
    "caps/app/plesk": ("plesk",),
    "caps/container/docker": ("mk_docker",),
    "caps/container/podman": ("mk_podman",),
    "caps/virt/hyperv": ("hyperv_vms",),
    "caps/backup/veeam": ("veeam_backup_status",),
    "caps/backup/tsm": ("mk_tsm",),
    "caps/backup/arcserve": ("arcserve_backup",),
    "caps/print/cups": ("mk_cups_queues",),
    "caps/net/isc_dhcpd": ("isc_dhcpd",),
}

# The human-readable title Checkmk's own Setup GUI shows for each rule in
# `BAKERY_RULES_BY_LABEL` - confirmed per rule against this Checkmk version's source
# (the `title=Title(...)`/`title=_(...)` argument on the `AgentConfig`/`HostRulespec`
# registration that owns that `RuleGroup.AgentConfig(<name>)`/varname - the exact spot
# `mk_oracle`'s title came from, see the module docstring). Every rule name in
# `BAKERY_RULES_BY_LABEL` has a confirmed title here today; a future rule added there
# without a confirmed entry here falls back to showing its raw varname rather than a
# guessed title - see `_rule_row`.
RULE_TITLE_BY_NAME: Mapping[str, str] = {
    "mk_oracle_unified": "Unified Oracle plug-in (beta)",
    "mk_oracle": "Oracle databases (Linux, Solaris, AIX, Windows)",
    "mk_mysql": "MySQL databases",
    "mk_postgres": "PostgreSQL database and sessions (Linux, Windows)",
    "mk_ms_sql": "Microsoft SQL Server (Linux, Windows)",
    "mk_mongodb": "MongoDB (Linux)",
    "mk_redis": "Redis databases",
    "mk_db2": "DB2 databases (Linux, AIX)",
    "mk_sap_hana": "SAP HANA",
    "apache_status": "Apache web servers (Linux)",
    "nginx_status": "NGINX web servers (Linux)",
    "mk_sap": "SAP R/3 monitoring plug-in",
    "msexch_database": "MS Exchange Database Latency (Windows)",
    "plesk": "Plesk backups and domains (Linux)",
    "mk_docker": "Docker node and containers",
    "mk_podman": "Podman hosts and containers (Linux)",
    "hyperv_vms": "Hyper-V VMs (Windows)",
    "veeam_backup_status": "Veeam backup status (Windows)",
    "mk_tsm": "TSM - IBM Tivoli Storage Manager (Linux, Unix)",
    "arcserve_backup": "Arcserve (German) backups (Windows)",
    "mk_cups_queues": "CUPS printer queues (Linux)",
    "isc_dhcpd": "ISC DHCP-Daemon (Linux)",
}


# Generic category glyphs for the handful of capabilities with no available brand or
# company mark at all (checked against Simple Icons, Devicon, and Font Awesome
# Free's brand set - see ICON_BY_LABEL below). Not meant to resemble any specific
# product, just to give these rows the same visual anchor as their branded neighbors.
_ICON_GENERIC_DATABASE = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" '
    'fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">'
    '<ellipse cx="12" cy="5" rx="7" ry="2.5"/>'
    '<path d="M5 5v6c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5V5"/>'
    '<path d="M5 11v6c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-6"/>'
    '</svg>'
)
_ICON_GENERIC_CLUSTER = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" '
    'fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">'
    '<circle cx="12" cy="4.5" r="2.2"/><circle cx="5" cy="18" r="2.2"/><circle cx="19" cy="18" r="2.2"/>'
    '<path d="M12 6.7v5M7 16.4l3.8-4M17 16.4l-3.8-4"/>'
    '</svg>'
)
_ICON_GENERIC_MAIL = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" '
    'fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">'
    '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M4 6.5l8 6 8-6"/>'
    '</svg>'
)
_ICON_GENERIC_BACKUP = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" '
    'fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">'
    '<path d="M12 3l7 3v5c0 5-3.4 8.4-7 10-3.6-1.6-7-5-7-10V6z"/>'
    '</svg>'
)
_ICON_GENERIC_NETWORK = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" '
    'fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">'
    '<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/>'
    '<circle cx="7" cy="7" r="0.8" fill="currentColor" stroke="none"/>'
    '<circle cx="7" cy="17" r="0.8" fill="currentColor" stroke="none"/>'
    '</svg>'
)
_ICON_GENERIC_OS = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" '
    'fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">'
    '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/>'
    '</svg>'
)


# Real brand/company marks, sourced once from open icon sets (Simple Icons/Devicon/
# Font Awesome Free - see the per-icon comment below) and inlined as static SVG
# literals, minified with svgo (integer coordinate precision - imperceptible at the
# 18px render size below) to keep the details output reasonably sized - see "Output
# size limit" in the README. No runtime fetch, matching this plugin's no-network-calls
# design (see the module docstring). Colors are each brand's own, except a few
# near-black/near-white marks (macOS, Linux Containers) and single-color company marks
# with no official brand color available here, which use `currentColor` so they stay
# visible in both the light and dark GUI themes, same reasoning as `_ADD_RULE_LINK_STYLE`
# below.
# Devicon (MIT) oracle-original
_ICON_ORACLE = (
    '<svg width="18" height="18" viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#ea1b22" d="M55 66h9l-5-7-8 13h-3l9-15 2-1 2 1 10 15h-4l-1-3h-9zm39 3V56h-4v15l1 1h15l2-3zm-52-2a5 5 0 1 0 0-11H28v16h3V59h11l2 2-2 3h-9l9 8h5l-6-5zM9 72a8 8 0 1 1 0-16h9a8 8 0 0 1 0 16zm9-3a5 5 0 0 0 6-5 5 5 0 0 0-6-5H9a5 5 0 0 0-5 5 5 5 0 0 0 5 5zm60 3a8 8 0 1 1 0-16h11l-2 3h-9a5 5 0 0 0-5 5q0 5 5 5h11l-2 3zm38-3-5-3h13l2-3h-15a5 5 0 0 1 5-4h9l2-3h-11a8 8 0 0 0 0 16h9l2-3z"/></svg>'
)
# Simple Icons (CC0) mysql
_ICON_MYSQL = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#4479A1" d="M16 6zM6 19H5v-5l-2 5H2l-1-5v5H0v-6h2l1 4 1-4h1zm4-4-2 4-1 1H6h1v-2l-1-3h1l1 2v1l1-3zm12 4h-3v-6h1v5zm-3 0-1-1 1-2q0-3-2-3l-2 1-1 2 1 2 1 1h3m-3-1-1-2 1-2h1l1 2zm-2-1-1 1-1 1-2-1h3v-1l-1-1h-1l-1-1 1-1 1-1 2 1h-3l1 1 1 1zm9-6h-1v1l1 1h1l-1-1zh-1V9l-1-1V7l-2-2h-2V4h-2l1 1v2h1v3l1 1v-1l1 1 1 1h-1v-1l-1-1V9l-1 1V7l-1-1V5l-1-1h1l1 1h2l2 3v1l1 1h1z"/></svg>'
)
# Simple Icons (CC0) postgresql
_ICON_POSTGRESQL = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#4169E1" d="m24 15-2-1h-2l3-6V3q-2-3-5-3h-5l-3 1Q7-1 2 1L0 6l3 10 2 1h2l2-3 1 1-2 1-1 1 1 1 4-1v5l2 2h1q3 0 3-3l1-4 3-1zM2 12 1 6l2-4h6Q7 6 7 7v4l1 3-2 2-1 1-1-2zm6 5 2-1 1-1 1 1zm2-4v1l-2-1-1-2 1-3 2-1 1 1zm8 5zl-1 1v1l-2 2-2-1v-3l-1-2v-2l-1-1v-1l1-5q-1-3-3-2L8 7l1-5h1l3-1h1l4 2 1 3-2 1q-1 3 1 5v1l1 1-1 2v2m1-2v-1h4zm0-9zv5-1h-1q-1-3-1-5zm1 7zl1-4V6l-2-3-2-2h2l4 2h1zm-9-6zH9V7zm8-1zl-1-1z"/></svg>'
)
# Devicon (MIT) microsoftsqlserver-plain
_ICON_MSSQL = (
    '<svg width="18" height="18" viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="currentColor" d="m55 4-4 1q-15 6-19 11v3l4 3 3 3q9 9 8 20 0 13-12 26L25 81q-7 4-9 8-7 9 4 17t33 11l11 1 1-1 1-2q11-19 11-37l-2-17 5-2 38-9q1-1-3-6-15-15-46-20l-6-3-7-17zm2 4 1 6h-1l-15-2 7-4 7-3zm-11 6 12 2-4 3-5 2h-1l-2-2-6-6zm-5 3 3 3-7-2-2-1 4-3zm20 3 1 3-9-1 3-2 4-2zm-18 3 2 7-2-3-3-4-2-2 3 1zm8 1 6 1-9 7v-2l-3-7zm8 3 2 6v4l-3-1-8-3 4-4 5-3zm9 0 7 2-4 2-9 4q2-3-1-8v-1zm10 5-4 10-3-1-4-2-2-1 7-4q7-6 7-4zm5-2 14 5-2 1-18 6 1-3 3-10zm-30 7 4 2 1 1-8 7v-2l-1-8zm45 2L86 54l-2-2-7-8zm5-1 13 11-4 1-23 3 2-2 10-14zm-35 6 2 1-11 6 1-4 2-5v-1l2 1zm-9 0-4 9-2-1-3-2 9-8zm19 6 5 5-21 7 2-3 9-10 1-1h1zm-8-2-2 3-6 7-4 5v-1l-1-6-1-1 3-1zm-20 6 2 1-7 5 1-2 2-4 1-1zm5 6 1 4-15 7-3 1 15-13 1-1v1zm-5 0L38 71q-4 3 0-2l8-7zm24 2 1 5v3h-1l-10-6 10-3zm-6 6 5 4-12 6v-2l1-11zm-9-1v8l-2 3-4-4-3-5 9-3zm-10 5 5 6 2 2-16 7 2-4 6-12q0-2 1 1m-5 0-1 2-6 12-2-8-1-2 5-2zm31 4-2 11-6-2-6-4 1-1 11-6 1-1 1 1zm-44 4 3 8-16 5h-1v-1l2-5 12-9zm32 4 8 4h1l-1 1-18 7 6-13zm-8 0-6 14-10-8 5-3zm17 6-1 4-3 10-12-3-4-2 2-1zm-39 2-7 9-3 4-1-1-4-4-1-5v-1h1l15-3zm8 4 3 2 1 1-21 7 6-7 5-7 2 1zm2 11-3 5-6-1-7-4h-1l2-1 19-5zm10-5q6 2 13 3h2l-4 1-23 7 2-2 7-10zm14 8-3 7-16-2-3-2 4-1 19-5z"/></svg>'
)
# Simple Icons (CC0) mongodb
_ICON_MONGODB = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#47A248" d="M17 10q-3-8-4-9l-1-1-1 1c0 1-4 4-4 10-1 6 4 10 5 10v3l1-3 1-1 3-8zm-5 8V9l1 11z"/></svg>'
)
# Simple Icons (CC0) redis
_ICON_REDIS = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#FF4438" d="M23 13q-3 4-7 5-5-1-5-5l4 2q7-1 7-7t-8-7Q8 1 3 5l1 5 7-4L0 18l2 5h1l6-7q-1 6 6 7 5 0 9-9zm-5-5q-1 3-3 3l-3-1 4-4q3 0 2 2"/></svg>'
)
# Simple Icons (CC0) sap
_ICON_SAP = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#0FAAFF" d="M0 6v12h12L24 6zm3 2 3 1-1 1H2l2 1 2 2 2-5h2l2 6V8h2q4 0 4 3-1 2-3 2h-1v3h-4v-1H8l-1 1H5v-1l-2 1-3-1 1-1h3l-1-1-2-1-1-1 1-2zm11 2v2l2-1zm-5 1-1 2h2z"/></svg>'
)
# Simple Icons (CC0) couchbase
_ICON_COUCHBASE = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#EA2328" d="M20 14a1 1 0 0 1-1 2H5l-1-2V9l1-1h3v4h8V8h3l1 1zM12 0a12 12 0 1 0 0 24 12 12 0 0 0 0-24"/></svg>'
)
# Simple Icons (CC0) apache
_ICON_APACHE = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#D22128" d="M18 2zm1 0zm-5 1v1l-2 3v1h2l1-1 1-1 1-3zm-2 5zl-1 4-1 1v1l-1 1h1l3-1 1-2 1-2h-1l2-2-1 1h-1l1-1h1V7l-1 1 1-1-1 1zm-4 8v3-1l3-1h-1l1-1 1-1-3 1zm7-16-1 2v1l2-2-2 2h3V1zm-3 7 2-3V2l-1 1-2 3zm-3 8v-1l1-2 1-3V8h1l-1-2-1 1-1 2-1 3-1 2 1 2zm-2-1v2l-1-1 1 3-1-1 1 1-2 1 2-1-2 6h1l2-6v-2z"/></svg>'
)
# Simple Icons (CC0) nginx
_ICON_NGINX = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#009639" d="M12 0 2 6v12l10 6 10-6V6zm6 17-2 1-1-1-6-7v7l-2 1-1-1V7l2-1 1 1 6 7V7l2-1 1 1z"/></svg>'
)
# Font Awesome Free (CC BY 4.0) brands/microsoft
_ICON_MICROSOFT = (
    '<svg width="16" height="18" viewBox="0 0 448 512" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="currentColor" d="M0 32h215v215H0zm233 0h215v215H233zM0 265h215v215H0zm233 0h215v215H233z"/></svg>'
)
# Simple Icons (CC0) plesk
_ICON_PLESK = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#52BBE6" d="M6 7v7h1zm14 0v7zm0 5 3 2h1l-3-2 3-3h-1zm-4-3zv3h2l1 1-1 1h-1l-1-1-1 1h4v-2h-1v-1h-1l-1-1zh2V9zM2 9H0v8h1v-3h3v-1l1-1-1-1v-1zm9 0h-1l-1 1-1 1v2l1 1h4l-1-1v1h-1l-1-1-1-1h4l-1-2zm0 1zv1H9l1-1zm-9 0h1l1 2-1 1-1 1H1v-4zm2 6zh5v-1z"/></svg>'
)
# Simple Icons (CC0) eclipsemosquitto
_ICON_MOSQUITTO = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#3C5280" d="M1 11q0 5 3 7l-1 1-3-8q0-5 4-8l3 3a8 8 0 0 0-2 10l1-1a7 7 0 0 1 2-9l1 1 1 1 1 1-2 2q0 3 2 3v1a4 4 0 0 1-2-6L8 8a5 5 0 0 0 0 7l-3 3A9 9 0 0 1 5 6L4 5zm12 3a3 3 0 0 0 0-5l1-1 1-1 1-1a7 7 0 0 1 2 9l1 1a8 8 0 0 0-2-10l3-3 4 8q0 5-3 8l-1-1 3-7-3-6-1 1a9 9 0 0 1 0 12l-3-3a5 5 0 0 0 0-7l-1 1a4 4 0 0 1-2 6zm-1 7v-4l1-4a2 2 0 1 0-2 0l1 4Z"/></svg>'
)
# Simple Icons (CC0) prometheus
_ICON_PROMETHEUS = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#E6522C" d="M12 0a12 12 0 1 0 0 24 12 12 0 0 0 0-24m0 22q-3 0-3-2h6q0 2-3 2m6-3H6v-2h12zm0-3H6v-1l-1-2h3l-1-3q1-3 1-6l2 4 1-4 1-3q-1 1 1 5v3l2-6 1 4 1 3-2 3h4z"/></svg>'
)
# Simple Icons (CC0) docker
_ICON_DOCKER = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#2496ED" d="M14 11h2V9h-2zm-3-5h2V3h-2v3m0 2h2V6h-2zM8 8h2V6H8zM5 8h2V6H5zm6 3h2V9h-2zm-3 0h2V9H8zm-3 0h2V9H5zm-3 0h3V9H2zm22-1-2-1h-1l-2-2-1 1v3l-1 1H0l1 4q0 3 2 3l5 2 3-1 4-1 3-2 2-5h1l2-1z"/></svg>'
)
# Simple Icons (CC0) linuxcontainers
_ICON_LINUXCONTAINERS = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="currentColor" d="m10 9 2 1-6 3v-2zm2-1-2 1 2 1zM6 5v1l1 1 3 2 2-1-2-1zm0-1zl7 3 5 3 6-3-12-7zm6 13v2l6-4v-1zm0-9v2l6 3v-2zM2 9l4 2 4-2-4-2zm22-1-6 3v4l6-3zM12 18v-1l-4-3H6l-1-1-5-3v2zm6-5-6-3-6 3 6 4zm6-1-12 7v4l12-7zm-12 9v-2L0 12v4l12 7zM0 10l2-1-2-1zm6-4V4L0 8l2 1zm0 5L2 9H1l-1 1 6 3z"/></svg>'
)
# Simple Icons (CC0) podman
_ICON_PODMAN = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#892CA0" d="M17 0H7L0 9l2 10h1l9 5 10-5 2-10zm0 1 6 8-2 10-9 4-9-4L1 9l6-8zm-6 2H9Q6 4 6 7l-1 4v1l-1 2v2H3v1h9v1H8h8-4v-3l2-2h4l1 2 1 3h-3 4-1v-4h1-2l-1-1h2-2v-1h1v-1h-1l-1-4q0-3-3-4zm0 0 3 1 3 3v4l1 2-2-1-2-2 2 1-2-1h2-2q0-3-2-3t-2 3H7h3l-3 1h1l2-1v1l-1 1H6V7l3-3zM8 5zh3-1zm7 0-1 1zM9 7 7 8l2 1zm6 0-1 1 1 1zM9 7zv1L8 8zm6 0zl-1 1zm-3 1 2 2-2 1-2-1zm0 0zv2h-1l1 1 1-1v1h1v-1h-1 1V9zm0 1zM8 9zm7 0zm-1 1 1 1v-1zm-5 0H8zm5 1 1 1-1 1zm-4 0-1 1zm3 0 1 2-1 1h-2l-1-2v-1l2 1zm-6 1h2q2 1 2 3v1H9h1v-2l-1 1H8l-2 1H4v-1q0-2 2-3zm-1 1-1 1zm4 0H9v1zm4 1zm4 0zv-1zM6 14l-1 1 1 1zm5 0h1v2h-1zm-5 1zm4 0zm4 0zl1 1zm4 0-1 1-1-1-1 2h-2v1l2-1-2 1h3l2-1 1 1-1-1 1 1v-1h-1v-1 1l1-1zM8 15zv1zm6 0zm4 0zh-1zM8 16zm8 0 1 1h-1 1zh1-1zm0 0zm-2 1zm4 0zm-4 0zm4 0zm-2 1zm-9 1zh6v-1zm3 2h5z"/></svg>'
)
# Simple Icons (CC0) virtualbox
_ICON_VIRTUALBOX = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#2F61B4" d="m0 2 5 18 3 2h4l2-6h7v3h-5l-1 3h8l1-3v-6H12l-2 6H8L4 5h3l1 5h3L9 2zm15 0-2 8h11V5l-2-3h-1zm3 3h3v2h-4z"/></svg>'
)
# Simple Icons (CC0) veritas
_ICON_VERITAS = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#B1181E" d="m0 10 1 4h2l1-4H3l-1 3zm5 0zv2l1 1h2v-1H5v-1h2-2zh2zm4 0zv3h1zh2v1l-1 1-1 1h1l2 1-2-1v-1h1a1 1 0 0 0 0-2zm3 0v4h1v-4zm2 0zv4h1v-4h1zm4 0-2 4h1zl2 4-1-4zm4 0a1 1 0 1 0 0 2h1v1h-2v1h2a1 1 0 0 0 0-2h-1l-1-1zh2z"/></svg>'
)
# Simple Icons (CC0) veeam
_ICON_VEEAM = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#00B336" d="m7 10-2 2q0 2 2 2h1v-1H7l-2-1h4zm4 0-2 2 2 2h1l1-1h-2l-1-1h3zm-7 0-2 3-1-3H0l1 3 1 1h1v-1zm12 0zl-2 3v1h1v-1h2v-1h-1zl1 3h1v-1zm3 0zv3h1zl2 3h1l1-3v3h1v-3l-1-1-2 3zM7 11zH5zm4 0 1 1h-2z"/></svg>'
)
# Font Awesome Free (CC BY 4.0) brands/skype
_ICON_SKYPE = (
    '<svg width="16" height="18" viewBox="0 0 448 512" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="currentColor" d="M425 300q4-21 4-44A205 205 0 0 0 180 55q-29-22-68-23a112 112 0 0 0-89 180q-4 21-4 44a205 205 0 0 0 249 201 112 112 0 0 0 180-89q-1-39-23-68m-195 91c-65 0-120-29-120-65 0-16 9-30 29-30 31 0 34 45 88 45 26 0 42-12 42-27 1-18-15-21-41-28-63-15-118-22-118-87 0-59 58-81 109-81 55 0 111 22 111 55 0 17-12 32-31 32-28 0-29-33-75-33-25 0-42 7-42 22 0 20 21 22 69 33 42 9 91 27 91 78 0 59-57 86-112 86"/></svg>'
)
# Simple Icons (CC0) amazonec2
_ICON_AMAZON_EC2 = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#FF9900" d="M6 18h11V7H6zM18 7h2v1zv1h2v1h-2v2h2-2v2h2v1h-2v2h2v1h-3v2h-1v-2h-1v2h-1v-2h-2v2-2h-2v2H9v-2H7v2H6v-2H4v-1h2v-2H4v-1h2v-2H4h2v-2H4V9h2V8H4V7h2V4h1v2h2V4h1v2h2V4v2h2V4h1v2h1V4h1v2zm-6 16H1V12h2v-1H1l-1 1v11l1 1h11l1-1v-2h-1ZM24 1v11l-1 1h-2v-1h2zH12v2h-1V1l1-1z"/></svg>'
)
# Devicon (MIT) azure-original, gradients flattened
_ICON_AZURE = (
    '<svg width="18" height="18" viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#0078D4" d="M46 0h41L45 125a6 6 0 0 1-7 5H7a6 6 0 0 1-6-3v-6L40 4a6 6 0 0 1 6-4" transform="translate(1 4)scale(.91904)"/><path fill="#0078d4" d="M97 82H38a3 3 0 0 0-2 4l38 36 4 2h34z"/><path fill="#0078D4" d="M46 0a6 6 0 0 0-6 5L1 121a6 6 0 0 0 6 9h32a7 7 0 0 0 6-5l7-23 28 26 5 2h36l-16-46H58L87 0z" transform="translate(1 4)scale(.91904)"/><path fill="#0078D4" d="M98 4a6 6 0 0 0-6-4H47a6 6 0 0 1 6 4l39 117a6 6 0 0 1-6 9h45a6 6 0 0 0 6-9z" transform="translate(1 4)scale(.91904)"/></svg>'
)
# Simple Icons (CC0) linux
_ICON_LINUX = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#FCC624" d="M13 0zC8 0 9 5 9 6L8 9l-3 5v2l-1 1-1 1H2v4l1 1h3l3 1 1-1 2-1 3 1 2 1 2-1 2-2 1-1-1-1v-1l-1-1v-4l-2-3-2-4q1-4-3-6m0 3zv2h-1V5h1-1V4v1h-1V4zm-3 0zv1h-1V4v2H9V4zm1 2 2 1h1v1l-1 1h-3L9 7V6h1zm3 2 2 5 1 3h1l-1-4h-1l2 2v2q2 1 1 2l-1-2-2 1-1 1v3q-3 2-5 1l-1-1 1-1-1-1-1-1-2-2v-1l2-3-1 1v4l1-3 2-5 1 1 1-1h1zm2 9 1 2 2-1h1l1 1v1l1 1-1 1-2 1-2 2-2-1v-2l1-2v-3M6 16l1 1 1 2 1 1 1 2-1 1H6l-3-1v-4l1-1h1zm7-9-2 1-1-1q-1 0 0 0l1 1zm-2-1"/></svg>'
)
# Devicon (MIT) windows8-original
_ICON_WINDOWS = (
    '<svg width="18" height="18" viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#00adef" d="m126 2-67 9v50h67zM2 67v42l50 7V67zm56 0 1 50 67 9V68zM2 19v43l50-1V12z"/></svg>'
)
# Simple Icons (CC0) macos
_ICON_MACOS = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="currentColor" d="M0 15zv-3l1-1v4h1v-3l1-1 1 1v3h1v-3l-2-1H0zm8-1zl1-1h1zm0 1zh1v-3l-2-1-2 1h1l1-1 1 1H8l-2 2zm6-3-2-1q-2 0-2 2l2 2 2-2h-1l-1 1-1-1 1-2 1 1zm3-3q-3 0-3 3t3 3 2-3-2-3m0 1 1 2-1 2-2-2zm3 3 2 2 2-2-2-1v-1h-1l1-1 1 1h1l-2-2-2 2 1 1h1l1 1-1 1z"/></svg>'
)

# Icons for the `caps/snmp_plugin/<family>` labels (see `snmp_plugin_match.py`) -
# same three-tier sourcing as above. Two families (Aruba Networks, Check Point) have
# no mark in Simple Icons, Devicon, or Font Awesome Free's brand sets - checked, not
# assumed - and HP ProCurve is Hewlett-Packard's networking division, but the "HP"
# mark belongs to HP Inc., not Hewlett Packard Enterprise (Aruba's actual current
# owner) - using it for Aruba would misattribute the brand, so Aruba gets the generic
# network glyph instead, same as Check Point.
# Simple Icons (CC0) cisco
_ICON_CISCO = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#1BA0D7" d="M16.331 18.171V17.06l-.022.01c-.25.121-.522.19-.801.203a1.186 1.186 0 01-.806-.237 1.038 1.038 0 01-.352-.498 1.21 1.21 0 01-.023-.667c.052-.225.178-.426.357-.569.16-.134.355-.218.562-.242a1.85 1.85 0 011.061.198l.024.013v-1.117l-.051-.014a2.862 2.862 0 00-1.011-.132 2.34 2.34 0 00-.903.206c-.287.132-.54.327-.739.571a2.221 2.221 0 00-.04 2.705c.295.378.709.645 1.175.756.491.12 1.006.102 1.487-.052l.082-.023M5.336 18.171V17.06l-.022.01c-.25.121-.522.19-.801.203a1.183 1.183 0 01-.806-.237 1.03 1.03 0 01-.351-.498 1.202 1.202 0 01-.024-.667c.052-.225.177-.426.357-.569.16-.134.355-.218.562-.242a1.85 1.85 0 011.061.198l.024.013v-1.117l-.051-.014a2.862 2.862 0 00-1.011-.132 2.344 2.344 0 00-.903.206 2.08 2.08 0 00-.74.571 2.224 2.224 0 00-.041 2.705 2.11 2.11 0 001.176.756c.491.12 1.005.102 1.487-.052l.083-.023M9.26 17.249l-.004.957.07.012c.22.041.441.069.664.085.195.019.391.022.587.012.187-.014.372-.049.551-.104.21-.06.405-.163.571-.305a1.16 1.16 0 00.333-.478 1.31 1.31 0 00-.007-.96 1.068 1.068 0 00-.298-.414 1.261 1.261 0 00-.438-.255l-.722-.268a.388.388 0 01-.197-.188.245.245 0 01.008-.219.382.382 0 01.154-.142.798.798 0 01.257-.074c.153-.022.308-.021.46.005.18.02.358.051.533.096l.038.008v-.883l-.069-.015a4.749 4.749 0 00-.543-.097 2.844 2.844 0 00-.714-.003c-.3.027-.585.143-.821.33-.16.126-.281.293-.351.484-.104.29-.105.608 0 .899.054.145.14.274.252.381.097.093.207.173.327.236.157.084.324.149.497.195.057.017.114.035.17.054l.085.031.024.01c.084.03.162.078.226.14.045.042.08.094.101.151a.325.325 0 01.001.161.339.339 0 01-.166.198.856.856 0 01-.275.086 2.032 2.032 0 01-.427.021 5.208 5.208 0 01-.557-.074 9.195 9.195 0 01-.287-.067l-.033-.006zm-2.475.995h1.05v-4.167h-1.05v4.167zm12.162-2.936a1.095 1.095 0 011.541.158 1.094 1.094 0 01-.157 1.541l-.017.014a1.096 1.096 0 01-1.367-1.713m-1.525.854a2.193 2.193 0 002.666 2.107 2.139 2.139 0 00.701-3.937 2.207 2.207 0 00-3.367 1.83M22.961 10.728a.52.52 0 001.039 0V9.573a.52.52 0 00-1.039 0v1.155M20.117 10.728a.522.522 0 001.041 0V8.139a.521.521 0 00-1.04 0v2.589M17.231 11.771a.521.521 0 001.039 0V6.17a.52.52 0 00-1.039 0v5.601M14.393 10.728a.521.521 0 001.04 0V8.139a.52.52 0 00-1.039 0v2.589M11.494 10.728a.522.522 0 001.039 0V9.573a.52.52 0 00-1.039 0v1.155M8.624 10.728a.52.52 0 001.039 0V8.139a.52.52 0 00-1.039 0v2.589M5.737 11.771a.52.52 0 001.039 0V6.17a.52.52 0 00-1.039 0v5.601M2.876 10.728a.522.522 0 001.04 0V8.139a.52.52 0 00-1.039 0v2.589M0 10.728a.521.521 0 001.039 0V9.573a.52.52 0 00-1.039 0v1.155"/></svg>'
)
# Simple Icons (CC0) fortinet
_ICON_FORTINET = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#EE3124" d="M0 9.785h6.788v4.454H0zm8.666-6.33h6.668v4.453H8.666zm0 12.637h6.668v4.454H8.666zm8.522-6.307H24v4.454h-6.812zM2.792 3.455C1.372 3.814.265 5.404 0 7.425v.506h6.788V3.454zM0 16.091v.554c.24 1.926 1.276 3.466 2.624 3.9h4.188v-4.454zm24-8.184v-.506c-.265-1.998-1.372-3.587-2.792-3.972h-4.02v4.454H24zM21.376 20.57c1.324-.458 2.36-1.974 2.624-3.9v-.554h-6.812v4.454Z"/></svg>'
)
# Simple Icons (CC0) paloaltonetworks
_ICON_PALO_ALTO = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#F04E23" d="m10.278 15.443 1.705 1.705-3.426 3.426-3.427-3.426 8.592-8.591-1.705-1.705 3.426-3.426 3.427 3.426-8.592 8.591zM0 12.017l3.426 3.426 8.591-8.59-3.426-3.427L0 12.017zm11.983 5.13 3.426 3.427L24 11.983l-3.426-3.426-8.591 8.59z"/></svg>'
)
# Simple Icons (CC0) f5
_ICON_F5 = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#E4002B" d="M12 0C5.373 0 0 5.373 0 12a11.943 11.943 0 002.336 7.1113c.509.004.8594-.111.8984-.33.046-.229.0068-.5825-.0332-.9395a55.067 55.067 0 01-.2344-7.4473c-.609.027-1.1547.055-1.6777.086.02-.471.046-.9188.084-1.3828.517-.05 1.064-.0936 1.666-.1446.026-.406.0568-.7983.0918-1.1953.27-2.43 2.828-3.9162 4.959-4.4902.946-.23 1.5245-.3022 1.9785-.3262.164-.005.3405-.0117.5175-.0117.442 0 .8899.0414 1.1739.2344.46.345.9135.6873 1.3965 1.0683.048.065.1024.1678-.0176.3438-.222.26-.4371.5084-.6621.7754-.13.157-.3454.1164-.5274.0664-.38-.194-.7462-.3728-1.1172-.5528-.672-.299-1.3666-.6061-2.1406-.5761-.483.039-.951.532-1 1.209a101.41 101.41 0 00-.1504 3.2285c1.343-.038 2.6837-.0624 4.0957-.0684l-.002.9453c-.46.206-.8954.413-1.3574.623-.953.011-1.8595.0202-2.7715.0352a125.13 125.13 0 00.1192 7.9317c.024.378.0424.7605.1504 1.0175.13.322.8798.5701 2.5098.6621.007.284.0153.5532.0253.8282-2.655-.077-5.205-.3302-7.248-.6992A11.962 11.962 0 0012 24c6.628 0 12-5.373 12-12a11.942 11.942 0 00-2.0957-6.7754c-.147.607-.2252 1.2378-.3672 1.8828-1.8-.234-3.9131-.4053-6.2871-.4883-.191.602-.3711 1.192-.5781 1.836 3.973.245 5.9048 1.2924 7.0508 2.5254 1.113 1.248 1.3501 2.6262 1.2851 3.9062-.143 2.081-1.0613 3.3971-2.3203 4.3711-1.274.96-2.8139 1.436-4.0469 1.539-1.819.137-4.2515-.2962-4.7695-.6132a178.03 178.03 0 01-.9492-2.2012c-.08-.166-.1294-.3371.0976-.5351.354-.339.6928-.6667 1.0508-1.0137.158-.155.3338-.2991.4668-.0781.489.755.9473 1.4477 1.4063 2.1367.522.77 1.3167 1.4695 3.0527 1.3535 1.459-.13 2.5675-1.2333 2.6855-2.4473.128-2.246-2.1446-3.8396-8.0546-4.3496a2571.27 2571.27 0 013.123-9.371c1.404.065 2.7043.1798 3.9453.3398.919.116 1.772.3287 2.627.4277A11.973 11.973 0 0012 0zm10.0195 21.1113c-.5006 0-.9082.4076-.9082.9082 0 .5007.4076.9082.9082.9082.5007 0 .9082-.4075.9082-.9082 0-.5006-.4075-.9082-.9082-.9082zm0 .127c.4318 0 .7793.3495.7793.7812a.7776.7776 0 01-.7793.7793c-.4317 0-.7812-.3475-.7812-.7793a.7809.7809 0 01.7812-.7812zm-.3652.2773v.9961h.1738v-.3926h.1387c.092 0 .1583.0112.1953.0332.062.037.0938.1146.0938.2286v.08l.002.0293a.07.07 0 01.0039.0118c0 .005-.0001.0068.0039.0098h.162l-.0058-.0137a.106.106 0 01-.0078-.0488.6846.6846 0 01-.004-.0743v-.0742a.276.276 0 00-.0527-.1543c-.037-.053-.0948-.0846-.1718-.0976A.408.408 0 0022.328 22c.066-.042.0977-.1103.0977-.1973 0-.124-.0503-.21-.1543-.252a.752.752 0 00-.2695-.035zm.1738.123h.1504a.45.45 0 01.211.0372c.042.024.0664.0735.0664.1445a.153.153 0 01-.1036.1563.451.451 0 01-.166.0214h-.1582z"/></svg>'
)
# Simple Icons (CC0) junipernetworks
_ICON_JUNIPER = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#84B135" d="M23.0864 13.1643c.0456 0 .0717-.0132.0717-.062 0-.0482-.0254-.0593-.0731-.0593h-.1023v.1213zm-.1037.0417v.1285h-.0445v-.334h.1487c.0846 0 .1172.0347.1172.1006 0 .054-.0229.0912-.0806.102l.0755.1314h-.0484l-.0746-.1285zm.0746-.2918a.2535.2535 0 0 0-.2533.2531c0 .1395.1136.2532.2533.2532a.2535.2535 0 0 0 .253-.2532.2534.2534 0 0 0-.253-.2531zm-.291.2531a.2912.2912 0 0 1 .291-.2908.291.291 0 0 1 .2905.2908.291.291 0 0 1-.2905.2907.2912.2912 0 0 1-.291-.2907zm-20.7445-.6602V8.8304h-.4212v3.6767c0 .8506.0337 1.5332-1.4404 1.5332A4.029 4.029 0 0 1 0 14.0369v.397a6.215 6.215 0 0 0 .1602.0022c1.7858 0 1.8616-.8002 1.8616-1.929zm15.5404-1.6972h3.1334c-.042-.918-.1011-1.7014-1.4404-1.7014-1.2887 0-1.6425.6992-1.693 1.7014zm1.7016-2.0889c1.794 0 1.853 1.2045 1.8447 2.4764h-3.5548c.0085 1.1204.2863 1.9544 1.7436 1.9544.775 0 1.1288-.2107 1.5079-.4886l.2357.3116c-.421.3117-.918.556-1.7436.556-1.8194 0-2.1565-1.053-2.1565-2.4091 0-1.356.3877-2.4007 2.123-2.4007zm-4.1484 2.7055c.7439 0 1.1135-.3625 1.1135-1.0949 0-.7322-.3988-1.0798-1.132-1.0798h-1.7285v2.1747zM15.109 8.839c1.0678 0 1.5519.5307 1.5519 1.474 0 .9497-.478 1.527-1.5578 1.527h-1.7348v1.5981h-.4124V8.839zm-2.9253 0v4.5991h-.4122V8.839zm-1.1939 4.5991h-.4296v-2.8134c0-.8086.0084-1.491-1.474-1.491-1.4743 0-1.4405.6824-1.4405 1.5331v2.7713h-.4212v-2.7713c0-1.1288.076-1.9289 1.8616-1.9289 1.7943 0 1.9037.8001 1.9037 1.8952zM2.7466 8.8304h.4297v2.8134c0 .8088-.0084 1.491 1.474 1.491 1.4742 0 1.4405-.6822 1.4405-1.533V8.8303h.4212v2.7713c0 1.1289-.0759 1.929-1.8616 1.929-1.7943 0-1.9038-.8001-1.9038-1.8952zm18.9675 1.8364v2.7713h.421v-2.7713c0-.8507-.0336-1.533 1.4407-1.533.1579 0 .298.0083.4242.023v-.4012a4.8535 4.8535 0 0 0-.4242-.0177c-1.7859 0-1.8617.8001-1.8617 1.929zm-.4315 4.3602c.1525.096.3017.1286.4542.1286.2624 0 .3789-.0737.3789-.2486 0-.18-.1508-.2057-.3789-.2468-.2743-.048-.4594-.0944-.4594-.3514 0-.2453.1577-.3413.4594-.3413.199 0 .3412.0447.4423.1132l-.072.1097c-.0908-.06-.2263-.0995-.3703-.0995-.228 0-.3257.0636-.3257.2144 0 .1612.132.192.3584.233.2776.0499.4782.091.4782.3635 0 .2521-.1612.3737-.5074.3737-.192 0-.3652-.0393-.5263-.1456zm-.7886-.4423l-.2538.2777v.396h-.132v-1.2703h.132v.7012l.643-.7012h.156l-.456.4989.5176.7715h-.1525l-.4543-.6738m-1.1006.0326c.18 0 .2914-.0549.2914-.2555 0-.1971-.108-.2485-.2965-.2485h-.4132v.504zm-.0377.1234h-.3806v.5178h-.132V13.988h.5486c.2948 0 .4286.1183.4286.3703 0 .2194-.1046.348-.3258.377l.3068.523h-.1439l-.3017-.5177m-.924-.1166c0-.3429-.1594-.528-.5058-.528-.3446 0-.5023.1851-.5023.528 0 .3446.1577.5298.5023.5298.3464 0 .5058-.1852.5058-.5298zm-.5058-.6566c.408 0 .6412.2024.6412.655 0 .4542-.2332.6565-.6412.6565-.4063 0-.6377-.2023-.6377-.6566 0-.4525.2314-.6549.6377-.6549zm-2.3571.0206l.3342 1.0508.3412-1.0508h.1166l.3394 1.0508.336-1.0508h.1303l-.408 1.2789h-.1165l-.343-1.0577-.341 1.0577h-.1183l-.4098-1.2789zm-1.392.1286v-.1286h1.0886v.1286h-.4766v1.1418h-.1355v-1.1418zm-.204-.1286v.1286h-.7046v.42h.6874v.127h-.6874v.4713h.7114v.1235h-.8468V13.988zm-2.0539 0l.7596 1.0475V13.988h.1303v1.2704h-.1235l-.7835-1.0784v1.0784h-.1303V13.988Z"/></svg>'
)
# Simple Icons (CC0) hp
_ICON_HP = (
    '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#0096D6" d="M12.0069 24h-.3572l2.459-6.7453h3.3796c.5907 0 1.2364-.4533 1.4424-1.0166l2.6652-7.3085c.4396-1.1952-.2473-2.1706-1.525-2.1706h-4.6983l-3.929 10.798-2.2255 6.127C3.929 22.434 0 17.6806 0 12.007 0 6.498 3.7092 1.8546 8.7647.4396L6.4705 6.759 2.6514 17.2547h2.5415L8.4488 8.339h1.9095l-3.2558 8.9158H9.644l3.0223-8.3251c.4396-1.1952-.2473-2.1706-1.525-2.1706h-2.143l2.459-6.7453C11.636 0 11.8145 0 11.9931 0 18.6285 0 24 5.3715 24 12.007c.0137 6.6216-5.3578 11.993-11.9931 11.993zM19.2742 8.325h-1.9096l-2.6789 7.336h1.9096l2.6789-7.336z"/></svg>'
)
# generic network glyph - no brand mark available in any icon set checked (see above)
_ICON_ARUBA = _ICON_GENERIC_NETWORK
_ICON_CHECKPOINT = _ICON_GENERIC_NETWORK


DISPLAY_NAME_BY_LABEL: Mapping[str, str] = {
    "caps/db/oracle": "Oracle Database",
    "caps/db/mysql": "MySQL",
    "caps/db/postgres": "PostgreSQL",
    "caps/db/mssql": "Microsoft SQL Server",
    "caps/db/mongodb": "MongoDB",
    "caps/db/redis": "Redis",
    "caps/db/db2": "IBM Db2",
    "caps/db/sap_hana": "SAP HANA",
    "caps/db/couchbase": "Couchbase",
    "caps/web/apache": "Apache HTTP Server",
    "caps/web/nginx": "nginx",
    "caps/app/sap_netweaver": "SAP NetWeaver",
    "caps/app/exchange": "Microsoft Exchange",
    "caps/app/plesk": "Plesk",
    "caps/mq/activemq": "Apache ActiveMQ",
    "caps/mq/mqtt": "MQTT (Mosquitto)",
    "caps/monitoring/prometheus": "Prometheus",
    "caps/monitoring/alertmanager": "Alertmanager",
    "caps/container/docker": "Docker",
    "caps/container/lxc": "LXC",
    "caps/container/podman": "Podman",
    "caps/virt/hyperv": "Hyper-V",
    "caps/virt/virtualbox_guest": "VirtualBox",
    "caps/cluster/corosync": "Corosync",
    "caps/cluster/pacemaker": "Pacemaker",
    "caps/cluster/keepalived": "Keepalived",
    "caps/cluster/veritas_cluster_server": "Veritas Cluster Server",
    "caps/mail/postfix": "Postfix",
    "caps/backup/veeam": "Veeam",
    "caps/backup/tsm": "IBM Storage Protect (TSM)",
    "caps/backup/arcserve": "Arcserve Backup",
    "caps/backup/zerto": "Zerto",
    "caps/lb/haproxy": "HAProxy",
    "caps/cache/varnish": "Varnish",
    "caps/print/cups": "CUPS",
    "caps/file/nfs_server": "NFS Server",
    "caps/net/isc_dhcpd": "ISC DHCP",
    "caps/collab/domino": "IBM Domino",
    "caps/collab/skype_for_business": "Skype for Business",
    "caps/cloud/aws-vm": "AWS EC2",
    "caps/cloud/azure-vm": "Azure VM",
    "caps/os_type/linux": "Linux",
    "caps/os_type/windows": "Windows",
    "caps/os_type/macos": "macOS",
    "caps/os_type/solaris": "Solaris",
    "caps/os_type/aix": "AIX",
    "caps/snmp_plugin/cisco": "Cisco",
    "caps/snmp_plugin/juniper": "Juniper Networks",
    "caps/snmp_plugin/fortinet": "Fortinet",
    "caps/snmp_plugin/aruba": "Aruba Networks",
    "caps/snmp_plugin/hp_procurve": "HP ProCurve",
    "caps/snmp_plugin/checkpoint": "Check Point",
    "caps/snmp_plugin/palo_alto": "Palo Alto Networks",
    "caps/snmp_plugin/f5_bigip": "F5 BIG-IP",
}


# Icons for every `caps/*` label in the README's "Detected capabilities" table, plus
# the `caps/snmp_plugin/<family>` labels from `snmp_plugin_match.py` - see the
# sourcing comment above `_ICON_ORACLE` for the tiering rationale. Any future/
# unrecognized `caps/*` label is deliberately absent here and keeps the icon-less
# fallback in `_capability_display`.
ICON_BY_LABEL: Mapping[str, str] = {
    "caps/db/oracle": _ICON_ORACLE,
    "caps/db/mysql": _ICON_MYSQL,
    "caps/db/postgres": _ICON_POSTGRESQL,
    "caps/db/mssql": _ICON_MSSQL,
    "caps/db/mongodb": _ICON_MONGODB,
    "caps/db/redis": _ICON_REDIS,
    "caps/db/db2": _ICON_GENERIC_DATABASE,
    "caps/db/sap_hana": _ICON_SAP,
    "caps/db/couchbase": _ICON_COUCHBASE,
    "caps/web/apache": _ICON_APACHE,
    "caps/web/nginx": _ICON_NGINX,
    "caps/app/sap_netweaver": _ICON_SAP,
    "caps/app/exchange": _ICON_MICROSOFT,
    "caps/app/plesk": _ICON_PLESK,
    "caps/mq/activemq": _ICON_APACHE,
    "caps/mq/mqtt": _ICON_MOSQUITTO,
    "caps/monitoring/prometheus": _ICON_PROMETHEUS,
    "caps/monitoring/alertmanager": _ICON_PROMETHEUS,
    "caps/container/docker": _ICON_DOCKER,
    "caps/container/lxc": _ICON_LINUXCONTAINERS,
    "caps/container/podman": _ICON_PODMAN,
    "caps/virt/hyperv": _ICON_MICROSOFT,
    "caps/virt/virtualbox_guest": _ICON_VIRTUALBOX,
    "caps/cluster/corosync": _ICON_GENERIC_CLUSTER,
    "caps/cluster/pacemaker": _ICON_GENERIC_CLUSTER,
    "caps/cluster/keepalived": _ICON_GENERIC_CLUSTER,
    "caps/cluster/veritas_cluster_server": _ICON_VERITAS,
    "caps/mail/postfix": _ICON_GENERIC_MAIL,
    "caps/backup/veeam": _ICON_VEEAM,
    "caps/backup/tsm": _ICON_GENERIC_BACKUP,
    "caps/backup/arcserve": _ICON_GENERIC_BACKUP,
    "caps/backup/zerto": _ICON_GENERIC_BACKUP,
    "caps/lb/haproxy": _ICON_GENERIC_NETWORK,
    "caps/cache/varnish": _ICON_GENERIC_NETWORK,
    "caps/print/cups": _ICON_GENERIC_NETWORK,
    "caps/file/nfs_server": _ICON_GENERIC_NETWORK,
    "caps/net/isc_dhcpd": _ICON_GENERIC_NETWORK,
    "caps/collab/domino": _ICON_GENERIC_MAIL,
    "caps/collab/skype_for_business": _ICON_SKYPE,
    "caps/cloud/aws-vm": _ICON_AMAZON_EC2,
    "caps/cloud/azure-vm": _ICON_AZURE,
    "caps/os_type/linux": _ICON_LINUX,
    "caps/os_type/windows": _ICON_WINDOWS,
    "caps/os_type/macos": _ICON_MACOS,
    "caps/os_type/solaris": _ICON_ORACLE,
    "caps/os_type/aix": _ICON_GENERIC_OS,
    "caps/snmp_plugin/cisco": _ICON_CISCO,
    "caps/snmp_plugin/juniper": _ICON_JUNIPER,
    "caps/snmp_plugin/fortinet": _ICON_FORTINET,
    "caps/snmp_plugin/aruba": _ICON_ARUBA,
    "caps/snmp_plugin/hp_procurve": _ICON_HP,
    "caps/snmp_plugin/checkpoint": _ICON_CHECKPOINT,
    "caps/snmp_plugin/palo_alto": _ICON_PALO_ALTO,
    "caps/snmp_plugin/f5_bigip": _ICON_F5,
}


def _caps_labels(
    section_labels: Section | None,
    section_caps_scout_snmp_plugin_match: SysInfo | None,
) -> list[str]:
    from_agent = (
        (key for key in section_labels if key.startswith(CAPS_LABEL_PREFIX))
        if section_labels is not None
        else ()
    )
    from_snmp = (
        (label.name for label in host_label_snmp_plugin_match(section_caps_scout_snmp_plugin_match))
        if section_caps_scout_snmp_plugin_match is not None
        else ()
    )
    return sorted(set(from_agent) | set(from_snmp))


# Solid, fixed-color chip (rather than a `currentColor` outline) so it reads as
# unambiguously clickable regardless of the row's own text color, and renders
# identically in both the light and dark GUI themes - the one place in this file's
# output that isn't governed by `currentColor`. The plus is a plain SVG stroke, not
# an emoji, so its weight and baseline stay identical across every OS/browser.
_ADD_RULE_LINK_STYLE = (
    "white-space:nowrap;background:#2f6f6b;color:#fff;border-radius:6px;"
    "padding:3px 10px;text-decoration:none;font-size:0.85em;font-weight:600;"
)
_ICON_PLUS = (
    '<svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">'
    '<path d="M5 0v10M0 5h10" stroke="#fff" stroke-width="1.6"/></svg>'
)

# A faint divider under every row - low-contrast grey (rather than currentColor,
# which would be as strong as the text/icons) so it reads as a subtle separator in
# both the light and dark GUI themes. Applied identically to both `<td>`s of every
# row (with `border-collapse` on the `<table>`) so the two cells' borders merge into
# one continuous line, including rows whose Rules cell is just the em dash - a row
# never draws a stray full-width divider just because it has no rule.
_ROW_DIVIDER_STYLE = "border-bottom:1px solid rgba(128,128,128,0.35);"
_TD_CAPABILITY_STYLE = f"{_ROW_DIVIDER_STYLE}padding:6px 1.5em 6px 0;vertical-align:top;"
_TD_RULES_STYLE = f"{_ROW_DIVIDER_STYLE}padding:6px 0;vertical-align:top;"
_TH_STYLE = (
    f"{_ROW_DIVIDER_STYLE}text-align:left;padding:0 0 8px 0;"
    "font-size:0.8em;text-transform:uppercase;letter-spacing:0.04em;opacity:0.65;"
)
_TH_CAPABILITY_STYLE = f"{_TH_STYLE}padding-right:1.5em;"


def _capability_display(key: str) -> str:
    name = DISPLAY_NAME_BY_LABEL.get(key, key)
    icon = ICON_BY_LABEL.get(key)
    if icon is None:
        return name
    return f'<span style="display:inline-flex;align-items:center;gap:0.4em;">{icon}{name}</span>'


def _rule_chip(rule_name: str) -> str:
    url = f"wato.py?mode=new_rule&varname=agent_config:{rule_name}&_new_dflt_rule=1"
    return f'<a href="{url}" style="{_ADD_RULE_LINK_STYLE}">{_ICON_PLUS}&nbsp;Add rule</a>'


def _rule_row(rule_name: str) -> str:
    title = RULE_TITLE_BY_NAME.get(rule_name, rule_name)
    # Monospace only for the raw-varname fallback (it reads as code); a real title is
    # prose, so it gets plain, slightly muted text instead.
    style = "font-family:monospace;opacity:0.7;font-size:0.85em;" if title == rule_name else "opacity:0.7;font-size:0.9em;"
    label = f'<span style="{style}">{title}</span>'
    return (
        '<div style="display:flex;justify-content:space-between;align-items:center;gap:1em;">'
        f"{label}{_rule_chip(rule_name)}"
        "</div>"
    )


def _rules_cell(key: str) -> str:
    rules = BAKERY_RULES_BY_LABEL.get(key, ())
    if not rules:
        return '<span style="opacity:0.4;">&mdash;</span>'
    rows = "".join(_rule_row(r) for r in rules)
    if len(rules) == 1:
        return rows
    return f'<div style="display:flex;flex-direction:column;gap:6px;">{rows}</div>'


def _row(key: str) -> str:
    return (
        "<tr>"
        f'<td style="{_TD_CAPABILITY_STYLE}">{_capability_display(key)}</td>'
        f'<td style="{_TD_RULES_STYLE}">{_rules_cell(key)}</td>'
        "</tr>"
    )


def discover_capabilities_scout(
    section_labels: Section | None,
    section_caps_scout_snmp_plugin_match: SysInfo | None,
) -> DiscoveryResult:
    if _caps_labels(section_labels, section_caps_scout_snmp_plugin_match):
        yield Service()


def check_capabilities_scout(
    section_labels: Section | None,
    section_caps_scout_snmp_plugin_match: SysInfo | None,
) -> CheckResult:
    caps = _caps_labels(section_labels, section_caps_scout_snmp_plugin_match)
    if not caps:
        yield Result(state=State.OK, summary="No caps-scout capabilities currently detected")
        return

    table = (
        '<table style="border-collapse:collapse;width:100%;max-width:38em;">'
        f'<tr><th style="{_TH_CAPABILITY_STYLE}">Capability</th>'
        f'<th style="{_TH_STYLE}">Rules</th></tr>'
        + "".join(_row(key) for key in caps)
        + "</table>"
    )
    yield Result(
        state=State.OK,
        summary=", ".join(caps),
        details=table,
    )


check_plugin_capabilities_scout = CheckPlugin(
    name="capabilities_scout",
    service_name="Capabilities Scout",
    sections=["labels", "caps_scout_snmp_plugin_match"],
    discovery_function=discover_capabilities_scout,
    check_function=check_capabilities_scout,
)

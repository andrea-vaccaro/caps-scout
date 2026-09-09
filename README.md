# caps-scout

A Checkmk agent plugin that discovers host capabilities and reports them as Checkmk
host labels, as `caps/<capability>`. The goal is to eventually cover most of
Checkmk's official plugin surface; currently it detects database engines.

## Why

Checkmk ships dedicated plugins for monitoring specific, already-configured database
connections (Oracle, MySQL, PostgreSQL, ...), but nothing detects *which* database
engines are actually present on a host in the first place. caps-scout fills that gap:
it looks for running database processes and emits a host label for each engine it
finds, regardless of whether a corresponding official Checkmk plugin is already
installed and monitoring it — so the capability is visible on the host either way.

Full design rationale — including a survey of every host/service label Checkmk's
built-in plugins currently generate, and the decisions that shaped this project's
scope — is in [`docs/checkmk-label-catalog.md`](docs/checkmk-label-catalog.md).

## How it works

caps-scout runs as a Checkmk agent plugin: the Checkmk agent executes it each cycle
and includes its stdout in the agent output sent to the site. It prints a standard
Checkmk `<<<labels:sep(0)>>>` section — a JSON object of label key/value pairs —
which Checkmk's core turns into host labels automatically. No Checkmk-side plugin
code is required.

**caps-scout only emits a label when it finds something worth attention — a detected
capability. It prints nothing at all when it finds none of the capabilities it checks
for.** This means empty output is the expected, healthy result on most hosts — it does
*not* mean caps-scout failed to run. If you need to confirm caps-scout itself is
executing (as opposed to confirming it found no capabilities), check the agent's own
plugin execution log/output rather than looking for a caps-scout section.

### Scope

- Platforms built today: Linux and Windows (see Building, below). The OS probe (next
  section) also recognizes macOS, Solaris, and AIX for when those targets are added.
- Detected DB engines: presence of Oracle, MySQL, PostgreSQL, MSSQL, MongoDB, Redis,
  DB2, and SAP HANA, via process-name matching (`ora_pmon_*`, `mysqld`,
  `postgres`/`postmaster`, `sqlservr`, `mongod`, `redis-server`, `db2sysc`,
  `hdbdaemon`). One `caps/db/<engine>: "yes"` label per engine found.
- Detected web/app engines: presence of Apache, nginx, SAP NetWeaver (ABAP stack
  only), and Microsoft Exchange (Mailbox role only), via process-name matching
  (`httpd`/`apache2`, `nginx`, `disp+work`, `Microsoft.Exchange.Store.Service`).
  One `caps/web/<engine>: "yes"` or `caps/app/<engine>: "yes"` label per engine
  found.
- Detected Plesk: `caps/app/plesk: "yes"` if `/etc/psa/.psa.shadow` exists —
  file-based, not process-based, since Plesk's control-panel process can be
  stopped independently of the rest of the product (Linux only, mirroring
  Checkmk's own Plesk agent scripts).
- Detected Couchbase: `caps/db/couchbase: "yes"` if `/opt/couchbase` exists —
  directory-based, not process-based: Couchbase's per-service processes aren't
  guaranteed present on every node, and its always-present processes
  (`beam.smp`, `memcached`) are too generic to match reliably. Only catches
  the default install path.
- Detected messaging/monitoring engines: presence of ActiveMQ, Mosquitto (MQTT),
  Prometheus, and Alertmanager. ActiveMQ is Java, so its process name is just
  `java` — detection instead matches `activemq.jar` in the full command line
  (`caps/mq/activemq`). MQTT detection only covers Mosquitto, the most common
  self-hosted broker — other implementations (HiveMQ, EMQX, VerneMQ) aren't
  detected (`caps/mq/mqtt`). Prometheus and Alertmanager match their own
  binary names (`caps/monitoring/prometheus`, `caps/monitoring/alertmanager`).
- Detected container/virtualization engines: Docker (`caps/container/docker`,
  `dockerd` process) and LXC (`caps/container/lxc`, `lxc monitor` process —
  only while at least one container is running). Podman
  (`caps/container/podman`) is daemonless by default, so detection is
  file-based: it checks for the root API socket at `/run/podman/podman.sock`
  (the path Checkmk's own agent config uses for auto-detection), which misses
  a purely rootless setup with only per-user sockets. Hyper-V
  (`caps/virt/hyperv`) matches the `vmms.exe` management service (Windows
  only). VirtualBox (`caps/virt/virtualbox_guest`) matches the `VBoxService`
  guest-additions daemon — this detects the host itself running *as* a
  VirtualBox guest VM, not a host running VirtualBox as a hypervisor, since
  that's the only capability Checkmk's own `vbox` plugin actually checks for.
- Detected clustering/HA engines: Corosync (`caps/cluster/corosync`, `corosync`
  process) and Pacemaker/Heartbeat (`caps/cluster/pacemaker`, `crmd` or
  `pacemaker-contr` process) — both matching the exact gating logic in
  Checkmk's own core agent (`agents/check_mk_agent.linux:1170`). keepalived
  (`caps/cluster/keepalived`) matches its own standard process name. Veritas
  Cluster Server (`caps/cluster/veritas_cluster_server`) is file-based: it
  checks for `/opt/VRTSvcs/bin/haclus`, again matching Checkmk's own core
  agent's gating exactly (`agents/check_mk_agent.linux:1368`).
- Detected Postfix: `caps/mail/postfix: "yes"` if the command line of the
  running `master` process contains `postfix/master`, `postfix/sbin/master`,
  or `postfix/bin/master`. The bare `master` process name is too generic to
  match on its own (shared with Jenkins, gunicorn, etc.) — this matches
  Checkmk's own core-agent verification exactly
  (`agents/check_mk_agent.linux:1231`).
- Detected backup/DR engines: Veeam (`caps/backup/veeam`) matches the
  `Veeam.Backup.Service` process, the exact same check Checkmk's own
  `veeam_backup_status.ps1` agent script uses. IBM TSM/Storage Protect
  (`caps/backup/tsm`) matches `dsmserv` (server) or `dsmcad` (client
  scheduler), IBM's own standard process names. Arcserve Backup
  (`caps/backup/arcserve`) matches `dbeng.exe` or `jobeng.exe`, its primary
  server's core DB/Job Engine components — a different, older product line
  than Arcserve UDP/D2D, whose service name doesn't apply here. Zerto
  (`caps/backup/zerto`) matches `Zerto.Zvm.Service`, detecting a host
  running the Zerto Virtual Manager itself, not a host merely protected by
  Zerto's separate VRA appliance (which isn't detectable this way).
- Detected load balancing/caching engines: HAProxy (`caps/lb/haproxy`) matches
  the `haproxy` process, and Varnish (`caps/cache/varnish`) matches
  `varnishd`. Checkmk's own core agent instead checks for a stats
  socket/CLI-tool availability for both, which is about whether monitoring
  is configured, not whether the engine is present — caps-scout wants the
  latter, so it matches the daemon process directly.
- Detected file/print/network services: CUPS (`caps/print/cups`) matches
  `cupsd`. NFS server (`caps/file/nfs_server`) matches `rpc.mountd` rather
  than `nfsd` itself, since `nfsd` usually runs as kernel threads, not a
  normal process — `rpc.mountd` is a userspace daemon that only runs while
  the NFS server is active, matching the gating in Checkmk's own agent
  script. ISC DHCP (`caps/net/isc_dhcpd`) matches `dhcpd` — the underlying
  Checkmk plugin family is ISC DHCP only, with no BIND/`named` component.
- Detected collaboration engines: IBM Domino (`caps/collab/domino`) matches
  `nserver`, and Skype for Business (`caps/collab/skype_for_business`)
  matches `RtcSrv`/`Rtcsrv` — the Front End server role only, matching the
  scope of Checkmk's own check.
- Detected cloud VM provisioning, purely from local host state, no network
  call to any instance metadata service: AWS (`caps/cloud/aws-vm: "yes"` if
  `/sys/devices/virtual/dmi/id/board_asset_tag` contains an
  instance-ID-shaped value, `i-` + hex — AWS's own documented,
  non-privileged EC2 detection method; covers essentially all of today's
  EC2 fleet except a documented, permanent exception: legacy GPU/FPGA
  instance families, which never run on the Nitro hardware this check
  relies on) and Azure (`caps/cloud/azure-vm: "yes"` if
  `/sys/devices/virtual/dmi/id/chassis_asset_tag` exactly equals the fixed
  value Azure hard-codes into every VM, `7783-7084-3265-9085-8269-3286-77`
  — the same check `cloud-init` itself uses). Both are unrelated to
  Checkmk's `aws`/`azure` plugins, which need API credentials and report on
  cloud-side resources, not the host itself — these answer "was this host
  provisioned by AWS/Azure", not "what cloud resources exist".
- Detected OS: one `caps/os_type/<name>: "yes"` label for the host's OS (`linux`,
  `windows`, `macosx`, `solaris`, or `aix`), determined at compile time — the same
  one-build-per-platform approach Checkmk's own agents use for `AgentOS`/
  `cmk/os_family` (see `docs/checkmk-label-catalog.md`). This intentionally
  duplicates the core agent's `cmk/os_family` label.
- Labels are emitted whenever a capability is detected, regardless of whether a
  corresponding official Checkmk plugin is already installed and monitoring it —
  caps-scout does not check for or suppress on an installed plugin.

## Building

```sh
cargo build --release
```

Cross-compiling for Windows requires the `x86_64-pc-windows-gnu` target and a mingw
linker:

```sh
rustup target add x86_64-pc-windows-gnu
# apt install mingw-w64   (or equivalent for your OS)
cargo build --release --target x86_64-pc-windows-gnu
```

## Installing as a Checkmk agent plugin

Drop the compiled binary into the host's Checkmk agent plugin directory:

- Linux: `/usr/lib/check_mk_agent/plugins/caps-scout`
- Windows: `C:\ProgramData\checkmk\agent\plugins\caps-scout.exe`

Make sure it's executable (Linux: `chmod +x`). The Checkmk agent will pick it up and
run it on the next cycle.

## SNMP plugin-match labels (Checkmk-side plugin)

`checkmk_plugin/` ships a second, independent piece: a Checkmk-side `agent_based`
plugin — not the Rust binary above — that emits `caps/snmp_plugin/<family>: "yes"`
host labels identifying which of Checkmk's own SNMP device plugin families would
actually attach to this host (currently: `cisco`, `juniper`, `fortinet`, `aruba`,
`hp_procurve`, `checkpoint`, `palo_alto`, `f5_bigip` — a deliberate subset of the
~150 SNMP-monitored appliance families Checkmk ships, not the full catalog), so the
label points straight at a plugin the user might go activate. It fetches the two
universal SNMPv2-MIB System-group scalars (`sysDescr`, `sysObjectID`) and, per
family, replicates the exact `detect=` condition that family's own plugin uses to
decide it applies — cited from Checkmk's source per function. See the module
docstring in
`checkmk_plugin/cmk_addons/plugins/caps_scout/agent_based/snmp_plugin_match.py` for
the full rationale, including where a family's real condition was simplified to
avoid an extra per-vendor SNMP fetch.

This deliberately reuses the host's already-configured "SNMP credentials" rule —
Checkmk's core fetches the data the same way it would for any other SNMP-based
check, so no credentials are entered or duplicated anywhere in this plugin.

The same MKP also ships a **"Capabilities Scout" service**
(`checkmk_plugin/cmk_addons/plugins/caps_scout/agent_based/capabilities_scout.py`)
that makes caps-scout's own `caps/*` host labels visible as a service instead of
only in the host's label set. It doesn't fetch or parse anything itself — it
subscribes to the same `labels` agent section Checkmk's core already parses into
host labels (the section the Rust binary above writes, `agents/check_mk_agent.linux`
also writes for its own `cmk/*` labels), and filters it down to the `caps/*` keys.
One service is discovered per host once any `caps/*` label is present; its summary
and details both list every `caps/*` label key found (the value is always `"yes"`, so
it's omitted), one per line as a bullet point (`• caps/<key>`) in the details. For
labels with a known corresponding Checkmk agent-bakery rule (the rule that deploys or
configures the plugin actually monitoring that engine — `mk_postgres`, `apache_status`,
`mk_docker`, and so on; see `BAKERY_RULE_BY_LABEL` in
`capabilities_scout.py` for the full, deliberately non-exhaustive list), the bullet
also gets an **"Add rule"** link straight to that rule's "new rule" WATO page.
Rendering it as a clickable link rather than literal `<a href=...>` text requires a
rule in Setup → Services → Service monitoring rules → **"Escape HTML in service
output (dangerous to deactivate - read help)"** (ruleset
`extra_service_conf:_ESCAPE_PLUGIN_OUTPUT`), set to "Don't escape HTML" and scoped
via a service condition to `Capabilities Scout` — then **activate changes**, since
the setting only takes effect on the core after that. Off by default since plugin
output is normally untrusted, but safe here because every value it can ever contain
comes from this plugin's own fixed code, never from external input.

On a host where caps-scout finds many capabilities, the details' per-row markup
(the flex row and the "Add rule" pill's inline styles, on top of the label itself)
can add up past Checkmk's default long-output size limit — 2000 bytes. When that
happens, the details view shows a warning that the output was truncated, with a
link in that warning message itself; clicking it goes straight to **Setup → Global
settings → "Maximum long output size"**, where raising the value (in bytes) is the
fix — there's nothing to change in this plugin.

The same MKP also ships a **bakery rule** for the Rust agent plugin itself — an
alternative to the manual copy-and-`chmod` steps under "Installing as a Checkmk agent
plugin" above. It bakes the plugin binaries at
`checkmk_plugin/cmk_addons/plugins/caps_scout/agents/caps-scout` (Linux) and
`caps-scout.exe` (Windows, built per the cross-compiling instructions under
"Building") straight onto the agent package, so a host just needs to be covered by
the rule to pick it up. It's Setup -> Agents -> "Windows, Linux, Solaris, AIX agent
settings" -> **"caps-scout (capability discovery)"**: a single "Deploy the caps-scout
plug-in" checkbox — there's nothing else to configure, since the plugin takes no
arguments. See `checkmk_plugin/cmk_addons/plugins/caps_scout/bakery/caps_scout.py`
(the bakery plugin) and `.../rulesets/caps_scout_bakery.py` (the WATO rule).

Build and install it as an MKP:

```sh
cd checkmk_plugin
python3 build_mkp.py --manifest manifest.json --output caps-scout-snmp-1.2.0.mkp
mkp add caps-scout-snmp-1.2.0.mkp
mkp enable caps-scout-snmp 1.2.0
```

After enabling a rule, "bake" and "sign" the agent package (Setup -> Agents -> "Bake
and sign agents", or the CLI `cmk-agent-ctl`/`cmk --bake-agents` equivalent) and
activate changes, same as for any other bakery rule.

Then run (or wait for) service discovery / "Update host labels" on an SNMP-monitored
host. `manifest.json`'s `version.min_required`/`version.packaged` target Checkmk
2.3.0 (the `cmk_addons.plugins` layout this uses) — adjust to your site's version if
different.

Unit tests for the plugin's `parse_snmp_capabilities` and
`host_label_snmp_capabilities` functions live in `checkmk_plugin/tests/` and run with
the standard library alone (no Checkmk installation or extra dependency needed —
`tests/_cmk_stub.py` fakes the handful of `cmk.agent_based.v2` names the plugin
imports at load time):

```sh
cd checkmk_plugin
python3 -m unittest discover -s tests -v
```

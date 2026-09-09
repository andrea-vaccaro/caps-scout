# caps-scout

A Checkmk agent plugin that discovers host capabilities and reports them as Checkmk
host labels, as `caps/<capability>`. The goal is to eventually cover most of
Checkmk's official plugin surface; the current coverage spans databases, web/app
servers, containers and virtualization, clustering/HA, backup/DR, messaging and
monitoring engines, collaboration platforms, and cloud VM provisioning — see
[Detected capabilities](#detected-capabilities) below for the full list.

## Why

Checkmk ships dedicated plugins for monitoring specific, already-configured
integrations (a database connection, a web server's status page, ...), but nothing
detects *which* of those engines are actually present on a host in the first place.

caps-scout fills that gap: it looks for the engine itself — a running process, or,
where a process match isn't reliable, a file or directory only that engine would
create — and emits a host label for each one it finds, regardless of whether a
corresponding official Checkmk plugin is already installed and monitoring it — so
the capability is visible on the host either way.

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

Platforms built today: Linux and Windows (see Building, below). The OS probe (the
last row of the table below) also recognizes macOS, Solaris, and AIX for when those
targets are added.

Every label below is `"yes"`-valued and emitted only when the capability is found —
see "How it works" above. Labels are emitted regardless of whether a corresponding
official Checkmk plugin is already installed and monitoring the engine — caps-scout
does not check for or suppress on an installed plugin.

### Detected capabilities

| Category | Engine | Label | Detected via | Notes |
| --- | --- | --- | --- | --- |
| Database | Oracle | `caps/db/oracle` | `ora_pmon_*` process | |
| Database | MySQL | `caps/db/mysql` | `mysqld` process | |
| Database | PostgreSQL | `caps/db/postgres` | `postgres`/`postmaster` process | |
| Database | MSSQL | `caps/db/mssql` | `sqlservr` process | |
| Database | MongoDB | `caps/db/mongodb` | `mongod` process | |
| Database | Redis | `caps/db/redis` | `redis-server` process | |
| Database | DB2 | `caps/db/db2` | `db2sysc` process | |
| Database | SAP HANA | `caps/db/sap_hana` | `hdbdaemon` process | |
| Database | Couchbase | `caps/db/couchbase` | `/opt/couchbase` exists | File-based: per-service processes aren't guaranteed present, and always-present ones (`beam.smp`, `memcached`) are too generic. Default install path only. |
| Web / app | Apache | `caps/web/apache` | `httpd`/`apache2` process | |
| Web / app | nginx | `caps/web/nginx` | `nginx` process | |
| Web / app | SAP NetWeaver | `caps/app/sap_netweaver` | `disp+work` process | ABAP stack only |
| Web / app | Microsoft Exchange | `caps/app/exchange` | `Microsoft.Exchange.Store.Service` process | Mailbox role only |
| Web / app | Plesk | `caps/app/plesk` | `/etc/psa/.psa.shadow` exists | File-based (Linux only) — the control-panel process can stop independently of the rest of the product |
| Messaging / monitoring | ActiveMQ | `caps/mq/activemq` | `activemq.jar` in the command line | Process name is just `java`, so it can't be matched directly |
| Messaging / monitoring | MQTT (Mosquitto) | `caps/mq/mqtt` | `mosquitto` process | Mosquitto only — HiveMQ, EMQX, VerneMQ etc. aren't detected |
| Messaging / monitoring | Prometheus | `caps/monitoring/prometheus` | `prometheus` process | |
| Messaging / monitoring | Alertmanager | `caps/monitoring/alertmanager` | `alertmanager` process | |
| Container / virtualization | Docker | `caps/container/docker` | `dockerd` process | |
| Container / virtualization | LXC | `caps/container/lxc` | `lxc monitor` process | Only while at least one container is running |
| Container / virtualization | Podman | `caps/container/podman` | `/run/podman/podman.sock` exists | Root API socket only — misses a purely rootless setup |
| Container / virtualization | Hyper-V | `caps/virt/hyperv` | `vmms.exe` process | Windows only |
| Container / virtualization | VirtualBox guest | `caps/virt/virtualbox_guest` | `VBoxService` process | Detects the host running *as* a VirtualBox guest, not a VirtualBox hypervisor host |
| Clustering / HA | Corosync | `caps/cluster/corosync` | `corosync` process | |
| Clustering / HA | Pacemaker/Heartbeat | `caps/cluster/pacemaker` | `crmd`/`pacemaker-contr` process | |
| Clustering / HA | keepalived | `caps/cluster/keepalived` | `keepalived` process | |
| Clustering / HA | Veritas Cluster Server | `caps/cluster/veritas_cluster_server` | `/opt/VRTSvcs/bin/haclus` exists | File-based |
| Mail | Postfix | `caps/mail/postfix` | `master` process, command line contains `postfix/master` (or `postfix/sbin\|bin/master`) | Bare `master` is too generic (shared with Jenkins, gunicorn, etc.) |
| Backup / DR | Veeam | `caps/backup/veeam` | `Veeam.Backup.Service` process | |
| Backup / DR | IBM TSM/Storage Protect | `caps/backup/tsm` | `dsmserv` (server) / `dsmcad` (client scheduler) process | |
| Backup / DR | Arcserve Backup | `caps/backup/arcserve` | `dbeng.exe`/`jobeng.exe` process | The older Arcserve Backup line, not UDP/D2D |
| Backup / DR | Zerto | `caps/backup/zerto` | `Zerto.Zvm.Service` process | Zerto Virtual Manager host only, not a host merely protected by a separate VRA appliance |
| Load balancing / caching | HAProxy | `caps/lb/haproxy` | `haproxy` process | |
| Load balancing / caching | Varnish | `caps/cache/varnish` | `varnishd` process | |
| File / print / network | CUPS | `caps/print/cups` | `cupsd` process | |
| File / print / network | NFS server | `caps/file/nfs_server` | `rpc.mountd` process | Not `nfsd` itself, which usually runs as kernel threads |
| File / print / network | ISC DHCP | `caps/net/isc_dhcpd` | `dhcpd` process | ISC DHCP only, no BIND/`named` component |
| Collaboration | IBM Domino | `caps/collab/domino` | `nserver` process | |
| Collaboration | Skype for Business | `caps/collab/skype_for_business` | `RtcSrv`/`Rtcsrv` process | Front End server role only |
| Cloud VM provisioning | AWS EC2 | `caps/cloud/aws-vm` | DMI board asset tag matches `i-<hex>` | AWS's documented, non-privileged EC2 detection method; misses only legacy GPU/FPGA families (never on Nitro hardware) |
| Cloud VM provisioning | Azure VM | `caps/cloud/azure-vm` | DMI chassis asset tag equals Azure's fixed VM marker | Same check `cloud-init` itself uses |
| OS | Linux / Windows / macOS / Solaris / AIX | `caps/os_type/<name>` | Compiled per-platform | Duplicates the core agent's own `cmk/os_family` label |

Both cloud checks read local host state only (DMI/SMBIOS data) — no network call to
an instance metadata service — and are unrelated to Checkmk's `aws`/`azure` plugins,
which need API credentials and report on cloud-*side* resources rather than the host
itself: these answer "was this host provisioned by AWS/Azure", not "what cloud
resources exist".

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

## Testing the agent plugin

```sh
cargo test
```

This runs the per-probe unit tests embedded in `src/` (each probe module tests its own
matching logic in isolation) alongside two black-box test files in `tests/`:

- `binary_output.rs` runs the compiled binary and asserts the *shape* of its stdout
  contract — empty, or a well-formed `<<<labels:sep(0)>>>` section whose JSON keys all
  start with `caps/` and whose values are all `"yes"` — regardless of what's actually
  installed on the machine running the tests.
- `docker_apache.rs` is a component test: it starts a real `httpd:alpine` container and
  confirms caps-scout detects it as `caps/web/apache`. It needs a working Docker daemon
  and network access to pull the image, but runs under plain `cargo test` with no
  `#[ignore]` flag — it instead detects at runtime whether those prerequisites are met,
  printing why and returning early (counted as passed, not skipped) if they aren't, so
  the reason is visible in normal test output instead of hidden behind a flag.

## Installing as a Checkmk agent plugin

Drop the compiled binary into the host's Checkmk agent plugin directory:

- Linux: `/usr/lib/check_mk_agent/plugins/caps-scout`
- Windows: `C:\ProgramData\checkmk\agent\plugins\caps-scout.exe`

Make sure it's executable (Linux: `chmod +x`). The Checkmk agent will pick it up and
run it on the next cycle.

## Checkmk-side plugin (`checkmk_plugin/`)

`checkmk_plugin/` packages three independent pieces into a single Checkmk MKP, all
under the `caps_scout` plugin family:

- **SNMP plugin-match labels** — host labels pointing at Checkmk's own SNMP device
  plugins that would apply to a host.
- **Capabilities Scout service** — a service that surfaces the Rust agent plugin's
  own `caps/*` labels.
- **Bakery rule** — deploys the Rust agent plugin itself via Checkmk's Agent Bakery,
  as an alternative to the manual install above.

They ship together as one MKP because they're all part of the same project, but each
works independently of the other two — enable only the parts you want.

### SNMP plugin-match labels

This is a Checkmk-side `agent_based` plugin — not the Rust binary above — that emits
`caps/snmp_plugin/<family>: "yes"` host labels identifying which of Checkmk's own
SNMP device plugin families would actually attach to this host, so the label points
straight at a plugin the user might go activate.

It fetches the two universal SNMPv2-MIB System-group scalars (`sysDescr`,
`sysObjectID`) and, per family, replicates the exact `detect=` condition that
family's own plugin uses to decide it applies — cited from Checkmk's source per
function. See the module docstring in
`checkmk_plugin/cmk_addons/plugins/caps_scout/agent_based/snmp_plugin_match.py` for
the full rationale, including where a family's real condition was simplified to
avoid an extra per-vendor SNMP fetch.

This deliberately reuses the host's already-configured "SNMP credentials" rule —
Checkmk's core fetches the data the same way it would for any other SNMP-based
check, so no credentials are entered or duplicated anywhere in this plugin.

This covers a deliberate subset of the ~150 SNMP-monitored appliance families
Checkmk ships, not the full catalog:

| Family | Label | Matches |
| --- | --- | --- |
| Cisco | `caps/snmp_plugin/cisco` | `sysDescr` contains "cisco" |
| Juniper | `caps/snmp_plugin/juniper` | `sysObjectID` starts with `.1.3.6.1.4.1.2636.1.1.1` (general Junos signal; the legacy Trapeze-wifi and ScreenOS/NetScreen sub-lines aren't covered) |
| Fortinet | `caps/snmp_plugin/fortinet` | `sysObjectID` matches a FortiGate/FortiMail/FortiSandbox/FortiAuthenticator OID prefix |
| Aruba | `caps/snmp_plugin/aruba` | `sysDescr` matches `Aruba.+2930M.*`, or `sysObjectID` starts with `.1.3.6.1.4.1.14823.1.1` (WLC) — only these two product lines, not Aruba's full catalog |
| HP ProCurve | `caps/snmp_plugin/hp_procurve` | `sysObjectID` contains `.11.2.3.7.11` or `.11.2.3.7.8` |
| Check Point | `caps/snmp_plugin/checkpoint` | `sysObjectID` starts with `.1.3.6.1.4.1.2620`, or `sysDescr` matches a Gaia/IPSO/`cpx` pattern |
| Palo Alto | `caps/snmp_plugin/palo_alto` | `sysObjectID` contains `25461` |
| F5 BIG-IP | `caps/snmp_plugin/f5_bigip` | `sysObjectID` contains `.1.3.6.1.4.1.3375.2` |

Check Point and F5 BIG-IP's real `detect=` conditions also AND in a second,
vendor-specific OID beyond `sysDescr`/`sysObjectID`; that second condition is
dropped here to avoid an extra per-vendor SNMP fetch tree, at the cost of being
slightly more permissive than the real plugin for those two families — see the
module docstring for details.

### Capabilities Scout service

`checkmk_plugin/cmk_addons/plugins/caps_scout/agent_based/capabilities_scout.py`
makes caps-scout's own `caps/*` host labels visible as a service instead of only in
the host's label set. It doesn't fetch or parse anything itself — it subscribes to
the same `labels` agent section Checkmk's core already parses into host labels (the
section the Rust binary writes, and that `agents/check_mk_agent.linux` also writes
for its own `cmk/*` labels), and filters it down to the `caps/*` keys.

One service is discovered per host once any `caps/*` label is present. Its summary
and details both list every `caps/*` label key found (the value is always `"yes"`,
so it's omitted), one per line as a bullet point (`• caps/<key>`) in the details.

**"Add rule" links.** For labels with a known corresponding Checkmk agent-bakery
rule (the rule that deploys or configures the plugin actually monitoring that
engine — `mk_postgres`, `apache_status`, `mk_docker`, and so on; see
`BAKERY_RULE_BY_LABEL` in `capabilities_scout.py` for the full, deliberately
non-exhaustive list), the bullet also gets an **"Add rule"** link straight to that
rule's "new rule" WATO page.

**Enabling clickable links.** Rendering that link as clickable HTML rather than
literal `<a href=...>` text requires a rule in Setup → Services → Service monitoring
rules → **"Escape HTML in service output (dangerous to deactivate - read help)"**
(ruleset `extra_service_conf:_ESCAPE_PLUGIN_OUTPUT`), set to "Don't escape HTML" and
scoped via a service condition to `Capabilities Scout` — then **activate changes**,
since the setting only takes effect on the core after that. Off by default since
plugin output is normally untrusted, but safe here because every value it can ever
contain comes from this plugin's own fixed code, never from external input.

**Output size limit.** On a host where caps-scout finds many capabilities, the
details' per-row markup (the flex row and the "Add rule" pill's inline styles, on
top of the label itself) can add up past Checkmk's default long-output size limit —
2000 bytes. When that happens, the details view shows a warning that the output was
truncated, with a link in that warning message itself; clicking it goes straight to
**Setup → Global settings → "Maximum long output size"**, where raising the value
(in bytes) is the fix — there's nothing to change in this plugin.

### Bakery rule for the agent plugin

`checkmk_plugin/cmk_addons/plugins/caps_scout/bakery/caps_scout.py` deploys the Rust
agent plugin itself via Checkmk's Agent Bakery — an alternative to the manual
copy-and-`chmod` steps under "Installing as a Checkmk agent plugin" above. It bakes
the plugin binaries at
`checkmk_plugin/cmk_addons/plugins/caps_scout/agents/caps-scout` (Linux) and
`caps-scout.exe` (Windows) straight onto the agent package, so a host just needs to
be covered by the rule to pick it up.

The corresponding WATO rule
(`checkmk_plugin/cmk_addons/plugins/caps_scout/rulesets/caps_scout_bakery.py`) lives
under Setup → Agents → "Windows, Linux, Solaris, AIX agent settings" →
**"caps-scout (capability discovery)"**: a single "Deploy the caps-scout plug-in"
checkbox — there's nothing else to configure, since the plugin takes no arguments.

Those two binaries are build output, not checked into the repo (see `.gitignore`) —
`build_mkp.py` builds them itself from `src/` via `cargo` (native + the
`x86_64-pc-windows-gnu` target, so the Windows cross-compile toolchain from
"Building" above must be set up) every time it runs, so the MKP can never ship a
binary older than the source it came from. Pass `--skip-agent-build` to reuse
whatever is already in that `agents/` folder instead.

After enabling the rule, "bake" and "sign" the agent package (Setup → Agents →
"Bake and sign agents", or the CLI `cmk-agent-ctl`/`cmk --bake-agents` equivalent)
and activate changes, same as for any other bakery rule.

### Building and installing the MKP

```sh
cd checkmk_plugin
python3 build_mkp.py --manifest manifest.json --output caps-scout-snmp-1.3.1.mkp
mkp add caps-scout-snmp-1.3.1.mkp
mkp enable caps-scout-snmp 1.3.1
```

Then run (or wait for) service discovery / "Update host labels" on a host, so the
new services and labels this MKP adds get picked up. `manifest.json`'s
`version.min_required`/`version.packaged` target Checkmk 2.3.0 (the
`cmk_addons.plugins` layout this uses) — adjust to your site's version if different.

### Running the tests

Unit tests for the SNMP plugin's `parse_snmp_plugin_match`/
`host_label_snmp_plugin_match` functions, and for the Capabilities Scout service's
discovery/check functions, live in `checkmk_plugin/tests/` and run with the standard
library alone — no Checkmk installation or extra dependency needed.
`tests/_cmk_stub.py` fakes the handful of `cmk.agent_based.v2` names these plugins
import at load time:

```sh
cd checkmk_plugin
python3 -m unittest discover -s tests -v
```

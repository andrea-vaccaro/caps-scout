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
| Database | Couchbase | `caps/db/couchbase` | `/opt/couchbase` exists | Directory-based — per-service processes aren't reliably present; default install path only |
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
- **Capabilities Scout service** — a service that surfaces every `caps/*` label on
  the host, from both the Rust agent plugin and the SNMP plugin-match labels above.
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

This covers 94 of the ~150-280 SNMP-monitored appliance families Checkmk ships,
not the full catalog — a further ~26 directories are known but not yet
individually researched, and a handful (`hp_proliant`, `keepalived`, `entersekt`,
`quantum`, `fujitsu`, `primekey`, `artec`, `zertificon`, plus `oracle_snmp`,
`supermicro`, `domino`, `quanta`, `stormshield`, `synology` found while wiring in
this batch) were deliberately excluded because their real Checkmk condition isn't
meaningfully expressible via `sysDescr`/`sysObjectID` alone — either it depends on
a third OID this plugin doesn't fetch, or the only remainder after dropping an
`exists()` half is too generic to mean anything (a bare "contains linux" or the
shared generic net-snmp enterprise OID with no vendor narrowing) — see the module
docstring for the full reasoning per family:

| Family | Label | Matches |
| --- | --- | --- |
| Cisco | `caps/snmp_plugin/cisco` | `sysDescr` contains "cisco" |
| Juniper | `caps/snmp_plugin/juniper` | `sysObjectID` starts with `.1.3.6.1.4.1.2636.1.1.1` (Junos), `.1.3.6.1.4.1.14525.3` (legacy Trapeze wifi), or `.1.3.6.1.4.1.3224.1` (ScreenOS/NetScreen) |
| Fortinet | `caps/snmp_plugin/fortinet` | `sysObjectID` matches a FortiGate/FortiMail/FortiSandbox/FortiAuthenticator OID prefix |
| Aruba | `caps/snmp_plugin/aruba` | `sysDescr` matches `Aruba.+2930M.*`, or `sysObjectID` starts with `.1.3.6.1.4.1.14823.1.1` (WLC) — only these two product lines, not Aruba's full catalog |
| HP ProCurve | `caps/snmp_plugin/hp_procurve` | `sysObjectID` contains `.11.2.3.7.11` or `.11.2.3.7.8` |
| Check Point | `caps/snmp_plugin/checkpoint` | `sysObjectID` starts with `.1.3.6.1.4.1.2620`, or `sysDescr` matches a Gaia/IPSO/`cpx` pattern |
| Palo Alto | `caps/snmp_plugin/palo_alto` | `sysObjectID` contains `25461` |
| F5 BIG-IP | `caps/snmp_plugin/f5_bigip` | `sysObjectID` contains `.1.3.6.1.4.1.3375.2` |
| Acme Packet | `caps/snmp_plugin/acme` | sysObjectID under Acme Packet's enterprise OID |
| ADVA | `caps/snmp_plugin/adva` | sysDescr equals "Fiber Service Platform F7" |
| AKCP | `caps/snmp_plugin/akcp` | sysObjectID under AKCP's enterprise OID |
| Alcatel | `caps/snmp_plugin/alcatel` | sysObjectID under either of Alcatel's two enterprise sub-branches |
| APC | `caps/snmp_plugin/apc` | sysObjectID under APC's enterprise branch, or sysDescr contains "apc", or two NetBotz-specific OIDs, or the STS OID |
| Arbor Networks | `caps/snmp_plugin/arbor` | sysDescr starts with "Peakflow" or "Pravail" |
| Arris | `caps/snmp_plugin/arris` | sysObjectID equals Arris CMTS OID |
| ATTO | `caps/snmp_plugin/atto` | sysObjectID under Atto's enterprise OID |
| AudioCodes | `caps/snmp_plugin/audiocodes` | sysObjectID contains AudioCodes OID |
| Avaya | `caps/snmp_plugin/avaya` | sysObjectID contains Avaya enterprise OID |
| Barracuda | `caps/snmp_plugin/barracuda` | sysObjectID under net-snmp OID AND sysDescr contains "barracuda" |
| Bintec/Teldat | `caps/snmp_plugin/bintec` | sysObjectID under Bintec/Teldat sub-branch (simplified to the branch prefix) |
| IBM/Lenovo BladeCenter | `caps/snmp_plugin/blade` | sysDescr contains an IBM/Lenovo BladeCenter management-module string, or "bx600", or sysObjectID equals the BX OID |
| BlueCat | `caps/snmp_plugin/bluecat` | sysObjectID equals BlueCat's OID |
| Blue Coat | `caps/snmp_plugin/bluecoat` | sysObjectID contains Blue Coat's OID |
| Brocade | `caps/snmp_plugin/brocade` | sysObjectID under either of Brocade's two enterprise sub-branches |
| Bosch VIP (video/IP cameras) | `caps/snmp_plugin/bvip` | sysDescr contains flexidome/vip-x/dinion/autodome |
| Casa Systems | `caps/snmp_plugin/casa` | sysObjectID under Casa's enterprise OID |
| Ciena CES | `caps/snmp_plugin/ciena_ces` | sysObjectID under either of Ciena's two enterprise sub-branches |
| IBM DataPower | `caps/snmp_plugin/datapower` | sysObjectID equals one of 3 IBM DataPower OIDs |
| NetApp DataFort (Decru) | `caps/snmp_plugin/decru` | sysDescr contains "datafort" |
| Didactum | `caps/snmp_plugin/didactum` | sysDescr contains "didactum" |
| DOCSIS cable modem/CMTS | `caps/snmp_plugin/docsis` | sysObjectID equals one of 5 cable-modem/CMTS OIDs |
| Eltek | `caps/snmp_plugin/eltek` | sysObjectID under Eltek's enterprise OID |
| EMC Isilon/Data Domain | `caps/snmp_plugin/emc` | sysDescr contains "isilon" or starts with "Data Domain OS" |
| Enterasys | `caps/snmp_plugin/enterasys` | sysObjectID under either of 2 Enterasys sub-branches |
| Enviromux | `caps/snmp_plugin/enviromux` | sysObjectID under one of 5 Enviromux sub-branches |
| Epson projector | `caps/snmp_plugin/epson` | sysObjectID contains "1248" |
| FireEye | `caps/snmp_plugin/fireeye` | sysObjectID under FireEye's enterprise OID |
| Fujitsu ETERNUS DX/AF | `caps/snmp_plugin/fjdarye` | sysObjectID equals one of 3 Fujitsu ETERNUS disk-array OIDs |
| genua | `caps/snmp_plugin/genua` | sysDescr contains genuscreen/genubox/genucrypt |
| Gude | `caps/snmp_plugin/gude` | sysObjectID under Gude's whole enterprise branch (simplified) |
| H3C/3Com | `caps/snmp_plugin/h3c` | sysDescr contains "3com s" |
| Hitachi HUS | `caps/snmp_plugin/hitachi` | sysDescr contains hm700/800/850/900, or sysObjectID under Hitachi's enterprise OID |
| Hitachi HNAS | `caps/snmp_plugin/hitachi_hnas` | sysObjectID under HNAS's enterprise sub-branch |
| HP (ProCurve model/EML tape library) | `caps/snmp_plugin/hp` | sysDescr contains "hp" and a specific ProCurve switch model, or sysObjectID equals the EML tape-library OID |
| HP BladeSystem | `caps/snmp_plugin/hp_blade` | sysObjectID contains HP BladeSystem OID |
| HP-UX | `caps/snmp_plugin/hpux` | sysDescr starts with "HP-UX" |
| Huawei | `caps/snmp_plugin/huawei` | sysObjectID contains either of 2 Huawei sub-OIDs |
| HW group | `caps/snmp_plugin/hwg` | sysDescr contains "hwg" or "STE2" |
| Icom repeater | `caps/snmp_plugin/icom` | sysDescr contains "fr5000" |
| Infoblox | `caps/snmp_plugin/infoblox` | sysDescr contains "infoblox" or sysObjectID under Infoblox's OID |
| innovaphone | `caps/snmp_plugin/innovaphone` | sysObjectID equals innovaphone's OID |
| Intel TrueScale | `caps/snmp_plugin/intel_true_scale` | sysObjectID under Intel's TrueScale OID |
| ISPRO sensors | `caps/snmp_plugin/ispro` | sysObjectID under ISPRO sensors OID |
| Janitza | `caps/snmp_plugin/janitza` | sysObjectID equals one of 3 Janitza OIDs |
| Kemp LoadMaster | `caps/snmp_plugin/kemp_loadmaster` | sysObjectID equals either of 2 Kemp OIDs |
| Kentix | `caps/snmp_plugin/kentix` | sysObjectID under Kentix's enterprise OID |
| Knuerr | `caps/snmp_plugin/knuerr` | sysObjectID equals Knuerr's OID |
| Kyocera printer | `caps/snmp_plugin/kyocera` | sysDescr contains "kyocera" |
| Liebert/Emerson LGP | `caps/snmp_plugin/lgp` | sysObjectID equals a specific Liebert/Emerson sub-OID |
| Liebert/Emerson | `caps/snmp_plugin/liebert` | sysObjectID under the same Liebert/Emerson sub-branch, broader prefix |
| McAfee/Skyhigh Secure Gateway | `caps/snmp_plugin/mcafee` | sysDescr/sysObjectID match for Email/Web Gateway or its Skyhigh Secure rebrand |
| Meinberg LANTIME | `caps/snmp_plugin/meinberg` | sysObjectID equals either of 2 Meinberg OIDs |
| Cisco Meraki | `caps/snmp_plugin/meraki` | sysObjectID under Cisco Meraki's own enterprise OID (distinct from the main `cisco` family) |
| MikroTik | `caps/snmp_plugin/mikrotik` | sysObjectID contains MikroTik's OID |
| Moxa | `caps/snmp_plugin/moxa` | sysObjectID under Moxa's enterprise OID |
| Avaya/Extreme VSP | `caps/snmp_plugin/netextreme` | sysObjectID under either of 2 Avaya/Extreme VSP sub-branches |
| Netgear | `caps/snmp_plugin/netgear` | sysObjectID under Netgear's enterprise OID |
| Citrix NetScaler/ADC | `caps/snmp_plugin/netscaler` | sysObjectID under Citrix NetScaler/ADC's OID |
| Nimble Storage | `caps/snmp_plugin/nimble` | sysObjectID under Nimble Storage's OID |
| Pandacom | `caps/snmp_plugin/pandacom` | sysObjectID equals Pandacom's OID |
| Papouch TH2E | `caps/snmp_plugin/papouch` | sysDescr contains "th2e" AND sysObjectID starts with a specific value |
| Perle | `caps/snmp_plugin/perle` | sysObjectID under Perle's enterprise OID |
| pfSense | `caps/snmp_plugin/pfsense` | sysDescr contains "pfsense" |
| Poseidon | `caps/snmp_plugin/poseidon` | sysObjectID under Poseidon's enterprise OID |
| Ricoh/Canon printer | `caps/snmp_plugin/printer` | sysObjectID contains Ricoh's OID, or sysDescr contains "canon" |
| Pulse Secure | `caps/snmp_plugin/pulse_secure` | sysObjectID contains Pulse Secure's OID |
| Qlogic SANbox | `caps/snmp_plugin/qlogic` | sysObjectID under Qlogic's SANbox branch (simplified) |
| QNAP | `caps/snmp_plugin/qnap` | sysDescr starts with "Linux TS-" or "NAS Q" |
| Raritan | `caps/snmp_plugin/raritan` | sysObjectID equals Raritan's OID |
| Rittal CMC | `caps/snmp_plugin/rittal` | sysObjectID contains one of 3 Rittal CMC OIDs, or sysDescr starts with "Rittal LCP" |
| AVTECH Room Alert | `caps/snmp_plugin/roomalert` | sysObjectID contains AVTECH RoomAlert's OID (32E), or (OID contains + sysDescr contains "3S") for the 3S variant |
| SafeNet HSM | `caps/snmp_plugin/safenet` | sysObjectID under SafeNet's own enterprise OID |
| Sentry (Server Technology) PDU | `caps/snmp_plugin/sentry` | sysObjectID equals either of 2 Sentry PDU OIDs |
| Silver Peak | `caps/snmp_plugin/silverpeak` | sysObjectID under Silver Peak's enterprise OID |
| Siemens HiPath/OpenScape | `caps/snmp_plugin/sni_octopuse` | sysDescr contains "agent for hipath" |
| Sophos | `caps/snmp_plugin/sophos` | sysObjectID contains Sophos's OID |
| Riverbed Steelhead | `caps/snmp_plugin/steelhead` | sysObjectID under Riverbed Steelhead's OID |
| Teracom TCW241 | `caps/snmp_plugin/teracom` | sysDescr contains "teracom" |
| UPS (multi-vendor) | `caps/snmp_plugin/ups` | sysObjectID equals/starts-with one of ~19 UPS-vendor OIDs (APC, Liebert, Eaton, MGE, Tripplite, and more) |
| Vutlan EMS | `caps/snmp_plugin/vutlan` | sysDescr contains "vutlan ems" |
| Wagner Titanus | `caps/snmp_plugin/wagner` | sysObjectID equals either of 2 Wagner Titanus OIDs |
| Watchdog Sensors | `caps/snmp_plugin/watchdog` | sysObjectID under either of 2 Watchdog OIDs |
| W&T | `caps/snmp_plugin/wut` | sysObjectID under W&T's enterprise branch (simplified) |
| Zebra printer | `caps/snmp_plugin/zebra` | sysDescr contains "zebra" |

Check Point and F5 BIG-IP's real `detect=` conditions (and most of the rows above)
also AND in a second, vendor-specific OID beyond `sysDescr`/`sysObjectID`; that
second condition is dropped here to avoid an extra per-vendor SNMP fetch tree, at
the cost of being slightly more permissive than the real plugin for those
families — see the module docstring for details, per family.

### Capabilities Scout service

`checkmk_plugin/cmk_addons/plugins/caps_scout/agent_based/capabilities_scout.py`
makes every `caps/*` host label visible as a service instead of only in the host's
label set. It combines `caps/*` labels from **both** other pieces above, since
they're two independent sources that don't otherwise meet anywhere:

- The Rust agent plugin's labels: it subscribes to the same `labels` agent section
  Checkmk's core already parses into host labels (the section the Rust binary
  writes, and that `agents/check_mk_agent.linux` also writes for its own `cmk/*`
  labels), and filters it down to the `caps/*` keys.
- The SNMP plugin-match labels: those are computed by an SNMP section's
  `host_label_function`, not written into the `labels` agent section at all, so
  this plugin also subscribes to the raw `caps_scout_snmp_plugin_match` SNMP
  section directly and calls `host_label_snmp_plugin_match` on it, reusing the
  same per-family detection logic rather than re-implementing it.

Either source can be absent for a given host — a pure-agent host has no SNMP
section, a pure-SNMP device (e.g. a Cisco appliance with no Checkmk agent
installed) has no `labels` agent section — the service is discovered as soon as
either one has `caps/*` labels to show.

One service is discovered per host once any `caps/*` label is present. Its summary
lists every `caps/*` label key found (the value is always `"yes"`, so it's omitted).
The details render as a two-column **Capability / Rules** table, one row per label,
with only a row divider drawn between rows — never a column divider between the two
cells — so it reads as a table without looking like a spreadsheet.

**Logos.** The Capability cell shows that engine's actual logo next to a
human-readable name (e.g. the Docker whale next to "Docker") instead of the raw
`caps/container/docker`-style key, for every label in this README's "Detected
capabilities" table, plus every one of the 94 `caps/snmp_plugin/<family>` labels
from the SNMP plugin-match table above — sourced from Simple Icons/Devicon/Font
Awesome Free, inlined as static SVG, no runtime fetch (see
`DISPLAY_NAME_BY_LABEL`/`ICON_BY_LABEL` in `capabilities_scout.py`). Real brand
marks (Cisco, Huawei, Netgear, MikroTik, pfSense, and many more) come first;
where a specific product has none but its actual current owning company does
(verified, not assumed from the name — e.g. Dell for EMC, NetApp for Decru,
Schneider Electric for APC), that company's mark is reused instead; everything
else falls back to a small generic glyph by category — network/telecom
appliance, environmental/power-quality sensor, UPS/PDU power, or printer — the
same tier of fallback already used for HAProxy/Varnish/CUPS/NFS/ISC DHCP. Any
future/unrecognized `caps/*` label outside both tables falls back to the raw
label key, no icon.

**"Add rule" chips.** The Rules cell lists every Checkmk agent-bakery rule that applies
to that capability (the rule that deploys or configures the plugin actually monitoring
that engine — `mk_postgres`, `apache_status`, `mk_docker`, and so on; see
`BAKERY_RULES_BY_LABEL` in `capabilities_scout.py` for the full, deliberately
non-exhaustive list), each shown as the same title Checkmk's own Setup GUI uses for
that rule (e.g. `mk_oracle` shows as "Oracle databases (Linux, Solaris, AIX,
Windows)") next to a solid **"Add rule"** chip straight to that rule's "new rule" WATO
page. Titles come from `RULE_TITLE_BY_NAME`, confirmed per rule against Checkmk's
source the same way `BAKERY_RULES_BY_LABEL` itself is — a rule with no confirmed title
yet falls back to showing its raw varname in monospace rather than a guessed title.
`BAKERY_RULES_BY_LABEL` maps a label to a
*tuple* of rule names — most entries are a single rule, but a capability can have two
confirmed, mutually-exclusive rules for the same engine (Oracle's legacy `mk_oracle`
plugin and its newer `mk_oracle_unified` replacement are one real example — Checkmk's
own rule help text says explicitly not to configure both), in which case each gets its
own row within the cell. A capability with no known rule at all gets a muted em dash
instead — never a broken link, and never a stray full-width divider, since both cells
of every row draw the same row-divider border regardless of what's in them.

This chip deliberately always points at "new rule," never at an already-existing rule
or the ruleset's overview page, even though an admin may have already configured one:
`cmk.agent_based.v2` check functions can only declare `item`/`params`/`section*`
parameters (`packages/cmk-check-engine/.../plugin_backend/utils.py` in Checkmk's
source enforces this), so this plugin has no way to learn the current host's identity —
and without that, it can't tell whether some existing rule elsewhere in the site's WATO
config (scoped by folder, host tags, or an explicit host list) is even the one that
applies to this host. Counting existing rules and guessing from that count would be
misleading, so it doesn't try; "Add rule" always lands on WATO's normal rule list for
that ruleset, where any existing rules are visible and manageable as usual.

**Enabling clickable links.** Rendering that link as clickable HTML rather than
literal `<a href=...>` text requires a rule in Setup → Services → Service monitoring
rules → **"Escape HTML in service output (dangerous to deactivate - read help)"**
(ruleset `extra_service_conf:_ESCAPE_PLUGIN_OUTPUT`), set to "Don't escape HTML" and
scoped via a service condition to `Capabilities Scout` — then **activate changes**,
since the setting only takes effect on the core after that. Off by default since
plugin output is normally untrusted, but safe here because every value it can ever
contain comes from this plugin's own fixed code, never from external input.

**Output size limit.** On a host where caps-scout finds many capabilities, the
details' per-row markup (the table cells' inline styles, the "Add rule" chips, plus
the inlined logo SVG, on top of the label itself) can add up past Checkmk's default
long-output size limit — 2000 bytes; a row with a logo runs roughly 300–1300 bytes
depending on the icon. When that happens, the details view shows a warning that the
output was truncated, with a link in that warning message itself; clicking it goes
straight to **Setup → Global settings → "Maximum long output size"**, where raising
the value (in bytes) is the fix — there's nothing to change in this plugin.

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
python3 build_mkp.py --manifest manifest.json --output caps-scout-1.4.0.mkp
mkp add caps-scout-1.4.0.mkp
mkp enable caps-scout 1.4.0
```

Then run (or wait for) service discovery / "Update host labels" on a host, so the
new services and labels this MKP adds get picked up. `manifest.json`'s
`version.min_required`/`version.packaged` target Checkmk 2.5.0 — the version this
plugin is developed and tested against, including the bakery rule's
`cmk.bakery.v2_unstable` dependency — adjust to your site's version if different.

`./deploy.sh [site] [--skip-agent-build]` (site defaults to `v250`) automates the
above for a local dev site: it bumps `manifest.json`'s patch version, builds the
MKP, and adds/enables it on the given site (disabling the previously-deployed
version), via `sudo su - <site>` — so it prompts for your sudo password once.
Bumping the version on every run matters: the site's package manager keys
installed packages by `(name, version)`, so re-adding/enabling an already-installed
version number is a no-op and silently keeps the old content.

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

## License

GPL-3.0. See [`LICENSE`](LICENSE).

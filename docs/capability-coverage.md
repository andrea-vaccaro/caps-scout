# Capability coverage tracker

Tracking document for the caps-scout long-term plan. This surveys every Checkmk
plugin family and classifies each one against caps-scout's actual scope - but
caps-scout has *two* independent detection mechanisms, covered here as two
separate chapters:

1. **[Agent plugins coverage](#agent-plugins-coverage)** - the Rust agent plugin
   (`src/`), which detects a software engine's local presence on a host that runs
   the Checkmk agent, usually via a running process.
2. **[SNMP plugins coverage](#snmp-plugins-coverage)** - a second, independent,
   Checkmk-side-only feature
   ([`snmp_match.py`](../checkmk_plugin/cmk_addons/plugins/caps_scout/agent_based/snmp_match.py))
   that detects which of Checkmk's own SNMP device plugin families would attach to
   a *network/hardware appliance* host - one that doesn't run a Checkmk agent at
   all, so the first mechanism can never apply to it.

Both chapters survey the same underlying source (`cmk/plugins/`, source:
`~/workspace/check_mk/cmk/plugins`) but at different points in time and for
different purposes. The Agent plugins survey was taken 2026-09-02 and found
**280** families (corrected from an original count of 279 - `aws` was present
in the source tree but missed by the original survey pass); of those, **151**
are SNMP-monitored network/hardware appliances, excluded entirely from the
Agent plugins chapter's own totals below to avoid double-counting - they're
tracked exclusively in the SNMP plugins coverage chapter. That chapter's own
independent, exhaustive re-scan, done later against an earlier checkout dated
2026-08-27, found **279** real directories (a naive `ls | wc -l` gives 281, but
two entries, `BUILD` and `OWNERS`, aren't plugin families at all) - `aws`
doesn't exist as a directory in that earlier checkout at all, so that 279 most
likely reflects an older upstream snapshot missing a family the 2026-09-02
survey correctly includes, rather than a correction to it. Both totals are left
as independently taken, not reconciled into one number. One thing that *is*
corrected as part of this restructure: `cbl` and `strem1` were misclassified in
the Agent plugins chapter's own "Niche/legacy" bucket by the earlier survey -
the SNMP re-scan found they're SNMP-only appliances, not local software with an
unclear signature; both moved into the SNMP plugins chapter instead.

This complements [`checkmk-label-catalog.md`](checkmk-label-catalog.md), which
surveys *labels* (what Checkmk's own plugins already emit, per-attribute detail).
This document surveys *plugin families* (one row per family) and asks a coarser
question: is there a caps-scout-shaped capability-presence gap here at all, by
either mechanism?

---

## Agent plugins coverage

The Rust agent plugin (`src/`) detects a software engine's presence on the
monitored host itself - usually via a locally running process's name,
occasionally via its full command line instead (e.g. ActiveMQ's
`caps/mq/activemq` probe: it's a Java process, so the short process name is
just `java`, too generic - the distinctive marker, `activemq.jar`, only shows
up in the full command line), or via another host-local marker entirely (e.g.
Plesk's `caps/app/plesk` probe checks for a file, since its own control-panel
process can be stopped independently of the rest of the product) - of a
software engine that Checkmk itself only ever monitors through an
already-configured connection, never detects the unconfigured presence of.
This is the same gap the DB-engine probes (`oracle`, `mysql`, `postgres`,
`mssql`, `mongodb`, `redis`, `db2`, `sap_hana`) already fill.

**Classification rule**, applied to every family that isn't already tracked by
the [SNMP plugins coverage](#snmp-plugins-coverage) chapter - SNMP-monitored
network/hardware appliances are excluded from this chapter's totals entirely,
to avoid double-counting:

1. **Covered** - caps-scout already has a probe for it.
2. **Not covered** - a real gap of the same shape as the DB engines: a local
   software engine/daemon that Checkmk only monitors via a configured
   connection, never detects the presence of.
3. **Not applicable** - everything else: OS built-in resource metrics, per-OS
   agent sections, generic utilities/active checks, cloud/API-managed
   products, centrally-managed endpoint security, capabilities Checkmk
   *already* presence-detects natively, and local software with no reliable
   single-process signature to match on.

### Summary

| Status | Families |
|---|---|
| Covered | 41 |
| Not covered | 0 |
| Not applicable | 88 |
| **Total surveyed** | **129** |

### Covered (41)

41 plugin families (42 rows - `corosync` covers two distinct capabilities),
grouped by type.

#### Databases

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Oracle | `oracle` | `caps/db/oracle` | process name contains `ora_pmon_` |
| MySQL | `mysql` | `caps/db/mysql` | process name contains `mysqld` |
| PostgreSQL | `postgres` | `caps/db/postgres` | process name contains `postgres` or `postmaster` |
| MSSQL | `mssql` | `caps/db/mssql` | process name contains `sqlservr` |
| MongoDB | `mongodb` | `caps/db/mongodb` | process name contains `mongod` |
| Redis | `redis` | `caps/db/redis` | process name contains `redis-server` |
| DB2 | `db2` | `caps/db/db2` | process name contains `db2sysc` |
| SAP HANA | `sap_hana` | `caps/db/sap_hana` | process name contains `hdbdaemon` |
| Couchbase | `couchbase` | `caps/db/couchbase` | directory `/opt/couchbase` exists (default install path, not process-based - see `src/probes/couchbase.rs`) |

#### Mail

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Postfix | `postfix` | `caps/mail/postfix` | command line contains `postfix/master`, `postfix/sbin/master`, or `postfix/bin/master` - the bare `master` process name is too generic (shared with Jenkins, gunicorn, etc.); matches Checkmk's own core-agent verification exactly (`agents/check_mk_agent.linux:1231`) |

#### Web / application servers

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Apache | `apache` | `caps/web/apache` | process name contains `httpd` or `apache2` |
| nginx | `nginx` | `caps/web/nginx` | process name contains `nginx` |
| SAP NetWeaver | `sap` | `caps/app/sap_netweaver` | process name contains `disp+work` (ABAP stack only) |
| Microsoft Exchange | `msexch` | `caps/app/exchange` | process name contains `Microsoft.Exchange.Store.Service` (Mailbox role only) |
| Plesk | `plesk` | `caps/app/plesk` | file `/etc/psa/.psa.shadow` exists (not process-based - see `src/probes/plesk.rs`) |

#### Messaging / streaming / monitoring

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| ActiveMQ | `activemq` | `caps/mq/activemq` | command line contains `activemq.jar` (Java process, name alone is too generic - see `src/probes/activemq.rs`) |
| MQTT (Mosquitto) | `mqtt` | `caps/mq/mqtt` | process name contains `mosquitto` (Mosquitto only; `mqtt` is a protocol, other brokers like HiveMQ/EMQX/VerneMQ aren't detected) |
| Prometheus | `prometheus` | `caps/monitoring/prometheus` | process name contains `prometheus` |
| Alertmanager | `alertmanager` | `caps/monitoring/alertmanager` | process name contains `alertmanager` |

#### Container / virtualization runtimes

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Docker | `docker` | `caps/container/docker` | process name contains `dockerd` |
| Podman | `podman` | `caps/container/podman` | file `/run/podman/podman.sock` exists (root socket only, per Checkmk's own socket auto-detection config - not process-based, see `src/probes/podman.rs`) |
| LXC | `lxc` | `caps/container/lxc` | process name contains `lxc monitor` (only while >=1 container is running - see `src/probes/lxc.rs`) |
| Hyper-V | `hyperv` | `caps/virt/hyperv` | process name contains `vmms.exe` (Windows only) |
| VirtualBox (guest) | `vbox` | `caps/virt/virtualbox_guest` | process name contains `VBoxService` - detects this host *is* a VirtualBox guest VM, not that it runs VirtualBox as a hypervisor (matches the actual scope of Checkmk's own `vbox_guest` plugin - see `src/probes/virtualbox_guest.rs`) |

#### Clustering / HA

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Corosync | `corosync` | `caps/cluster/corosync` | process name contains `corosync` |
| Pacemaker/Heartbeat | `corosync` (bundles `heartbeat_crm.py` etc.; a distinct capability, not a separate plugin family) | `caps/cluster/pacemaker` | process name contains `crmd` or `pacemaker-contr` - matches Checkmk's own core-agent gating exactly (`agents/check_mk_agent.linux:1170`) |
| keepalived | `keepalived` | `caps/cluster/keepalived` | process name contains `keepalived` |
| Veritas Cluster Server | `veritas` | `caps/cluster/veritas_cluster_server` | file `/opt/VRTSvcs/bin/haclus` exists - matches Checkmk's own core-agent gating exactly (`agents/check_mk_agent.linux:1368`), not process-based - see `src/probes/veritas.rs` |

#### Backup / DR

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Veeam | `veeam` | `caps/backup/veeam` | process name contains `Veeam.Backup.Service` - matches Checkmk's own agent script exactly (`veeam/agents/veeam_backup_status.ps1`) |
| IBM TSM / Storage Protect | `tsm` | `caps/backup/tsm` | process name contains `dsmserv` (server) or `dsmcad` (client scheduler) |
| Arcserve Backup | `arcserve` | `caps/backup/arcserve` | process name contains `dbeng.exe` or `jobeng.exe` - Arcserve's own docs confirm these as the primary server's core DB/Job Engine components; not the same product as Arcserve UDP/D2D's `CASAD2DWebSvc` |
| Zerto Virtual Manager | `zerto` | `caps/backup/zerto` | process name contains `Zerto.Zvm.Service` - detects a host running ZVM itself, not a host merely protected by Zerto's separate VRA appliance (which isn't detectable this way - see `src/probes/zerto.rs`) |

#### Load balancing / caching

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| HAProxy | `haproxy` | `caps/lb/haproxy` | process name contains `haproxy` - Checkmk's own core agent instead checks for a stats socket (opt-in config), which caps-scout deliberately doesn't mirror since it wants "is it present", not "is it monitorable" - see `src/probes/haproxy.rs` |
| Varnish | `varnish` | `caps/cache/varnish` | process name contains `varnishd` |

#### File / print / network services

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| CUPS | `cups` | `caps/print/cups` | process name contains `cupsd` |
| NFS server | `nfsexports` | `caps/file/nfs_server` | process name contains `rpc.mountd` - `nfsd` itself usually runs as kernel threads, not a normal process; `rpc.mountd` is a userspace daemon that only runs while the NFS server is active, matching Checkmk's own gating (`nfsexports/agents/nfsexports`) - see `src/probes/nfs_server.rs` |
| ISC DHCP | `isc` | `caps/net/isc_dhcpd` | process name contains `dhcpd` - this plugin family is ISC DHCP only, no BIND/`named` component (corrects the original candidate note's premise) |

#### Collaboration

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| IBM Domino | `domino` | `caps/collab/domino` | process name contains `nserver` |
| Skype for Business | `skype` | `caps/collab/skype_for_business` | process name contains `RtcSrv` or `Rtcsrv` (Front End role only - matches Checkmk's own check, which also targets a "skype frontend server") |

#### Cloud provisioning

Not gap-filling probes in the DB-engine sense - `caps-scout` doesn't monitor
AWS/Azure resources via their APIs the way Checkmk's `aws`/`azure` special
agents do (which need credentials and report on cloud-side resources like EC2
instances or Azure VMs as *managed objects*, not on the host itself). This is
a different question entirely: "was *this host* provisioned by AWS/Azure",
answered purely from local host state, no network call.

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| AWS EC2 provisioning | `aws` (loosely - see note above; Checkmk's `aws` plugin is unrelated in mechanism) | `caps/cloud/aws-vm` | file `/sys/devices/virtual/dmi/id/board_asset_tag` contains an instance-ID-shaped value (`i-` + hex) - AWS's own documented, non-privileged EC2 detection method (docs.aws.amazon.com/AWSEC2/latest/UserGuide/identify_ec2_instances.html). Covers essentially all of today's EC2 fleet (Nitro-based, including legacy instance type names transparently migrated to Nitro hardware) except a documented, permanent exception: legacy GPU/FPGA families (G2, G3, P2, P3, F1), which never run on Nitro - see `src/probes/aws_vm.rs` |
| Azure VM provisioning | `azure` (loosely - see note above) | `caps/cloud/azure-vm` | file `/sys/devices/virtual/dmi/id/chassis_asset_tag` exactly equals `7783-7084-3265-9085-8269-3286-77` - the fixed value Azure hard-codes into every VM's DMI chassis asset tag (public cloud and Azure Stack), verified against `cloud-init`'s own detection logic (`tools/ds-identify`, `is_azure_chassis()`, github.com/canonical/cloud-init). Unlike AWS's shape-matched instance ID, this is an exact-match constant. `cloud-init` also excludes containers here since they inherit the host's DMI data; this probe doesn't, kept in parity with `aws_vm` - see `src/probes/azure_vm.rs` |

#### Operating system

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Host OS | `checkmk` (core agent's `os_family`/`AgentOS`) | `caps/os_type/<name>` | compile-time `cfg!(target_os = ...)`, not a runtime probe |

### Not covered (0)

None remaining - every plugin family originally identified as a
caps-scout-shaped presence gap has since been implemented and moved into
[Covered](#covered-41) above. This section stays as a placeholder: a future
survey (e.g. after a new Checkmk plugin family is added upstream) may find new
candidates here.

### Not applicable (88)

88 families, grouped by why they fall outside this chapter's scope.
SNMP-monitored network/hardware appliances are tracked separately - see the
[SNMP plugins coverage](#snmp-plugins-coverage) chapter for that breakdown
(117 covered, 23 researched but not covered, plus 21 more `cmk/plugins/`
directories confirmed to have no SNMP signal at all).

- **OS built-in resource metrics** (23) - always-there facts about any host,
  not "engine presence": `apt`, `cpu`, `df`, `diskstat`, `dmi`, `dmraid`,
  `kernel`, `logins`, `lparstat`, `lvm`, `mdraid`, `memory`, `mounts`, `ntp`,
  `smart`, `statgrab`, `suseconnect`, `time`, `uptime`, `vxvm`, `zfs`,
  `zpool`, `zypper`

- **Per-OS agent sections** (7) - platform variants of the core agent, not
  capabilities: `aix`, `hpux`, `lnx`, `openbsd`, `solaris`, `vms`, `windows`

- **Generic utilities / protocol active checks** (25) - Nagios-style
  connectivity tests or generic agent plumbing, not tied to a specific engine:
  `collection`, `diagnostics`, `dns`, `emailchecks`, `filehandler`,
  `fileinfo`, `files`, `form_submit`, `generic_agent_options`, `inotify`,
  `jar_signature`, `job`, `ldapcheck`, `monitoring_plugins`, `mtr`, `network`,
  `ps` (user-configured process-discovery ruleset - not something caps-scout
  detects), `sftp`, `smb`, `smtp`, `sql`, `ssh`, `systemd` (same reasoning as
  `ps`), `tcp`, `traceroute`

- **Cloud/API-managed products** (12) - no local host process to probe; data
  comes from a cloud API or central console: `appdynamics`, `azure_status`,
  `cisco_meraki`, `datadog`, `extremecloud_iq`, `hivemanager`,
  `hivemanager_ng`, `jira`, `mobileiron`, `msoffice`, `ruckus_spot`,
  `salesforce` (`azure` moved to Covered - see Cloud provisioning; it's an
  API-managed product for resource monitoring, but also loosely covers the
  `caps/cloud/azure-vm` local-provisioning probe, same relationship as `aws`)

- **Centrally-managed endpoint security** (3) - agent reports to a management
  console via API, not a distinguishing local-process signal: `kaspersky`,
  `mcafee`, `symantec`

- **Already presence-detected by Checkmk itself** (3) - no gap to fill,
  unlike the DB engines: `ceph` (`cmk/ceph/mon: "yes"`, `cmk/ceph/osd: "yes"`),
  `omd` (`cmk/check_mk_server: "yes"`), `pvecm` (Proxmox VE cluster status;
  Proxmox VE object presence is separately labeled via `cmk/pve/entity`) - see
  `checkmk-label-catalog.md` for the label detail.

- **Niche/legacy, or no reliable single-process signature** (15) - real local
  software in some cases, but not confident enough to guess a detection
  pattern, or superseded by a clearer candidate above (e.g.
  `nullmailer`/`qmail_stats` vs. `postfix` as the mail-server signal):
  `cadvisor` (metrics exporter for containers already covered by
  `docker`/`podman`, not a distinct engine), `drbd` (kernel module, not a
  persistent daemon), `entersekt`, `hyperv_cluster` (aggregates the `hyperv`
  candidate above), `jolokia` (JMX-HTTP bridge, not itself an engine),
  `libelle`, `mailman_lists`, `nullmailer`, `qmail_stats`, `sansymphony`,
  `scaleio`, `security_master`, `sylo`, `uniserv`, `zorp`

---

## SNMP plugins coverage

Everything above is about `src/`, the Rust agent plugin: it detects a software
engine's *local presence on a host that runs the Checkmk agent*, usually via a
running process. SNMP-monitored network/hardware appliances (routers,
switches, firewalls, PDUs, environmental sensors, and similar gear) don't run
a Checkmk agent at all - they're reached over SNMP, so there's no local
process for the Rust agent to ever detect. That's a fundamentally different
problem, solved by a second, independent, Checkmk-side-only feature:
[`checkmk_plugin/cmk_addons/plugins/caps_scout/agent_based/snmp_match.py`](../checkmk_plugin/cmk_addons/plugins/caps_scout/agent_based/snmp_match.py).
It fetches the two universal SNMPv2-MIB System-group scalars (`sysDescr`,
`sysObjectID`) - the same way Checkmk's own core does for its `cmk/device_type`
label - and replicates the exact `detect=` condition each of Checkmk's own
SNMP device plugin families uses, emitting a `caps/snmp/<family>` host
label per match. No credentials of its own: it reuses the host's
already-configured SNMP credentials rule, the same as any other SNMP-based
check.

**Classification rule** (analogous to the Agent plugins chapter, but for SNMP
`detect=` conditions instead of local processes):

1. **Covered** - a real SNMP `detect=`/`DETECT_*` condition exists and is
   meaningfully expressible via `sysDescr`/`sysObjectID` alone.
2. **Not covered** - a real SNMP condition exists, but it depends entirely on
   a third OID this plugin doesn't fetch, or the only `sysDescr`/`sysObjectID`
   remainder is too generic to mean anything (or, in one case, the condition
   as written can never fire at all - see below).
3. **Not applicable** - no SNMP `detect=`/`DETECT_*` condition anywhere in
   the family's source at all: special agents, agent-section-only plugins
   that parse the *agent's* own stdout, or shared library/support code.

An exhaustive pass over all 279 real directories under Checkmk's
`cmk/plugins/` (a naive `ls | wc -l` gives 281, but two entries, `BUILD` and
`OWNERS`, aren't plugin families at all) resolved the full picture. 118 of
those directories are agent plugin families already classified in the
[Agent plugins coverage](#agent-plugins-coverage) chapter, so they're excluded
from this chapter's totals entirely, to avoid double-counting.

### Summary

| Status | Families |
|---|---|
| Covered | 117 |
| Not covered | 23 |
| Not applicable | 21 |
| **Total surveyed** | **161** |

### Covered (117)

117 plugin families, grouped by device type.

#### Network switches, routers & data-center fabric

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| Cisco | `cisco` | `caps/snmp/cisco` | `sysDescr` contains "cisco" |
| Juniper | `juniper` | `caps/snmp/juniper` | `sysObjectID` starts with `.1.3.6.1.4.1.2636.1.1.1` (Junos), `.1.3.6.1.4.1.14525.3` (legacy Trapeze wifi), or `.1.3.6.1.4.1.3224.1` (ScreenOS/NetScreen) |
| Aruba | `aruba` | `caps/snmp/aruba` | `sysDescr` matches `Aruba.+2930M.*`, or `sysObjectID` starts with `.1.3.6.1.4.1.14823.1.1` (WLC) — only these two product lines, not Aruba's full catalog |
| HP ProCurve | `hp_procurve` | `caps/snmp/hp_procurve` | `sysObjectID` contains `.11.2.3.7.11` or `.11.2.3.7.8` |
| ADVA | `adva` | `caps/snmp/adva` | sysDescr equals "Fiber Service Platform F7" |
| Alcatel | `alcatel` | `caps/snmp/alcatel` | sysObjectID under either of Alcatel's two enterprise sub-branches |
| Bintec/Teldat | `bintec` | `caps/snmp/bintec` | sysObjectID under Bintec/Teldat sub-branch (simplified to the branch prefix) |
| Ciena CES | `ciena_ces` | `caps/snmp/ciena_ces` | sysObjectID under either of Ciena's two enterprise sub-branches |
| Enterasys | `enterasys` | `caps/snmp/enterasys` | sysObjectID under either of 2 Enterasys sub-branches |
| H3C/3Com | `h3c` | `caps/snmp/h3c` | sysDescr contains "3com s" |
| HP (ProCurve model/EML tape library) | `hp` | `caps/snmp/hp` | sysDescr contains "hp" and a specific ProCurve switch model, or sysObjectID equals the EML tape-library OID |
| Huawei | `huawei` | `caps/snmp/huawei` | sysObjectID contains either of 2 Huawei sub-OIDs |
| Intel TrueScale | `intel_true_scale` | `caps/snmp/intel_true_scale` | sysObjectID under Intel's TrueScale OID |
| Cisco Meraki | `meraki` | `caps/snmp/meraki` | sysObjectID under Cisco Meraki's own enterprise OID (distinct from the main `cisco` family) |
| MikroTik | `mikrotik` | `caps/snmp/mikrotik` | sysObjectID contains MikroTik's OID |
| Moxa | `moxa` | `caps/snmp/moxa` | sysObjectID under Moxa's enterprise OID |
| Avaya/Extreme VSP | `netextreme` | `caps/snmp/netextreme` | sysObjectID under either of 2 Avaya/Extreme VSP sub-branches |
| Netgear | `netgear` | `caps/snmp/netgear` | sysObjectID under Netgear's enterprise OID |
| Pandacom | `pandacom` | `caps/snmp/pandacom` | sysObjectID equals Pandacom's OID |
| Perle | `perle` | `caps/snmp/perle` | sysObjectID under Perle's enterprise OID |
| CBL AirLaser | `cbl` | `caps/snmp/cbl` | sysDescr contains "airlaser" |
| HPE/H3C switch | `hp_hh3c` | `caps/snmp/hp_hh3c` | sysObjectID under a distinct OID branch AND sysDescr contains "H3C" or "HPE" — distinct from `h3c` |
| 3Com SuperStack 3 | `superstack3` | `caps/snmp/superstack3` | sysDescr contains "3com superstack 3" — distinct from `h3c`'s "3com s" |
| Arista Networks | `arista` | `caps/snmp/arista` | sysDescr starts with "arista networks" |

#### Firewalls, VPN & security gateway appliances

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| Fortinet | `fortinet` | `caps/snmp/fortinet` | `sysObjectID` matches a FortiGate/FortiMail/FortiSandbox/FortiAuthenticator OID prefix |
| Check Point | `checkpoint` | `caps/snmp/checkpoint` | `sysObjectID` starts with `.1.3.6.1.4.1.2620`, or `sysDescr` matches a Gaia/IPSO/`cpx` pattern |
| Palo Alto | `palo_alto` | `caps/snmp/palo_alto` | `sysObjectID` contains `25461` |
| Arbor Networks | `arbor` | `caps/snmp/arbor` | sysDescr starts with "Peakflow" or "Pravail" |
| Barracuda | `barracuda` | `caps/snmp/barracuda` | sysObjectID under net-snmp OID AND sysDescr contains "barracuda" |
| Blue Coat | `bluecoat` | `caps/snmp/bluecoat` | sysObjectID contains Blue Coat's OID |
| IBM DataPower | `datapower` | `caps/snmp/datapower` | sysObjectID equals one of 3 IBM DataPower OIDs |
| FireEye | `fireeye` | `caps/snmp/fireeye` | sysObjectID under FireEye's enterprise OID |
| genua | `genua` | `caps/snmp/genua` | sysDescr contains genuscreen/genubox/genucrypt |
| McAfee/Skyhigh Secure Gateway | `mcafee` | `caps/snmp/mcafee` | sysDescr/sysObjectID match for Email/Web Gateway or its Skyhigh Secure rebrand |
| pfSense | `pfsense` | `caps/snmp/pfsense` | sysDescr contains "pfsense" |
| Pulse Secure | `pulse_secure` | `caps/snmp/pulse_secure` | sysObjectID contains Pulse Secure's OID |
| SafeNet HSM | `safenet` | `caps/snmp/safenet` | sysObjectID under SafeNet's own enterprise OID |
| Sophos | `sophos` | `caps/snmp/sophos` | sysObjectID contains Sophos's OID |
| Cisco Secure Email/Web Manager | `cisco_sma` | `caps/snmp/cisco_sma` | sysObjectID equals `.15497.1.1` — distinct from the main `cisco` family |
| CoreProcess Secure | `cpsecure` | `caps/snmp/cpsecure` | sysObjectID equals `.26546.1.1.2` |
| eWON industrial router | `ewon` | `caps/snmp/ewon` | sysObjectID equals `.8284.2.1` |
| Symantec/Broadcom Brightmail | `sym_brightmail` | `caps/snmp/sym_brightmail` | sysDescr contains "el5_sms" or "el6" |

#### Load balancers / ADCs

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| F5 BIG-IP | `f5_bigip` | `caps/snmp/f5_bigip` | `sysObjectID` contains `.1.3.6.1.4.1.3375.2` |
| Kemp LoadMaster | `kemp_loadmaster` | `caps/snmp/kemp_loadmaster` | sysObjectID equals either of 2 Kemp OIDs |
| Citrix NetScaler/ADC | `netscaler` | `caps/snmp/netscaler` | sysObjectID under Citrix NetScaler/ADC's OID |
| F5 rSeries | `f5os_rseries` | `caps/snmp/f5os_rseries` | sysDescr contains "rSeries" AND sysObjectID starts with `.12276.1.3.` — distinct from `f5_bigip` |

#### WAN optimization / traffic management

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| Silver Peak | `silverpeak` | `caps/snmp/silverpeak` | sysObjectID under Silver Peak's enterprise OID |
| Riverbed Steelhead | `steelhead` | `caps/snmp/steelhead` | sysObjectID under Riverbed Steelhead's OID |
| Packeteer PacketShaper | `packeteer` | `caps/snmp/packeteer` | sysObjectID under Packeteer's enterprise OID |

#### Telecom, VoIP, PBX & radio

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| Acme Packet | `acme` | `caps/snmp/acme` | sysObjectID under Acme Packet's enterprise OID |
| AudioCodes | `audiocodes` | `caps/snmp/audiocodes` | sysObjectID contains AudioCodes OID |
| Avaya | `avaya` | `caps/snmp/avaya` | sysObjectID contains Avaya enterprise OID |
| Icom repeater | `icom` | `caps/snmp/icom` | sysDescr contains "fr5000" |
| innovaphone | `innovaphone` | `caps/snmp/innovaphone` | sysObjectID equals innovaphone's OID |
| Siemens HiPath/OpenScape | `sni_octopuse` | `caps/snmp/sni_octopuse` | sysDescr contains "agent for hipath" |
| IPR400 VoIP intercom | `ipr400` | `caps/snmp/ipr400` | sysDescr starts with "ipr voip device ipr400" |

#### Cable / broadband (CMTS)

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| Arris | `arris` | `caps/snmp/arris` | sysObjectID equals Arris CMTS OID |
| Casa Systems | `casa` | `caps/snmp/casa` | sysObjectID under Casa's enterprise OID |
| DOCSIS cable modem/CMTS | `docsis` | `caps/snmp/docsis` | sysObjectID equals one of 5 cable-modem/CMTS OIDs |

#### Storage, SAN, tape & RAID

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| ATTO | `atto` | `caps/snmp/atto` | sysObjectID under Atto's enterprise OID |
| Brocade | `brocade` | `caps/snmp/brocade` | sysObjectID under either of Brocade's two enterprise sub-branches |
| NetApp DataFort (Decru) | `decru` | `caps/snmp/decru` | sysDescr contains "datafort" |
| EMC Isilon/Data Domain | `emc` | `caps/snmp/emc` | sysDescr contains "isilon" or starts with "Data Domain OS" |
| Fujitsu ETERNUS DX/AF | `fjdarye` | `caps/snmp/fjdarye` | sysObjectID equals one of 3 Fujitsu ETERNUS disk-array OIDs |
| Hitachi HUS | `hitachi` | `caps/snmp/hitachi` | sysDescr contains hm700/800/850/900, or sysObjectID under Hitachi's enterprise OID |
| Hitachi HNAS | `hitachi_hnas` | `caps/snmp/hitachi_hnas` | sysObjectID under HNAS's enterprise sub-branch |
| Nimble Storage | `nimble` | `caps/snmp/nimble` | sysObjectID under Nimble Storage's OID |
| Qlogic SANbox | `qlogic` | `caps/snmp/qlogic` | sysObjectID under Qlogic's SANbox branch (simplified) |
| QNAP | `qnap` | `caps/snmp/qnap` | sysDescr starts with "Linux TS-" or "NAS Q" |
| BDT tape library | `bdt_tape` | `caps/snmp/bdt_tape` | sysObjectID contains `.20884.77.83.1` (older) or `.20884.10893.2.101` (newer) |
| NetApp filer (ONTAP) | `netapp` | `caps/snmp/netapp` | sysDescr contains "ontap" or sysObjectID under NetApp's enterprise OID |

#### UPS, PDU, power & precision cooling

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| APC | `apc` | `caps/snmp/apc` | sysObjectID under APC's enterprise branch, or sysDescr contains "apc", or two NetBotz-specific OIDs, or the STS OID |
| Eltek | `eltek` | `caps/snmp/eltek` | sysObjectID under Eltek's enterprise OID |
| Janitza | `janitza` | `caps/snmp/janitza` | sysObjectID equals one of 3 Janitza OIDs |
| Knuerr | `knuerr` | `caps/snmp/knuerr` | sysObjectID equals Knuerr's OID |
| Liebert/Emerson LGP | `lgp` | `caps/snmp/lgp` | sysObjectID equals a specific Liebert/Emerson sub-OID |
| Liebert/Emerson | `liebert` | `caps/snmp/liebert` | sysObjectID under the same Liebert/Emerson sub-branch, broader prefix |
| Raritan | `raritan` | `caps/snmp/raritan` | sysObjectID equals Raritan's OID |
| Sentry (Server Technology) PDU | `sentry` | `caps/snmp/sentry` | sysObjectID equals either of 2 Sentry PDU OIDs |
| UPS (multi-vendor) | `ups` | `caps/snmp/ups` | sysObjectID equals/starts-with one of ~19 UPS-vendor OIDs (APC, Liebert, Eaton, MGE, Tripplite, and more) |
| BayTech/BlueNET PDU | `bluenet` | `caps/snmp/bluenet` | sysObjectID starts with `.21695.1` or contains `.31770.2.1` |
| Orion UPS/power | `orion` | `caps/snmp/orion` | sysObjectID under Orion's enterprise OID |

#### Environmental / industrial sensors & building monitoring

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| AKCP | `akcp` | `caps/snmp/akcp` | sysObjectID under AKCP's enterprise OID |
| Didactum | `didactum` | `caps/snmp/didactum` | sysDescr contains "didactum" |
| Enviromux | `enviromux` | `caps/snmp/enviromux` | sysObjectID under one of 5 Enviromux sub-branches |
| Gude | `gude` | `caps/snmp/gude` | sysObjectID under Gude's whole enterprise branch (simplified) |
| HW group | `hwg` | `caps/snmp/hwg` | sysDescr contains "hwg" or "STE2" |
| ISPRO sensors | `ispro` | `caps/snmp/ispro` | sysObjectID under ISPRO sensors OID |
| Kentix | `kentix` | `caps/snmp/kentix` | sysObjectID under Kentix's enterprise OID |
| Papouch TH2E | `papouch` | `caps/snmp/papouch` | sysDescr contains "th2e" AND sysObjectID starts with a specific value |
| Poseidon | `poseidon` | `caps/snmp/poseidon` | sysObjectID under Poseidon's enterprise OID |
| AVTECH Room Alert | `roomalert` | `caps/snmp/roomalert` | sysObjectID contains AVTECH RoomAlert's OID (32E), or (OID contains + sysDescr contains "3S") for the 3S variant |
| Teracom TCW241 | `teracom` | `caps/snmp/teracom` | sysDescr contains "teracom" |
| Vutlan EMS | `vutlan` | `caps/snmp/vutlan` | sysDescr contains "vutlan ems" |
| Wagner Titanus | `wagner` | `caps/snmp/wagner` | sysObjectID equals either of 2 Wagner Titanus OIDs |
| Watchdog Sensors | `watchdog` | `caps/snmp/watchdog` | sysObjectID under either of 2 Watchdog OIDs |
| W&T | `wut` | `caps/snmp/wut` | sysObjectID under W&T's enterprise branch (simplified) |
| Climaveneta | `climaveneta` | `caps/snmp/climaveneta` | sysDescr equals "pCO Gateway" |
| EMKA enclosure monitoring | `emka` | `caps/snmp/emka` | sysDescr contains "emka" AND sysObjectID starts with EMKA's enterprise OID |
| Hepta | `hepta` | `caps/snmp/hepta` | sysObjectID under Hepta's enterprise OID |
| Infratec Plus RMS200 | `infratec_plus` | `caps/snmp/infratec_plus` | sysObjectID equals Infratec Plus's OID |
| Sensatronics (newer) | `sensatronics` | `caps/snmp/sensatronics` | sysObjectID equals Sensatronics's OID |
| Sensatronics EM1 (older) | `strem1` | `caps/snmp/strem1` | sysDescr contains "Sensatronics EM1" |

#### Blade / rack / server infrastructure

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| IBM/Lenovo BladeCenter | `blade` | `caps/snmp/blade` | sysDescr contains an IBM/Lenovo BladeCenter management-module string, or "bx600", or sysObjectID equals the BX OID |
| HP BladeSystem | `hp_blade` | `caps/snmp/hp_blade` | sysObjectID contains HP BladeSystem OID |
| Rittal CMC | `rittal` | `caps/snmp/rittal` | sysObjectID contains one of 3 Rittal CMC OIDs, or sysDescr starts with "Rittal LCP" |
| HP Modular Cooling System | `hp_mcs` | `caps/snmp/hp_mcs` | sysObjectID under HP MCS's enterprise OID |

#### Printers & imaging/presentation hardware

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| Epson projector | `epson` | `caps/snmp/epson` | sysObjectID contains "1248" |
| Kyocera printer | `kyocera` | `caps/snmp/kyocera` | sysDescr contains "kyocera" |
| Ricoh/Canon printer | `printer` | `caps/snmp/printer` | sysObjectID contains Ricoh's OID, or sysDescr contains "canon" |
| Zebra printer | `zebra` | `caps/snmp/zebra` | sysDescr contains "zebra" |
| SEH PSrv print server | `seh` | `caps/snmp/seh` | sysObjectID contains SEH's OID |

#### DNS / DDI appliances

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| BlueCat | `bluecat` | `caps/snmp/bluecat` | sysObjectID equals BlueCat's OID |
| Infoblox | `infoblox` | `caps/snmp/infoblox` | sysDescr contains "infoblox" or sysObjectID under Infoblox's OID |

#### Video / IP camera & surveillance

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| Bosch VIP (video/IP cameras) | `bvip` | `caps/snmp/bvip` | sysDescr contains flexidome/vip-x/dinion/autodome |

#### Time / NTP appliances

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| Meinberg LANTIME | `meinberg` | `caps/snmp/meinberg` | sysObjectID equals either of 2 Meinberg OIDs |

#### Operating systems identified via SNMP

| Vendor/Product | Checkmk plugin family | Label | Matches |
|---|---|---|---|
| HP-UX | `hpux` | `caps/snmp/hpux` | sysDescr starts with "HP-UX" |

### Not covered (23)

22 excluded outright, plus 1 left ambiguous pending a decision.

| Family | Status | Why not covered |
| --- | --- | --- |
| `hp_proliant` | Excluded | Depends entirely on a third OID (`cpqSeUtilProductName`), not `sysDescr`/`sysObjectID` at all |
| `keepalived` | Excluded | Real condition is `sysDescr` contains "linux" AND a third-OID `exists()` check; dropping the `exists()` leaves only "generic Linux" |
| `entersekt` | Excluded | Same shape as `keepalived` — "linux" + `exists()`; dropping it leaves nothing product-specific |
| `quantum` | Excluded | Vendor-identifying half depends on a third OID's value; the remainder alone is just the generic net-snmp OID |
| `fujitsu` | Excluded | Dropping its `exists()` leaves `sysObjectID` under Microsoft's or generic net-snmp's enterprise prefixes — would misfire on unrelated hosts |
| `primekey` | Excluded | Sole condition is the bare generic net-snmp enterprise OID, with no vendor-specific narrowing at all |
| `artec` | Excluded | Condition is generic net-snmp OID AND `sysDescr` contains "version" AND "serial" — too common to be a meaningful vendor signal |
| `zertificon` | Excluded | Real condition is `exists(sysDescr) AND not_exists(sysDescr)` on the same OID — logically impossible, nothing to replicate |
| `oracle_snmp` | Excluded | Its Oracle DIVA CSM check depends on a third OID; unrelated to this repo's own agent-based `caps/db/oracle` |
| `domino` | Excluded | Reduces to a generic Windows/net-snmp-agent OID shared with `hp_proliant`/`supermicro` — not Domino-specific |
| `supermicro` | Excluded | Same shared generic Windows/net-snmp OID as `domino`, plus a dropped `all_of(contains("linux"), exists(...))` half too generic alone |
| `quanta` | Excluded | Reduces to the bare generic net-snmp enterprise OID once its `exists()` is dropped |
| `stormshield` | Excluded | One branch is the bare generic net-snmp OID; the vendor-specific branches both require a dropped `exists()` |
| `synology` | Excluded | Reduces to "`sysDescr` starts with Linux" once its `exists()` is dropped — any Linux host, not Synology-specific |
| `etherbox2` | Excluded | Both variants depend entirely on a third vendor OID, not `sysDescr`/`sysObjectID` |
| `fast_lta` | Excluded | `sysObjectID` half is the bare generic net-snmp OID, gated by a required `exists()` we don't replicate |
| `emerson` | Excluded | Depends entirely on a third OID |
| `hr` | Excluded | Depends entirely on the generic, cross-vendor HOST-RESOURCES-MIB OID — not product-identifying at all |
| `poe` | Excluded | Depends entirely on the generic POWER-ETHERNET-MIB OID |
| `openbsd` | Excluded | Depends entirely on a custom OpenBSD-specific OID |
| `rmon` | Excluded | `sysDescr`/`sysObjectID` remainder is either 100% redundant with the existing `cisco` family or too broad to name a product |
| `carel` | Excluded | Reduces to the same generic pCO-embedded-controller platform shared with the already-covered `climaveneta` |
| `security_master` | Ambiguous | Cited source is missing the leading `.` every real `sysObjectID` value has — looks like an upstream Checkmk bug that would never fire if copied faithfully; deferred pending a decision on whether to replicate the bug or fix it |

### Not applicable (21)

21 directories confirmed to have no SNMP `detect=`/`DETECT_*` condition
anywhere - special agents, agent-section-only plugins that parse the agent's
own stdout, or shared library/support code - and not already classified in
the [Agent plugins coverage](#agent-plugins-coverage) chapter. Derived from
the real `cmk/plugins/` directory listing (279 total) minus the 140
directories accounted for by the 117 Covered + 23 Not covered families above
(five of those 140 don't map 1:1 onto a family name of the same spelling -
`meraki` and the generic cisco/fortinet checks come from the `network`
directory's shared `lib.py`; `intel_true_scale` is directory `intel`;
`oracle_snmp` is directory `oracle`; `netapp` is directory `df`; `arista` is
directory `entity_sensors`), minus the 118 agent plugin families:

`allnet`, `allnet_ip_sensoric`, `areca`, `broadcom_storage`, `citrix`, `ddn_s2a`, `epower`, `fritzbox`, `hp_msa`, `hpe_3par`, `ibm`, `ibmsvc`, `lsi`, `nvidia`, `openhardwaremonitor`, `siemens_plc`, `storeonce`, `stulz`, `tinkerforge`, `unitrends`, `vnx_quotas`

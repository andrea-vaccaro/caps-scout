# Capability coverage tracker

Tracking document for the caps-scout long-term plan. This surveys every Checkmk
plugin family (source: `~/workspace/check_mk/cmk/plugins`, 280 families, survey
taken 2026-09-02; corrected from the original count of 279 — `aws` was
present in the source tree but missed by the original survey pass) and
classifies each one against caps-scout's actual scope:
presence-detection — usually via a locally running process's name,
occasionally via its full command line instead (e.g. ActiveMQ's
`caps/mq/activemq` probe: it's a Java process, so the short process name is
just `java`, too generic — the distinctive marker, `activemq.jar`, only
shows up in the full command line), or via another host-local marker
entirely (e.g. Plesk's `caps/app/plesk` probe checks for a file, since its
own control-panel process can be stopped independently of the rest of the
product) — of a software engine that Checkmk itself only ever monitors
through an already-configured connection, never detects the unconfigured
presence of. This is the same gap the DB-engine probes
(`oracle`, `mysql`, `postgres`, `mssql`, `mongodb`, `redis`, `db2`,
`sap_hana`) already fill.

This complements [`checkmk-label-catalog.md`](checkmk-label-catalog.md), which
surveys *labels* (what Checkmk's own plugins already emit, per-attribute detail).
This document surveys *plugin families* (one row per family) and asks a coarser
question: is there a caps-scout-shaped capability-presence gap here at all?

**Classification rule**, applied to every family:

1. **Covered** — caps-scout already has a probe for it.
2. **Candidate** — a real gap of the same shape as the DB engines: a local
   software engine/daemon that Checkmk only monitors via a configured
   connection, never detects the presence of.
3. **Not applicable** — everything else: SNMP-monitored network/hardware
   appliances, OS built-in resource metrics, per-OS agent sections, generic
   utilities/active checks, cloud/API-managed products, centrally-managed
   endpoint security, capabilities Checkmk *already* presence-detects natively,
   and local software with no reliable single-process signature to match on.

## Summary

| Bucket | Families |
|---|---|
| Covered | 41 |
| Candidate | 0 |
| Not applicable | 239 |
| **Total surveyed** | **280** |

---

## Covered

41 plugin families (42 rows — `corosync` covers two distinct capabilities),
grouped the same way as the candidate gaps below.

### Databases

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
| Couchbase | `couchbase` | `caps/db/couchbase` | directory `/opt/couchbase` exists (default install path, not process-based — see `src/probes/couchbase.rs`) |

### Mail

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Postfix | `postfix` | `caps/mail/postfix` | command line contains `postfix/master`, `postfix/sbin/master`, or `postfix/bin/master` — the bare `master` process name is too generic (shared with Jenkins, gunicorn, etc.); matches Checkmk's own core-agent verification exactly (`agents/check_mk_agent.linux:1231`) |

### Web / application servers

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Apache | `apache` | `caps/web/apache` | process name contains `httpd` or `apache2` |
| nginx | `nginx` | `caps/web/nginx` | process name contains `nginx` |
| SAP NetWeaver | `sap` | `caps/app/sap_netweaver` | process name contains `disp+work` (ABAP stack only) |
| Microsoft Exchange | `msexch` | `caps/app/exchange` | process name contains `Microsoft.Exchange.Store.Service` (Mailbox role only) |
| Plesk | `plesk` | `caps/app/plesk` | file `/etc/psa/.psa.shadow` exists (not process-based — see `src/probes/plesk.rs`) |

### Messaging / streaming / monitoring

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| ActiveMQ | `activemq` | `caps/mq/activemq` | command line contains `activemq.jar` (Java process, name alone is too generic — see `src/probes/activemq.rs`) |
| MQTT (Mosquitto) | `mqtt` | `caps/mq/mqtt` | process name contains `mosquitto` (Mosquitto only; `mqtt` is a protocol, other brokers like HiveMQ/EMQX/VerneMQ aren't detected) |
| Prometheus | `prometheus` | `caps/monitoring/prometheus` | process name contains `prometheus` |
| Alertmanager | `alertmanager` | `caps/monitoring/alertmanager` | process name contains `alertmanager` |

### Container / virtualization runtimes

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Docker | `docker` | `caps/container/docker` | process name contains `dockerd` |
| Podman | `podman` | `caps/container/podman` | file `/run/podman/podman.sock` exists (root socket only, per Checkmk's own socket auto-detection config — not process-based, see `src/probes/podman.rs`) |
| LXC | `lxc` | `caps/container/lxc` | process name contains `lxc monitor` (only while ≥1 container is running — see `src/probes/lxc.rs`) |
| Hyper-V | `hyperv` | `caps/virt/hyperv` | process name contains `vmms.exe` (Windows only) |
| VirtualBox (guest) | `vbox` | `caps/virt/virtualbox_guest` | process name contains `VBoxService` — detects this host *is* a VirtualBox guest VM, not that it runs VirtualBox as a hypervisor (matches the actual scope of Checkmk's own `vbox_guest` plugin — see `src/probes/virtualbox_guest.rs`) |

### Clustering / HA

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Corosync | `corosync` | `caps/cluster/corosync` | process name contains `corosync` |
| Pacemaker/Heartbeat | `corosync` (bundles `heartbeat_crm.py` etc.; a distinct capability, not a separate plugin family) | `caps/cluster/pacemaker` | process name contains `crmd` or `pacemaker-contr` — matches Checkmk's own core-agent gating exactly (`agents/check_mk_agent.linux:1170`) |
| keepalived | `keepalived` | `caps/cluster/keepalived` | process name contains `keepalived` |
| Veritas Cluster Server | `veritas` | `caps/cluster/veritas_cluster_server` | file `/opt/VRTSvcs/bin/haclus` exists — matches Checkmk's own core-agent gating exactly (`agents/check_mk_agent.linux:1368`), not process-based — see `src/probes/veritas.rs` |

### Backup / DR

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Veeam | `veeam` | `caps/backup/veeam` | process name contains `Veeam.Backup.Service` — matches Checkmk's own agent script exactly (`veeam/agents/veeam_backup_status.ps1`) |
| IBM TSM / Storage Protect | `tsm` | `caps/backup/tsm` | process name contains `dsmserv` (server) or `dsmcad` (client scheduler) |
| Arcserve Backup | `arcserve` | `caps/backup/arcserve` | process name contains `dbeng.exe` or `jobeng.exe` — Arcserve's own docs confirm these as the primary server's core DB/Job Engine components; not the same product as Arcserve UDP/D2D's `CASAD2DWebSvc` |
| Zerto Virtual Manager | `zerto` | `caps/backup/zerto` | process name contains `Zerto.Zvm.Service` — detects a host running ZVM itself, not a host merely protected by Zerto's separate VRA appliance (which isn't detectable this way — see `src/probes/zerto.rs`) |

### Load balancing / caching

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| HAProxy | `haproxy` | `caps/lb/haproxy` | process name contains `haproxy` — Checkmk's own core agent instead checks for a stats socket (opt-in config), which caps-scout deliberately doesn't mirror since it wants "is it present", not "is it monitorable" — see `src/probes/haproxy.rs` |
| Varnish | `varnish` | `caps/cache/varnish` | process name contains `varnishd` |

### File / print / network services

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| CUPS | `cups` | `caps/print/cups` | process name contains `cupsd` |
| NFS server | `nfsexports` | `caps/file/nfs_server` | process name contains `rpc.mountd` — `nfsd` itself usually runs as kernel threads, not a normal process; `rpc.mountd` is a userspace daemon that only runs while the NFS server is active, matching Checkmk's own gating (`nfsexports/agents/nfsexports`) — see `src/probes/nfs_server.rs` |
| ISC DHCP | `isc` | `caps/net/isc_dhcpd` | process name contains `dhcpd` — this plugin family is ISC DHCP only, no BIND/`named` component (corrects the original candidate note's premise) |

### Collaboration

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| IBM Domino | `domino` | `caps/collab/domino` | process name contains `nserver` |
| Skype for Business | `skype` | `caps/collab/skype_for_business` | process name contains `RtcSrv` or `Rtcsrv` (Front End role only — matches Checkmk's own check, which also targets a "skype frontend server") |

### Cloud provisioning

Not gap-filling probes in the DB-engine sense — `caps-scout` doesn't monitor
AWS/Azure resources via their APIs the way Checkmk's `aws`/`azure` special
agents do (which need credentials and report on cloud-side resources like
EC2 instances or Azure VMs as *managed objects*, not on the host itself).
This is a different question entirely: "was *this host* provisioned by
AWS/Azure", answered purely from local host state, no network call.

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| AWS EC2 provisioning | `aws` (loosely — see note above; Checkmk's `aws` plugin is unrelated in mechanism) | `caps/cloud/aws-vm` | file `/sys/devices/virtual/dmi/id/board_asset_tag` contains an instance-ID-shaped value (`i-` + hex) — AWS's own documented, non-privileged EC2 detection method (docs.aws.amazon.com/AWSEC2/latest/UserGuide/identify_ec2_instances.html). Covers essentially all of today's EC2 fleet (Nitro-based, including legacy instance type names transparently migrated to Nitro hardware) except a documented, permanent exception: legacy GPU/FPGA families (G2, G3, P2, P3, F1), which never run on Nitro — see `src/probes/aws_vm.rs` |
| Azure VM provisioning | `azure` (loosely — see note above) | `caps/cloud/azure-vm` | file `/sys/devices/virtual/dmi/id/chassis_asset_tag` exactly equals `7783-7084-3265-9085-8269-3286-77` — the fixed value Azure hard-codes into every VM's DMI chassis asset tag (public cloud and Azure Stack), verified against `cloud-init`'s own detection logic (`tools/ds-identify`, `is_azure_chassis()`, github.com/canonical/cloud-init). Unlike AWS's shape-matched instance ID, this is an exact-match constant. `cloud-init` also excludes containers here since they inherit the host's DMI data; this probe doesn't, kept in parity with `aws_vm` — see `src/probes/azure_vm.rs` |

### Operating system

| Capability | Checkmk plugin family | Label | Detection |
|---|---|---|---|
| Host OS | `checkmk` (core agent's `os_family`/`AgentOS`) | `caps/os_type/<name>` | compile-time `cfg!(target_os = ...)`, not a runtime probe |

---

## Candidate gaps

None remaining — every plugin family originally identified as a
caps-scout-shaped presence gap has since been implemented and moved into
[Covered](#covered) above. This section stays as a placeholder: a future
survey (e.g. after a new Checkmk plugin family is added upstream) may find
new candidates here.

---

## Not applicable

240 families, grouped by why they fall outside caps-scout's scope. Every
family in `cmk/plugins` was placed in exactly one bucket (Covered, Candidate,
or one of these); nothing was skipped.

- **SNMP-monitored network/hardware appliances & environmental sensors** (149) —
  the large majority of the catalog: routers, switches, firewalls/UTMs, load
  balancer *appliances*, UPS/PDU, HVAC/cooling controllers, environmental
  sensors, printers, tape/storage arrays, HBAs/RAID controllers, industrial
  controllers, and similar hardware reached only over SNMP/API, never a local
  process on the monitored host itself: `acme`, `adva`, `akcp`, `alcatel`,
  `allnet`, `allnet_ip_sensoric`, `apc`, `arbor`, `areca`, `arris`, `artec`,
  `aruba`, `atto`, `audiocodes`, `avaya`, `barracuda`, `bdt_tape`, `bintec`,
  `blade`, `bluecat`, `bluecoat`, `bluenet`, `broadcom_storage`, `brocade`,
  `bvip`, `carel`, `casa`, `checkpoint`, `ciena_ces`, `cisco`, `cisco_sma`,
  `citrix`, `climaveneta`, `cpsecure`, `datapower`, `ddn_s2a`, `decru`,
  `didactum`, `docsis`, `eltek`, `emc`, `emerson`, `emka`, `enterasys`,
  `entity_sensors`, `enviromux`, `epower`, `epson`, `etherbox2`, `ewon`,
  `f5_bigip`, `f5os_rseries`, `fast_lta`, `fireeye`, `fjdarye`, `fortinet`,
  `fritzbox`, `fujitsu`, `genua`, `gude`, `h3c`, `hepta`, `hitachi`,
  `hitachi_hnas`, `hp`, `hp_blade`, `hpe_3par`, `hp_hh3c`, `hp_mcs`, `hp_msa`,
  `hp_procurve`, `hp_proliant`, `hr`, `huawei`, `hwg`, `ibm`, `ibmsvc`, `icom`,
  `infoblox`, `infratec_plus`, `innovaphone`, `intel`, `ipr400`, `ispro`,
  `janitza`, `juniper`, `kemp_loadmaster`, `kentix`, `knuerr`, `kyocera`,
  `lgp`, `liebert`, `lsi`, `meinberg`, `mikrotik`, `moxa`, `netextreme`,
  `netgear`, `netscaler`, `nimble`, `nvidia`, `openhardwaremonitor`, `orion`,
  `packeteer`, `palo_alto`, `pandacom`, `papouch`, `perle`, `pfsense`,
  `poe`, `poseidon`, `primekey`, `printer`, `pulse_secure`, `qlogic`, `qnap`,
  `quanta`, `quantum`, `raritan`, `rittal`, `rmon`, `roomalert`, `safenet`,
  `seh`, `sensatronics`, `sentry`, `siemens_plc`, `silverpeak`,
  `sni_octopuse`, `sophos`, `steelhead`, `storeonce`, `stormshield`, `stulz`,
  `supermicro`, `superstack3`, `sym_brightmail`, `synology`, `teracom`,
  `tinkerforge`, `unitrends`, `ups`, `vnx_quotas`, `vutlan`, `wagner`,
  `watchdog`, `wut`, `zebra`, `zertificon`

- **OS built-in resource metrics** (23) — always-there facts about any host,
  not "engine presence": `apt`, `cpu`, `df`, `diskstat`, `dmi`, `dmraid`,
  `kernel`, `logins`, `lparstat`, `lvm`, `mdraid`, `memory`, `mounts`, `ntp`,
  `smart`, `statgrab`, `suseconnect`, `time`, `uptime`, `vxvm`, `zfs`,
  `zpool`, `zypper`

- **Per-OS agent sections** (7) — platform variants of the core agent, not
  capabilities: `aix`, `hpux`, `lnx`, `openbsd`, `solaris`, `vms`, `windows`

- **Generic utilities / protocol active checks** (25) — Nagios-style
  connectivity tests or generic agent plumbing, not tied to a specific engine:
  `collection`, `diagnostics`, `dns`, `emailchecks`, `filehandler`,
  `fileinfo`, `files`, `form_submit`, `generic_agent_options`, `inotify`,
  `jar_signature`, `job`, `ldapcheck`, `monitoring_plugins`, `mtr`, `network`,
  `ps` (user-configured process-discovery ruleset — not something caps-scout
  detects), `sftp`, `smb`, `smtp`, `sql`, `ssh`, `systemd` (same reasoning as
  `ps`), `tcp`, `traceroute`

- **Cloud/API-managed products** (12) — no local host process to probe; data
  comes from a cloud API or central console: `appdynamics`, `azure_status`,
  `cisco_meraki`, `datadog`, `extremecloud_iq`, `hivemanager`,
  `hivemanager_ng`, `jira`, `mobileiron`, `msoffice`, `ruckus_spot`,
  `salesforce` (`azure` moved to Covered — see Cloud provisioning; it's an
  API-managed product for resource monitoring, but also loosely covers the
  `caps/cloud/azure-vm` local-provisioning probe, same relationship as
  `aws`)

- **Centrally-managed endpoint security** (3) — agent reports to a
  management console via API, not a distinguishing local-process signal:
  `kaspersky`, `mcafee`, `symantec`

- **Already presence-detected by Checkmk itself** (3) — no gap to fill,
  unlike the DB engines: `ceph` (`cmk/ceph/mon: "yes"`, `cmk/ceph/osd:
  "yes"`), `omd` (`cmk/check_mk_server: "yes"`), `pvecm` (Proxmox VE cluster
  status; Proxmox VE object presence is separately labeled via
  `cmk/pve/entity`) — see `checkmk-label-catalog.md` for the label detail.

- **Niche/legacy, or no reliable single-process signature** (17) —
  real local software in some cases, but not confident enough to guess a
  detection pattern, or superseded by a clearer candidate above (e.g.
  `nullmailer`/`qmail_stats` vs. `postfix` as the mail-server signal):
  `cadvisor` (metrics exporter for containers already covered by
  `docker`/`podman`, not a distinct engine), `cbl`, `drbd` (kernel module,
  not a persistent daemon), `entersekt`, `hyperv_cluster` (aggregates the
  `hyperv` candidate above), `jolokia` (JMX-HTTP bridge, not itself an
  engine), `libelle`, `mailman_lists`, `nullmailer`, `qmail_stats`,
  `sansymphony`, `scaleio`, `security_master`, `strem1`, `sylo`, `uniserv`,
  `zorp`

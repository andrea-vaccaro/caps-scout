mod emit;
mod probes;

use probes::RealFileSystem;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

fn main() {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
    );
    let filesystem = RealFileSystem;

    let labels: Vec<(&str, &str)> = [
        probes::detect_oracle(&system),
        probes::detect_mysql(&system),
        probes::detect_postgres(&system),
        probes::detect_mssql(&system),
        probes::detect_mongodb(&system),
        probes::detect_redis(&system),
        probes::detect_db2(&system),
        probes::detect_sap_hana(&system),
        probes::detect_apache(&system),
        probes::detect_nginx(&system),
        probes::detect_sap_netweaver(&system),
        probes::detect_msexch(&system),
        probes::detect_plesk(&filesystem),
        probes::detect_couchbase(&filesystem),
        probes::detect_activemq(&system),
        probes::detect_mqtt(&system),
        probes::detect_prometheus(&system),
        probes::detect_alertmanager(&system),
        probes::detect_docker(&system),
        probes::detect_podman(&filesystem),
        probes::detect_lxc(&system),
        probes::detect_hyperv(&system),
        probes::detect_virtualbox_guest(&system),
        probes::detect_corosync(&system),
        probes::detect_pacemaker(&system),
        probes::detect_keepalived(&system),
        probes::detect_veritas(&filesystem),
        probes::detect_postfix(&system),
        probes::detect_veeam(&system),
        probes::detect_tsm(&system),
        probes::detect_arcserve(&system),
        probes::detect_zerto(&system),
        probes::detect_haproxy(&system),
        probes::detect_varnish(&system),
        probes::detect_cups(&system),
        probes::detect_nfs_server(&system),
        probes::detect_isc_dhcpd(&system),
        probes::detect_domino(&system),
        probes::detect_skype(&system),
        probes::detect_aws_vm(&filesystem),
        probes::detect_azure_vm(&filesystem),
        probes::detect_os(),
    ]
    .into_iter()
    .flatten()
    .map(|key| (key, "yes"))
    .collect();

    emit::emit_labels(&labels);
}

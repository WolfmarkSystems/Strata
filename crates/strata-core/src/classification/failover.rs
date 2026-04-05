use std::path::{Path, PathBuf};

use super::cluster;
use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records, parse_reg_u32};

pub fn get_failover_config() -> FailoverCluster {
    let cluster_reg_path = default_reg_path("cluster.reg");
    let topology_path = std::env::var("FORENSIC_CLUSTER_TOPOLOGY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("cluster")
                .join("cluster_topology.json")
        });
    get_failover_config_from_sources(&cluster_reg_path, &topology_path)
}

pub fn get_failover_config_from_sources(
    cluster_reg_path: &Path,
    topology_path: &Path,
) -> FailoverCluster {
    let mut config = FailoverCluster::default();
    let records = load_reg_records(cluster_reg_path);

    for record in &records {
        let lower = record.path.to_ascii_lowercase();

        if (lower.ends_with("\\cluster")
            || lower.ends_with("\\cluster\\cluster")
            || lower == "hkey_local_machine\\cluster")
            && config.name.is_empty()
        {
            config.name = record
                .values
                .get("ClusterName")
                .or_else(|| record.values.get("Name"))
                .and_then(|raw| decode_reg_string(raw))
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_default();
        }

        if lower.contains("\\cluster\\nodes\\") {
            if let Some(node_name) = record
                .values
                .get("NodeName")
                .or_else(|| record.values.get("Name"))
                .and_then(|raw| decode_reg_string(raw))
                .filter(|value| !value.trim().is_empty())
            {
                config.nodes.push(node_name);
            }
        }

        if lower.contains("\\cluster\\groups\\") {
            if let Some(group_name) = record
                .values
                .get("Name")
                .and_then(|raw| decode_reg_string(raw))
                .filter(|value| !value.trim().is_empty())
            {
                config.resource_groups.push(group_name);
            }
        }

        if lower.contains("clusterawareupdating") && config.cluster_aware_updating.is_none() {
            config.cluster_aware_updating = record
                .values
                .get("Enable")
                .or_else(|| record.values.get("Enabled"))
                .and_then(|raw| parse_reg_u32(raw))
                .map(|value| value != 0);
        }

        if lower.ends_with("\\currentcontrolset\\services\\clussvc") {
            config.cluster_service_start = record
                .values
                .get("Start")
                .and_then(|raw| parse_reg_u32(raw))
                .map(start_type_label)
                .unwrap_or("Unknown")
                .to_string();

            config.cluster_service_image = record
                .values
                .get("ImagePath")
                .and_then(|raw| decode_reg_string(raw))
                .unwrap_or_default();
        }
    }

    let topology = cluster::get_cluster_info_from_path(topology_path);
    if config.name.is_empty() {
        config.name = topology.name;
    }
    config.nodes.extend(topology.nodes);
    config.enabled = !config.name.is_empty()
        || !config.nodes.is_empty()
        || matches!(
            config.cluster_service_start.as_str(),
            "Automatic" | "Boot" | "System"
        );

    config.nodes.sort();
    config.nodes.dedup();
    config.resource_groups.sort();
    config.resource_groups.dedup();

    apply_risk_heuristics(&mut config);
    config
}

fn apply_risk_heuristics(config: &mut FailoverCluster) {
    if !config.cluster_service_image.trim().is_empty()
        && !is_expected_cluster_service_path(&config.cluster_service_image)
    {
        config
            .reasons
            .push("clussvc_binary_outside_windows_cluster_path".to_string());
    }

    if config.enabled && config.nodes.len() == 1 {
        config
            .reasons
            .push("single_node_cluster_configuration".to_string());
    }

    if matches!(config.cluster_aware_updating, Some(false)) && config.enabled {
        config
            .reasons
            .push("cluster_aware_updating_disabled".to_string());
    }

    config.suspicious = !config.reasons.is_empty();
}

fn is_expected_cluster_service_path(path: &str) -> bool {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();
    normalized.contains(r"\windows\cluster\clussvc.exe")
        || normalized.contains(r"%systemroot%\cluster\clussvc.exe")
        || normalized.contains(r"\systemroot\cluster\clussvc.exe")
}

fn start_type_label(value: u32) -> &'static str {
    match value {
        0 => "Boot",
        1 => "System",
        2 => "Automatic",
        3 => "Manual",
        4 => "Disabled",
        _ => "Unknown",
    }
}

#[derive(Debug, Clone, Default)]
pub struct FailoverCluster {
    pub name: String,
    pub nodes: Vec<String>,
    pub resource_groups: Vec<String>,
    pub cluster_service_start: String,
    pub cluster_service_image: String,
    pub cluster_aware_updating: Option<bool>,
    pub enabled: bool,
    pub suspicious: bool,
    pub reasons: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parses_failover_cluster_and_merges_topology() {
        let dir = tempfile::tempdir().expect("temp dir");
        let reg_path = dir.path().join("cluster.reg");
        let topology_path = dir.path().join("cluster_topology.json");

        strata_fs::write(
            &reg_path,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\Cluster]
"ClusterName"="CORP-CLUSTER"

[HKEY_LOCAL_MACHINE\Cluster\Nodes\1]
"NodeName"="NODE-A"

[HKEY_LOCAL_MACHINE\Cluster\Nodes\2]
"NodeName"="NODE-B"

[HKEY_LOCAL_MACHINE\Cluster\Groups\{1234-5678}]
"Name"="Available Storage"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ClusterAwareUpdating]
"Enabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClusSvc]
"Start"=dword:00000002
"ImagePath"="%SystemRoot%\\Cluster\\clussvc.exe"
"#,
        )
        .expect("write cluster reg");

        strata_fs::write(
            &topology_path,
            r#"{"name":"ignored-name","nodes":["NODE-A","NODE-C"],"enabled":true}"#,
        )
        .expect("write topology");

        let cfg = get_failover_config_from_sources(&reg_path, &topology_path);
        assert_eq!(cfg.name, "CORP-CLUSTER");
        assert_eq!(cfg.nodes, vec!["NODE-A", "NODE-B", "NODE-C"]);
        assert_eq!(cfg.resource_groups, vec!["Available Storage"]);
        assert_eq!(cfg.cluster_service_start, "Automatic");
        assert_eq!(cfg.cluster_aware_updating, Some(true));
        assert!(cfg.enabled);
        assert!(!cfg.suspicious);
    }

    #[test]
    fn flags_suspicious_cluster_service_binary_and_disabled_cau() {
        let dir = tempfile::tempdir().expect("temp dir");
        let reg_path = dir.path().join("cluster.reg");
        let topology_path = dir.path().join("cluster_topology.json");

        strata_fs::write(
            &reg_path,
            r#"
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\Cluster]
"ClusterName"="SINGLE-NODE"

[HKEY_LOCAL_MACHINE\Cluster\Nodes\1]
"NodeName"="NODE-ONLY"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ClusterAwareUpdating]
"Enable"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClusSvc]
"Start"=dword:00000002
"ImagePath"="C:\\Users\\Public\\clussvc.exe"
"#,
        )
        .expect("write cluster reg");

        strata_fs::write(&topology_path, "{}").expect("write topology");

        let cfg = get_failover_config_from_sources(&reg_path, &topology_path);
        assert!(cfg.suspicious);
        assert!(cfg
            .reasons
            .iter()
            .any(|reason| reason == "clussvc_binary_outside_windows_cluster_path"));
        assert!(cfg
            .reasons
            .iter()
            .any(|reason| reason == "single_node_cluster_configuration"));
        assert!(cfg
            .reasons
            .iter()
            .any(|reason| reason == "cluster_aware_updating_disabled"));
    }
}

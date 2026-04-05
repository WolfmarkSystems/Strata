use serde_json::Value;
use std::path::{Path, PathBuf};

pub fn get_cluster_info() -> ClusterInfo {
    let path = std::env::var("FORENSIC_CLUSTER_TOPOLOGY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("cluster")
                .join("cluster_topology.json")
        });
    get_cluster_info_from_path(&path)
}

pub fn get_cluster_info_from_path(path: &Path) -> ClusterInfo {
    let Ok(data) = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
    else {
        return ClusterInfo::default();
    };

    let Ok(json) = serde_json::from_slice::<Value>(&data) else {
        return parse_cluster_info_from_lines(&String::from_utf8_lossy(&data));
    };

    let name = json
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let nodes = json
        .get("nodes")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|value| value.as_str().map(ToString::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let shared_volumes = json
        .get("shared_volumes")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|value| value.as_str().map(ToString::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    ClusterInfo {
        name,
        nodes,
        quorum: json
            .get("quorum")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        shared_volumes,
        enabled: json
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn parse_cluster_info_from_lines(text: &str) -> ClusterInfo {
    let mut info = ClusterInfo::default();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "name" => info.name = value.trim().to_string(),
            "node" | "nodes" => info.nodes.extend(
                value
                    .split(',')
                    .map(|node| node.trim().to_string())
                    .filter(|node| !node.is_empty()),
            ),
            "quorum" => info.quorum = value.trim().to_string(),
            "shared_volume" | "shared_volumes" => info.shared_volumes.extend(
                value
                    .split(',')
                    .map(|volume| volume.trim().to_string())
                    .filter(|volume| !volume.is_empty()),
            ),
            "enabled" => {
                let lower = value.trim().to_ascii_lowercase();
                info.enabled = matches!(lower.as_str(), "1" | "true" | "yes");
            }
            _ => {}
        }
    }

    info.nodes.sort();
    info.nodes.dedup();
    info.shared_volumes.sort();
    info.shared_volumes.dedup();
    info
}

#[derive(Debug, Clone, Default)]
pub struct ClusterInfo {
    pub name: String,
    pub nodes: Vec<String>,
    pub quorum: String,
    pub shared_volumes: Vec<String>,
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parses_cluster_topology_json() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("cluster_topology.json");

        strata_fs::write(
            &file,
            r#"{
  "name": "corp-cluster",
  "nodes": ["node-a", "node-b"],
  "quorum": "NodeAndDiskMajority",
  "shared_volumes": ["CSV01", "CSV02"],
  "enabled": true
}"#,
        )
        .expect("write json");

        let info = get_cluster_info_from_path(&file);
        assert_eq!(info.name, "corp-cluster");
        assert_eq!(info.nodes, vec!["node-a", "node-b"]);
        assert_eq!(info.quorum, "NodeAndDiskMajority");
        assert_eq!(info.shared_volumes, vec!["CSV01", "CSV02"]);
        assert!(info.enabled);
    }
}

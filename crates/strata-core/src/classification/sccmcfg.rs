use serde_json::Value;
use std::path::PathBuf;

use super::sccm_parse;

pub fn get_sccm_config() -> SccmConfig {
    let clients = sccm_parse::get_sccm_clients();
    let deployments = sccm_parse::get_sccm_software_deployments();
    let collections = sccm_parse::get_sccm_collections();
    let task_sequences = sccm_parse::get_sccm_task_sequence();
    let override_json = load_sccm_config_override();

    get_sccm_config_from_inputs(
        &clients,
        &deployments,
        &collections,
        &task_sequences,
        override_json.as_ref(),
    )
}

pub fn get_sccm_config_from_inputs(
    clients: &[sccm_parse::SccmClient],
    deployments: &[sccm_parse::SoftwareDeployment],
    collections: &[sccm_parse::SccmCollection],
    task_sequences: &[sccm_parse::TaskSequence],
    override_json: Option<&Value>,
) -> SccmConfig {
    let site_code = override_json
        .and_then(|json| json.get("site_code").and_then(Value::as_str))
        .map(ToString::to_string)
        .or_else(|| {
            clients
                .iter()
                .find(|client| !client.site_code.trim().is_empty())
                .map(|client| client.site_code.clone())
        })
        .unwrap_or_default();

    let management_point = override_json
        .and_then(|json| json.get("management_point").and_then(Value::as_str))
        .map(ToString::to_string)
        .unwrap_or_default();

    let last_heartbeat = clients
        .iter()
        .map(|client| client.last_heartbeat)
        .max()
        .unwrap_or(0);

    let active_clients = clients.iter().filter(|client| client.active).count();
    let healthy = !site_code.is_empty() && (active_clients > 0 || !clients.is_empty());

    SccmConfig {
        site_code,
        management_point,
        client_count: clients.len() as u32,
        active_client_count: active_clients as u32,
        deployment_count: deployments.len() as u32,
        collection_count: collections.len() as u32,
        task_sequence_count: task_sequences.len() as u32,
        last_heartbeat,
        healthy,
    }
}

#[derive(Debug, Clone, Default)]
pub struct SccmConfig {
    pub site_code: String,
    pub management_point: String,
    pub client_count: u32,
    pub active_client_count: u32,
    pub deployment_count: u32,
    pub collection_count: u32,
    pub task_sequence_count: u32,
    pub last_heartbeat: u64,
    pub healthy: bool,
}

fn load_sccm_config_override() -> Option<Value> {
    let path = std::env::var("FORENSIC_SCCM_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("sccm")
                .join("sccm_config.json")
        });

    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    serde_json::from_slice::<Value>(&data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_sccm_config_from_parsed_collections() {
        let clients = vec![
            sccm_parse::SccmClient {
                hostname: "host-a".to_string(),
                client_id: "CID-001".to_string(),
                last_heartbeat: 1_700_000_000,
                site_code: "PR1".to_string(),
                active: true,
            },
            sccm_parse::SccmClient {
                hostname: "host-b".to_string(),
                client_id: "CID-002".to_string(),
                last_heartbeat: 1_700_000_100,
                site_code: "PR1".to_string(),
                active: false,
            },
        ];

        let deployments = vec![sccm_parse::SoftwareDeployment {
            package_id: "PKG001".to_string(),
            package_name: "Security Update".to_string(),
            target_machines: vec!["host-a".to_string()],
            status: "InProgress".to_string(),
            start_time: 1_700_000_050,
        }];

        let collections = vec![sccm_parse::SccmCollection {
            collection_id: "COL001".to_string(),
            name: "Workstations".to_string(),
            member_count: 2,
            collection_type: "Device".to_string(),
        }];

        let task_sequences = vec![sccm_parse::TaskSequence {
            package_id: "TS001".to_string(),
            name: "Build".to_string(),
            steps: vec!["Apply OS".to_string()],
        }];

        let override_json = serde_json::json!({
            "management_point": "mp01.corp.local"
        });

        let cfg = get_sccm_config_from_inputs(
            &clients,
            &deployments,
            &collections,
            &task_sequences,
            Some(&override_json),
        );

        assert_eq!(cfg.site_code, "PR1");
        assert_eq!(cfg.management_point, "mp01.corp.local");
        assert_eq!(cfg.client_count, 2);
        assert_eq!(cfg.active_client_count, 1);
        assert_eq!(cfg.deployment_count, 1);
        assert_eq!(cfg.collection_count, 1);
        assert_eq!(cfg.task_sequence_count, 1);
        assert_eq!(cfg.last_heartbeat, 1_700_000_100);
        assert!(cfg.healthy);
    }
}

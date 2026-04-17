//! Cloud CLI credential + configuration artifacts (CLOUD-1).
//!
//! Air-gapped: parses local files only. Never logs credential values.
//!
//! MITRE: T1552.001 (credentials in files), T1078.004 (cloud accounts).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::fs;
use std::path::Path;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudCliArtifact {
    pub provider: String,
    pub artifact_type: String,
    pub profile_name: Option<String>,
    pub account_id: Option<String>,
    pub tenant_id: Option<String>,
    pub region: Option<String>,
    pub credentials_present: bool,
    pub aws_key_type: Option<String>,
    pub role_arn: Option<String>,
    pub last_active: Option<DateTime<Utc>>,
    pub terraform_resources: Vec<String>,
}

pub fn classify(path: &Path) -> Option<&'static str> {
    let lower = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    if lower.contains("/.aws/credentials") || name == "credentials" && lower.contains("/.aws/") {
        return Some("AWSCredentials");
    }
    if lower.contains("/.aws/config") {
        return Some("AWSConfig");
    }
    if lower.contains("/.azure/accesstokens.json") {
        return Some("AzureAccessTokens");
    }
    if lower.contains("/.azure/azureprofile.json") {
        return Some("AzureProfile");
    }
    if lower.contains("/.config/gcloud/application_default_credentials.json") {
        return Some("GcpAdc");
    }
    if lower.contains("/.config/gcloud/properties") {
        return Some("GcpProperties");
    }
    if name == "terraform.tfstate" {
        return Some("TerraformState");
    }
    if lower.contains("/.kube/config") {
        return Some("KubeConfig");
    }
    None
}

fn parse_ini(body: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut sections: Vec<(String, Vec<(String, String)>)> = Vec::new();
    let mut current: Option<(String, Vec<(String, String)>)> = None;
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Some(finished) = current.take() {
                sections.push(finished);
            }
            current = Some((rest.to_string(), Vec::new()));
        } else if let Some((key, value)) = line.split_once('=') {
            if let Some((_, kvs)) = current.as_mut() {
                kvs.push((key.trim().to_string(), value.trim().to_string()));
            }
        }
    }
    if let Some(finished) = current {
        sections.push(finished);
    }
    sections
}

fn classify_aws_key(access_key: &str) -> &'static str {
    if access_key.starts_with("AKIA") {
        "LongTerm"
    } else if access_key.starts_with("ASIA") {
        "Temporary"
    } else {
        "Unknown"
    }
}

pub fn parse_aws_credentials(body: &str) -> Vec<CloudCliArtifact> {
    let mut out = Vec::new();
    for (profile, kvs) in parse_ini(body) {
        let access = kvs
            .iter()
            .find(|(k, _)| k == "aws_access_key_id")
            .map(|(_, v)| v.clone());
        let has_secret = kvs.iter().any(|(k, _)| k == "aws_secret_access_key");
        let key_type = access.as_deref().map(classify_aws_key).map(String::from);
        out.push(CloudCliArtifact {
            provider: "AWS".into(),
            artifact_type: "Credentials".into(),
            profile_name: Some(profile),
            account_id: access,
            tenant_id: None,
            region: None,
            credentials_present: has_secret,
            aws_key_type: key_type,
            role_arn: None,
            last_active: None,
            terraform_resources: Vec::new(),
        });
    }
    out
}

pub fn parse_aws_config(body: &str) -> Vec<CloudCliArtifact> {
    let mut out = Vec::new();
    for (profile, kvs) in parse_ini(body) {
        let region = kvs.iter().find(|(k, _)| k == "region").map(|(_, v)| v.clone());
        let role = kvs
            .iter()
            .find(|(k, _)| k == "role_arn")
            .map(|(_, v)| v.clone());
        out.push(CloudCliArtifact {
            provider: "AWS".into(),
            artifact_type: "Config".into(),
            profile_name: Some(profile),
            account_id: None,
            tenant_id: None,
            region,
            credentials_present: false,
            aws_key_type: None,
            role_arn: role,
            last_active: None,
            terraform_resources: Vec::new(),
        });
    }
    out
}

pub fn parse_azure_access_tokens(body: &str) -> Vec<CloudCliArtifact> {
    let Ok(tokens) = serde_json::from_str::<Vec<serde_json::Value>>(body) else {
        return Vec::new();
    };
    tokens
        .into_iter()
        .map(|t| CloudCliArtifact {
            provider: "Azure".into(),
            artifact_type: "AccessToken".into(),
            profile_name: t
                .get("subscriptionName")
                .and_then(|v| v.as_str())
                .map(String::from),
            account_id: t
                .get("subscriptionId")
                .and_then(|v| v.as_str())
                .map(String::from),
            tenant_id: t
                .get("tenantId")
                .and_then(|v| v.as_str())
                .map(String::from),
            region: None,
            credentials_present: t.get("accessToken").is_some() || t.get("refreshToken").is_some(),
            aws_key_type: None,
            role_arn: None,
            last_active: t
                .get("expiresOn")
                .and_then(|v| v.as_str())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            terraform_resources: Vec::new(),
        })
        .collect()
}

pub fn parse_terraform_state(body: &str) -> Vec<CloudCliArtifact> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let resources = v.get("resources").and_then(|r| r.as_array());
    let Some(resources) = resources else {
        return Vec::new();
    };
    let mut names: Vec<String> = Vec::new();
    for res in resources {
        let kind = res.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let name = res.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if !kind.is_empty() {
            names.push(format!("{}.{}", kind, name));
        }
    }
    vec![CloudCliArtifact {
        provider: "Terraform".into(),
        artifact_type: "StateFile".into(),
        profile_name: None,
        account_id: None,
        tenant_id: None,
        region: None,
        credentials_present: false,
        aws_key_type: None,
        role_arn: None,
        last_active: None,
        terraform_resources: names,
    }]
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let Some(kind) = classify(path) else {
        return Vec::new();
    };
    let Ok(body) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let records = match kind {
        "AWSCredentials" => parse_aws_credentials(&body),
        "AWSConfig" => parse_aws_config(&body),
        "AzureAccessTokens" => parse_azure_access_tokens(&body),
        "TerraformState" => parse_terraform_state(&body),
        _ => vec![CloudCliArtifact {
            provider: match kind {
                "GcpAdc" | "GcpProperties" => "GCP".into(),
                "KubeConfig" => "Kubernetes".into(),
                "AzureProfile" => "Azure".into(),
                _ => "Unknown".into(),
            },
            artifact_type: kind.to_string(),
            profile_name: None,
            account_id: None,
            tenant_id: None,
            region: None,
            credentials_present: false,
            aws_key_type: None,
            role_arn: None,
            last_active: None,
            terraform_resources: Vec::new(),
        }],
    };
    records
        .into_iter()
        .map(|r| {
            let mut a = Artifact::new("Cloud CLI Config", &path.to_string_lossy());
            a.timestamp = r.last_active.map(|d| d.timestamp() as u64);
            a.add_field(
                "title",
                &format!(
                    "{} {}: {}",
                    r.provider,
                    r.artifact_type,
                    r.profile_name.as_deref().unwrap_or("-")
                ),
            );
            a.add_field("file_type", "Cloud CLI Config");
            a.add_field("provider", &r.provider);
            a.add_field("artifact_type", &r.artifact_type);
            if let Some(v) = &r.profile_name {
                a.add_field("profile_name", v);
            }
            if let Some(v) = &r.account_id {
                a.add_field("account_id", v);
            }
            if let Some(v) = &r.tenant_id {
                a.add_field("tenant_id", v);
            }
            if let Some(v) = &r.region {
                a.add_field("region", v);
            }
            if let Some(k) = &r.aws_key_type {
                a.add_field("aws_key_type", k);
            }
            if let Some(arn) = &r.role_arn {
                a.add_field("role_arn", arn);
            }
            for res in &r.terraform_resources {
                a.add_field("terraform_resource", res);
            }
            if r.credentials_present {
                a.add_field("credentials_present", "true");
                a.add_field("suspicious", "true");
                a.add_field("forensic_value", "High");
            } else {
                a.add_field("forensic_value", "Medium");
            }
            a.add_field("mitre", "T1552.001");
            a.add_field("mitre_secondary", "T1078.004");
            a
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_recognises_cloud_paths() {
        assert_eq!(
            classify(Path::new("/home/alice/.aws/credentials")),
            Some("AWSCredentials")
        );
        assert_eq!(
            classify(Path::new("/home/alice/.aws/config")),
            Some("AWSConfig")
        );
        assert_eq!(
            classify(Path::new("/home/alice/.azure/accessTokens.json")),
            Some("AzureAccessTokens")
        );
        assert_eq!(
            classify(Path::new("/projects/foo/terraform.tfstate")),
            Some("TerraformState")
        );
        assert_eq!(
            classify(Path::new("/home/alice/.kube/config")),
            Some("KubeConfig")
        );
    }

    #[test]
    fn parse_aws_credentials_identifies_long_and_temp_keys() {
        let body = "[default]\n\
                    aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n\
                    aws_secret_access_key = ...redacted...\n\n\
                    [temp-role]\n\
                    aws_access_key_id = ASIAIOSFODNN7EXAMPLE\n\
                    aws_secret_access_key = ...redacted...\n";
        let records = parse_aws_credentials(body);
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .any(|r| r.aws_key_type.as_deref() == Some("LongTerm")));
        assert!(records
            .iter()
            .any(|r| r.aws_key_type.as_deref() == Some("Temporary")));
    }

    #[test]
    fn parse_azure_access_tokens_captures_tenant() {
        let body = r#"[
            {"subscriptionName":"Prod","subscriptionId":"sub-1","tenantId":"tenant-a",
             "accessToken":"token","expiresOn":"2024-06-01T12:00:00Z"}
        ]"#;
        let records = parse_azure_access_tokens(body);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tenant_id.as_deref(), Some("tenant-a"));
        assert!(records[0].credentials_present);
    }

    #[test]
    fn parse_terraform_state_lists_resources() {
        let body = r#"{"resources":[{"type":"aws_instance","name":"web"},{"type":"aws_s3_bucket","name":"data"}]}"#;
        let records = parse_terraform_state(body);
        assert_eq!(records.len(), 1);
        assert!(records[0]
            .terraform_resources
            .iter()
            .any(|r| r == "aws_instance.web"));
    }

    #[test]
    fn scan_emits_aws_credentials_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let aws = dir.path().join("home").join("alice").join(".aws");
        std::fs::create_dir_all(&aws).expect("mkdirs");
        let path = aws.join("credentials");
        std::fs::write(
            &path,
            b"[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = redacted\n",
        )
        .expect("w");
        let arts = scan(&path);
        assert!(arts
            .iter()
            .any(|a| a.data.get("credentials_present").map(|s| s.as_str()) == Some("true")));
    }
}

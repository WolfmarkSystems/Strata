//! Docker + container artifact parser (CONT-1).
//!
//! MITRE: T1610 (deploy container), T1611 (escape to host),
//! T1552.007 (credentials in container env).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::fs;
use std::path::Path;
use strata_plugin_sdk::Artifact;

const SENSITIVE_MOUNT_PREFIXES: &[&str] =
    &["/etc", "/root", "/var/log", "/var/run/docker.sock", "/"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerArtifact {
    pub container_id: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub image_sha256: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub entrypoint: Option<String>,
    pub privileged: bool,
    pub mounts: Vec<String>,
    pub suspicious_env_vars: Vec<String>,
    pub suspicious_mounts: Vec<String>,
    pub suspicious_log_lines: Vec<String>,
}

pub fn is_container_path(path: &Path) -> bool {
    let lower = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    lower.contains("/var/lib/docker/containers/")
        && (name == "config.v2.json" || name == "hostconfig.json")
}

fn container_id_from_path(path: &Path) -> String {
    let lower = path.to_string_lossy().replace('\\', "/");
    if let Some(idx) = lower.find("/containers/") {
        let rest = &lower[idx + "/containers/".len()..];
        let end = rest.find('/').unwrap_or(rest.len());
        return rest[..end].chars().take(12).collect();
    }
    "unknown".to_string()
}

pub fn parse_config_v2(body: &str) -> Option<ContainerArtifact> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let id = v
        .get("ID")
        .and_then(|x| x.as_str())
        .map(|s| s.chars().take(12).collect::<String>())
        .unwrap_or_else(|| "unknown".to_string());
    let name = v
        .get("Name")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let image = v
        .get("Image")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let image_sha256 = v
        .get("ImageID")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let created = v
        .get("Created")
        .and_then(|x| x.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    let entrypoint = v
        .get("Config")
        .and_then(|c| c.get("Entrypoint"))
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        });
    let env_array = v
        .get("Config")
        .and_then(|c| c.get("Env"))
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    let mut suspicious_env: Vec<String> = Vec::new();
    for entry in env_array {
        let Some(s) = entry.as_str() else { continue };
        let upper = s.to_ascii_uppercase();
        if upper.contains("PASSWORD")
            || upper.contains("SECRET")
            || upper.contains("TOKEN")
            || upper.starts_with("KEY=")
            || upper.contains("_KEY=")
        {
            let var_name = s.split('=').next().unwrap_or(s);
            suspicious_env.push(var_name.to_string());
        }
    }
    Some(ContainerArtifact {
        container_id: id,
        name,
        image,
        image_sha256,
        created,
        entrypoint,
        privileged: false,
        mounts: Vec::new(),
        suspicious_env_vars: suspicious_env,
        suspicious_mounts: Vec::new(),
        suspicious_log_lines: Vec::new(),
    })
}

pub fn parse_hostconfig(body: &str) -> Option<(bool, Vec<String>, Vec<String>)> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let privileged = v
        .get("Privileged")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let binds = v
        .get("Binds")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    let mut mounts: Vec<String> = Vec::new();
    let mut sensitive: Vec<String> = Vec::new();
    for entry in binds {
        let Some(s) = entry.as_str() else { continue };
        mounts.push(s.to_string());
        let host = s.split(':').next().unwrap_or(s);
        if SENSITIVE_MOUNT_PREFIXES
            .iter()
            .any(|p| host == *p || host.starts_with(&format!("{}/", p)))
        {
            sensitive.push(s.to_string());
        }
    }
    Some((privileged, mounts, sensitive))
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    if !is_container_path(path) {
        return Vec::new();
    }
    let Ok(body) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let cid = container_id_from_path(path);
    let mut out = Vec::new();
    if name == "config.v2.json" {
        if let Some(mut art) = parse_config_v2(&body) {
            art.container_id = cid.clone();
            let mut a = Artifact::new("Docker Container", &path.to_string_lossy());
            a.timestamp = art.created.map(|d| d.timestamp() as u64);
            a.add_field(
                "title",
                &format!(
                    "Container {} ({}) from {}",
                    art.container_id,
                    art.name.as_deref().unwrap_or("-"),
                    art.image.as_deref().unwrap_or("-")
                ),
            );
            a.add_field("file_type", "Docker Container");
            a.add_field("container_id", &art.container_id);
            if let Some(n) = &art.name {
                a.add_field("name", n);
            }
            if let Some(i) = &art.image {
                a.add_field("image", i);
            }
            if let Some(s) = &art.image_sha256 {
                a.add_field("image_sha256", s);
            }
            if let Some(e) = &art.entrypoint {
                a.add_field("entrypoint", e);
            }
            for env in &art.suspicious_env_vars {
                a.add_field("suspicious_env_var", env);
            }
            a.add_field("mitre", "T1610");
            if !art.suspicious_env_vars.is_empty() {
                a.add_field("mitre_secondary", "T1552.007");
                a.add_field("suspicious", "true");
                a.add_field("forensic_value", "High");
            } else {
                a.add_field("forensic_value", "Medium");
            }
            out.push(a);
        }
    } else if name == "hostconfig.json" {
        if let Some((privileged, mounts, sensitive)) = parse_hostconfig(&body) {
            let mut a = Artifact::new("Docker Container", &path.to_string_lossy());
            a.add_field(
                "title",
                &format!(
                    "Host config for container {} (privileged={}, {} mounts, {} sensitive)",
                    cid,
                    privileged,
                    mounts.len(),
                    sensitive.len()
                ),
            );
            a.add_field("file_type", "Docker Container");
            a.add_field("container_id", &cid);
            a.add_field("privileged", if privileged { "true" } else { "false" });
            for m in &mounts {
                a.add_field("mount", m);
            }
            for m in &sensitive {
                a.add_field("sensitive_mount", m);
            }
            a.add_field("mitre", "T1610");
            if privileged || !sensitive.is_empty() {
                a.add_field("mitre_secondary", "T1611");
                a.add_field("suspicious", "true");
                a.add_field("forensic_value", "High");
            } else {
                a.add_field("forensic_value", "Medium");
            }
            out.push(a);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_container_path_matches_known_layout() {
        assert!(is_container_path(Path::new(
            "/var/lib/docker/containers/abc123/config.v2.json"
        )));
        assert!(is_container_path(Path::new(
            "/var/lib/docker/containers/abc123/hostconfig.json"
        )));
        assert!(!is_container_path(Path::new("/var/lib/docker/other")));
    }

    #[test]
    fn parse_config_v2_extracts_env_and_metadata() {
        let body = r#"{
            "ID":"abc123def456",
            "Name":"/app",
            "Image":"nginx:1.25",
            "ImageID":"sha256:deadbeef",
            "Created":"2024-06-01T12:00:00Z",
            "Config":{"Entrypoint":["/docker-entrypoint.sh","nginx","-g","daemon off;"],
                      "Env":["PATH=/usr/bin","AWS_SECRET_ACCESS_KEY=xxxxx","API_TOKEN=abcd"]}
        }"#;
        let art = parse_config_v2(body).expect("parsed");
        assert_eq!(art.container_id, "abc123def456");
        assert!(art
            .entrypoint
            .as_deref()
            .unwrap_or("")
            .contains("docker-entrypoint"));
        assert!(art.suspicious_env_vars.iter().any(|e| e.contains("SECRET")));
        assert!(art.suspicious_env_vars.iter().any(|e| e.contains("TOKEN")));
    }

    #[test]
    fn parse_hostconfig_flags_privileged_and_sensitive_mounts() {
        let body = r#"{"Privileged":true,"Binds":["/etc:/host-etc","/home/user:/data"]}"#;
        let (privileged, mounts, sensitive) = parse_hostconfig(body).expect("parsed");
        assert!(privileged);
        assert_eq!(mounts.len(), 2);
        assert!(sensitive.iter().any(|m| m.starts_with("/etc:")));
    }

    #[test]
    fn scan_emits_container_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let container = dir
            .path()
            .join("var")
            .join("lib")
            .join("docker")
            .join("containers")
            .join("abcdef1234567890");
        std::fs::create_dir_all(&container).expect("mkdirs");
        let path = container.join("config.v2.json");
        std::fs::write(
            &path,
            r#"{"ID":"abcdef1234567890","Name":"/test","Image":"alpine","Created":"2024-06-01T12:00:00Z","Config":{"Env":["FOO=bar","API_TOKEN=xxx"]}}"#,
        )
        .expect("w");
        let arts = scan(&path);
        assert!(arts
            .iter()
            .any(|a| a.data.get("file_type").map(|s| s.as_str()) == Some("Docker Container")));
        assert!(arts.iter().any(|a| a
            .data
            .get("suspicious_env_var")
            .map(|s| s.contains("TOKEN"))
            .unwrap_or(false)));
    }

    #[test]
    fn scan_hostconfig_flags_privileged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let container = dir
            .path()
            .join("var")
            .join("lib")
            .join("docker")
            .join("containers")
            .join("privileged1234");
        std::fs::create_dir_all(&container).expect("mkdirs");
        let path = container.join("hostconfig.json");
        std::fs::write(&path, r#"{"Privileged":true,"Binds":["/etc:/host-etc"]}"#).expect("w");
        let arts = scan(&path);
        assert!(arts
            .iter()
            .any(|a| a.data.get("privileged").map(|s| s.as_str()) == Some("true")));
    }
}

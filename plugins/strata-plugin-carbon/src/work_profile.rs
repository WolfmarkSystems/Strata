//! Android work-profile + MDM artifact parser (AND-3).
//!
//! MITRE: T1485 (remote wipe), T1078 (valid accounts via MDM).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::fs;
use std::path::Path;
use strata_plugin_sdk::Artifact;

const KNOWN_MDM_PACKAGES: &[(&str, &str)] = &[
    ("com.airwatch.androidagent", "VMware AirWatch / Workspace ONE"),
    ("com.mobileiron", "MobileIron / Ivanti"),
    ("com.microsoft.intune", "Microsoft Intune"),
    ("com.citrix.mdm", "Citrix Endpoint Management"),
    ("com.jamf.management.jamfnow", "JAMF Now"),
    ("com.soti.mobicontrol", "SOTI MobiControl"),
    ("com.blackberry.dynamics.android", "BlackBerry Dynamics"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkProfileArtifact {
    pub artifact_type: String,
    pub profile_id: u32,
    pub mdm_package: Option<String>,
    pub description: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub wipe_detected: bool,
}

pub fn is_work_profile_path(path: &Path) -> bool {
    let lower = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    (lower.contains("/data/system/users/") && name == "userinfo.xml")
        || (lower.contains("/data/system/") && name == "device_policies.xml")
        || (lower.contains("/data/system/users/") && name == "package-restrictions.xml")
}

fn profile_id_from_path(path: &Path) -> u32 {
    let lower = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    // /data/system/users/<id>/userinfo.xml
    let mut iter = lower.rsplit('/');
    let _name = iter.next();
    iter.next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0)
}

pub fn mdm_for_package(pkg: &str) -> Option<&'static str> {
    let lower = pkg.to_ascii_lowercase();
    for (canonical, label) in KNOWN_MDM_PACKAGES {
        if lower.contains(canonical) {
            return Some(label);
        }
    }
    if lower.ends_with(".mdm") || lower.ends_with(".mam") {
        return Some("Generic MDM");
    }
    None
}

fn extract_xml_attr(body: &str, attr: &str) -> Option<String> {
    let needle = format!("{}=\"", attr);
    let pos = body.find(&needle)? + needle.len();
    let end = body[pos..].find('"')?;
    Some(body[pos..pos + end].to_string())
}

fn find_all_xml_attr<'a>(body: &'a str, tag: &str, attr: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut cursor = 0;
    let open = format!("<{}", tag);
    while let Some(pos) = body[cursor..].find(&open) {
        let block_start = cursor + pos;
        let block_end = body[block_start..].find('>').map(|e| block_start + e).unwrap_or(body.len());
        let block = &body[block_start..=block_end];
        if let Some(attr_pos) = block.find(&format!("{}=\"", attr)) {
            let after = &block[attr_pos + attr.len() + 2..];
            if let Some(end) = after.find('"') {
                out.push(&after[..end]);
            }
        }
        cursor = block_end + 1;
    }
    out
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    if !is_work_profile_path(path) {
        return Vec::new();
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let Ok(body) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let profile_id = profile_id_from_path(path);
    match name.as_str() {
        "userinfo.xml" => {
            let flags = extract_xml_attr(&body, "flags").unwrap_or_default();
            let is_managed = flags
                .trim_start_matches("0x")
                .parse::<u32>()
                .unwrap_or(0)
                & 0x30
                != 0;
            let user_name = extract_xml_attr(&body, "name").unwrap_or_default();
            let mut a = Artifact::new("Android Work Profile", &path.to_string_lossy());
            a.add_field(
                "title",
                &format!(
                    "User profile {} ({}): {}",
                    profile_id,
                    if is_managed { "work" } else { "personal" },
                    user_name
                ),
            );
            a.add_field("file_type", "Android Work Profile");
            a.add_field("profile_id", &profile_id.to_string());
            a.add_field("managed", if is_managed { "true" } else { "false" });
            a.add_field("user_name", &user_name);
            a.add_field("mitre", "T1078");
            a.add_field("forensic_value", "Medium");
            out.push(a);
        }
        "device_policies.xml" => {
            let device_owner = extract_xml_attr(&body, "device-owner");
            let profile_owner = extract_xml_attr(&body, "profile-owner");
            let admins = find_all_xml_attr(&body, "admin", "name");
            for admin in &admins {
                if let Some(label) = mdm_for_package(admin) {
                    let mut a = Artifact::new("MDM Enrollment", &path.to_string_lossy());
                    a.add_field("title", &format!("MDM detected: {} ({})", label, admin));
                    a.add_field("file_type", "MDM Enrollment");
                    a.add_field("mdm_package", admin);
                    a.add_field("mdm_vendor", label);
                    a.add_field("mitre", "T1078");
                    a.add_field("forensic_value", "Medium");
                    out.push(a);
                }
            }
            if let Some(owner) = device_owner.as_deref() {
                let mut a = Artifact::new("MDM Enrollment", &path.to_string_lossy());
                a.add_field("title", &format!("Device owner: {}", owner));
                a.add_field("file_type", "MDM Enrollment");
                a.add_field("mdm_package", owner);
                a.add_field("role", "device-owner");
                a.add_field("mitre", "T1078");
                a.add_field("forensic_value", "Medium");
                out.push(a);
            }
            if let Some(owner) = profile_owner.as_deref() {
                let mut a = Artifact::new("MDM Enrollment", &path.to_string_lossy());
                a.add_field("title", &format!("Profile owner: {}", owner));
                a.add_field("file_type", "MDM Enrollment");
                a.add_field("mdm_package", owner);
                a.add_field("role", "profile-owner");
                a.add_field("mitre", "T1078");
                a.add_field("forensic_value", "Medium");
                out.push(a);
            }
            if body.contains("<wipeData") || body.contains("wipeData=\"true\"") {
                let mut a = Artifact::new("Remote Wipe Command", &path.to_string_lossy());
                a.add_field("title", "Remote wipeData command present in device_policies.xml");
                a.add_field("file_type", "Remote Wipe Command");
                a.add_field("mitre", "T1485");
                a.add_field("forensic_value", "High");
                a.add_field("suspicious", "true");
                out.push(a);
            }
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_work_profile_path_matches_known_files() {
        assert!(is_work_profile_path(Path::new("/data/system/users/10/userInfo.xml")));
        assert!(is_work_profile_path(Path::new("/data/system/device_policies.xml")));
        assert!(!is_work_profile_path(Path::new("/tmp/other.xml")));
    }

    #[test]
    fn mdm_for_package_recognises_known_and_generic_mdm() {
        assert_eq!(
            mdm_for_package("com.microsoft.intune"),
            Some("Microsoft Intune")
        );
        assert_eq!(mdm_for_package("com.acme.mdm"), Some("Generic MDM"));
        assert!(mdm_for_package("com.google.chrome").is_none());
    }

    #[test]
    fn scan_userinfo_marks_work_profile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let users = dir.path().join("data").join("system").join("users").join("10");
        std::fs::create_dir_all(&users).expect("mkdirs");
        let path = users.join("userInfo.xml");
        std::fs::write(
            &path,
            r#"<user id="10" name="Work Profile" flags="48" created="1717243200000"/>"#,
        )
        .expect("w");
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("managed").map(|s| s.as_str()) == Some("true")));
    }

    #[test]
    fn scan_device_policies_flags_mdm_and_wipe() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sys = dir.path().join("data").join("system");
        std::fs::create_dir_all(&sys).expect("mkdirs");
        let path = sys.join("device_policies.xml");
        std::fs::write(
            &path,
            r#"<policies>
                <admin name="com.microsoft.intune"/>
                <admin name="com.example.app"/>
                <wipeData time="1717243200"/>
            </policies>"#,
        )
        .expect("w");
        let out = scan(&path);
        assert!(out
            .iter()
            .any(|a| a.data.get("mdm_vendor").map(|s| s.as_str()) == Some("Microsoft Intune")));
        assert!(out
            .iter()
            .any(|a| a.data.get("file_type").map(|s| s.as_str()) == Some("Remote Wipe Command")));
    }

    #[test]
    fn profile_id_from_path_parses_directory_segment() {
        assert_eq!(
            profile_id_from_path(Path::new("/data/system/users/11/userInfo.xml")),
            11
        );
        assert_eq!(
            profile_id_from_path(Path::new("/data/system/users/0/userInfo.xml")),
            0
        );
    }
}

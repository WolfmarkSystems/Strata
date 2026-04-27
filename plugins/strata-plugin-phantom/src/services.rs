//! Windows Services deep parse (W-11).
//!
//! Registry path: `HKLM\SYSTEM\CurrentControlSet\Services\<Name>`. This
//! module takes the already-decoded service record and applies the
//! suspicion heuristics listed in SPRINT W-11 — it does not re-parse
//! the registry hive itself (`crate::parsers::system` handles that).
//!
//! MITRE: T1543.003.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsService {
    pub service_name: String,
    pub display_name: Option<String>,
    pub image_path: String,
    pub start_type: String,
    pub service_type: String,
    pub object_name: Option<String>,
    pub suspicious_reason: Option<String>,
}

pub fn start_type_name(v: u32) -> &'static str {
    match v {
        0 => "Boot",
        1 => "System",
        2 => "Automatic",
        3 => "Manual",
        4 => "Disabled",
        _ => "Unknown",
    }
}

pub fn service_type_name(v: u32) -> &'static str {
    match v {
        1 => "KernelDriver",
        2 => "FilesystemDriver",
        16 => "OwnProcess",
        32 => "ShareProcess",
        _ => "Other",
    }
}

const STANDARD_ACCOUNTS: &[&str] = &[
    "localsystem",
    "nt authority\\system",
    "nt authority\\localservice",
    "nt authority\\networkservice",
    "localservice",
    "networkservice",
];

/// Heuristic suspicion check. Returns `Some(reason)` when the service
/// is worth flagging.
pub fn check_suspicion(s: &WindowsService) -> Option<String> {
    let path = s.image_path.to_ascii_lowercase();
    if path.contains("\\temp\\")
        || path.contains("\\appdata\\")
        || path.contains("\\downloads\\")
        || path.contains("\\users\\public\\")
    {
        return Some("ImagePath in user-writable location".into());
    }
    if has_encoded_chars(&s.image_path) {
        return Some("ImagePath contains encoded characters".into());
    }
    if service_name_entropy(&s.service_name) > 3.5 {
        return Some(format!(
            "Service name has high entropy ({:.2})",
            service_name_entropy(&s.service_name)
        ));
    }
    if let Some(obj) = s.object_name.as_deref() {
        let lc = obj.to_ascii_lowercase();
        if !STANDARD_ACCOUNTS.iter().any(|a| lc == *a)
            && !lc.starts_with("nt service\\")
            && !lc.is_empty()
        {
            return Some(format!("Unusual ObjectName: {}", obj));
        }
    }
    if s.start_type == "Automatic" && s.display_name.is_none() && s.object_name.is_none() {
        return Some("Automatic start service with no DisplayName".into());
    }
    None
}

fn has_encoded_chars(s: &str) -> bool {
    s.contains("%u")
        || s.contains("%x")
        || s.bytes()
            .filter(|b| {
                !(b.is_ascii_alphanumeric()
                    || *b == b'\\'
                    || *b == b'/'
                    || *b == b':'
                    || *b == b' '
                    || *b == b'.'
                    || *b == b'-'
                    || *b == b'_')
            })
            .count()
            > 2
}

/// Shannon entropy of a service-name string.
pub fn service_name_entropy(name: &str) -> f64 {
    if name.is_empty() {
        return 0.0;
    }
    let bytes = name.as_bytes();
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_service_in_temp_directory() {
        let s = WindowsService {
            service_name: "UpdateSvc".into(),
            display_name: Some("Update Service".into()),
            image_path: "C:\\Users\\alice\\AppData\\Local\\Temp\\svc.exe".into(),
            start_type: "Automatic".into(),
            service_type: "OwnProcess".into(),
            object_name: Some("LocalSystem".into()),
            suspicious_reason: None,
        };
        assert!(check_suspicion(&s).is_some());
    }

    #[test]
    fn flags_high_entropy_name() {
        let s = WindowsService {
            service_name: "X2qW9ztEv3rBf".into(),
            display_name: None,
            image_path: "C:\\Windows\\System32\\svchost.exe".into(),
            start_type: "Manual".into(),
            service_type: "OwnProcess".into(),
            object_name: Some("LocalSystem".into()),
            suspicious_reason: None,
        };
        let reason = check_suspicion(&s).expect("flagged");
        assert!(reason.contains("entropy"));
    }

    #[test]
    fn flags_unusual_object_name() {
        let s = WindowsService {
            service_name: "WebDeploy".into(),
            display_name: Some("WebDeploy".into()),
            image_path: "C:\\Program Files\\WebDeploy\\svc.exe".into(),
            start_type: "Manual".into(),
            service_type: "OwnProcess".into(),
            object_name: Some("EVIL\\admin".into()),
            suspicious_reason: None,
        };
        let reason = check_suspicion(&s).expect("flagged");
        assert!(reason.contains("ObjectName"));
    }

    #[test]
    fn clean_service_not_flagged() {
        let s = WindowsService {
            service_name: "WinDefend".into(),
            display_name: Some("Windows Defender".into()),
            image_path: "C:\\Windows\\System32\\svchost.exe".into(),
            start_type: "Automatic".into(),
            service_type: "OwnProcess".into(),
            object_name: Some("LocalSystem".into()),
            suspicious_reason: None,
        };
        assert!(check_suspicion(&s).is_none());
    }

    #[test]
    fn start_and_service_type_name_mappings() {
        assert_eq!(start_type_name(2), "Automatic");
        assert_eq!(start_type_name(3), "Manual");
        assert_eq!(service_type_name(16), "OwnProcess");
        assert_eq!(service_type_name(32), "ShareProcess");
    }
}

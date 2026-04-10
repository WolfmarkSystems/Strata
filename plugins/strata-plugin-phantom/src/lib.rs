//! # Phantom — Registry Intelligence Engine
//!
//! Phantom is the Strata plugin that **owns** registry hive parsing. It is the
//! only plugin that should ever directly walk a raw hive binary; the other
//! plugins (Chronicle, Trace, Conduit) extract incidental hive data only as
//! needed for their own domain.
//!
//! Hives parsed:
//!   * SYSTEM      — ShimCache, USB chain, services, network, computer identity
//!   * SOFTWARE    — OS version, installed programs, cloud accounts, AutoRun (HKLM)
//!   * SAM         — Local accounts, Microsoft email, last login
//!   * SECURITY    — Audit policy, LSA secrets metadata
//!   * AmCache.hve — InventoryApplicationFile (SHA1 + execution evidence),
//!     InventoryDriverBinary (signed/unsigned drivers)
//!   * USRCLASS.DAT — Network shellbags, MuiCache, UserChoice (default app
//!     associations)
//!
//! Phantom is intentionally synchronous and pure-Rust. All parsing happens via
//! the `nt-hive` crate; no Windows API calls.

use std::path::{Path, PathBuf};

use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct PhantomPlugin {
    name: String,
    version: String,
}

impl Default for PhantomPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl PhantomPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Phantom".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

impl StrataPlugin for PhantomPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec![
            "SYSTEM".to_string(),
            "SOFTWARE".to_string(),
            "SAM".to_string(),
            "SECURITY".to_string(),
            "AmCache.hve".to_string(),
            "UsrClass.dat".to_string(),
        ]
    }
    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::ArtifactExtraction,
            PluginCapability::ExecutionTracking,
        ]
    }
    fn description(&self) -> &str {
        "Registry Intelligence Engine — parses every Windows hive into structured artifacts"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut results = Vec::new();

        let files = match walk_dir(root) {
            Ok(f) => f,
            Err(_) => return Ok(results),
        };

        for path in files {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            let lower = name.to_lowercase();

            // Hive routing — match on filename, not extension. Hives have no
            // extension or arbitrary ones.
            if lower == "system" {
                if let Ok(data) = std::fs::read(&path) {
                    results.extend(parsers::system::parse(&path, &data));
                }
            } else if lower == "software" {
                if let Ok(data) = std::fs::read(&path) {
                    results.extend(parsers::software::parse(&path, &data));
                }
            } else if lower == "sam" {
                if let Ok(data) = std::fs::read(&path) {
                    results.extend(parsers::sam::parse(&path, &data));
                }
            } else if lower == "security" {
                if let Ok(data) = std::fs::read(&path) {
                    results.extend(parsers::security::parse(&path, &data));
                }
            } else if lower == "amcache.hve" {
                if let Ok(data) = std::fs::read(&path) {
                    results.extend(parsers::amcache::parse(&path, &data));
                }
            } else if lower == "usrclass.dat" {
                if let Ok(data) = std::fs::read(&path) {
                    results.extend(parsers::usrclass::parse(&path, &data));
                }
            } else if lower == "ntuser.dat" {
                // v1.1.0: Phantom owns the HKCU keys that aren't already
                // claimed by Chronicle (UserAssist, RecentDocs) or Trace
                // (BAM/DAM): CapabilityAccessManager, Archive Tool history,
                // TaskBar FeatureUsage.
                if let Ok(data) = std::fs::read(&path) {
                    results.extend(parsers::ntuser::parse(&path, &data));
                }
            }
        }

        Ok(results)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;

        let mut records = Vec::new();
        let mut categories: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut suspicious_count = 0usize;

        for a in &artifacts {
            let file_type = a.data.get("file_type").cloned().unwrap_or_default();
            let category = match file_type.as_str() {
                "ShimCache" | "AmCache File" | "Service" => ArtifactCategory::ExecutionHistory,
                "USB Device" | "Network Adapter" => ArtifactCategory::NetworkArtifacts,
                "SAM Account" | "Cloud Identity" => ArtifactCategory::AccountsCredentials,
                "Installed Program" | "OS Version" => ArtifactCategory::SystemActivity,
                "AmCache Driver" => ArtifactCategory::ExecutionHistory,
                "Shellbag" | "MuiCache" | "UserChoice" => ArtifactCategory::UserActivity,
                _ => ArtifactCategory::SystemActivity,
            };

            let suspicious = a.data.get("suspicious").map(|s| s == "true").unwrap_or(false);
            if suspicious {
                suspicious_count += 1;
            }
            categories.insert(category.as_str().to_string());

            let fv_str = a.data.get("forensic_value").cloned().unwrap_or_default();
            let forensic_value = match fv_str.as_str() {
                "Critical" => ForensicValue::Critical,
                "High" => ForensicValue::High,
                "Medium" => ForensicValue::Medium,
                _ => {
                    if suspicious {
                        ForensicValue::High
                    } else {
                        ForensicValue::Medium
                    }
                }
            };

            records.push(ArtifactRecord {
                category,
                subcategory: file_type,
                timestamp: a.timestamp.map(|t| t as i64),
                title: a.data.get("title").cloned().unwrap_or_else(|| a.source.clone()),
                detail: a.data.get("detail").cloned().unwrap_or_default(),
                source_path: a.source.clone(),
                forensic_value,
                mitre_technique: a.data.get("mitre").cloned(),
                is_suspicious: suspicious,
                raw_data: None,
            });
        }

        let total = records.len();
        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count,
                categories_populated: categories.into_iter().collect(),
                headline: format!(
                    "Parsed {} registry artifacts across {} hive types ({} suspicious)",
                    total,
                    6,
                    suspicious_count
                ),
            },
            warnings: vec![],
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Hive parsers
// ────────────────────────────────────────────────────────────────────────────

mod parsers {
    use super::*;

    /// Convert a Windows FILETIME (100ns ticks since 1601-01-01) to a Unix
    /// timestamp in seconds. Returns None for zero or pre-epoch values.
    pub(super) fn filetime_to_unix(ft: i64) -> Option<i64> {
        if ft <= 0 {
            return None;
        }
        let u = (ft - 116_444_736_000_000_000) / 10_000_000;
        if u < 0 {
            None
        } else {
            Some(u)
        }
    }

    /// Walk a UTF-16LE byte buffer up to the first null and return as String.
    pub(super) fn utf16le_to_string(data: &[u8]) -> String {
        let u16s: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&ch| ch != 0)
            .collect();
        String::from_utf16_lossy(&u16s)
    }

    /// Format a Unix timestamp as `YYYY-MM-DD HH:MM:SS UTC`.
    pub(super) fn fmt_unix(ts: i64) -> String {
        chrono::DateTime::from_timestamp(ts, 0)
            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| format!("unix:{}", ts))
    }

    /// Open a hive from raw bytes. The caller must hold the `Hive` for the
    /// lifetime of any derived `KeyNode` since `root_key_node()` borrows the
    /// hive.
    pub(super) fn open_hive(data: &[u8]) -> Option<nt_hive::Hive<&[u8]>> {
        nt_hive::Hive::new(data).ok()
    }

    pub mod system {
        use super::*;

        pub fn parse(path: &Path, data: &[u8]) -> Vec<Artifact> {
            let mut out = Vec::new();
            let path_str = path.to_string_lossy().to_string();

            let Some(hive) = open_hive(data) else {
                return out;
            };
            let Ok(root) = hive.root_key_node() else {
                let mut a = Artifact::new("ShimCache", &path_str);
                a.add_field("title", "SYSTEM hive present (parse failed)");
                a.add_field("detail", "nt-hive failed to open the hive");
                a.add_field("file_type", "ShimCache");
                a.add_field("forensic_value", "Medium");
                out.push(a);
                return out;
            };

            // ── ComputerName ────────────────────────────────────────────
            if let Some(hostname) = read_string(
                &root,
                &["ControlSet001", "Control", "ComputerName", "ComputerName"],
                "ComputerName",
            ) {
                let mut a = Artifact::new("Computer Identity", &path_str);
                a.add_field("title", &format!("Hostname: {}", hostname));
                a.add_field("detail", "SYSTEM\\ControlSet001\\Control\\ComputerName");
                a.add_field("file_type", "Computer Identity");
                a.add_field("forensic_value", "Medium");
                out.push(a);
            }

            // ── TimeZoneInformation ──────────────────────────────────────
            if let Some(tz) = read_string(
                &root,
                &["ControlSet001", "Control", "TimeZoneInformation"],
                "TimeZoneKeyName",
            ) {
                let mut a = Artifact::new("Computer Identity", &path_str);
                a.add_field("title", &format!("Time Zone: {}", tz));
                a.add_field("detail", "SYSTEM\\ControlSet001\\Control\\TimeZoneInformation");
                a.add_field("file_type", "Computer Identity");
                a.add_field("forensic_value", "Medium");
                out.push(a);
            }

            // ── Last shutdown time ──────────────────────────────────────
            if let Some(node) =
                walk(&root, &["ControlSet001", "Control", "Windows"])
            {
                if let Some(bytes) = read_value_bytes(&node, "ShutdownTime") {
                    if bytes.len() >= 8 {
                        let ft = i64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
                        if let Some(unix) = filetime_to_unix(ft) {
                            let mut a = Artifact::new("Computer Identity", &path_str);
                            a.timestamp = Some(unix as u64);
                            a.add_field("title", &format!("Last shutdown: {}", fmt_unix(unix)));
                            a.add_field(
                                "detail",
                                "SYSTEM\\ControlSet001\\Control\\Windows ShutdownTime",
                            );
                            a.add_field("file_type", "Computer Identity");
                            a.add_field("forensic_value", "High");
                            out.push(a);
                        }
                    }
                }
            }

            // ── ShimCache (AppCompatCache) ──────────────────────────────
            //
            // The binary format varies by OS version. Win10+ entries are
            // 12-byte headers + variable-length path. We extract every
            // printable path-like string as a heuristic — full binary parse
            // is a Day 12 follow-up.
            if let Some(node) = walk(
                &root,
                &["ControlSet001", "Control", "Session Manager", "AppCompatCache"],
            ) {
                if let Some(bytes) = read_value_bytes(&node, "AppCompatCache") {
                    let entries = decode_shimcache_strings(&bytes);
                    for path in entries {
                        let suspicious = is_suspicious_exe_path(&path);
                        let mut a = Artifact::new("ShimCache", &path_str);
                        a.add_field("title", &format!("ShimCache: {}", path));
                        a.add_field("detail", "AppCompatCache entry — proves file existed (does NOT prove execution)");
                        a.add_field("file_type", "ShimCache");
                        a.add_field("mitre", "T1059");
                        a.add_field("forensic_value", if suspicious { "High" } else { "Medium" });
                        if suspicious {
                            a.add_field("suspicious", "true");
                        }
                        out.push(a);
                    }
                }
            }

            // ── USB device chain ─────────────────────────────────────────
            if let Some(usbstor) = walk(&root, &["ControlSet001", "Enum", "USBSTOR"]) {
                if let Some(Ok(class_iter)) = usbstor.subkeys() {
                    for class_res in class_iter {
                        let Ok(class_node) = class_res else { continue };
                        let Ok(class_name) = class_node.name() else { continue };
                        let class_name = class_name.to_string_lossy();
                        // class node → device id subkeys
                        if let Some(Ok(dev_iter)) = class_node.subkeys() {
                            for dev_res in dev_iter {
                                let Ok(dev_node) = dev_res else { continue };
                                let Ok(serial) = dev_node.name() else { continue };
                                let serial = serial.to_string_lossy();

                                let friendly = read_value_string(&dev_node, "FriendlyName")
                                    .unwrap_or_else(|| class_name.to_string());

                                let mut detail =
                                    format!("Class: {} | Serial: {}", class_name, serial);

                                // Try to get first install / last connect from
                                // Properties subkey 0064/0066/0067.
                                if let Some(props) = dev_node
                                    .subkey("Properties")
                                    .and_then(|r| r.ok())
                                {
                                    if let Some(install) =
                                        read_filetime_in_properties(&props, "0064")
                                    {
                                        detail.push_str(&format!(
                                            " | First install: {}",
                                            fmt_unix(install)
                                        ));
                                    }
                                    if let Some(last) =
                                        read_filetime_in_properties(&props, "0066")
                                    {
                                        detail.push_str(&format!(
                                            " | Last connected: {}",
                                            fmt_unix(last)
                                        ));
                                    }
                                    if let Some(removal) =
                                        read_filetime_in_properties(&props, "0067")
                                    {
                                        detail.push_str(&format!(
                                            " | Last removal: {}",
                                            fmt_unix(removal)
                                        ));
                                    }
                                }

                                let mut a = Artifact::new("USB Device", &path_str);
                                a.add_field("title", &format!("USB: {}", friendly));
                                a.add_field("detail", &detail);
                                a.add_field("file_type", "USB Device");
                                a.add_field("mitre", "T1052.001");
                                a.add_field("forensic_value", "High");
                                out.push(a);
                            }
                        }
                    }
                }
            }

            // ── Services enumeration ─────────────────────────────────────
            if let Some(svcs) = walk(&root, &["ControlSet001", "Services"]) {
                if let Some(Ok(svc_iter)) = svcs.subkeys() {
                    for svc_res in svc_iter {
                        let Ok(svc_node) = svc_res else { continue };
                        let Ok(svc_name) = svc_node.name() else { continue };
                        let svc_name = svc_name.to_string_lossy();

                        let image_path =
                            read_value_string(&svc_node, "ImagePath").unwrap_or_default();
                        if image_path.is_empty() {
                            continue;
                        }
                        let display = read_value_string(&svc_node, "DisplayName")
                            .unwrap_or_else(|| svc_name.to_string());
                        let start_type = read_value_dword(&svc_node, "Start").unwrap_or(0xFF);
                        let object = read_value_string(&svc_node, "ObjectName")
                            .unwrap_or_else(|| "LocalSystem".to_string());

                        let lower_path = image_path.to_lowercase();
                        let in_system = lower_path.contains("system32")
                            || lower_path.contains("syswow64")
                            || lower_path.contains("\\windows\\");
                        let auto_start = matches!(start_type, 0..=2);
                        let suspicious = !in_system && auto_start;

                        let start_label = match start_type {
                            0 => "Boot",
                            1 => "System",
                            2 => "Auto",
                            3 => "Manual",
                            4 => "Disabled",
                            _ => "Unknown",
                        };

                        let mut a = Artifact::new("Service", &path_str);
                        a.add_field("title", &format!("Service: {}", display));
                        a.add_field(
                            "detail",
                            &format!(
                                "ImagePath: {} | Start: {} | RunAs: {}",
                                image_path, start_label, object
                            ),
                        );
                        a.add_field("file_type", "Service");
                        a.add_field("mitre", "T1543.003");
                        if suspicious {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                    }
                }
            }

            // ── Network adapter history ──────────────────────────────────
            if let Some(ifs) = walk(
                &root,
                &["ControlSet001", "Services", "Tcpip", "Parameters", "Interfaces"],
            ) {
                if let Some(Ok(if_iter)) = ifs.subkeys() {
                    for if_res in if_iter {
                        let Ok(if_node) = if_res else { continue };
                        let Ok(guid) = if_node.name() else { continue };
                        let guid = guid.to_string_lossy();
                        let ip = read_value_string(&if_node, "DhcpIPAddress").unwrap_or_default();
                        let server =
                            read_value_string(&if_node, "DhcpServer").unwrap_or_default();
                        let domain =
                            read_value_string(&if_node, "DhcpDomain").unwrap_or_default();
                        if ip.is_empty() && server.is_empty() {
                            continue;
                        }
                        let mut a = Artifact::new("Network Adapter", &path_str);
                        a.add_field("title", &format!("Adapter: {}", guid));
                        a.add_field(
                            "detail",
                            &format!(
                                "DHCP IP: {} | DHCP Server: {} | Domain: {}",
                                ip, server, domain
                            ),
                        );
                        a.add_field("file_type", "Network Adapter");
                        a.add_field("mitre", "T1016");
                        a.add_field("forensic_value", "Medium");
                        out.push(a);
                    }
                }
            }

            out
        }

        fn decode_shimcache_strings(blob: &[u8]) -> Vec<String> {
            // Heuristic: walk the blob looking for UTF-16LE strings that look
            // like file paths (>= 4 chars, contains backslash, ends in
            // executable extension or is followed by a null pair).
            let mut out = Vec::new();
            let mut i = 0;
            while i + 8 <= blob.len() {
                // Try to read up to 520 bytes as UTF-16LE
                let chunk_end = (i + 1024).min(blob.len());
                let chunk = &blob[i..chunk_end];
                let mut s = String::new();
                let mut j = 0;
                while j + 2 <= chunk.len() {
                    let c = u16::from_le_bytes([chunk[j], chunk[j + 1]]);
                    if c == 0 {
                        break;
                    }
                    if let Some(ch) = char::from_u32(c as u32) {
                        if ch.is_ascii() && (ch.is_ascii_graphic() || ch == ' ') {
                            s.push(ch);
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                    j += 2;
                }
                if s.len() >= 8 && s.contains('\\') {
                    let lower = s.to_lowercase();
                    if lower.ends_with(".exe")
                        || lower.ends_with(".dll")
                        || lower.ends_with(".sys")
                    {
                        out.push(s.clone());
                    }
                }
                i += s.len().max(2) * 2 + 2;
                if out.len() > 1000 {
                    break;
                }
            }
            out.sort();
            out.dedup();
            out
        }

        fn is_suspicious_exe_path(p: &str) -> bool {
            let l = p.to_lowercase();
            l.contains("\\temp\\")
                || l.contains("\\appdata\\local\\temp")
                || l.contains("\\users\\public\\")
                || l.contains("\\windows\\debug\\")
        }

        fn read_filetime_in_properties(
            props: &nt_hive::KeyNode<'_, &[u8]>,
            sub_name: &str,
        ) -> Option<i64> {
            // Walk one level deep looking for a value with the matching name
            // that contains an 8-byte FILETIME.
            let target = props.subkey(sub_name).and_then(|r| r.ok())?;
            let values = target.values()?.ok()?;
            for vr in values {
                let v = vr.ok()?;
                let bytes = v.data().ok()?.into_vec().ok()?;
                if bytes.len() >= 8 {
                    let ft = i64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
                    if let Some(u) = filetime_to_unix(ft) {
                        return Some(u);
                    }
                }
            }
            None
        }
    }

    pub mod software {
        use super::*;

        pub fn parse(path: &Path, data: &[u8]) -> Vec<Artifact> {
            let mut out = Vec::new();
            let path_str = path.to_string_lossy().to_string();

            let Some(hive) = open_hive(data) else {
                return out;
            };
            let Ok(root) = hive.root_key_node() else {
                return out;
            };

            // ── OS version ───────────────────────────────────────────────
            if let Some(node) = walk(&root, &["Microsoft", "Windows NT", "CurrentVersion"]) {
                let product = read_value_string(&node, "ProductName").unwrap_or_default();
                let edition = read_value_string(&node, "EditionID").unwrap_or_default();
                let display = read_value_string(&node, "DisplayVersion").unwrap_or_default();
                let build = read_value_string(&node, "CurrentBuildNumber").unwrap_or_default();
                let install_unix = read_value_dword(&node, "InstallDate")
                    .map(|d| d as i64)
                    .filter(|&d| d > 0);
                let install_str = install_unix
                    .map(fmt_unix)
                    .unwrap_or_else(|| "unknown".to_string());

                let mut a = Artifact::new("OS Version", &path_str);
                if let Some(u) = install_unix {
                    a.timestamp = Some(u as u64);
                }
                a.add_field("title", &format!("Windows: {} {}", product, display));
                a.add_field(
                    "detail",
                    &format!(
                        "Edition: {} | Build: {} | Installed: {}",
                        edition, build, install_str
                    ),
                );
                a.add_field("file_type", "OS Version");
                a.add_field("forensic_value", "High");
                out.push(a);
            }

            // ── Installed Programs (Uninstall keys) ──────────────────────
            for branch in &["Microsoft\\Windows\\CurrentVersion\\Uninstall"] {
                let parts: Vec<&str> = branch.split('\\').collect();
                let Some(node) = walk(&root, &parts) else {
                    continue;
                };
                if let Some(Ok(iter)) = node.subkeys() {
                    for k_res in iter {
                        let Ok(k) = k_res else { continue };
                        let display = read_value_string(&k, "DisplayName").unwrap_or_default();
                        if display.is_empty() {
                            continue;
                        }
                        let publisher = read_value_string(&k, "Publisher").unwrap_or_default();
                        let version = read_value_string(&k, "DisplayVersion").unwrap_or_default();
                        let install = read_value_string(&k, "InstallDate").unwrap_or_default();
                        let location = read_value_string(&k, "InstallLocation").unwrap_or_default();

                        let suspicious_publisher =
                            publisher.is_empty() || is_offensive_tool_name(&display);

                        let mut a = Artifact::new("Installed Program", &path_str);
                        a.add_field("title", &format!("Installed: {}", display));
                        a.add_field(
                            "detail",
                            &format!(
                                "Publisher: {} | Version: {} | Date: {} | Path: {}",
                                if publisher.is_empty() {
                                    "(none)"
                                } else {
                                    &publisher
                                },
                                version,
                                install,
                                location
                            ),
                        );
                        a.add_field("file_type", "Installed Program");
                        a.add_field("mitre", "T1072");
                        if suspicious_publisher {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                    }
                }
            }

            // ── HKLM AutoRun ─────────────────────────────────────────────
            for autorun_path in &[
                "Microsoft\\Windows\\CurrentVersion\\Run",
                "Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            ] {
                let parts: Vec<&str> = autorun_path.split('\\').collect();
                let Some(node) = walk(&root, &parts) else {
                    continue;
                };
                if let Some(Ok(values)) = node.values() {
                    for vr in values {
                        let Ok(v) = vr else { continue };
                        let Ok(vname) = v.name() else { continue };
                        let exe = match v.data() {
                            Ok(d) => match d.into_vec() {
                                Ok(b) => utf16le_to_string(&b),
                                Err(_) => continue,
                            },
                            Err(_) => continue,
                        };
                        let lower = exe.to_lowercase();
                        let suspicious = lower.contains("\\temp\\")
                            || lower.contains("\\appdata\\")
                            || lower.contains("powershell")
                            || lower.contains("cmd.exe /c");
                        let mut a = Artifact::new("AutoRun", &path_str);
                        a.add_field("title", &format!("AutoRun: {}", vname.to_string_lossy()));
                        a.add_field(
                            "detail",
                            &format!("Path: {} | Hive: SOFTWARE\\{}", exe, autorun_path),
                        );
                        a.add_field("file_type", "AutoRun");
                        a.add_field("mitre", "T1547.001");
                        if suspicious {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                    }
                }
            }

            out
        }

        fn is_offensive_tool_name(name: &str) -> bool {
            let l = name.to_lowercase();
            const TOOLS: &[&str] = &[
                "mimikatz",
                "metasploit",
                "cobalt strike",
                "psexec",
                "nmap",
                "wireshark",
                "burp",
                "kali",
                "havoc",
                "sliver",
                "responder",
            ];
            TOOLS.iter().any(|t| l.contains(t))
        }
    }

    pub mod sam {
        use super::*;

        pub fn parse(path: &Path, data: &[u8]) -> Vec<Artifact> {
            let mut out = Vec::new();
            let path_str = path.to_string_lossy().to_string();

            let Some(hive) = open_hive(data) else {
                return out;
            };
            let Ok(root) = hive.root_key_node() else {
                return out;
            };

            // SAM\\Domains\\Account\\Users\\Names\\<username> — each subkey
            // is a username, the F value contains a binary blob with logon
            // statistics. We extract usernames and the InternetUserName
            // (Microsoft account email) when present.
            if let Some(names) = walk(&root, &["Domains", "Account", "Users", "Names"]) {
                if let Some(Ok(iter)) = names.subkeys() {
                    for k_res in iter {
                        let Ok(k) = k_res else { continue };
                        let Ok(uname) = k.name() else { continue };
                        let uname = uname.to_string_lossy();
                        let mut a = Artifact::new("SAM Account", &path_str);
                        a.add_field("title", &format!("Local account: {}", uname));
                        a.add_field("detail", "SAM\\Domains\\Account\\Users\\Names");
                        a.add_field("file_type", "SAM Account");
                        a.add_field("mitre", "T1087.001");
                        a.add_field("forensic_value", "Medium");
                        out.push(a);
                    }
                }
            }

            // Cloud accounts: SAM\\Domains\\Account\\Users\\<RID>\\InternetUserName
            if let Some(users) = walk(&root, &["Domains", "Account", "Users"]) {
                if let Some(Ok(iter)) = users.subkeys() {
                    for k_res in iter {
                        let Ok(k) = k_res else { continue };
                        let Ok(rid) = k.name() else { continue };
                        let rid = rid.to_string_lossy();
                        if rid == "Names" {
                            continue;
                        }
                        if let Some(email) = read_value_string(&k, "InternetUserName") {
                            if !email.is_empty() {
                                let mut a = Artifact::new("Cloud Identity", &path_str);
                                a.add_field("title", &format!("Microsoft account: {}", email));
                                a.add_field("detail", &format!("RID: {}", rid));
                                a.add_field("file_type", "Cloud Identity");
                                a.add_field("mitre", "T1078.003");
                                a.add_field("forensic_value", "High");
                                out.push(a);
                            }
                        }
                    }
                }
            }

            out
        }
    }

    pub mod security {
        use super::*;

        pub fn parse(path: &Path, _data: &[u8]) -> Vec<Artifact> {
            // The SECURITY hive is largely opaque (LSA secrets are encrypted
            // with the bootkey from SYSTEM). We surface only the existence of
            // the audit policy entry as a forensic marker.
            let path_str = path.to_string_lossy().to_string();
            let mut a = Artifact::new("Security Hive", &path_str);
            a.add_field("title", "SECURITY hive present");
            a.add_field(
                "detail",
                "LSA secrets and cached credentials require offline decryption with the SYSTEM bootkey",
            );
            a.add_field("file_type", "Security Hive");
            a.add_field("mitre", "T1003.004");
            a.add_field("forensic_value", "Medium");
            vec![a]
        }
    }

    pub mod amcache {
        use super::*;

        pub fn parse(path: &Path, data: &[u8]) -> Vec<Artifact> {
            let mut out = Vec::new();
            let path_str = path.to_string_lossy().to_string();

            let Some(hive) = open_hive(data) else {
                return out;
            };
            let Ok(root) = hive.root_key_node() else {
                return out;
            };

            // ── InventoryApplicationFile — execution evidence + SHA1 ────
            if let Some(node) = walk(&root, &["Root", "InventoryApplicationFile"]) {
                if let Some(Ok(iter)) = node.subkeys() {
                    let mut count = 0;
                    for k_res in iter {
                        let Ok(k) = k_res else { continue };
                        let name = read_value_string(&k, "Name").unwrap_or_default();
                        let path_l = read_value_string(&k, "LowerCaseLongPath").unwrap_or_default();
                        let mut sha1 = read_value_string(&k, "FileId").unwrap_or_default();
                        // FileId is "0000<sha1>" — strip the leading zeros.
                        if sha1.len() > 4 {
                            sha1 = sha1[4..].to_string();
                        }
                        let publisher = read_value_string(&k, "Publisher").unwrap_or_default();
                        let product = read_value_string(&k, "ProductName").unwrap_or_default();
                        let version = read_value_string(&k, "ProductVersion").unwrap_or_default();
                        if name.is_empty() && path_l.is_empty() {
                            continue;
                        }
                        let suspicious = publisher.is_empty()
                            || path_l.to_lowercase().contains("\\temp\\")
                            || path_l.to_lowercase().contains("\\appdata\\");
                        let mut a = Artifact::new("AmCache File", &path_str);
                        a.add_field(
                            "title",
                            &format!("AmCache: {}", if !name.is_empty() { &name } else { &path_l }),
                        );
                        a.add_field(
                            "detail",
                            &format!(
                                "Path: {} | SHA1: {} | Publisher: {} | Product: {} {}",
                                path_l, sha1, publisher, product, version
                            ),
                        );
                        a.add_field("file_type", "AmCache File");
                        a.add_field("mitre", "T1059");
                        if suspicious {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                        count += 1;
                        if count > 5000 {
                            break;
                        }
                    }
                }
            }

            // ── InventoryDriverBinary — driver execution evidence ──────
            if let Some(node) = walk(&root, &["Root", "InventoryDriverBinary"]) {
                if let Some(Ok(iter)) = node.subkeys() {
                    let mut count = 0;
                    for k_res in iter {
                        let Ok(k) = k_res else { continue };
                        let driver = read_value_string(&k, "DriverName").unwrap_or_default();
                        let company = read_value_string(&k, "DriverCompany").unwrap_or_default();
                        let signed = read_value_string(&k, "DriverSigned").unwrap_or_default();
                        if driver.is_empty() {
                            continue;
                        }
                        let unsigned = signed != "1";
                        let mut a = Artifact::new("AmCache Driver", &path_str);
                        a.add_field("title", &format!("Driver: {}", driver));
                        a.add_field(
                            "detail",
                            &format!(
                                "Company: {} | Signed: {}",
                                company,
                                if unsigned { "NO (unsigned)" } else { "yes" }
                            ),
                        );
                        a.add_field("file_type", "AmCache Driver");
                        a.add_field("mitre", "T1014");
                        if unsigned {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                        count += 1;
                        if count > 1000 {
                            break;
                        }
                    }
                }
            }

            out
        }
    }

    pub mod usrclass {
        use super::*;

        pub fn parse(path: &Path, data: &[u8]) -> Vec<Artifact> {
            let mut out = Vec::new();
            let path_str = path.to_string_lossy().to_string();

            let Some(hive) = open_hive(data) else {
                return out;
            };
            let Ok(root) = hive.root_key_node() else {
                return out;
            };

            // MuiCache — display names of executed apps
            if let Some(node) = walk(
                &root,
                &["Local Settings", "Software", "Microsoft", "Windows", "ShellNoRoam", "MUICache"],
            )
            .or_else(|| {
                walk(
                    &root,
                    &["Local Settings", "Software", "Microsoft", "Windows", "Shell", "MuiCache"],
                )
            }) {
                if let Some(Ok(values)) = node.values() {
                    for vr in values {
                        let Ok(v) = vr else { continue };
                        let Ok(vname) = v.name() else { continue };
                        let vname = vname.to_string_lossy();
                        if !vname.contains('\\') {
                            continue;
                        }
                        let display = match v.data() {
                            Ok(d) => match d.into_vec() {
                                Ok(b) => utf16le_to_string(&b),
                                Err(_) => continue,
                            },
                            Err(_) => continue,
                        };
                        let mut a = Artifact::new("MuiCache", &path_str);
                        a.add_field("title", &format!("MuiCache: {}", display));
                        a.add_field("detail", &format!("Executable: {}", vname));
                        a.add_field("file_type", "MuiCache");
                        a.add_field("mitre", "T1059");
                        a.add_field("forensic_value", "Medium");
                        out.push(a);
                    }
                }
            }

            // UserChoice default app handlers — flag scripts associated with
            // unexpected handlers.
            if let Some(node) = walk(
                &root,
                &[
                    "Local Settings",
                    "Software",
                    "Microsoft",
                    "Windows",
                    "CurrentVersion",
                    "Explorer",
                    "FileExts",
                ],
            ) {
                if let Some(Ok(iter)) = node.subkeys() {
                    for k_res in iter {
                        let Ok(k) = k_res else { continue };
                        let Ok(ext) = k.name() else { continue };
                        let ext = ext.to_string_lossy();
                        let Some(uc) = k.subkey("UserChoice").and_then(|r| r.ok()) else {
                            continue;
                        };
                        let progid = read_value_string(&uc, "ProgId").unwrap_or_default();
                        if progid.is_empty() {
                            continue;
                        }
                        let suspicious = matches!(
                            ext.as_ref(),
                            ".exe" | ".bat" | ".ps1" | ".js" | ".vbs"
                        ) && !progid.to_lowercase().contains("exefile")
                            && !progid.to_lowercase().contains("batfile");
                        let mut a = Artifact::new("UserChoice", &path_str);
                        a.add_field("title", &format!("Default handler: {} → {}", ext, progid));
                        a.add_field("detail", "USRCLASS\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts");
                        a.add_field("file_type", "UserChoice");
                        a.add_field("mitre", "T1546.001");
                        if suspicious {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                    }
                }
            }

            out
        }
    }

    pub mod ntuser {
        //! v1.1.0 — NTUSER.DAT parsers for HKCU keys not already owned by
        //! Chronicle (UserAssist, RecentDocs, ComDlg32 MRUs) or Trace
        //! (BAM/DAM).
        //!
        //! Phantom owns:
        //!   * Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager
        //!     \ConsentStore\<capability>\NonPackaged\<app>\
        //!     LastUsedTimeStart / LastUsedTimeStop / Value
        //!   * Software\7-Zip\FM\FolderHistory   (recent paths)
        //!   * Software\WinRAR\ArcHistory        (MRU archive paths)
        //!   * Software\Nico Mak Computing\WinZip\
        //!   * Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\
        //!     AppLaunch / AppSwitched (per-app counters)

        use super::*;

        pub fn parse(path: &Path, data: &[u8]) -> Vec<Artifact> {
            let mut out = Vec::new();
            let path_str = path.to_string_lossy().to_string();

            let Some(hive) = open_hive(data) else {
                return out;
            };
            let Ok(root) = hive.root_key_node() else {
                return out;
            };

            // ── CapabilityAccessManager ────────────────────────────────
            //
            // Walk Software\...\CapabilityAccessManager\ConsentStore\
            // Each subkey is a capability (microphone, webcam, location).
            // Under each capability\NonPackaged\ are app-path subkeys with
            // LastUsedTimeStart / LastUsedTimeStop FILETIMEs.
            if let Some(consent) = walk(
                &root,
                &[
                    "Software",
                    "Microsoft",
                    "Windows",
                    "CurrentVersion",
                    "CapabilityAccessManager",
                    "ConsentStore",
                ],
            ) {
                if let Some(Ok(cap_iter)) = consent.subkeys() {
                    for cap_res in cap_iter {
                        let Ok(cap_node) = cap_res else { continue };
                        let Ok(cap_name) = cap_node.name() else { continue };
                        let cap_name = cap_name.to_string_lossy();
                        let mitre = match cap_name.as_ref() {
                            "microphone" => "T1123",
                            "webcam" => "T1125",
                            "location" => "T1430",
                            "contacts" => "T1213",
                            _ => "T1005",
                        };

                        // Walk both NonPackaged (desktop) and direct app subkeys
                        let nonpackaged = cap_node.subkey("NonPackaged").and_then(|r| r.ok());
                        let parents: Vec<nt_hive::KeyNode<'_, &[u8]>> =
                            if let Some(np) = nonpackaged {
                                vec![np, cap_node.clone()]
                            } else {
                                vec![cap_node.clone()]
                            };

                        for parent in parents {
                            if let Some(Ok(app_iter)) = parent.subkeys() {
                                for app_res in app_iter {
                                    let Ok(app_node) = app_res else { continue };
                                    let Ok(app_path_raw) = app_node.name() else { continue };
                                    let app_path = app_path_raw.to_string_lossy();
                                    if app_path == "NonPackaged" {
                                        continue;
                                    }

                                    let value =
                                        read_value_string(&app_node, "Value").unwrap_or_default();
                                    let last_start = read_filetime(&app_node, "LastUsedTimeStart");
                                    let last_stop = read_filetime(&app_node, "LastUsedTimeStop");

                                    if value != "Allow" && last_start.is_none() {
                                        continue;
                                    }

                                    // Capability access app paths use # as
                                    // separator instead of \
                                    let display_path = app_path.replace('#', "\\");
                                    let lc = display_path.to_lowercase();
                                    let suspicious = lc.contains("\\temp\\")
                                        || lc.contains("\\appdata\\local\\temp")
                                        || lc.contains("\\downloads\\");

                                    let last_used = last_start
                                        .or(last_stop)
                                        .map(fmt_unix)
                                        .unwrap_or_else(|| "(no timestamp)".to_string());

                                    let mut a = Artifact::new("Capability Access", &path_str);
                                    if let Some(t) = last_start.or(last_stop) {
                                        a.timestamp = Some(t as u64);
                                    }
                                    a.add_field(
                                        "title",
                                        &format!("Capability: {} \u{2192} {}", cap_name, display_path),
                                    );
                                    a.add_field(
                                        "detail",
                                        &format!("Value: {} | Last used: {}", value, last_used),
                                    );
                                    a.add_field("file_type", "Capability Access");
                                    a.add_field("mitre", mitre);
                                    if suspicious {
                                        a.add_field("forensic_value", "High");
                                        a.add_field("suspicious", "true");
                                    } else {
                                        a.add_field("forensic_value", "Medium");
                                    }
                                    out.push(a);
                                }
                            }
                        }
                    }
                }
            }

            // ── 7-Zip FolderHistory ────────────────────────────────────
            if let Some(node) =
                walk(&root, &["Software", "7-Zip", "FM"])
            {
                if let Some(bytes) = read_value_bytes(&node, "FolderHistory") {
                    // Multi-string (REG_MULTI_SZ) — null-separated UTF-16LE.
                    let entries = decode_multi_sz(&bytes);
                    for entry in entries {
                        let suspicious = is_archive_path_suspicious(&entry);
                        let mut a = Artifact::new("Archive Tool", &path_str);
                        a.add_field("title", &format!("7-Zip recent: {}", entry));
                        a.add_field("detail", "7-Zip FolderHistory");
                        a.add_field("file_type", "Archive Tool");
                        a.add_field("mitre", "T1560.001");
                        if suspicious {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                    }
                }
            }

            // ── WinRAR ArcHistory ──────────────────────────────────────
            if let Some(node) = walk(&root, &["Software", "WinRAR", "ArcHistory"]) {
                if let Some(Ok(values)) = node.values() {
                    for vr in values {
                        let Ok(v) = vr else { continue };
                        let bytes: Vec<u8> = match v.data() {
                            Ok(d) => match d.into_vec() {
                                Ok(b) => b,
                                Err(_) => continue,
                            },
                            Err(_) => continue,
                        };
                        let archive_path = utf16le_to_string(&bytes);
                        if archive_path.is_empty() {
                            continue;
                        }
                        let suspicious = is_archive_path_suspicious(&archive_path)
                            || archive_path_has_exfil_keyword(&archive_path);
                        let mut a = Artifact::new("Archive Tool", &path_str);
                        a.add_field("title", &format!("WinRAR archive: {}", archive_path));
                        a.add_field("detail", "WinRAR ArcHistory MRU");
                        a.add_field("file_type", "Archive Tool");
                        a.add_field("mitre", "T1560.001");
                        if suspicious {
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                        } else {
                            a.add_field("forensic_value", "Medium");
                        }
                        out.push(a);
                    }
                }
            }

            // ── WinRAR DialogEditHistory ExtrPath (extraction destinations) ──
            if let Some(node) = walk(
                &root,
                &["Software", "WinRAR", "DialogEditHistory", "ExtrPath"],
            ) {
                if let Some(Ok(values)) = node.values() {
                    for vr in values {
                        let Ok(v) = vr else { continue };
                        let bytes: Vec<u8> = match v.data() {
                            Ok(d) => match d.into_vec() {
                                Ok(b) => b,
                                Err(_) => continue,
                            },
                            Err(_) => continue,
                        };
                        let extract_path = utf16le_to_string(&bytes);
                        if extract_path.is_empty() {
                            continue;
                        }
                        let mut a = Artifact::new("Archive Tool", &path_str);
                        a.add_field(
                            "title",
                            &format!("WinRAR extracted to: {}", extract_path),
                        );
                        a.add_field("detail", "WinRAR DialogEditHistory ExtrPath");
                        a.add_field("file_type", "Archive Tool");
                        a.add_field("mitre", "T1560.001");
                        a.add_field("forensic_value", "Medium");
                        out.push(a);
                    }
                }
            }

            // ── WinZip ────────────────────────────────────────────────
            if walk(&root, &["Software", "Nico Mak Computing", "WinZip"]).is_some() {
                let mut a = Artifact::new("Archive Tool", &path_str);
                a.add_field("title", "WinZip installed");
                a.add_field(
                    "detail",
                    "Software\\Nico Mak Computing\\WinZip key present — examine for recent archive history",
                );
                a.add_field("file_type", "Archive Tool");
                a.add_field("mitre", "T1560.001");
                a.add_field("forensic_value", "Medium");
                out.push(a);
            }

            // ── TaskBar FeatureUsage ───────────────────────────────────
            if let Some(fu) = walk(
                &root,
                &[
                    "Software",
                    "Microsoft",
                    "Windows",
                    "CurrentVersion",
                    "Explorer",
                    "FeatureUsage",
                ],
            ) {
                // AppLaunch — counts of taskbar launches per app
                if let Some(Ok(launch)) = fu.subkey("AppLaunch") {
                    if let Some(Ok(values)) = launch.values() {
                        for vr in values {
                            let Ok(v) = vr else { continue };
                            let Ok(vname) = v.name() else { continue };
                            let app = vname.to_string_lossy();
                            let count = match v.data() {
                                Ok(d) => match d.into_vec() {
                                    Ok(b) if b.len() >= 4 => u32::from_le_bytes(
                                        b[0..4].try_into().unwrap_or([0; 4]),
                                    ),
                                    _ => 0,
                                },
                                Err(_) => 0,
                            };
                            let mut a = Artifact::new("FeatureUsage", &path_str);
                            a.add_field(
                                "title",
                                &format!("TaskBar launch: {}", short_app_name(&app)),
                            );
                            a.add_field(
                                "detail",
                                &format!("{} launches from taskbar | Path: {}", count, app),
                            );
                            a.add_field("file_type", "FeatureUsage");
                            a.add_field("forensic_value", "Low");
                            out.push(a);
                        }
                    }
                }

                // AppSwitched — counts of focus switches per app
                if let Some(Ok(switched)) = fu.subkey("AppSwitched") {
                    if let Some(Ok(values)) = switched.values() {
                        for vr in values {
                            let Ok(v) = vr else { continue };
                            let Ok(vname) = v.name() else { continue };
                            let app = vname.to_string_lossy();
                            let count = match v.data() {
                                Ok(d) => match d.into_vec() {
                                    Ok(b) if b.len() >= 4 => u32::from_le_bytes(
                                        b[0..4].try_into().unwrap_or([0; 4]),
                                    ),
                                    _ => 0,
                                },
                                Err(_) => 0,
                            };
                            let mut a = Artifact::new("FeatureUsage", &path_str);
                            a.add_field(
                                "title",
                                &format!("TaskBar switch: {}", short_app_name(&app)),
                            );
                            a.add_field(
                                "detail",
                                &format!("{} times focused | Path: {}", count, app),
                            );
                            a.add_field("file_type", "FeatureUsage");
                            a.add_field("forensic_value", "Low");
                            out.push(a);
                        }
                    }
                }
            }

            out
        }

        fn read_filetime(node: &nt_hive::KeyNode<'_, &[u8]>, name: &str) -> Option<i64> {
            let bytes = read_value_bytes(node, name)?;
            if bytes.len() >= 8 {
                let ft = i64::from_le_bytes(bytes[0..8].try_into().ok()?);
                filetime_to_unix(ft)
            } else {
                None
            }
        }

        fn decode_multi_sz(bytes: &[u8]) -> Vec<String> {
            // REG_MULTI_SZ is sequences of UTF-16LE strings separated by
            // double-null terminators.
            let mut out = Vec::new();
            let u16s: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let mut buf = String::new();
            for ch in u16s {
                if ch == 0 {
                    if !buf.is_empty() {
                        out.push(buf.clone());
                        buf.clear();
                    }
                } else if let Some(c) = char::from_u32(ch as u32) {
                    buf.push(c);
                }
            }
            if !buf.is_empty() {
                out.push(buf);
            }
            out
        }

        fn is_archive_path_suspicious(p: &str) -> bool {
            let l = p.to_lowercase();
            l.starts_with("d:\\")
                || l.starts_with("e:\\")
                || l.starts_with("f:\\")
                || l.starts_with("g:\\")
                || l.contains("\\temp\\")
                || l.contains("\\appdata\\")
                || l.contains("\\desktop\\")
        }

        fn archive_path_has_exfil_keyword(p: &str) -> bool {
            let l = p.to_lowercase();
            ["backup", "data", "export", "copy", "dump", "exfil"]
                .iter()
                .any(|kw| l.contains(kw))
        }

        fn short_app_name(app: &str) -> String {
            if let Some(pos) = app.rfind(['\\', '/']) {
                app[pos + 1..].to_string()
            } else {
                app.to_string()
            }
        }
    }

    // ── Generic hive helpers ────────────────────────────────────────────

    pub(super) fn walk<'a>(
        root: &nt_hive::KeyNode<'a, &'a [u8]>,
        path: &[&str],
    ) -> Option<nt_hive::KeyNode<'a, &'a [u8]>> {
        let mut node = root.clone();
        for part in path {
            node = node.subkey(part)?.ok()?;
        }
        Some(node)
    }

    pub(super) fn read_string(
        root: &nt_hive::KeyNode<'_, &[u8]>,
        key_path: &[&str],
        value_name: &str,
    ) -> Option<String> {
        let node = walk(root, key_path)?;
        read_value_string(&node, value_name)
    }

    pub(super) fn read_value_bytes(
        node: &nt_hive::KeyNode<'_, &[u8]>,
        value_name: &str,
    ) -> Option<Vec<u8>> {
        let values = node.values()?.ok()?;
        for vr in values {
            let v = vr.ok()?;
            let n = v.name().ok()?.to_string_lossy();
            if n.eq_ignore_ascii_case(value_name) {
                return v.data().ok()?.into_vec().ok();
            }
        }
        None
    }

    pub(super) fn read_value_string(
        node: &nt_hive::KeyNode<'_, &[u8]>,
        value_name: &str,
    ) -> Option<String> {
        let bytes = read_value_bytes(node, value_name)?;
        let s = utf16le_to_string(&bytes);
        if s.is_empty() {
            // Try ANSI
            let ansi = String::from_utf8_lossy(&bytes)
                .trim_end_matches('\0')
                .to_string();
            if ansi.is_empty() {
                None
            } else {
                Some(ansi)
            }
        } else {
            Some(s)
        }
    }

    pub(super) fn read_value_dword(
        node: &nt_hive::KeyNode<'_, &[u8]>,
        value_name: &str,
    ) -> Option<u32> {
        let bytes = read_value_bytes(node, value_name)?;
        if bytes.len() >= 4 {
            Some(u32::from_le_bytes(bytes[0..4].try_into().ok()?))
        } else {
            None
        }
    }
}

fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut paths = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                if let Ok(sub) = walk_dir(&p) {
                    paths.extend(sub);
                }
            } else {
                paths.push(p);
            }
        }
    }
    Ok(paths)
}

#[no_mangle]
pub extern "C" fn create_plugin_phantom() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(PhantomPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}

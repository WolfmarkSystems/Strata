//! # NetFlow — Network Forensics Plugin
//!
//! Covers FOR572-style network-forensic artifacts plus the exfil-tool
//! signatures that the FULL_COVERAGE_GAMEPLAN Phase 3 called for:
//!
//!   * PCAP / PCAPNG files — surfaces capture presence + size, plus magic
//!     byte validation. Full packet parsing is a follow-up.
//!   * IIS W3C access logs — flags webshell patterns, SQL injection
//!     patterns, scanning behavior.
//!   * Apache / Nginx access.log (Combined Log Format) — same patterns.
//!   * Windows DNS server zones (.dns files).
//!   * WLAN profile XML + WlanReport HTML.
//!   * Exfil-tool artifact detection: WinSCP.ini, rclone.conf, MEGAsync.cfg.
//!   * Power Efficiency Diagnostics HTML reports (flags long-running
//!     rclone / WinSCP sessions).
//!
//! NetFlow is v1.0.0 ship-ready for signature/presence detection; full
//! PCAP deep-parse is scaffolded as a follow-up.

use std::path::{Path, PathBuf};

use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct NetFlowPlugin {
    name: String,
    version: String,
}

impl Default for NetFlowPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl NetFlowPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata NetFlow".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    fn classify(path: &Path) -> Option<(&'static str, &'static str)> {
        let lc_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        let lc_path = path.to_string_lossy().to_lowercase();

        // PCAPs
        if lc_name.ends_with(".pcap") || lc_name.ends_with(".pcapng") || lc_name.ends_with(".cap")
        {
            return Some(("PCAP", "Packet Capture"));
        }

        // IIS W3C logs
        if lc_path.contains("\\logfiles\\w3svc") && lc_name.ends_with(".log") {
            return Some(("IIS Log", "Web Server"));
        }

        // Apache / Nginx access logs
        if lc_name == "access.log" || lc_name == "access_log" {
            return Some(("Access Log", "Web Server"));
        }

        // Windows DNS zones
        if lc_path.contains("\\system32\\dns\\") && lc_name.ends_with(".dns") {
            return Some(("DNS Zone", "DNS"));
        }

        // WLAN profile XML
        if lc_path.contains("\\wlansvc\\profiles\\") && lc_name.ends_with(".xml") {
            return Some(("WLAN Profile", "Wireless"));
        }

        // WLAN diagnostic report
        if lc_name.starts_with("wlan-report-") && lc_name.ends_with(".html") {
            return Some(("WLAN Report", "Wireless"));
        }

        // Exfil tool artifacts
        if lc_name == "winscp.ini" {
            return Some(("WinSCP Config", "Exfil Tool"));
        }
        if lc_name == "rclone.conf" {
            return Some(("Rclone Config", "Exfil Tool"));
        }
        if lc_name == "megasync.cfg" || lc_name == "megaclient.sqlite" {
            return Some(("MEGAsync Config", "Exfil Tool"));
        }
        if lc_name.starts_with("splashtop") && lc_name.ends_with(".log") {
            return Some(("Splashtop Log", "Remote Access"));
        }
        if lc_name.ends_with(".log") && lc_path.contains("\\logmein\\") {
            return Some(("LogMeIn Log", "Remote Access"));
        }
        if lc_path.contains("\\screenconnect") {
            return Some(("ScreenConnect Artifact", "Remote Access"));
        }
        if lc_name == "ftclog.txt" {
            return Some(("Splashtop FTC Log", "Remote Access"));
        }
        if lc_path.contains("\\ateraagent") {
            return Some(("Atera Agent", "Remote Access"));
        }

        // Power Efficiency Diagnostics
        if lc_path.contains("\\power efficiency diagnostics\\") && lc_name.ends_with(".html") {
            return Some(("Power Efficiency Report", "Long-Running Process"));
        }

        // Qbittorrent / BitTorrent / FrostWire — refined per-client classification
        if lc_path.contains("\\bittorrent\\") && lc_name.ends_with(".dat") {
            return Some(("BitTorrent Data", "Peer-to-Peer"));
        }
        if lc_path.contains("\\utorrent\\") && lc_name.ends_with(".dat") {
            return Some(("uTorrent Data", "Peer-to-Peer"));
        }
        if lc_path.contains("\\qbittorrent\\") && lc_name.ends_with(".ini") {
            return Some(("qBittorrent Config", "Peer-to-Peer"));
        }
        if lc_path.contains("\\qbittorrent\\logs\\") && lc_name.ends_with(".txt") {
            return Some(("qBittorrent Log", "Peer-to-Peer"));
        }
        if lc_path.contains("\\frostwire") {
            return Some(("FrostWire", "Peer-to-Peer"));
        }
        // Generic catch-all for other P2P client paths
        if lc_path.contains("\\bittorrent\\")
            || lc_path.contains("\\utorrent\\")
            || lc_path.contains("\\qbittorrent\\")
        {
            return Some(("P2P Client", "Peer-to-Peer"));
        }

        // ── v1.1.0: OneNote ──────────────────────────────────────────
        if lc_name == "recentsearches.db" && lc_path.contains("microsoft.office.onenote") {
            return Some(("OneNote Search DB", "Productivity"));
        }
        if lc_path.contains("microsoft.office.onenote") && lc_name.ends_with(".one") {
            return Some(("OneNote Notebook", "Productivity"));
        }

        // ── v1.1.0: VMware ───────────────────────────────────────────
        if lc_path.contains("\\vmware\\") && lc_name.ends_with(".cfg") {
            return Some(("VMware Config", "Virtualization"));
        }
        if lc_name.ends_with(".vmx") {
            return Some(("VMware VMX", "Virtualization"));
        }
        if lc_name.ends_with(".vmdk") {
            return Some(("VMware VMDK", "Virtualization"));
        }
        if lc_path.contains("\\vmware\\") && lc_name == "preferences.ini" {
            return Some(("VMware Preferences", "Virtualization"));
        }

        None
    }

    fn pcap_magic_check(data: &[u8]) -> Option<&'static str> {
        if data.len() < 4 {
            return None;
        }
        // libpcap: 0xa1b2c3d4 or 0xd4c3b2a1 (byte-order variants)
        let m = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        match m {
            0xa1b2_c3d4 | 0xd4c3_b2a1 => Some("PCAP (libpcap)"),
            0xa1b2_3c4d | 0x4d3c_b2a1 => Some("PCAP nanosecond"),
            0x0a0d_0d0a => Some("PCAPNG"),
            _ => None,
        }
    }

    /// Scan a line from an IIS / Apache access log for webshell / SQLi /
    /// scanning indicators. Returns a suspicious-reason label if any pattern
    /// matches.
    fn http_log_line_indicator(line: &str) -> Option<&'static str> {
        let l = line.to_lowercase();
        // Webshell patterns
        if l.contains("?cmd=")
            || l.contains("?exec=")
            || l.contains("?system(")
            || l.contains("?shell=")
            || l.contains("c99shell")
            || l.contains("r57shell")
            || l.contains("b374k")
            || l.contains("wso.php")
        {
            return Some("webshell");
        }
        // SQL injection patterns
        if l.contains("union+select")
            || l.contains("union%20select")
            || l.contains("or+1=1")
            || l.contains("or%201=1")
            || l.contains("'%20or%20'")
            || l.contains("%27+or+%27")
            || l.contains(" sleep(")
            || l.contains("sqlmap")
        {
            return Some("sql-injection");
        }
        // Scanner UAs
        if l.contains("nikto")
            || l.contains("sqlmap")
            || l.contains("nmap scripting engine")
            || l.contains("masscan")
            || l.contains("acunetix")
        {
            return Some("scanner-ua");
        }
        // Directory traversal
        if l.contains("..%2f") || l.contains("../../") || l.contains("..\\..\\") {
            return Some("directory-traversal");
        }
        None
    }

    fn parse_rclone_conf(text: &str) -> Vec<(String, String)> {
        // Returns (section, type) pairs
        let mut out = Vec::new();
        let mut current_section = String::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
                current_section = rest.to_string();
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                if k == "type" && !current_section.is_empty() {
                    out.push((current_section.clone(), v.to_string()));
                }
            }
        }
        out
    }
}

impl StrataPlugin for NetFlowPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec![
            "pcap".to_string(),
            "pcapng".to_string(),
            "log".to_string(),
            "xml".to_string(),
            "conf".to_string(),
            "ini".to_string(),
        ]
    }
    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::NetworkArtifacts,
            PluginCapability::ArtifactExtraction,
        ]
    }
    fn description(&self) -> &str {
        "Network forensics — PCAP, IIS/Apache logs, DNS, WLAN, exfil tools"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut out = Vec::new();

        let files = match walk_dir(root) {
            Ok(f) => f,
            Err(_) => return Ok(out),
        };

        for path in files {
            let Some((file_type, _category)) = Self::classify(&path) else {
                continue;
            };
            let path_str = path.to_string_lossy().to_string();

            match file_type {
                "PCAP" => {
                    // Bounded read: only load 4 bytes for magic check.
                    // PCAPs can be multi-GB; the full-load OOM'd on real
                    // evidence. File size comes from metadata.
                    let file_size = path.metadata().map(|m| m.len()).unwrap_or(0);
                    if let Ok(mut f) = std::fs::File::open(&path) {
                        use std::io::Read;
                        let mut header = [0u8; 4];
                        if f.read_exact(&mut header).is_ok() {
                            let magic = Self::pcap_magic_check(&header)
                                .unwrap_or("unknown magic");
                            let mut a = Artifact::new("Packet Capture", &path_str);
                            a.add_field("title", &format!("PCAP: {}", path.file_name().and_then(|n| n.to_str()).unwrap_or("")));
                            a.add_field(
                                "detail",
                                &format!(
                                    "Format: {} | Size: {} bytes",
                                    magic,
                                    file_size
                                ),
                            );
                            a.add_field("file_type", "PCAP");
                            a.add_field("mitre", "T1071");
                            a.add_field("forensic_value", "High");
                            out.push(a);
                        }
                    }
                }

                "IIS Log" | "Access Log" => {
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        let mut flagged = 0;
                        for (_i, line) in text.lines().enumerate().take(50_000) {
                            if let Some(reason) = Self::http_log_line_indicator(line) {
                                flagged += 1;
                                if flagged > 100 {
                                    break;
                                }
                                let mut a = Artifact::new("Web Attack", &path_str);
                                a.add_field("title", &format!("HTTP: {}", reason));
                                a.add_field(
                                    "detail",
                                    &line.chars().take(320).collect::<String>(),
                                );
                                a.add_field("file_type", file_type);
                                a.add_field("suspicious", "true");
                                a.add_field("forensic_value", "High");
                                a.add_field(
                                    "mitre",
                                    match reason {
                                        "webshell" => "T1505.003",
                                        "sql-injection" => "T1190",
                                        "scanner-ua" => "T1595",
                                        "directory-traversal" => "T1083",
                                        _ => "T1190",
                                    },
                                );
                                out.push(a);
                            }
                        }
                        if flagged == 0 {
                            let mut a = Artifact::new("Web Server Log", &path_str);
                            a.add_field("title", &format!("{} present", file_type));
                            a.add_field("detail", &format!("{} — no attack patterns matched", file_type));
                            a.add_field("file_type", file_type);
                            a.add_field("forensic_value", "Medium");
                            out.push(a);
                        }
                    }
                }

                "WLAN Profile" => {
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        let ssid = extract_xml_tag(&text, "name");
                        let auth = extract_xml_tag(&text, "authentication");
                        let mut a = Artifact::new("WLAN Profile", &path_str);
                        a.add_field("title", &format!("WiFi: {}", ssid));
                        a.add_field("detail", &format!("Auth: {}", auth));
                        a.add_field("file_type", "WLAN Profile");
                        a.add_field("mitre", "T1016");
                        a.add_field("forensic_value", "Medium");
                        out.push(a);
                    }
                }

                "WinSCP Config" => {
                    let mut a = Artifact::new("WinSCP", &path_str);
                    a.add_field("title", "WinSCP configuration present");
                    a.add_field(
                        "detail",
                        "Parse WinSCP.ini for saved sessions (hostname + username). Also check HKCU\\Software\\Martin Prikryl\\WinSCP 2.",
                    );
                    a.add_field("file_type", "WinSCP Config");
                    a.add_field("mitre", "T1048");
                    a.add_field("forensic_value", "High");
                    a.add_field("suspicious", "true");
                    out.push(a);
                }

                "Rclone Config" => {
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        let remotes = Self::parse_rclone_conf(&text);
                        if remotes.is_empty() {
                            let mut a = Artifact::new("Rclone", &path_str);
                            a.add_field("title", "Rclone configuration present (empty)");
                            a.add_field("detail", "rclone.conf found but no remotes configured");
                            a.add_field("file_type", "Rclone Config");
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                            out.push(a);
                        } else {
                            for (name, kind) in remotes {
                                let mut a = Artifact::new("Rclone", &path_str);
                                a.add_field("title", &format!("Rclone remote: {}", name));
                                a.add_field("detail", &format!("Type: {} — potential exfil destination", kind));
                                a.add_field("file_type", "Rclone Config");
                                a.add_field("mitre", "T1537");
                                a.add_field("forensic_value", "Critical");
                                a.add_field("suspicious", "true");
                                out.push(a);
                            }
                        }
                    }
                }

                "MEGAsync Config" => {
                    let mut a = Artifact::new("MEGAsync", &path_str);
                    a.add_field("title", "MEGAsync configuration present");
                    a.add_field(
                        "detail",
                        "MEGAsync desktop sync client installed — examine logs for sync folder paths and upload history",
                    );
                    a.add_field("file_type", "MEGAsync Config");
                    a.add_field("mitre", "T1537");
                    a.add_field("forensic_value", "High");
                    a.add_field("suspicious", "true");
                    out.push(a);
                }

                "Splashtop Log" | "Splashtop FTC Log" | "LogMeIn Log" | "ScreenConnect Artifact" | "Atera Agent" => {
                    let mut a = Artifact::new("Remote Access Tool", &path_str);
                    a.add_field("title", &format!("{} artifact", file_type));
                    a.add_field(
                        "detail",
                        "Commercial remote-access tool — examine logs for session history + source IPs",
                    );
                    a.add_field("file_type", file_type);
                    a.add_field("mitre", "T1219");
                    a.add_field("forensic_value", "High");
                    out.push(a);
                }

                "Power Efficiency Report" => {
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        let lower = text.to_lowercase();
                        let flag = lower.contains("rclone")
                            || lower.contains("winscp")
                            || lower.contains("megasync");
                        let mut a = Artifact::new("Power Efficiency Report", &path_str);
                        a.add_field("title", "Power Efficiency Diagnostics");
                        a.add_field(
                            "detail",
                            if flag {
                                "Long-running exfil tool detected in power report"
                            } else {
                                "Power efficiency report (no exfil tool flags)"
                            },
                        );
                        a.add_field("file_type", "Power Efficiency Report");
                        a.add_field("forensic_value", if flag { "Critical" } else { "Medium" });
                        if flag {
                            a.add_field("suspicious", "true");
                            a.add_field("mitre", "T1567");
                        }
                        out.push(a);
                    }
                }

                "DNS Zone" => {
                    let mut a = Artifact::new("DNS Zone", &path_str);
                    a.add_field("title", "Server DNS zone file");
                    a.add_field(
                        "detail",
                        "Windows DNS server zone — cross-reference with incident timeline for malicious records",
                    );
                    a.add_field("file_type", "DNS Zone");
                    a.add_field("forensic_value", "Medium");
                    out.push(a);
                }

                "P2P Client" => {
                    let mut a = Artifact::new("P2P Client", &path_str);
                    a.add_field("title", "Torrent / P2P client artifact");
                    a.add_field(
                        "detail",
                        "P2P client data found — examine for downloaded/shared filenames and peer IPs",
                    );
                    a.add_field("file_type", "P2P Client");
                    a.add_field("mitre", "T1105");
                    a.add_field("forensic_value", "Medium");
                    out.push(a);
                }

                // ── v1.1.0: P2P client deep ─────────────────────────
                "BitTorrent Data" | "uTorrent Data" | "FrostWire" => {
                    let mut a = Artifact::new("P2P Client", &path_str);
                    a.add_field("title", &format!("{}: {}", file_type, path.file_name().and_then(|n| n.to_str()).unwrap_or("")));
                    a.add_field(
                        "detail",
                        "P2P client persistent data — typically resume.dat contains active torrents with hashes, file paths, and progress",
                    );
                    a.add_field("file_type", file_type);
                    a.add_field("mitre", "T1048");
                    a.add_field("forensic_value", "High");
                    a.add_field("suspicious", "true");
                    out.push(a);
                }

                "qBittorrent Config" => {
                    let mut a = Artifact::new("P2P Client", &path_str);
                    a.add_field("title", "qBittorrent installed");
                    a.add_field(
                        "detail",
                        "qBittorrent.ini contains default save path, recent torrents, and tracker settings",
                    );
                    a.add_field("file_type", "qBittorrent Config");
                    a.add_field("mitre", "T1048");
                    a.add_field("forensic_value", "High");
                    out.push(a);
                }

                "qBittorrent Log" => {
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        let mut download_count = 0;
                        for line in text.lines().take(2000) {
                            let lc = line.to_lowercase();
                            if lc.contains("torrent")
                                && (lc.contains("added")
                                    || lc.contains("finished")
                                    || lc.contains("completed"))
                            {
                                download_count += 1;
                                if download_count > 30 {
                                    break;
                                }
                                let mut a = Artifact::new("P2P Download", &path_str);
                                a.add_field("title", "qBittorrent download event");
                                a.add_field(
                                    "detail",
                                    &line.chars().take(280).collect::<String>(),
                                );
                                a.add_field("file_type", "qBittorrent Log");
                                a.add_field("forensic_value", "High");
                                a.add_field("suspicious", "true");
                                a.add_field("mitre", "T1105");
                                out.push(a);
                            }
                        }
                        if download_count == 0 {
                            let mut a = Artifact::new("P2P Client", &path_str);
                            a.add_field("title", "qBittorrent log present");
                            a.add_field("detail", "qBittorrent log file — no download events matched");
                            a.add_field("file_type", "qBittorrent Log");
                            a.add_field("forensic_value", "Medium");
                            out.push(a);
                        }
                    }
                }

                // ── v1.1.0: OneNote ─────────────────────────────────
                "OneNote Search DB" => {
                    let mut a = Artifact::new("OneNote", &path_str);
                    a.add_field("title", "OneNote search history database");
                    a.add_field(
                        "detail",
                        "RecentSearches.db — every term searched in OneNote",
                    );
                    a.add_field("file_type", "OneNote Search DB");
                    a.add_field("forensic_value", "Low");
                    out.push(a);
                }

                "OneNote Notebook" => {
                    let mut a = Artifact::new("OneNote", &path_str);
                    a.add_field("title", &format!("OneNote notebook: {}", path.file_name().and_then(|n| n.to_str()).unwrap_or("")));
                    a.add_field(
                        "detail",
                        "OneNote notebook section file — examine with OneNote or specialized parser",
                    );
                    a.add_field("file_type", "OneNote Notebook");
                    a.add_field("forensic_value", "Medium");
                    out.push(a);
                }

                // ── v1.1.0: VMware ──────────────────────────────────
                "VMware Config" | "VMware Preferences" => {
                    let mut a = Artifact::new("VMware", &path_str);
                    a.add_field("title", &format!("VMware: {}", file_type));
                    a.add_field(
                        "detail",
                        "VMware client configuration — may reference recent VM paths and disk locations",
                    );
                    a.add_field("file_type", file_type);
                    a.add_field("mitre", "T1564.006");
                    a.add_field("forensic_value", "Medium");
                    out.push(a);
                }

                "VMware VMX" => {
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        let mut display_name = String::new();
                        let mut disks = Vec::new();
                        for line in text.lines().take(500) {
                            let line = line.trim();
                            if let Some(rest) = line.strip_prefix("displayName") {
                                if let Some(eq) = rest.find('=') {
                                    display_name = rest[eq + 1..].trim().trim_matches('"').to_string();
                                }
                            }
                            if line.contains(".vmdk") {
                                if let Some(eq) = line.find('=') {
                                    let val = line[eq + 1..].trim().trim_matches('"');
                                    disks.push(val.to_string());
                                }
                            }
                        }
                        let title = if display_name.is_empty() {
                            format!("VMware VM: {}", path.file_name().and_then(|n| n.to_str()).unwrap_or(""))
                        } else {
                            format!("VMware VM: {}", display_name)
                        };
                        let mut a = Artifact::new("VMware VM", &path_str);
                        a.add_field("title", &title);
                        a.add_field(
                            "detail",
                            &format!("VMX configuration | Disks: {}", disks.join(", ")),
                        );
                        a.add_field("file_type", "VMware VMX");
                        a.add_field("mitre", "T1564.006");
                        a.add_field("forensic_value", "High");
                        out.push(a);
                    }
                }

                "VMware VMDK" => {
                    let mut a = Artifact::new("VMware VM", &path_str);
                    a.add_field("title", &format!("VMware disk: {}", path.file_name().and_then(|n| n.to_str()).unwrap_or("")));
                    a.add_field(
                        "detail",
                        "VMDK virtual disk — may contain a separate filesystem requiring its own evidence acquisition",
                    );
                    a.add_field("file_type", "VMware VMDK");
                    a.add_field("mitre", "T1564.006");
                    a.add_field("forensic_value", "Critical");
                    out.push(a);
                }

                _ => {}
            }
        }

        Ok(out)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;

        let mut records = Vec::new();
        let mut cats: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut suspicious = 0usize;
        for a in &artifacts {
            let ft = a.data.get("file_type").cloned().unwrap_or_default();
            let is_sus = a.data.get("suspicious").map(|s| s == "true").unwrap_or(false);
            if is_sus {
                suspicious += 1;
            }
            let category = ArtifactCategory::NetworkArtifacts;
            cats.insert(category.as_str().to_string());
            let fv = match a.data.get("forensic_value").map(|s| s.as_str()) {
                Some("Critical") => ForensicValue::Critical,
                Some("High") => ForensicValue::High,
                _ => {
                    if is_sus {
                        ForensicValue::High
                    } else {
                        ForensicValue::Medium
                    }
                }
            };
            records.push(ArtifactRecord {
                category,
                subcategory: ft,
                timestamp: None,
                title: a.data.get("title").cloned().unwrap_or_else(|| a.source.clone()),
                detail: a.data.get("detail").cloned().unwrap_or_default(),
                source_path: a.source.clone(),
                forensic_value: fv,
                mitre_technique: a.data.get("mitre").cloned(),
                is_suspicious: is_sus,
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
                suspicious_count: suspicious,
                categories_populated: cats.into_iter().collect(),
                headline: format!(
                    "NetFlow: {} network artifacts ({} flagged)",
                    total, suspicious
                ),
            },
            warnings: vec![],
        })
    }
}

fn extract_xml_tag(text: &str, tag: &str) -> String {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    if let Some(start) = text.find(&open) {
        let from = start + open.len();
        if let Some(end) = text[from..].find(&close) {
            return text[from..from + end].trim().to_string();
        }
    }
    String::new()
}

fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut out = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                if let Ok(sub) = walk_dir(&p) {
                    out.extend(sub);
                }
            } else {
                out.push(p);
            }
        }
    }
    Ok(out)
}

#[no_mangle]
pub extern "C" fn create_plugin_netflow() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(NetFlowPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}

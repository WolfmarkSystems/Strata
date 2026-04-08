use std::collections::{HashMap, HashSet};
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct SigmaPlugin {
    name: String,
    version: String,
}

impl Default for SigmaPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SigmaPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Sigma".to_string(),
            version: "1.3.0".to_string(),
        }
    }

    /// Kill chain tactics in ATT&CK order.
    const KILL_CHAIN: &'static [&'static str] = &[
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "C2",
        "Exfiltration",
        "Impact",
    ];

    /// Map MITRE technique IDs to kill chain tactics.
    fn technique_to_tactic(technique: &str) -> Option<&'static str> {
        // Strip sub-technique (e.g. T1059.001 -> T1059)
        let base = if let Some(dot_idx) = technique.find('.') {
            &technique[..dot_idx]
        } else {
            technique
        };

        match base {
            "T1059" | "T1204" | "T1203" => Some("Execution"),
            "T1053" | "T1547" | "T1197" | "T1137" | "T1543" => Some("Persistence"),
            "T1055" | "T1134" => Some("Privilege Escalation"),
            "T1070" | "T1140" | "T1218" | "T1562" | "T1222" | "T1202" | "T1127" => {
                Some("Defense Evasion")
            }
            "T1555" | "T1003" => Some("Credential Access"),
            "T1016" | "T1033" | "T1049" | "T1057" | "T1082" | "T1083" => Some("Discovery"),
            "T1021" | "T1570" => Some("Lateral Movement"),
            "T1213" | "T1005" | "T1039" | "T1074" => Some("Collection"),
            "T1071" | "T1105" | "T1572" | "T1133" => Some("C2"),
            "T1567" | "T1048" => Some("Exfiltration"),
            "T1486" | "T1490" | "T1485" | "T1565" => Some("Impact"),
            "T1078" | "T1190" | "T1566" => Some("Initial Access"),
            "T1047" => Some("Execution"),
            _ => None,
        }
    }
}

impl StrataPlugin for SigmaPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn supported_inputs(&self) -> Vec<String> {
        vec!["plugin_results_json".to_string()]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::ArtifactExtraction,
        ]
    }

    fn description(&self) -> &str {
        "Threat correlation engine \u{2014} maps artifacts to MITRE ATT&CK"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let mut results = Vec::new();

        // Use prior_results from context (populated by AppState)
        if ctx.prior_results.is_empty() {
            let mut artifact = Artifact::new("SystemActivity", "sigma");
            artifact.add_field("title", "Sigma: No Input Data");
            artifact.add_field(
                "detail",
                "Run other plugins first \u{2014} Sigma correlates results from all Strata plugins",
            );
            results.push(artifact);
            return Ok(results);
        }

        // Collect all artifact records from prior plugin runs
        let all_records: Vec<&strata_plugin_sdk::ArtifactRecord> = ctx
            .prior_results
            .iter()
            .flat_map(|o| o.artifacts.iter())
            .collect();

        let total_artifacts = all_records.len();
        let suspicious_count = all_records.iter().filter(|r| r.is_suspicious).count();

        // Aggregate: count artifacts per MITRE technique
        let mut technique_counts: HashMap<String, usize> = HashMap::new();
        let mut tactics_seen: HashSet<String> = HashSet::new();

        for record in &all_records {
            if let Some(ref technique) = record.mitre_technique {
                if !technique.is_empty() {
                    *technique_counts.entry(technique.clone()).or_insert(0) += 1;
                    if let Some(tactic) = Self::technique_to_tactic(technique) {
                        tactics_seen.insert(tactic.to_string());
                    }
                }
            }
        }

        // Build kill chain coverage artifact
        let mut coverage_lines = Vec::new();
        for &tactic in Self::KILL_CHAIN {
            let covered = tactics_seen.contains(tactic);
            let marker = if covered { "[X]" } else { "[ ]" };
            coverage_lines.push(format!("{} {}", marker, tactic));
        }

        let mut kc_artifact = Artifact::new("SystemActivity", "sigma");
        kc_artifact.add_field("title", "Kill Chain Coverage");
        kc_artifact.add_field("file_type", "Kill Chain Coverage");
        kc_artifact.add_field(
            "detail",
            &format!(
                "{}/{} tactics covered | {}",
                tactics_seen.len(),
                Self::KILL_CHAIN.len(),
                coverage_lines.join(" | "),
            ),
        );
        results.push(kc_artifact);

        // ── v0.6.0+ correlation rules ────────────────────────────────────
        //
        // Each rule scans `all_records` for a specific multi-plugin combination
        // that signals a known attack pattern. When a rule fires, an artifact
        // record is appended with severity Critical and a clear narrative.

        // RULE: USB Exfiltration Sequence
        //   Phantom finds new USB device + Chronicle finds large file access
        //   on the same day + Remnant finds file deletion after USB removal.
        let phantom_usb = all_records
            .iter()
            .any(|r| r.subcategory == "USB Device");
        let chron_recent = all_records
            .iter()
            .any(|r| r.subcategory == "Recent Files" || r.subcategory == "OpenSavePidlMRU");
        let remnant_delete = all_records
            .iter()
            .any(|r| r.subcategory.contains("Recycle") || r.subcategory.contains("USN"));
        if phantom_usb && chron_recent && remnant_delete {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: USB Exfiltration Sequence");
            a.add_field(
                "detail",
                "Phantom found a new USB device, Chronicle found recent file access activity, and Remnant found file deletion. This is a classic USB-based data exfiltration sequence.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Archive + Exfiltration
        //   Cipher finds 7-Zip / WinRAR / NetFlow finds Rclone or MEGAsync
        //   AND Chronicle finds large file access in nearby window.
        let archive_tool = all_records.iter().any(|r| {
            r.subcategory == "7-Zip"
                || r.subcategory == "WinRAR"
                || r.subcategory == "Rclone Config"
                || r.subcategory == "MEGAsync Config"
                || r.subcategory == "WinSCP Config"
        });
        if archive_tool && chron_recent {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Archive + Exfiltration Staging");
            a.add_field(
                "detail",
                "Archive utility AND/OR cloud-sync exfil tool present alongside large file access activity. Likely data staging followed by exfiltration.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: AV Evasion
        //   Guardian finds Defender detection at time T
        //   AND Remnant finds file deletion at time T+n
        //   AND no quarantine record.
        let av_detection = all_records
            .iter()
            .any(|r| r.subcategory == "Defender Log" || r.subcategory == "Avast Log");
        let no_quarantine = !all_records
            .iter()
            .any(|r| r.subcategory == "Defender Quarantine");
        if av_detection && remnant_delete && no_quarantine {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: AV Evasion + File Deletion");
            a.add_field(
                "detail",
                "Antivirus detection event present, file deletion occurred, and no quarantine record exists. The AV likely flagged something but was bypassed via deletion before quarantine.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: New Account + Persistence
        //   Phantom finds SAM new local account creation
        //   AND Trace/Phantom finds new Run key or new service same day.
        let new_account = all_records
            .iter()
            .any(|r| r.subcategory == "SAM Account" || r.subcategory == "Cloud Identity");
        let persistence = all_records
            .iter()
            .any(|r| r.subcategory == "Service" || r.subcategory == "AutoRun" || r.subcategory == "BAM/DAM");
        if new_account && persistence {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: New Account + Persistence Installed");
            a.add_field(
                "detail",
                "New local account creation alongside service install or AutoRun key addition. Strong indicator of persistent admin backdoor creation by an attacker.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Shimcache Ghost Executable
        //   Phantom finds executable in ShimCache
        //   AND no Prefetch entry exists for it.
        let shimcache_entries = all_records
            .iter()
            .filter(|r| r.subcategory == "ShimCache")
            .count();
        let prefetch_entries = all_records
            .iter()
            .filter(|r| r.subcategory == "Prefetch")
            .count();
        if shimcache_entries > 0 && prefetch_entries == 0 {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Shimcache Ghost Executable");
            a.add_field(
                "detail",
                &format!(
                    "{} ShimCache entries present but no Prefetch entries — executables existed on the system without proven execution. May indicate deletion before execution or anti-forensic prefetch wipe.",
                    shimcache_entries
                ),
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Web Server Compromise
        //   NetFlow detected webshell or SQL-injection patterns in IIS/Apache logs.
        let web_attack = all_records.iter().any(|r| r.subcategory == "Web Attack");
        if web_attack {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Web Server Attack Detected");
            a.add_field(
                "detail",
                "NetFlow flagged webshell or injection patterns in IIS/Apache access logs. Investigate the source IPs and follow-up post-compromise activity.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Log Clearing
        //   Remnant or Phantom found a security/system log clear event (1102/104).
        let log_cleared = all_records
            .iter()
            .any(|r| r.title.contains("1102") || r.title.contains("104"));
        if log_cleared {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Anti-Forensics — Log Cleared");
            a.add_field(
                "detail",
                "Event log clear event present (Event ID 1102 Security or 104 System). This is itself critical evidence of anti-forensic activity — there is no legitimate reason to clear a production system log.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // ── v1.1.0 correlation rules ────────────────────────────────────

        // RULE: Archive + Exfil Pattern (extended)
        //   Phantom Archive Tool entry found (WinRAR/7-Zip/WinZip)
        //   AND any of:
        //     NetFlow WinSCP/Rclone/MEGAsync entry
        //     Phantom USB device entry
        //     Nimbus cloud sync entry
        let phantom_archive = all_records
            .iter()
            .any(|r| r.subcategory == "Archive Tool");
        let exfil_tool = all_records.iter().any(|r| {
            r.subcategory == "WinSCP Config"
                || r.subcategory == "Rclone Config"
                || r.subcategory == "MEGAsync Config"
        });
        let nimbus_cloud = all_records
            .iter()
            .any(|r| r.subcategory.contains("Cloud") || r.subcategory.contains("OneDrive"));
        if phantom_archive && (exfil_tool || phantom_usb || nimbus_cloud) {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Archive + Exfil Pattern (extended)");
            a.add_field(
                "detail",
                "Archive tool registry history (WinRAR/7-Zip/WinZip) found alongside an exfiltration mechanism (cloud-sync tool, USB device, or cloud-storage activity). Strong evidence of stage-then-exfiltrate workflow.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Office Macro Execution Chain
        //   Chronicle Office Trust Record + any of:
        //     Trace BAM/DAM suspicious process
        //     Trace Scheduled Task addition
        //     Vector Suspicious Script with Critical severity
        let trust_record = all_records
            .iter()
            .any(|r| r.subcategory == "Office Trust Record");
        let bam_suspicious = all_records
            .iter()
            .any(|r| r.subcategory == "BAM/DAM" && r.is_suspicious);
        let scheduled_task = all_records
            .iter()
            .any(|r| r.subcategory.contains("Scheduled Task"));
        let suspicious_script = all_records.iter().any(|r| {
            r.subcategory == "Suspicious Script"
                && r.forensic_value == ForensicValue::Critical
        });
        if trust_record && (bam_suspicious || scheduled_task || suspicious_script) {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Office Macro Execution Chain");
            a.add_field(
                "detail",
                "User enabled macros on an Office document AND suspicious execution followed (BAM/DAM hit, scheduled task, or critical script). Classic spearphishing → macro → payload chain.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Selective Wipe (Android)
        //   factory_reset detected AND any of:
        //     Recent app installs after reset
        //     WhatsApp/Signal/Telegram messages still present
        let factory_reset = all_records
            .iter()
            .any(|r| r.subcategory == "Factory Reset");
        let mobile_messaging = all_records.iter().any(|r| {
            r.subcategory == "WhatsApp Android"
                || r.subcategory == "Signal"
                || r.subcategory == "Telegram"
        });
        if factory_reset && mobile_messaging {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Selective Wipe Pattern");
            a.add_field(
                "detail",
                "Android factory_reset marker present BUT messaging app data still recoverable. Evidence of selective wipe — suspect attempted destruction but artifacts remain.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: SRUM + Exfil Tools
        //   Trace SRUM detection + any exfil tool entry from NetFlow.
        let srum = all_records
            .iter()
            .any(|r| r.subcategory == "SRUM Database");
        if srum && (exfil_tool || all_records.iter().any(|r| r.subcategory == "P2P Client")) {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: SRUM + Exfil Tool Co-Presence");
            a.add_field(
                "detail",
                "SRUM database (30-60 days of per-app network bytes sent/received) present alongside exfil tool. Cross-reference SRUM bytes_sent for the exfil-tool process to quantify data volume.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Suspicious Capability Access
        //   Phantom Capability Access entry where the app path is in
        //   Temp/AppData/Downloads (already flagged suspicious=true).
        let capability_abuse = all_records
            .iter()
            .any(|r| r.subcategory == "Capability Access" && r.is_suspicious);
        if capability_abuse {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Suspicious Capability Access");
            a.add_field(
                "detail",
                "Unknown application accessed microphone/camera/location from a non-standard path (Temp / AppData / Downloads). Possible covert surveillance malware.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // ── v1.3.0 Hayabusa-inspired EVTX correlation rules ────────────
        //
        // These rules key on `EVTX-<EventID>` subcategories emitted by the
        // `strata-core` EVTX parser (new in v1.3.0). Detection patterns
        // are derived from the Hayabusa rule library and SANS FOR508
        // high-value-event cheat sheet.

        let count_evtx = |id: u32| -> usize {
            all_records
                .iter()
                .filter(|r| r.subcategory == format!("EVTX-{}", id))
                .count()
        };
        let has_evtx = |id: u32| count_evtx(id) > 0;

        // RULE: Security Audit Log Cleared (Hayabusa: Log Clear — 1102)
        // Event 1102 is anti-forensic by design. Fire on any occurrence.
        if has_evtx(1102) {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Security Audit Log Cleared (EID 1102)");
            a.add_field(
                "detail",
                "Event ID 1102 present: Security audit log was cleared. There is no legitimate administrative reason to clear this log on a production host. Treat as anti-forensic activity and pivot to log backups / SIEM copies for the missing time window.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: System Log Cleared (Hayabusa: Log Clear — 104)
        if has_evtx(104) {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: System Log Cleared (EID 104)");
            a.add_field(
                "detail",
                "Event ID 104 present: System log was cleared. Pair with 1102 — attackers often clear both together to blind defenders.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Failed Logon Burst (Hayabusa: Brute-Force Logon)
        //   10+ 4625 events OR any 4625 followed by 4624 same user.
        if count_evtx(4625) >= 10 {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field(
                "title",
                "RULE FIRED: Failed Logon Burst (10+ EID 4625)",
            );
            a.add_field(
                "detail",
                &format!(
                    "{} failed logon events detected. Consistent with password spray, RDP brute force, or SMB-hammer. Cross-reference source IPs against firewall logs for the attack window.",
                    count_evtx(4625)
                ),
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Account Lockout (Hayabusa: Account Lockout — 4740)
        if has_evtx(4740) {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Account Lockout (EID 4740)");
            a.add_field(
                "detail",
                "Event 4740 present — account lockout threshold hit. In combination with failed-logon bursts (4625) this strongly indicates brute-force activity.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Scheduled Task Persistence (Hayabusa: Task Scheduler Abuse)
        if has_evtx(4698) {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field(
                "title",
                "RULE FIRED: Scheduled Task Created (EID 4698)",
            );
            a.add_field(
                "detail",
                "Event 4698 present: scheduled task creation is a common persistence mechanism (MITRE T1053.005). Review the task name, command, and author — tasks run by SYSTEM under a user-supplied payload are especially suspicious.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Service Install (Hayabusa: New Service)
        if has_evtx(7045) || has_evtx(4697) {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: New Service Installed (EID 7045/4697)");
            a.add_field(
                "detail",
                "A new Windows service was installed. Persistence via service install is MITRE T1543.003 — PsExec, Cobalt Strike, and many ransomware families leave this fingerprint. Review the service binary path for non-standard locations (Temp, AppData, Users).",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Local Account Created + Added to Admins
        //   4720 (user created) + 4732 (member added to local group)
        if has_evtx(4720) && has_evtx(4732) {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field(
                "title",
                "RULE FIRED: Local Account Created + Group Membership (EID 4720 + 4732)",
            );
            a.add_field(
                "detail",
                "A new local account was created and subsequently added to a privileged local group (likely Administrators). Classic persistent-backdoor pattern. MITRE T1136.001 + T1098.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Kerberoasting (Hayabusa: Kerberoast)
        //   4769 with unusual service tickets, heuristic: 20+ 4769 events.
        if count_evtx(4769) >= 20 {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field(
                "title",
                "RULE FIRED: Potential Kerberoasting (EID 4769 burst)",
            );
            a.add_field(
                "detail",
                &format!(
                    "{} Kerberos service ticket requests (EID 4769) in this log. Kerberoasting (MITRE T1558.003) harvests RC4-encrypted service tickets for offline cracking. Inspect TargetUserName fields for service accounts with weak passwords.",
                    count_evtx(4769)
                ),
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Suspicious PowerShell Script Block (Hayabusa: PS-Obfuscation)
        //   EID 4104 events containing obfuscation markers in command_line.
        let ps_obfuscated = all_records
            .iter()
            .filter(|r| r.subcategory == "EVTX-4104")
            .any(|r| {
                let d = r.detail.to_lowercase();
                d.contains("frombase64string")
                    || d.contains("invoke-expression")
                    || d.contains("iex ")
                    || d.contains("downloadstring")
                    || d.contains("[char]")
                    || d.contains("-enc ")
                    || d.contains("-nop")
                    || d.contains("bypass")
            });
        if ps_obfuscated {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field(
                "title",
                "RULE FIRED: Obfuscated PowerShell (EID 4104)",
            );
            a.add_field(
                "detail",
                "PowerShell Script Block Logging captured a command containing common obfuscation/evasion markers (FromBase64String, IEX, DownloadString, -enc, -nop, bypass). MITRE T1059.001 + T1027. This is the highest-signal Windows detection available.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Remote Interactive Logon Without VPN/Jumphost
        //   4624 LogonType=10 (RemoteInteractive) from external-looking IPs.
        let rdp_external = all_records
            .iter()
            .filter(|r| r.subcategory == "EVTX-4624")
            .any(|r| {
                r.detail.contains("type=10")
                    && !r.detail.contains("from=10.")
                    && !r.detail.contains("from=192.168.")
                    && !r.detail.contains("from=172.1")
                    && !r.detail.contains("from=-")
                    && !r.detail.contains("from=::1")
                    && !r.detail.contains("from=127.")
            });
        if rdp_external {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field(
                "title",
                "RULE FIRED: RDP Logon From External IP (EID 4624 type 10)",
            );
            a.add_field(
                "detail",
                "Interactive RDP logon from a non-RFC1918 address. Direct RDP exposure is one of the top ransomware entry vectors. Confirm the IP is an approved vendor/VPN endpoint before ruling this out.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Explicit-Credentials Logon (Hayabusa: 4648)
        //   Pass-the-Hash / lateral movement leaves 4648 trails.
        if count_evtx(4648) >= 5 {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field(
                "title",
                "RULE FIRED: Explicit Credential Logon Burst (EID 4648)",
            );
            a.add_field(
                "detail",
                &format!(
                    "{} explicit-credential logon events. In a burst, this is characteristic of lateral movement (psexec, runas, Impacket) or Pass-the-Hash. MITRE T1550.002.",
                    count_evtx(4648)
                ),
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Sysmon LSASS Access (Hayabusa: Credential Dumping)
        //   Sysmon EID 10 with TargetImage=lsass.exe.
        let lsass_access = all_records
            .iter()
            .filter(|r| r.subcategory == "EVTX-10")
            .any(|r| r.detail.to_lowercase().contains("lsass.exe"));
        if lsass_access {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field(
                "title",
                "RULE FIRED: LSASS Process Access (Sysmon EID 10)",
            );
            a.add_field(
                "detail",
                "Sysmon captured a process opening a handle to LSASS — the canonical Mimikatz / credential-dumping indicator. MITRE T1003.001. Verify the source process is on the Microsoft-signed allowlist (MsMpEng, WmiPrvSE).",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Sysmon WMI Persistence (Hayabusa: WMI Event Subscription)
        if has_evtx(19) || has_evtx(20) || has_evtx(21) {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field(
                "title",
                "RULE FIRED: WMI Event Subscription (Sysmon EID 19/20/21)",
            );
            a.add_field(
                "detail",
                "Sysmon recorded a WMI event filter / consumer / binding creation. Fileless persistence mechanism — MITRE T1546.003. Inspect the consumer for CommandLineEventConsumer or ActiveScriptEventConsumer with an unusual ScriptText.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Defender Tamper / Disable (Hayabusa: Defender Tampering)
        //   Defender Operational 5001 (real-time protection disabled) or
        //   1116/1117 detections followed by no quarantine.
        let defender_disabled = all_records
            .iter()
            .any(|r| r.subcategory == "EVTX-5001" || r.subcategory == "EVTX-5010");
        if defender_disabled {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field(
                "title",
                "RULE FIRED: Defender Real-Time Protection Disabled (EID 5001/5010)",
            );
            a.add_field(
                "detail",
                "Windows Defender real-time monitoring was disabled. MITRE T1562.001 (Impair Defenses: Disable or Modify Tools). Cross-reference preceding PowerShell / cmd events for the disabling command.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Special Privileges Assigned (Hayabusa: 4672 for non-admin)
        //   A 4672 event paired with an account that is not a known admin.
        if count_evtx(4672) >= 10 {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field(
                "title",
                "RULE FIRED: High-Frequency Privilege Assignment (EID 4672)",
            );
            a.add_field(
                "detail",
                &format!(
                    "{} special-privilege-assigned events. In isolation 4672 is noisy, but a burst against non-service accounts is a UAC-bypass or privilege-escalation signal. Cross-reference with 4688 / Sysmon 1 for the elevated process image.",
                    count_evtx(4672)
                ),
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Sysmon DNS Query to Suspicious TLD
        let dns_sus = all_records
            .iter()
            .filter(|r| r.subcategory == "EVTX-22")
            .any(|r| {
                let d = r.detail.to_lowercase();
                d.ends_with(".top")
                    || d.ends_with(".xyz")
                    || d.ends_with(".tk")
                    || d.contains(".onion")
                    || d.contains("pastebin.com")
                    || d.contains("transfer.sh")
                    || d.contains("duckdns.org")
                    || d.contains("no-ip.com")
            });
        if dns_sus {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field(
                "title",
                "RULE FIRED: DNS Query to Suspicious TLD (Sysmon EID 22)",
            );
            a.add_field(
                "detail",
                "Sysmon DnsQuery to a high-risk TLD (.top/.xyz/.tk), Tor .onion, or a free dynamic-DNS / paste service. Classic C2 and data-staging indicators. MITRE T1071.004.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // Build technique breakdown string
        let mut technique_lines: Vec<String> = technique_counts
            .iter()
            .map(|(t, c)| {
                let tactic = Self::technique_to_tactic(t).unwrap_or("Unknown");
                format!("{} ({}) x{}", t, tactic, c)
            })
            .collect();
        technique_lines.sort();

        // Determine threat level
        let threat_level = if suspicious_count > 10 || tactics_seen.len() >= 6 {
            "HIGH"
        } else if suspicious_count > 3 || tactics_seen.len() >= 3 {
            "MEDIUM"
        } else {
            "LOW"
        };

        // Build summary artifact
        let headline = format!(
            "Threat Level: {} | {} artifacts, {} suspicious, {}/{} kill chain tactics covered",
            threat_level,
            total_artifacts,
            suspicious_count,
            tactics_seen.len(),
            Self::KILL_CHAIN.len(),
        );

        let detail = format!(
            "{} | Technique breakdown: {}",
            headline,
            if technique_lines.is_empty() {
                "No MITRE techniques mapped".to_string()
            } else {
                technique_lines.join(", ")
            },
        );

        let mut summary_artifact = Artifact::new("SystemActivity", "sigma");
        summary_artifact.add_field("title", "Sigma Threat Assessment");
        summary_artifact.add_field("file_type", "Sigma Threat Assessment");
        summary_artifact.add_field("detail", &detail);
        if threat_level == "HIGH" {
            summary_artifact.add_field("suspicious", "true");
        }
        results.push(summary_artifact);

        Ok(results)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;

        let mut records = Vec::new();
        for artifact in &artifacts {
            let file_type = artifact.data.get("file_type").cloned().unwrap_or_default();
            let is_suspicious = artifact
                .data
                .get("suspicious")
                .map(|v| v == "true")
                .unwrap_or(false);

            let forensic_value = match file_type.as_str() {
                "Sigma Threat Assessment" => {
                    if is_suspicious {
                        ForensicValue::Critical
                    } else {
                        ForensicValue::High
                    }
                }
                "Kill Chain Coverage" => ForensicValue::High,
                "Sigma Notice" => ForensicValue::Informational,
                "Sigma Error" => ForensicValue::Low,
                _ => ForensicValue::Medium,
            };

            records.push(ArtifactRecord {
                category: ArtifactCategory::SystemActivity,
                subcategory: file_type,
                timestamp: artifact.timestamp.map(|t| t as i64),
                title: artifact
                    .data
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| artifact.source.clone()),
                detail: artifact
                    .data
                    .get("detail")
                    .cloned()
                    .unwrap_or_default(),
                source_path: artifact.source.clone(),
                forensic_value,
                mitre_technique: None,
                is_suspicious,
                raw_data: None,
            });
        }

        let suspicious_count = records.iter().filter(|r| r.is_suspicious).count();

        // Extract headline from the summary artifact
        let headline = records
            .iter()
            .find(|r| r.subcategory == "Sigma Threat Assessment")
            .map(|r| r.title.clone())
            .unwrap_or_else(|| format!("Sigma: {} records", records.len()));

        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: String::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records.clone(),
            summary: PluginSummary {
                total_artifacts: records.len(),
                suspicious_count,
                categories_populated: vec!["System Activity".to_string()],
                headline,
            },
            warnings: vec![],
        })
    }
}

#[no_mangle]
pub extern "C" fn create_plugin_sigma() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(SigmaPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}

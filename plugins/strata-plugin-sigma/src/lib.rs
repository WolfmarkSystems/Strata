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
        // Sprint 5 Fix 3 widening. Remnant's primary deletion-
        // evidence subcategory is "Carved" / "Carved <file_type>"
        // (file-signature carving of recovered deleted content),
        // alongside the less-frequent Recycle-bin and USN-Journal
        // subcategories. Pre-Sprint-5 the predicate matched only
        // Recycle + USN; the carver records — which dominate
        // Remnant's emission on real evidence — silently missed
        // the USB Exfiltration rule and the AV Evasion rule.
        // Widening to match "Carved" as a third substring closes
        // the gap without risking false positives: "Carved" only
        // appears in Remnant-emitted deletion subcategories.
        let remnant_delete = all_records.iter().any(|r| {
            r.subcategory.contains("Recycle")
                || r.subcategory.contains("USN")
                || r.subcategory.contains("Carved")
        });
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

        // ── Windows persistence rules (post-v16 Sprint 2 Fix 2) ──
        //
        // Six rules pattern-matched on the existing "New Account
        // + Persistence Installed" rule above. Each keys on the
        // subcategory string Phantom actually emits (verified
        // against Charlie + Jo SQLite in
        // docs/RESEARCH_POST_V16_SIGMA_INVENTORY.md §1 — 120
        // combined persistence records across the six techniques).
        //
        // MITRE ATT&CK sub-techniques:
        //   Active Setup        → T1547.014
        //   Winlogon Helper DLL → T1547.004
        //   Browser Helper Object → T1176 (Browser Extensions;
        //                           BHO is a Windows-specific
        //                           instance with no dedicated
        //                           sub-technique)
        //   IFEO Debugger       → T1546.012 (Image File Execution
        //                         Options Injection)
        //   Boot Execute        → T1547.001 (Registry Run Keys /
        //                         Startup Folder — closest
        //                         defensible mapping; the raw
        //                         BootExecute key is
        //                         HKLM\SYSTEM\CurrentControlSet\
        //                         Control\Session Manager\
        //                         BootExecute)
        //   Shell Execute Hook  → T1546.015 (COM Hijacking —
        //                         Shell Execute Hooks are
        //                         implemented as COM objects)
        //
        // Each rule is unconditional on subcategory presence —
        // Phantom either emitted the record or it didn't. No
        // co-occurrence gating (unlike Rule 4) because these
        // registry locations have no legitimate userland reason
        // to carry non-default values.
        if all_records.iter().any(|r| r.subcategory == "Active Setup") {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Active Setup Persistence");
            a.add_field(
                "detail",
                "Phantom detected Active Setup persistence entries in the SOFTWARE hive. Active Setup runs installed components at every user logon and is a documented MITRE ATT&CK T1547.014 persistence technique. Investigate StubPath values for attacker-controlled commands.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("mitre", "T1547.014");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        if all_records.iter().any(|r| r.subcategory == "Winlogon Persistence") {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Winlogon Helper DLL Persistence");
            a.add_field(
                "detail",
                "Phantom detected Winlogon Helper DLL persistence entries (Shell, Userinit, Notify subkeys under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon). MITRE ATT&CK T1547.004 — attacker DLLs loaded at every logon. Investigate every value that deviates from the Windows-default DLL path.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("mitre", "T1547.004");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        if all_records.iter().any(|r| r.subcategory == "Browser Helper Object") {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Browser Helper Object Persistence");
            a.add_field(
                "detail",
                "Phantom detected Browser Helper Object (BHO) entries in the SOFTWARE hive. BHOs are COM objects loaded by Internet Explorer at startup; malicious BHOs inject into the browser process for credential capture, clickjacking, and man-in-the-browser attacks. MITRE ATT&CK T1176 (Browser Extensions / legacy BHO subclass). Investigate every CLSID that isn't installed by a known vendor.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("mitre", "T1176");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        if all_records.iter().any(|r| r.subcategory == "IFEO Debugger") {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: IFEO Debugger Persistence");
            a.add_field(
                "detail",
                "Phantom detected Image File Execution Options (IFEO) Debugger entries. IFEO is a legitimate Windows feature for redirecting process launches to a debugger, commonly abused to replace utilities like sethc.exe / utilman.exe with cmd.exe (sticky-keys attack) or to persistently hijack other executables. MITRE ATT&CK T1546.012 — any IFEO Debugger value pointing at a non-debugger executable is high-severity.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("mitre", "T1546.012");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        if all_records.iter().any(|r| r.subcategory == "Boot Execute") {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Boot Execute Persistence");
            a.add_field(
                "detail",
                "Phantom detected BootExecute registry entries (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute). BootExecute commands run under SMSS at system boot, before most services start — an ideal position for rootkits. MITRE ATT&CK T1547.001 (registry-driven autostart). The default value is `autocheck autochk *`; any addition beyond that is investigative.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("mitre", "T1547.001");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        if all_records.iter().any(|r| r.subcategory == "Shell Execute Hook") {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Shell Execute Hook Persistence");
            a.add_field(
                "detail",
                "Phantom detected Shell Execute Hook entries (HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks). Shell Execute Hooks are COM objects Explorer loads on every ShellExecute call, giving attacker-registered CLSIDs execution on nearly every GUI launch. MITRE ATT&CK T1546.015 (COM Hijacking). Each non-default CLSID is investigative.",
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("mitre", "T1546.015");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE: Log Clearing
        //   Sentinel emitted a security log clear (EVTX-1102) or a
        //   system log service-state event (EVTX-104).
        //
        // Post-Sprint-2: predicate realigned from
        // `r.title.contains("1102") || r.title.contains("104")` to
        // subcategory equality. The previous title-substring match
        // was the false-positive documented in
        // docs/FIELD_VALIDATION_REAL_IMAGES_v0.16.0_AMENDMENT.md §5
        // — on Charlie the predicate fired on a Recon email
        // artifact titled "Email Address Found:
        // 200104061723.jab03225@zinfandel.lacita.com" because the
        // timestamp prefix contained "104". The fix depends on
        // Sprint 2 Fix 1 (Sentinel emitting subcategory =
        // "EVTX-<id>"); before that fix this predicate would never
        // have matched, silently regressing to zero firings. With
        // Fix 1 landed first, the ordering is safe.
        let log_cleared = all_records
            .iter()
            .any(|r| r.subcategory == "EVTX-1102" || r.subcategory == "EVTX-104");
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

        // ── v1.4.0 CSAM Sentinel correlation rules ────────────────────
        //
        // These rules correlate against CSAM hits emitted by the Strata
        // CSAM Scanner sentinel plugin. CSAM hits surface in `prior_results`
        // as ArtifactRecords with subcategory "CSAM Hit" — the bridge
        // from the dedicated CSAM scan workflow into Sigma's correlation
        // pipeline lives in apps/tree/strata-tree/src/state_csam.rs
        // (`publish_csam_plugin_output`). Each hit's `detail` field is a
        // sequence of bracket-delimited tokens:
        //
        //   [match_type=ExactSha256] [confidence=Confirmed] [source=...] [sha256=...]
        //   [match_type=Perceptual] [confidence=High] [source=...] [sha256=...] [distance=3]
        //
        // Substring checks against these tokens are unambiguous because
        // the bracket delimiters cannot prefix any other token.
        //
        // **Audit cross-reference:** every CSAM hit recorded by the
        // scanner also writes a `CSAM_HIT_DETECTED` entry into the
        // unified case audit_log table (action_type column). The Sigma
        // rule firing alone is intelligence; confirmation requires
        // correlating against the chain entry that records the original
        // detection. The strata-csam crate's hash recipe is byte-
        // compatible with strata-tree's `compute_audit_entry_hash` so
        // the CSAM events are full chain-of-custody links.
        //
        // **MITRE:** N/A. Child-safety detection is not adversary-tactic
        // correlation, so neither rule contributes to the kill chain
        // tactic coverage map. The rules' detail strings explicitly
        // call out "MITRE: N/A — child safety" for the examiner.

        let csam_hit_records: Vec<&ArtifactRecord> = all_records
            .iter()
            .copied()
            .filter(|r| r.subcategory == "CSAM Hit")
            .collect();

        // RULE 28: CSAM Hash Match Detected
        //   Fires on any CSAM hit with confidence Confirmed (exact
        //   crypto hash match) or High (perceptual distance 0-5).
        //   Severity: CRITICAL.
        //   MITRE: N/A — child safety.
        //   Action: flag immediately, require qualified examiner review.
        let csam_hash_hits: usize = csam_hit_records
            .iter()
            .filter(|r| {
                r.detail.contains("[confidence=Confirmed]")
                    || r.detail.contains("[confidence=High]")
            })
            .count();
        if csam_hash_hits > 0 {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: CSAM Hash Match Detected");
            a.add_field(
                "detail",
                &format!(
                    "{} CSAM hit(s) with Confirmed or High confidence detected by the Strata CSAM Scanner. \
                     A Confirmed hit is an exact MD5/SHA1/SHA256 match against an examiner-imported CSAM \
                     hash database; a High hit is a perceptual hash within Hamming distance 5. Severity \
                     CRITICAL. Cross-reference action_type=CSAM_HIT_DETECTED entries in the case audit_log \
                     table for the original detection events and full chain-of-custody. MITRE: N/A — \
                     child-safety detection, not adversary tactic. Action: flag immediately and require \
                     qualified examiner review before any further handling. Strata never auto-displays \
                     matched images; viewing requires explicit examiner action through the Sentinel panel.",
                    csam_hash_hits
                ),
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // RULE 29: Probable CSAM Variant Detected
        //   Fires on any CSAM hit where match_type is Perceptual AND
        //   the perceptual Hamming distance is ≤ 10. Catches edits,
        //   crops, recompressions, and resizes that defeat exact
        //   crypto hashes.
        //   Severity: HIGH.
        //   MITRE: N/A — child safety.
        //   Action: flag for examiner review.
        let csam_perceptual_hits: usize = csam_hit_records
            .iter()
            .filter(|r| r.detail.contains("[match_type=Perceptual]"))
            .filter(|r| {
                // Parse the [distance=N] token. Token must be present
                // for a Perceptual hit, and N must be ≤ 10.
                r.detail
                    .split_whitespace()
                    .find_map(|tok| {
                        tok.strip_prefix("[distance=")
                            .and_then(|t| t.strip_suffix("]"))
                            .and_then(|n| n.parse::<u32>().ok())
                    })
                    .map(|d| d <= 10)
                    .unwrap_or(false)
            })
            .count();
        if csam_perceptual_hits > 0 {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: Probable CSAM Variant Detected");
            a.add_field(
                "detail",
                &format!(
                    "{} CSAM perceptual hit(s) within Hamming distance 10 of a known image. \
                     Catches edits, crops, recompressions, and resizes that defeat exact crypto \
                     hashes. Severity HIGH. Cross-reference action_type=CSAM_HIT_DETECTED entries \
                     in the case audit_log table for the matched source identifier and full \
                     distance metadata. MITRE: N/A — child-safety detection, not adversary tactic. \
                     Action: flag for examiner review. The dHash algorithm is documented in \
                     strata-csam/src/perceptual.rs and is locked as a forensic reproducibility \
                     contract — any change requires a major version bump and re-hash of stored \
                     perceptual databases.",
                    csam_perceptual_hits
                ),
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            results.push(a);
        }

        // ── Rule 30 — High-confidence temporal anomaly ──────────────
        // Fires when AnomalyEngine finds TemporalOutlier with confidence >= 0.8
        let ml_temporal: Vec<_> = ctx.prior_results
            .iter()
            .flat_map(|output| &output.artifacts)
            .filter(|r| {
                r.subcategory == "ML Anomaly"
                    && r.detail.contains("[anomaly_type=TemporalOutlier]")
                    && r.detail.contains("[confidence=")
                    && parse_ml_confidence(&r.detail) >= 0.80
            })
            .collect();
        if !ml_temporal.is_empty() {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: ML Temporal Anomaly Detected");
            a.add_field("detail", &format!(
                "ML anomaly engine found {} high-confidence temporal outlier(s). \
                 Activity detected outside the device's established behavioral baseline. \
                 [ML-ASSISTED — ADVISORY ONLY]",
                ml_temporal.len()
            ));
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            a.add_field("mitre", "T1059");
            results.push(a);
        }

        // ── Rule 31 — Stealth execution detected ──────────────────────
        // Fires when AnomalyEngine finds StealthExecution with confidence >= 0.75
        let ml_stealth: Vec<_> = ctx.prior_results
            .iter()
            .flat_map(|output| &output.artifacts)
            .filter(|r| {
                r.subcategory == "ML Anomaly"
                    && r.detail.contains("[anomaly_type=StealthExecution]")
                    && parse_ml_confidence(&r.detail) >= 0.75
            })
            .collect();
        if !ml_stealth.is_empty() {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: ML Stealth Execution Detected");
            a.add_field("detail", &format!(
                "ML anomaly engine found {} stealth execution(s) — single run, \
                 zero focus time, no user interaction artifacts. \
                 [ML-ASSISTED — ADVISORY ONLY]",
                ml_stealth.len()
            ));
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            a.add_field("mitre", "T1059.001");
            results.push(a);
        }

        // ── Rule 32 — Timestamp manipulation confirmed ────────────────
        // Fires when AnomalyEngine finds TimestampManipulation with confidence >= 0.85
        // ($SI/$FN mismatch is near-definitive)
        let ml_timestomp: Vec<_> = ctx.prior_results
            .iter()
            .flat_map(|output| &output.artifacts)
            .filter(|r| {
                r.subcategory == "ML Anomaly"
                    && r.detail.contains("[anomaly_type=TimestampManipulation]")
                    && parse_ml_confidence(&r.detail) >= 0.85
            })
            .collect();
        if !ml_timestomp.is_empty() {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: ML Timestamp Manipulation Confirmed");
            a.add_field("detail", &format!(
                "ML anomaly engine found {} timestamp manipulation indicator(s). \
                 Impossible clustering, future timestamps, or $SI/$FN mismatch. \
                 [ML-ASSISTED — ADVISORY ONLY]",
                ml_timestomp.len()
            ));
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            a.add_field("mitre", "T1070.006");
            results.push(a);
        }

        // ── Rule 33 — Anti-forensic chain detected ────────────────────
        // Fires when 2+ AntiForensicBehavior findings exist (coordinated cleanup)
        let ml_antiforensic: Vec<_> = ctx.prior_results
            .iter()
            .flat_map(|output| &output.artifacts)
            .filter(|r| {
                r.subcategory == "ML Anomaly"
                    && r.detail.contains("[anomaly_type=AntiForensicBehavior]")
            })
            .collect();
        if ml_antiforensic.len() >= 2 {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: ML Anti-Forensic Chain Detected");
            a.add_field("detail", &format!(
                "{} anti-forensic behavior indicators detected in coordinated pattern. \
                 VSS deletion + log clearing = deliberate evidence destruction. \
                 [ML-ASSISTED — ADVISORY ONLY]",
                ml_antiforensic.len()
            ));
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            a.add_field("mitre", "T1070");
            results.push(a);
        }

        // ── Rule 34 — Abnormal exfiltration pattern ───────────────────
        // Fires when AbnormalDataTransfer + TemporalOutlier in same session
        let has_transfer_anomaly = ctx.prior_results
            .iter()
            .flat_map(|output| &output.artifacts)
            .any(|r| {
                r.subcategory == "ML Anomaly"
                    && r.detail.contains("[anomaly_type=AbnormalDataTransfer]")
            });
        let has_temporal_anomaly = !ml_temporal.is_empty();
        if has_transfer_anomaly && has_temporal_anomaly {
            let mut a = Artifact::new("Sigma Rule", "sigma");
            a.add_field("title", "RULE FIRED: ML Abnormal Exfiltration Pattern");
            a.add_field("detail",
                "Abnormal data transfer coincides with temporal anomaly — \
                 off-hours exfiltration pattern. \
                 [ML-ASSISTED — ADVISORY ONLY]"
            );
            a.add_field("file_type", "Sigma Rule");
            a.add_field("suspicious", "true");
            a.add_field("mitre", "T1048");
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
                confidence: 0,
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

/// Parse a confidence value from bracket-delimited ML anomaly detail strings.
/// Format: `[confidence=0.88]`
fn parse_ml_confidence(detail: &str) -> f32 {
    if let Some(start) = detail.find("[confidence=") {
        let after = &detail[start + 12..];
        if let Some(end) = after.find(']') {
            return after[..end].parse::<f32>().unwrap_or(0.0);
        }
    }
    0.0
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────
//
// These are the first tests in the SigmaPlugin source. They cover the
// v1.4.0 CSAM correlation rules by feeding synthetic prior_results
// into `SigmaPlugin::run()` — the same code path the host uses.
// Tests use only public APIs; no private field access.

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an `ArtifactRecord` representing a CSAM hit with the
    /// exact bracket-delimited detail format published by
    /// strata-tree's `state_csam.rs::publish_csam_plugin_output`.
    /// Tests use this helper rather than constructing detail strings
    /// inline so the format stays consistent across tests AND with
    /// the production bridge.
    fn csam_hit_record(
        file_path: &str,
        match_type: &str,
        confidence: &str,
        source: &str,
        sha256: &str,
        distance: Option<u32>,
    ) -> ArtifactRecord {
        let distance_token = match distance {
            Some(d) => format!(" [distance={}]", d),
            None => String::new(),
        };
        let detail = format!(
            "[match_type={}] [confidence={}] [source={}] [sha256={}]{}",
            match_type, confidence, source, sha256, distance_token,
        );
        ArtifactRecord {
            category: ArtifactCategory::Media,
            subcategory: "CSAM Hit".to_string(),
            timestamp: Some(0),
            title: file_path.to_string(),
            detail,
            source_path: file_path.to_string(),
            forensic_value: ForensicValue::Critical,
            mitre_technique: None,
            is_suspicious: true,
            raw_data: None,
            confidence: 0,
        }
    }

    /// Wrap one or more records in a synthetic `PluginOutput` so they
    /// can be passed as `prior_results` to `SigmaPlugin::run()`.
    fn synthetic_csam_plugin_output(records: Vec<ArtifactRecord>) -> PluginOutput {
        let total = records.len();
        PluginOutput {
            plugin_name: "Strata CSAM Scanner".to_string(),
            plugin_version: "0.1.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count: total,
                categories_populated: vec!["Media".to_string()],
                headline: format!("CSAM scan: {} hit(s)", total),
            },
            warnings: vec![],
        }
    }

    /// Run Sigma over the given prior outputs and return the firing
    /// rule titles (i.e., entries with file_type=="Sigma Rule").
    fn run_sigma(prior: Vec<PluginOutput>) -> Vec<String> {
        let plugin = SigmaPlugin::new();
        let ctx = PluginContext {
            root_path: "/tmp".to_string(),
            vfs: None,
            config: HashMap::new(),
            prior_results: prior,
        };
        let artifacts = plugin.run(ctx).expect("sigma run");
        artifacts
            .into_iter()
            .filter(|a| {
                a.data
                    .get("file_type")
                    .map(|v| v == "Sigma Rule")
                    .unwrap_or(false)
            })
            .filter_map(|a| a.data.get("title").cloned())
            .collect()
    }

    // ── Rule 28 — CSAM Hash Match Detected ─────────────────────────

    #[test]
    fn rule_28_fires_on_confirmed_exact_hash_hit() {
        let hit = csam_hit_record(
            "/evidence/photo_001.jpg",
            "ExactSha256",
            "Confirmed",
            "ncmec_2024",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            None,
        );
        let titles = run_sigma(vec![synthetic_csam_plugin_output(vec![hit])]);
        assert!(
            titles.iter().any(|t| t == "RULE FIRED: CSAM Hash Match Detected"),
            "expected Rule 28 to fire, got: {:?}",
            titles
        );
    }

    #[test]
    fn rule_28_fires_on_high_confidence_perceptual_hit() {
        // confidence=High = perceptual distance 0-5; Rule 28 includes
        // both Confirmed and High because both indicate strong matches.
        let hit = csam_hit_record(
            "/evidence/edited.jpg",
            "Perceptual",
            "High",
            "perceptual_db",
            "0000000000000000000000000000000000000000000000000000000000000000",
            Some(3),
        );
        let titles = run_sigma(vec![synthetic_csam_plugin_output(vec![hit])]);
        assert!(
            titles.iter().any(|t| t == "RULE FIRED: CSAM Hash Match Detected"),
            "expected Rule 28 to fire on High-confidence perceptual hit, got: {:?}",
            titles
        );
    }

    #[test]
    fn rule_28_does_not_fire_on_medium_confidence_alone() {
        // Medium = perceptual distance 6-10 — strong enough for Rule 29
        // but NOT for Rule 28 (which requires Confirmed or High only).
        let hit = csam_hit_record(
            "/evidence/distant.jpg",
            "Perceptual",
            "Medium",
            "perceptual_db",
            "0000000000000000000000000000000000000000000000000000000000000000",
            Some(8),
        );
        let titles = run_sigma(vec![synthetic_csam_plugin_output(vec![hit])]);
        assert!(
            !titles.iter().any(|t| t == "RULE FIRED: CSAM Hash Match Detected"),
            "Rule 28 must NOT fire on Medium-only confidence, got: {:?}",
            titles
        );
        // But Rule 29 SHOULD fire — distance 8 ≤ 10.
        assert!(
            titles
                .iter()
                .any(|t| t == "RULE FIRED: Probable CSAM Variant Detected"),
            "Rule 29 should fire on Medium perceptual hit at distance 8, got: {:?}",
            titles
        );
    }

    /// **LOAD-BEARING NEGATIVE TEST. DO NOT REMOVE.**
    ///
    /// This test confirms that Rules 28 and 29 require
    /// `subcategory == "CSAM Hit"` and do NOT fire on substring
    /// matches against arbitrary record details. Without it, a
    /// future bug where the subcategory check is dropped from the
    /// rule filters would silently start firing CSAM rules on
    /// unrelated data — and the existing positive tests would not
    /// catch it because they all use real CSAM Hit records.
    ///
    /// If you change the rule filters in lib.rs, this test must
    /// continue to pass. If you need to weaken the subcategory
    /// requirement, the spec rule must be re-reviewed first.
    #[test]
    fn rule_28_does_not_fire_with_no_csam_hits() {
        // Synthetic prior_results with NO CSAM Hit records.
        let unrelated = ArtifactRecord {
            category: ArtifactCategory::SystemActivity,
            subcategory: "EVTX-1234".to_string(),
            timestamp: Some(0),
            title: "unrelated".to_string(),
            detail: "[match_type=Confirmed]".to_string(), // looks like CSAM but isn't
            source_path: String::new(),
            forensic_value: ForensicValue::Low,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        };
        let prior = PluginOutput {
            plugin_name: "Strata Other".to_string(),
            plugin_version: "1.0.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![unrelated],
            summary: PluginSummary {
                total_artifacts: 1,
                suspicious_count: 0,
                categories_populated: vec![],
                headline: String::new(),
            },
            warnings: vec![],
        };
        let titles = run_sigma(vec![prior]);
        assert!(
            !titles.iter().any(|t| t == "RULE FIRED: CSAM Hash Match Detected"),
            "Rule 28 must require subcategory='CSAM Hit', got: {:?}",
            titles
        );
        assert!(
            !titles
                .iter()
                .any(|t| t == "RULE FIRED: Probable CSAM Variant Detected"),
            "Rule 29 must require subcategory='CSAM Hit', got: {:?}",
            titles
        );
    }

    // ── Rule 29 — Probable CSAM Variant Detected ───────────────────

    #[test]
    fn rule_29_fires_on_perceptual_within_distance_10() {
        let hit = csam_hit_record(
            "/evidence/cropped.jpg",
            "Perceptual",
            "Medium",
            "perceptual_db",
            "0000000000000000000000000000000000000000000000000000000000000000",
            Some(7),
        );
        let titles = run_sigma(vec![synthetic_csam_plugin_output(vec![hit])]);
        assert!(
            titles
                .iter()
                .any(|t| t == "RULE FIRED: Probable CSAM Variant Detected"),
            "expected Rule 29 to fire at distance 7, got: {:?}",
            titles
        );
    }

    #[test]
    fn rule_29_fires_at_exactly_distance_10() {
        // Boundary: distance == 10 must fire (≤ 10).
        let hit = csam_hit_record(
            "/evidence/edge.jpg",
            "Perceptual",
            "Medium",
            "perceptual_db",
            "0000000000000000000000000000000000000000000000000000000000000000",
            Some(10),
        );
        let titles = run_sigma(vec![synthetic_csam_plugin_output(vec![hit])]);
        assert!(
            titles
                .iter()
                .any(|t| t == "RULE FIRED: Probable CSAM Variant Detected"),
            "Rule 29 boundary (distance=10) must fire, got: {:?}",
            titles
        );
    }

    #[test]
    fn rule_29_does_not_fire_at_distance_11() {
        // Boundary: distance == 11 must NOT fire (> 10). This is the
        // NeedsReview confidence range — too distant for Rule 29.
        let hit = csam_hit_record(
            "/evidence/far.jpg",
            "Perceptual",
            "NeedsReview",
            "perceptual_db",
            "0000000000000000000000000000000000000000000000000000000000000000",
            Some(11),
        );
        let titles = run_sigma(vec![synthetic_csam_plugin_output(vec![hit])]);
        assert!(
            !titles
                .iter()
                .any(|t| t == "RULE FIRED: Probable CSAM Variant Detected"),
            "Rule 29 must NOT fire at distance 11, got: {:?}",
            titles
        );
    }

    #[test]
    fn rule_29_does_not_fire_on_exact_hash_match() {
        // Exact crypto matches are NOT perceptual — Rule 29 only fires
        // on match_type=Perceptual.
        let hit = csam_hit_record(
            "/evidence/exact.jpg",
            "ExactMd5",
            "Confirmed",
            "ncmec_2024",
            "d41d8cd98f00b204e9800998ecf8427ed41d8cd98f00b204e9800998ecf8427e",
            None,
        );
        let titles = run_sigma(vec![synthetic_csam_plugin_output(vec![hit])]);
        assert!(
            !titles
                .iter()
                .any(|t| t == "RULE FIRED: Probable CSAM Variant Detected"),
            "Rule 29 must NOT fire on exact hash hit, got: {:?}",
            titles
        );
        // But Rule 28 SHOULD fire.
        assert!(
            titles.iter().any(|t| t == "RULE FIRED: CSAM Hash Match Detected"),
            "Rule 28 should fire on Confirmed exact hit, got: {:?}",
            titles
        );
    }

    // ── Rule 28 + Rule 29 overlap (intentional) ────────────────────

    #[test]
    fn high_confidence_perceptual_fires_both_rules() {
        // A perceptual hit at distance 3 has confidence=High AND
        // distance ≤ 10 — both rules should fire on the same hit.
        // Overlap is intentional; the rules cover distinct concerns.
        let hit = csam_hit_record(
            "/evidence/both.jpg",
            "Perceptual",
            "High",
            "perceptual_db",
            "0000000000000000000000000000000000000000000000000000000000000000",
            Some(3),
        );
        let titles = run_sigma(vec![synthetic_csam_plugin_output(vec![hit])]);
        assert!(
            titles.iter().any(|t| t == "RULE FIRED: CSAM Hash Match Detected"),
            "Rule 28 should fire, got: {:?}",
            titles
        );
        assert!(
            titles
                .iter()
                .any(|t| t == "RULE FIRED: Probable CSAM Variant Detected"),
            "Rule 29 should fire, got: {:?}",
            titles
        );
    }

    // ── Multi-hit aggregation ──────────────────────────────────────

    #[test]
    fn rules_fire_once_for_multiple_hits() {
        // The rule narrative includes the count, but the rule itself
        // fires ONCE per scan with the aggregate count, not once per
        // hit. This matches the existing rule pattern (e.g.
        // count_evtx-based rules at v1.3.0).
        let hits = vec![
            csam_hit_record(
                "/a.jpg",
                "ExactSha256",
                "Confirmed",
                "db",
                "1111111111111111111111111111111111111111111111111111111111111111",
                None,
            ),
            csam_hit_record(
                "/b.jpg",
                "ExactSha256",
                "Confirmed",
                "db",
                "2222222222222222222222222222222222222222222222222222222222222222",
                None,
            ),
            csam_hit_record(
                "/c.jpg",
                "Perceptual",
                "Medium",
                "db",
                "3333333333333333333333333333333333333333333333333333333333333333",
                Some(7),
            ),
        ];
        let titles = run_sigma(vec![synthetic_csam_plugin_output(hits)]);
        let r28_count = titles
            .iter()
            .filter(|t| *t == "RULE FIRED: CSAM Hash Match Detected")
            .count();
        let r29_count = titles
            .iter()
            .filter(|t| *t == "RULE FIRED: Probable CSAM Variant Detected")
            .count();
        assert_eq!(r28_count, 1, "Rule 28 should fire exactly once aggregating multi hits");
        assert_eq!(r29_count, 1, "Rule 29 should fire exactly once aggregating multi hits");
    }

    // ── Sprint 2 Fix 2 — six Windows persistence rules ─────────────

    /// Build a synthetic Phantom record with the given subcategory
    /// so the rule predicates (which key on `r.subcategory ==
    /// "Active Setup"` etc.) can be exercised without a real
    /// Charlie SQLite round-trip.
    fn phantom_persistence_record(subcategory: &str) -> ArtifactRecord {
        ArtifactRecord {
            category: ArtifactCategory::SystemActivity,
            subcategory: subcategory.to_string(),
            timestamp: Some(0),
            title: format!("{subcategory} — synthetic"),
            detail: format!("registry value at HKLM\\\\... (synthetic for rule test, not real {subcategory} data)"),
            source_path: "/case/extracted/C_/Windows/System32/config/SOFTWARE".to_string(),
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        }
    }

    fn synthetic_phantom_output(records: Vec<ArtifactRecord>) -> PluginOutput {
        let total = records.len();
        PluginOutput {
            plugin_name: "Strata Phantom".to_string(),
            plugin_version: "1.0.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count: 0,
                categories_populated: vec!["SystemActivity".to_string()],
                headline: format!("Phantom: {} synthetic", total),
            },
            warnings: vec![],
        }
    }

    /// Run Sigma and return every artifact's title, including
    /// the two meta-records (Kill Chain Coverage and Sigma Threat
    /// Assessment) which `run_sigma()` filters out because it
    /// keys on `file_type == "Sigma Rule"`. The ≥8 tripwire below
    /// counts production-output cardinality (rule fires + meta
    /// records), which is what `strata ingest run` produces on a
    /// real Charlie case.
    fn run_sigma_all_titles(prior: Vec<PluginOutput>) -> Vec<String> {
        let plugin = SigmaPlugin::new();
        let ctx = PluginContext {
            root_path: "/tmp".to_string(),
            vfs: None,
            config: HashMap::new(),
            prior_results: prior,
        };
        let artifacts = plugin.run(ctx).expect("sigma run");
        artifacts
            .into_iter()
            .filter_map(|a| a.data.get("title").cloned())
            .collect()
    }

    #[test]
    fn sigma_rule_firings_on_charlie_gte_8() {
        // Sprint 2 Fix 2 top-line acceptance tripwire per
        // docs/RESEARCH_POST_V16_SIGMA_INVENTORY.md §5. The fixture
        // synthesizes one Phantom record per Sprint 2 target
        // subcategory (Active Setup, Winlogon Persistence, Browser
        // Helper Object, IFEO Debugger, Boot Execute, Shell
        // Execute Hook) — matching the shape of what Phantom emits
        // on Charlie + Jo — then counts Sigma artifact titles.
        // Must include the six new persistence rules PLUS the two
        // always-emitted meta-records ("Kill Chain Coverage",
        // "Sigma Threat Assessment"). Total ≥ 8.
        //
        // The "Charlie" in the name refers to the Sigma inventory
        // target image class. This is a unit test against synthetic
        // records because unit tests are the ship criterion per the
        // Sprint 2 prompt — the real-Charlie re-run validates
        // end-to-end at Session D-style post-sprint audit time.
        let records: Vec<ArtifactRecord> = [
            "Active Setup",
            "Winlogon Persistence",
            "Browser Helper Object",
            "IFEO Debugger",
            "Boot Execute",
            "Shell Execute Hook",
        ]
        .iter()
        .map(|s| phantom_persistence_record(s))
        .collect();
        let all_titles =
            run_sigma_all_titles(vec![synthetic_phantom_output(records)]);
        let rule_fires = all_titles
            .iter()
            .filter(|t| t.starts_with("RULE FIRED:"))
            .count();
        assert_eq!(
            rule_fires, 6,
            "expected exactly 6 RULE FIRED titles across the six new \
             persistence rules, got {rule_fires}. Titles: {all_titles:?}"
        );
        for expected_title in [
            "RULE FIRED: Active Setup Persistence",
            "RULE FIRED: Winlogon Helper DLL Persistence",
            "RULE FIRED: Browser Helper Object Persistence",
            "RULE FIRED: IFEO Debugger Persistence",
            "RULE FIRED: Boot Execute Persistence",
            "RULE FIRED: Shell Execute Hook Persistence",
        ] {
            assert!(
                all_titles.iter().any(|t| t == expected_title),
                "expected {expected_title} in titles, got: {all_titles:?}"
            );
        }
        // Including the two always-emitted meta-records:
        let total = all_titles.len();
        assert!(
            total >= 8,
            "expected Sigma output to contain ≥8 records (6 persistence rules + \
             2 meta-records), got {total}: {all_titles:?}"
        );
    }

    #[test]
    fn sigma_rule_7_does_not_fire_on_recon_email_false_positive() {
        // Sprint 2 Fix 3 anti-tripwire. Closes Defect 3 from
        // docs/RESEARCH_POST_V16_SIGMA_INVENTORY.md §4 (Tier 3).
        //
        // The exact false-positive firing documented in
        // docs/FIELD_VALIDATION_REAL_IMAGES_v0.16.0_AMENDMENT.md §5:
        //   - Recon emits an Email Address artifact with title
        //     "Email Address Found:
        //     200104061723.jab03225@zinfandel.lacita.com"
        //   - The title contains the substring "104"
        //   - Pre-Sprint-2 Rule 7 predicate was
        //     `r.title.contains("1102") || r.title.contains("104")`
        //     which matched that timestamp-prefixed email address
        //   - "RULE FIRED: Anti-Forensics — Log Cleared" fired
        //     spuriously
        //
        // Post-Sprint-2 the predicate is
        // `r.subcategory == "EVTX-1102" || r.subcategory == "EVTX-104"`.
        // Recon's subcategory on this record is "Email Address
        // Found", not EVTX-anything, so the rule must NOT fire.
        //
        // Fix 3 depends on Fix 1 having landed first — before
        // Sentinel emits EVTX-<id> subcategories, the realigned
        // predicate silently never fires anywhere and this test
        // passes for the wrong reason. With Fix 1 in place, the
        // anti-tripwire only protects against regression, not
        // initial correctness.
        let recon_email_record = ArtifactRecord {
            category: ArtifactCategory::NetworkArtifacts,
            subcategory: "Email Address Found".to_string(),
            timestamp: Some(0),
            title:
                "Email Address Found: 200104061723.jab03225@zinfandel.lacita.com"
                    .to_string(),
            detail: "extracted from /case/extracted/... content".to_string(),
            source_path: "/case/extracted/Charlie/file.txt".to_string(),
            forensic_value: ForensicValue::Medium,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        };
        let recon_output = PluginOutput {
            plugin_name: "Strata Recon".to_string(),
            plugin_version: "1.0.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![recon_email_record],
            summary: PluginSummary {
                total_artifacts: 1,
                suspicious_count: 0,
                categories_populated: vec!["NetworkArtifacts".to_string()],
                headline: "Recon: 1 artifact (synthetic)".to_string(),
            },
            warnings: vec![],
        };
        let all_titles = run_sigma_all_titles(vec![recon_output]);
        assert!(
            !all_titles
                .iter()
                .any(|t| t == "RULE FIRED: Anti-Forensics — Log Cleared"),
            "Rule 7 must NOT fire on a Recon email-address artifact whose title \
             contains '104' as part of a timestamp prefix. If this assertion \
             fails, the predicate has regressed to the pre-Sprint-2 title-\
             substring match that produced the false positive documented in \
             FIELD_VALIDATION_REAL_IMAGES_v0.16.0_AMENDMENT.md §5. Titles: {all_titles:?}"
        );
    }

    #[test]
    fn sigma_rule_7_fires_on_typed_evtx_1102_record() {
        // Positive-side tripwire for the realigned predicate. A
        // synthetic Sentinel-style record carrying subcategory =
        // "EVTX-1102" (the security audit log clear event) must
        // fire Rule 7. This proves the predicate responds to the
        // new typed subcategories Sentinel emits after Fix 1.
        let sentinel_1102 = ArtifactRecord {
            category: ArtifactCategory::SystemActivity,
            subcategory: "EVTX-1102".to_string(),
            timestamp: Some(0),
            title: "Security Log Cleared (EventID 1102)".to_string(),
            detail: "operator-initiated Security.evtx clear".to_string(),
            source_path: "/C/Windows/System32/winevt/Logs/Security.evtx".to_string(),
            forensic_value: ForensicValue::Critical,
            mitre_technique: Some("T1070.001".to_string()),
            is_suspicious: true,
            raw_data: None,
            confidence: 0,
        };
        let sentinel_output = PluginOutput {
            plugin_name: "Strata Sentinel".to_string(),
            plugin_version: "1.0.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![sentinel_1102],
            summary: PluginSummary {
                total_artifacts: 1,
                suspicious_count: 1,
                categories_populated: vec!["SystemActivity".to_string()],
                headline: "Sentinel: 1 EVTX-1102 (synthetic)".to_string(),
            },
            warnings: vec![],
        };
        let all_titles = run_sigma_all_titles(vec![sentinel_output]);
        assert!(
            all_titles
                .iter()
                .any(|t| t == "RULE FIRED: Anti-Forensics — Log Cleared"),
            "Rule 7 must fire on a typed EVTX-1102 subcategory record; got: {all_titles:?}"
        );
    }

    #[test]
    fn sigma_rule_1_matches_carved_subcategory_post_sprint5_widening() {
        // Sprint 5 Fix 3 companion tripwire. Rule 1 (USB
        // Exfiltration) and Rule 3 (AV Evasion) both consume
        // `remnant_delete`, which Sprint 5 widened to include the
        // "Carved" substring so Remnant's carver-emitted
        // subcategories reach the predicate.
        //
        // Fixture: build the three inputs Rule 1 needs — USB
        // Device (Phantom), Recent Files (Chronicle), and a
        // Remnant record with subcategory "Carved PDF". Rule 1
        // must fire.
        let usb = ArtifactRecord {
            category: ArtifactCategory::NetworkArtifacts,
            subcategory: "USB Device".to_string(),
            timestamp: Some(0),
            title: "USB Device: Kingston DataTraveler".to_string(),
            detail: "VID_0951&PID_1666".to_string(),
            source_path: "HKLM\\SYSTEM\\ControlSet001\\Enum\\USBSTOR".to_string(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1091".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        };
        let recent = ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Recent Files".to_string(),
            timestamp: Some(0),
            title: "secrets.xlsx".to_string(),
            detail: "/Users/alice/Recent/secrets.xlsx.lnk".to_string(),
            source_path: "Chronicle synthetic".to_string(),
            forensic_value: ForensicValue::Medium,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        };
        let carved = ArtifactRecord {
            category: ArtifactCategory::SystemActivity,
            subcategory: "Carved PDF".to_string(),
            timestamp: Some(0),
            title: "Carved PDF at 0x1000".to_string(),
            detail: "PDF magic header carved from unallocated space".to_string(),
            source_path: "Remnant synthetic".to_string(),
            forensic_value: ForensicValue::Critical,
            mitre_technique: Some("T1070.004".to_string()),
            is_suspicious: true,
            raw_data: None,
            confidence: 0,
        };
        let output = PluginOutput {
            plugin_name: "Synthetic".to_string(),
            plugin_version: "1.0.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![usb, recent, carved],
            summary: PluginSummary {
                total_artifacts: 3,
                suspicious_count: 1,
                categories_populated: vec!["SystemActivity".to_string()],
                headline: "synthetic".to_string(),
            },
            warnings: vec![],
        };
        let titles = run_sigma_all_titles(vec![output]);
        assert!(
            titles
                .iter()
                .any(|t| t == "RULE FIRED: USB Exfiltration Sequence"),
            "Rule 1 must fire on USB + Recent + Carved — Sprint 5 widened the \
             predicate to include 'Carved' substring. Titles: {titles:?}"
        );
    }

    #[test]
    fn sigma_persistence_rules_do_not_fire_on_empty_input() {
        // Anti-tripwire. With no Phantom records, none of the six
        // new persistence rules should fire. Protects against a
        // future regression that accidentally makes them
        // unconditional.
        let titles = run_sigma(vec![]);
        for absent in [
            "RULE FIRED: Active Setup Persistence",
            "RULE FIRED: Winlogon Helper DLL Persistence",
            "RULE FIRED: Browser Helper Object Persistence",
            "RULE FIRED: IFEO Debugger Persistence",
            "RULE FIRED: Boot Execute Persistence",
            "RULE FIRED: Shell Execute Hook Persistence",
        ] {
            assert!(
                !titles.iter().any(|t| t == absent),
                "{absent} must NOT fire on empty input; got: {titles:?}"
            );
        }
    }
}

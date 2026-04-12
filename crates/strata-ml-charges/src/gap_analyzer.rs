use strata_charges::ChargeEntry;
use strata_plugin_sdk::PluginOutput;

use crate::types::EvidenceGap;

/// Analyzes evidence gaps — artifacts expected for a charge but not found.
pub struct EvidenceGapAnalyzer;

impl EvidenceGapAnalyzer {
    /// For a given charge, identify what artifacts SHOULD be present
    /// but weren't found in the plugin outputs.
    pub fn analyze(
        charge: &ChargeEntry,
        outputs: &[PluginOutput],
    ) -> Vec<EvidenceGap> {
        let mut gaps = Vec::new();
        let all_text = collect_all_text(outputs);

        // Match gap rules by charge section/category
        let section = charge.section.as_str();
        let category = charge.category.to_lowercase();

        // CSAM charges (§ 2252, § 2256, etc.)
        if section.starts_with("2252") || section.starts_with("2256") || category.contains("csam")
            || category.contains("child")
        {
            if !all_text.contains("browser history") && !all_text.contains("chrome") {
                gaps.push(EvidenceGap {
                    charge: charge.clone(),
                    missing_artifact_type: "Browser history".to_string(),
                    why_expected: "CSAM charges typically involve browser-based access to illegal material".to_string(),
                    investigative_recommendation: "Browser history may have been deleted. Check: Chrome SQLite WAL files, DNS cache, NetFlow logs".to_string(),
                });
            }
            if !all_text.contains("download") {
                gaps.push(EvidenceGap {
                    charge: charge.clone(),
                    missing_artifact_type: "Download artifacts".to_string(),
                    why_expected: "Possession charges require evidence of acquisition".to_string(),
                    investigative_recommendation: "Check browser download databases, USN Journal for file creation events, P2P client artifacts".to_string(),
                });
            }
            if all_text.contains("csam") && !all_text.contains("media") && !all_text.contains("image") {
                gaps.push(EvidenceGap {
                    charge: charge.clone(),
                    missing_artifact_type: "Media files".to_string(),
                    why_expected: "CSAM hash matched but original files not recovered".to_string(),
                    investigative_recommendation: "Files deleted after hash match. Recommend: file carving on unallocated space, cloud storage warrant".to_string(),
                });
            }
            if all_text.contains("onedrive") || all_text.contains("icloud") || all_text.contains("google drive") {
                gaps.push(EvidenceGap {
                    charge: charge.clone(),
                    missing_artifact_type: "Cloud storage contents".to_string(),
                    why_expected: "Cloud sync artifacts detected but cloud contents not acquired".to_string(),
                    investigative_recommendation: "Cloud storage sync detected. Request warrant for cloud account contents.".to_string(),
                });
            }
        }

        // CFAA charges (§ 1030)
        if section.starts_with("1030") || category.contains("computer") {
            if !all_text.contains("evtx") && !all_text.contains("event log") && !all_text.contains("logon") {
                gaps.push(EvidenceGap {
                    charge: charge.clone(),
                    missing_artifact_type: "Windows Security Event Logs".to_string(),
                    why_expected: "CFAA charges require proof of access — logon events are primary evidence".to_string(),
                    investigative_recommendation: "Windows Security log may have been cleared. Check: Application log for authentication events, firewall logs, SRUM network activity".to_string(),
                });
            }
            if !all_text.contains("network") && !all_text.contains("remote") {
                gaps.push(EvidenceGap {
                    charge: charge.clone(),
                    missing_artifact_type: "Network access artifacts".to_string(),
                    why_expected: "CFAA requires proof of unauthorized access to protected computer".to_string(),
                    investigative_recommendation: "Check RDP history, VPN logs, SSH known_hosts, network adapter history".to_string(),
                });
            }
        }

        // Sexual assault (UCMJ Art. 120)
        if section == "120" || category.contains("sexual assault") {
            if !all_text.contains("message") && !all_text.contains("sms") && !all_text.contains("chat") {
                gaps.push(EvidenceGap {
                    charge: charge.clone(),
                    missing_artifact_type: "Communications".to_string(),
                    why_expected: "Sexual assault cases typically involve preceding communications".to_string(),
                    investigative_recommendation: "Communications may be on second device or cloud. Recommend: warrant for iCloud/Google account, check for secondary phone".to_string(),
                });
            }
            if !all_text.contains("location") && !all_text.contains("gps") {
                gaps.push(EvidenceGap {
                    charge: charge.clone(),
                    missing_artifact_type: "Location data".to_string(),
                    why_expected: "Location data can corroborate or refute proximity claims".to_string(),
                    investigative_recommendation: "Check Google Location History, Apple Significant Locations, cell tower records".to_string(),
                });
            }
        }

        // Obstruction / destruction (§ 1519)
        if (section == "1519" || category.contains("obstruction"))
            && !all_text.contains("usn journal") && !all_text.contains("$usnjrnl")
        {
                gaps.push(EvidenceGap {
                    charge: charge.clone(),
                    missing_artifact_type: "USN Journal records".to_string(),
                    why_expected: "USN Journal documents file creation/deletion sequence for destruction charges".to_string(),
                    investigative_recommendation: "USN Journal may have been cleared or overwritten. Check $UsnJrnl:$J for sequence gaps".to_string(),
                });
        }

        gaps
    }
}

fn collect_all_text(outputs: &[PluginOutput]) -> String {
    let mut text = String::new();
    for output in outputs {
        text.push_str(&output.plugin_name.to_lowercase());
        text.push(' ');
        for record in &output.artifacts {
            text.push_str(&record.title.to_lowercase());
            text.push(' ');
            text.push_str(&record.detail.to_lowercase());
            text.push(' ');
            text.push_str(&record.subcategory.to_lowercase());
            text.push(' ');
        }
    }
    text
}

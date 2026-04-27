//! Detection pipeline — scans plugin outputs for anti-forensic behaviors.

use chrono::{DateTime, Utc};
use strata_plugin_sdk::PluginOutput;

/// A single detected anti-forensic behavior before scoring.
#[derive(Debug, Clone)]
pub struct DetectedBehavior {
    pub factor_id: &'static str,
    pub timestamp: Option<DateTime<Utc>>,
    pub detail: String,
    pub source_plugin: String,
    pub artifact_id: String,
}

/// Scans plugin outputs for anti-forensic indicators.
pub struct AntiForensicDetector;

impl AntiForensicDetector {
    /// Detect all anti-forensic behaviors from plugin outputs.
    pub fn detect(outputs: &[PluginOutput]) -> Vec<DetectedBehavior> {
        let mut behaviors = Vec::new();
        for output in outputs {
            Self::detect_vss_deletion(output, &mut behaviors);
            Self::detect_evtx_clearing(output, &mut behaviors);
            Self::detect_secure_delete_tools(output, &mut behaviors);
            Self::detect_timestamp_stomp(output, &mut behaviors);
            Self::detect_browser_hist_clear(output, &mut behaviors);
            Self::detect_usn_journal_gap(output, &mut behaviors);
            Self::detect_recycle_mass_delete(output, &mut behaviors);
            Self::detect_hibernate_pagefile(output, &mut behaviors);
            Self::detect_audit_disabled(output, &mut behaviors);
            Self::detect_encrypted_container(output, &mut behaviors);
            Self::detect_antiforensic_search(output, &mut behaviors);
        }
        behaviors
    }

    fn detect_vss_deletion(output: &PluginOutput, out: &mut Vec<DetectedBehavior>) {
        for record in &output.artifacts {
            if record.subcategory == "VSS Deletion"
                || (record.detail.contains("vssadmin") && record.detail.contains("delete shadows"))
            {
                out.push(DetectedBehavior {
                    factor_id: "VSS_DELETION",
                    timestamp: record.timestamp.and_then(ts_to_dt),
                    detail: record.detail.clone(),
                    source_plugin: output.plugin_name.clone(),
                    artifact_id: record.source_path.clone(),
                });
            }
        }
    }

    fn detect_evtx_clearing(output: &PluginOutput, out: &mut Vec<DetectedBehavior>) {
        for record in &output.artifacts {
            let detail_lower = record.detail.to_lowercase();
            if record.subcategory.contains("EVTX") || record.subcategory.contains("Event Log") {
                if detail_lower.contains("event id: 1102")
                    || detail_lower.contains("eventid=1102")
                    || (detail_lower.contains("1102") && detail_lower.contains("audit log cleared"))
                {
                    out.push(DetectedBehavior {
                        factor_id: "EVTX_SECURITY_CLEAR",
                        timestamp: record.timestamp.and_then(ts_to_dt),
                        detail: record.detail.clone(),
                        source_plugin: output.plugin_name.clone(),
                        artifact_id: record.source_path.clone(),
                    });
                }
                if detail_lower.contains("event id: 104")
                    || detail_lower.contains("eventid=104")
                    || (detail_lower.contains("104") && detail_lower.contains("system log cleared"))
                {
                    out.push(DetectedBehavior {
                        factor_id: "EVTX_SYSTEM_CLEAR",
                        timestamp: record.timestamp.and_then(ts_to_dt),
                        detail: record.detail.clone(),
                        source_plugin: output.plugin_name.clone(),
                        artifact_id: record.source_path.clone(),
                    });
                }
            }
        }
    }

    fn detect_secure_delete_tools(output: &PluginOutput, out: &mut Vec<DetectedBehavior>) {
        const TOOLS: &[&str] = &[
            "ccleaner",
            "eraser",
            "sdelete",
            "cipher.exe /w",
            "bleachbit",
            "privazer",
            "secure eraser",
        ];
        for record in &output.artifacts {
            let lower = record.detail.to_lowercase();
            if record.subcategory.contains("Prefetch")
                || record.subcategory.contains("Execution")
                || record.subcategory.contains("SRUM Activity")
            {
                for tool in TOOLS {
                    if lower.contains(tool) {
                        out.push(DetectedBehavior {
                            factor_id: "SECURE_DELETE_TOOL",
                            timestamp: record.timestamp.and_then(ts_to_dt),
                            detail: record.detail.clone(),
                            source_plugin: output.plugin_name.clone(),
                            artifact_id: record.source_path.clone(),
                        });
                        break;
                    }
                }
            }
        }
    }

    fn detect_timestamp_stomp(output: &PluginOutput, out: &mut Vec<DetectedBehavior>) {
        for record in &output.artifacts {
            let lower = record.detail.to_lowercase();
            if record.subcategory.contains("Timestamp")
                || (lower.contains("$si") && lower.contains("$fn") && lower.contains("mismatch"))
                || lower.contains("timestomp")
            {
                out.push(DetectedBehavior {
                    factor_id: "TIMESTAMP_STOMP",
                    timestamp: record.timestamp.and_then(ts_to_dt),
                    detail: record.detail.clone(),
                    source_plugin: output.plugin_name.clone(),
                    artifact_id: record.source_path.clone(),
                });
            }
        }
    }

    fn detect_browser_hist_clear(output: &PluginOutput, out: &mut Vec<DetectedBehavior>) {
        for record in &output.artifacts {
            let lower = record.detail.to_lowercase();
            if (lower.contains("history") && lower.contains("cleared"))
                || (lower.contains("history absent") && lower.contains("cache present"))
                || (record.subcategory.contains("Browser")
                    && lower.contains("selective")
                    && lower.contains("cleanup"))
            {
                out.push(DetectedBehavior {
                    factor_id: "BROWSER_HIST_CLEAR",
                    timestamp: record.timestamp.and_then(ts_to_dt),
                    detail: record.detail.clone(),
                    source_plugin: output.plugin_name.clone(),
                    artifact_id: record.source_path.clone(),
                });
            }
        }
    }

    fn detect_usn_journal_gap(output: &PluginOutput, out: &mut Vec<DetectedBehavior>) {
        for record in &output.artifacts {
            let lower = record.detail.to_lowercase();
            if (record.subcategory.contains("USN") && lower.contains("gap"))
                || lower.contains("journal cleared")
                || lower.contains("usn sequence gap")
            {
                out.push(DetectedBehavior {
                    factor_id: "MFT_LOG_GAP",
                    timestamp: record.timestamp.and_then(ts_to_dt),
                    detail: record.detail.clone(),
                    source_plugin: output.plugin_name.clone(),
                    artifact_id: record.source_path.clone(),
                });
            }
        }
    }

    fn detect_recycle_mass_delete(output: &PluginOutput, out: &mut Vec<DetectedBehavior>) {
        for record in &output.artifacts {
            let lower = record.detail.to_lowercase();
            if record.subcategory.contains("Recycle")
                && (lower.contains("mass delete") || lower.contains("bulk delete"))
            {
                out.push(DetectedBehavior {
                    factor_id: "RECYCLE_MASS_DELETE",
                    timestamp: record.timestamp.and_then(ts_to_dt),
                    detail: record.detail.clone(),
                    source_plugin: output.plugin_name.clone(),
                    artifact_id: record.source_path.clone(),
                });
            }
        }
    }

    fn detect_hibernate_pagefile(output: &PluginOutput, out: &mut Vec<DetectedBehavior>) {
        for record in &output.artifacts {
            let lower = record.detail.to_lowercase();
            if lower.contains("hiberfil")
                && (lower.contains("disabled") || lower.contains("deleted"))
            {
                out.push(DetectedBehavior {
                    factor_id: "HIBERNATE_DISABLED",
                    timestamp: record.timestamp.and_then(ts_to_dt),
                    detail: record.detail.clone(),
                    source_plugin: output.plugin_name.clone(),
                    artifact_id: record.source_path.clone(),
                });
            }
            if lower.contains("pagefile") && lower.contains("clear") {
                out.push(DetectedBehavior {
                    factor_id: "PAGEFILE_CLEAR",
                    timestamp: record.timestamp.and_then(ts_to_dt),
                    detail: record.detail.clone(),
                    source_plugin: output.plugin_name.clone(),
                    artifact_id: record.source_path.clone(),
                });
            }
        }
    }

    fn detect_audit_disabled(output: &PluginOutput, out: &mut Vec<DetectedBehavior>) {
        for record in &output.artifacts {
            let lower = record.detail.to_lowercase();
            if (lower.contains("audit") && lower.contains("disabled"))
                || (lower.contains("group policy")
                    && lower.contains("security")
                    && lower.contains("off"))
            {
                out.push(DetectedBehavior {
                    factor_id: "EVENT_LOG_AUDIT_OFF",
                    timestamp: record.timestamp.and_then(ts_to_dt),
                    detail: record.detail.clone(),
                    source_plugin: output.plugin_name.clone(),
                    artifact_id: record.source_path.clone(),
                });
            }
        }
    }

    fn detect_encrypted_container(output: &PluginOutput, out: &mut Vec<DetectedBehavior>) {
        for record in &output.artifacts {
            let lower = record.detail.to_lowercase();
            if lower.contains("veracrypt") || lower.contains("truecrypt") {
                out.push(DetectedBehavior {
                    factor_id: "ENCRYPTED_CONTAINER",
                    timestamp: record.timestamp.and_then(ts_to_dt),
                    detail: record.detail.clone(),
                    source_plugin: output.plugin_name.clone(),
                    artifact_id: record.source_path.clone(),
                });
            }
        }
    }

    fn detect_antiforensic_search(output: &PluginOutput, out: &mut Vec<DetectedBehavior>) {
        const TERMS: &[&str] = &[
            "how to delete",
            "undetectable",
            "wipe evidence",
            "forensics",
            "hide files",
            "encrypt evidence",
            "cover tracks",
            "anti-forensic",
            "antiforensic",
            "destroy evidence",
        ];
        for record in &output.artifacts {
            if !record.subcategory.contains("Browser")
                && !record.subcategory.contains("Web")
                && !record.subcategory.contains("Search")
            {
                continue;
            }
            let lower = record.detail.to_lowercase();
            for term in TERMS {
                if lower.contains(term) {
                    out.push(DetectedBehavior {
                        factor_id: "ANTIFORENSIC_SEARCH",
                        timestamp: record.timestamp.and_then(ts_to_dt),
                        detail: record.detail.clone(),
                        source_plugin: output.plugin_name.clone(),
                        artifact_id: record.source_path.clone(),
                    });
                    break;
                }
            }
        }
    }
}

fn ts_to_dt(epoch: i64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(epoch, 0)
}

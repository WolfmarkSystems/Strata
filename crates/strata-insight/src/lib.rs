pub mod behavior;
pub mod correlation;
pub mod credentials;
pub mod hash;
pub mod integrity;
pub mod ioc_scanner;
pub mod kb_assist;
pub mod scoring;
pub mod sqlite_viewer;
pub mod threat;
pub mod timeline;
pub mod yara;

pub use behavior::{
    analyze_network_connections, analyze_process_activity, analyze_usb_usage, Connection,
    NetworkAnalysis, Process, ProcessAnalysis, SuspiciousConnection, SuspiciousProcess,
    UsbAnalysis, UsbDevice, UsbEvent,
};
pub use correlation::{build_link_graph, CorrelatedEvent, CorrelationEngine, LinkType};
pub use hash::{
    check_hash_against_known_malware, check_hash_against_nsrl, compare_hashes, compute_file_hashes,
    get_hash_algorithm, hash_file, HashAlgorithm, HashSet,
};
pub use integrity::{
    check_file_integrity, check_tampering, verify_chain_of_custody, verify_digital_signature,
    AuditEntry, IntegrityResult, SignatureVerification, TamperEvent,
};
pub use ioc_scanner::{
    create_ioc_rule, match_hash, match_keyword, match_path, match_regex, scan_text_for_rule,
    IocHit, IocHitContext, IocRule, IocRuleInput, IocRuleType, IocScanOptions, IocScanResult,
    IocScope, IocSeverity,
};
pub use scoring::{
    get_suspicious_extensions, get_suspicious_paths, score_row, FileTableRowLike, ScoreResult,
    ScoreSignal, ScoreWeights, ScoringContext, StringsInfo,
};
pub use threat::{
    analyze_behavior, analyze_threat_indicators, calculate_risk_score, check_malware_signatures,
    BehaviorReport, IndicatorType, MalwareMatch, RiskLevel, SuspiciousBehavior, ThreatAnalysis,
    ThreatIndicator,
};
pub use timeline::{
    extract_timeline_from_logs, extract_timeline_from_mft, extract_timeline_from_registry,
    filter_timeline, merge_timeline_events, sort_timeline, LogEntry, MftEntry, RegistryEntry,
    TimelineEvent as TLEvent, TimelineFilter,
};

pub use kb_assist::{
    combined_search, query_kb_bridge, summarize_artifacts_plain_language, CombinedSearchResult,
    KbHit,
};
use strata_core::filesystem::TimelineEntry;

#[derive(Debug, Clone)]
pub struct TimelineStats {
    pub earliest: i64,
    pub latest: i64,
    pub file_count: usize,
    pub dir_count: usize,
    pub total_size: u64,
}

pub fn analyze_timeline(entries: &[TimelineEntry]) -> TimelineStats {
    let mut earliest = i64::MAX;
    let mut latest = i64::MIN;
    let mut file_count = 0;
    let mut dir_count = 0;
    let mut total_size: u64 = 0;

    for entry in entries {
        if entry.timestamp < earliest {
            earliest = entry.timestamp;
        }
        if entry.timestamp > latest {
            latest = entry.timestamp;
        }

        if entry.action == "FILE" {
            file_count += 1;
            if let Some(size) = entry.size {
                total_size += size;
            }
        } else if entry.action == "DIR" {
            dir_count += 1;
        }
    }

    TimelineStats {
        earliest: if earliest == i64::MAX { 0 } else { earliest },
        latest: if latest == i64::MIN { 0 } else { latest },
        file_count,
        dir_count,
        total_size,
    }
}

pub fn filter_by_date_range(entries: &[TimelineEntry], start: i64, end: i64) -> Vec<TimelineEntry> {
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        entries
            .par_iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }
}

pub fn filter_by_type(entries: &[TimelineEntry], file_type: &str) -> Vec<TimelineEntry> {
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        entries
            .par_iter()
            .filter(|e| e.action == file_type)
            .cloned()
            .collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        entries
            .iter()
            .filter(|e| e.action == file_type)
            .cloned()
            .collect()
    }
}

pub fn group_by_day(
    entries: &[TimelineEntry],
) -> std::collections::BTreeMap<String, Vec<TimelineEntry>> {
    use std::collections::BTreeMap;

    let mut groups: BTreeMap<String, Vec<TimelineEntry>> = BTreeMap::new();

    for entry in entries {
        let day = ntfs_timestamp_to_date(entry.timestamp);
        groups.entry(day).or_default().push(entry.clone());
    }

    groups
}

pub fn ntfs_timestamp_to_date(timestamp: i64) -> String {
    if timestamp <= 0 {
        return "Unknown".to_string();
    }

    let secs = timestamp / 10_000_000;
    let nanos = (timestamp % 10_000_000) as u32 * 100;

    if let Some(t) = std::time::UNIX_EPOCH.checked_add(std::time::Duration::new(secs as u64, nanos))
    {
        let datetime: time::OffsetDateTime = t.into();
        format!(
            "{:04}-{:02}-{:02}",
            datetime.year(),
            datetime.month(),
            datetime.day()
        )
    } else {
        "Invalid".to_string()
    }
}

pub fn sort_by_size(entries: &mut [TimelineEntry]) {
    entries.sort_by(|a, b| {
        let a_size = a.size.unwrap_or(0);
        let b_size = b.size.unwrap_or(0);
        b_size.cmp(&a_size)
    });
}

pub fn get_largest_files(entries: &[TimelineEntry], count: usize) -> Vec<TimelineEntry> {
    let mut sorted = entries.to_vec();
    sort_by_size(&mut sorted);
    sorted.into_iter().take(count).collect()
}

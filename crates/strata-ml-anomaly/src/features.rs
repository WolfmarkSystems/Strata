use chrono::{DateTime, Datelike, Timelike, Utc};
use strata_plugin_sdk::PluginOutput;

/// A timestamped entry extracted from plugin outputs.
#[derive(Debug, Clone)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub artifact_type: String,
    pub plugin: String,
    pub title: String,
    pub detail: String,
    pub source_path: String,
    pub is_suspicious: bool,
}

/// An execution event extracted from Prefetch / AmCache / BAM / SRUM.
#[derive(Debug, Clone)]
pub struct ExecutionEvent {
    pub timestamp: Option<DateTime<Utc>>,
    pub executable: String,
    pub source_path: String,
    pub plugin: String,
    pub run_count: Option<u32>,
    pub focus_time_ms: Option<u64>,
    pub has_lnk: bool,
    pub has_jumplist: bool,
    pub has_userassist: bool,
    pub is_system_path: bool,
}

/// A network transfer event extracted from NetFlow / SRUM artifacts.
#[derive(Debug, Clone)]
pub struct TransferEvent {
    pub timestamp: Option<DateTime<Utc>>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub destination: String,
    pub source_path: String,
}

/// A cluster of files sharing nearly identical timestamps.
#[derive(Debug, Clone)]
pub struct TimestampCluster {
    pub representative_time: DateTime<Utc>,
    pub file_count: usize,
    pub span_seconds: f64,
    pub paths: Vec<String>,
}

/// Basic statistical summary of a numeric series.
#[derive(Debug, Clone)]
pub struct BaselineStats {
    pub mean: f64,
    pub std_dev: f64,
    pub median: f64,
    pub iqr: f64,
    pub q1: f64,
    pub q3: f64,
}

impl BaselineStats {
    /// Z-score for a value relative to this baseline.
    pub fn z_score(&self, value: f64) -> f64 {
        if self.std_dev == 0.0 {
            return 0.0;
        }
        (value - self.mean) / self.std_dev
    }

    /// IQR-based outlier detection (> 1.5 * IQR from quartiles).
    pub fn is_outlier_iqr(&self, value: f64) -> bool {
        let lower = self.q1 - 1.5 * self.iqr;
        let upper = self.q3 + 1.5 * self.iqr;
        value < lower || value > upper
    }

    /// Extreme outlier (> 3.0 * IQR from quartiles).
    pub fn is_extreme_outlier_iqr(&self, value: f64) -> bool {
        let lower = self.q1 - 3.0 * self.iqr;
        let upper = self.q3 + 3.0 * self.iqr;
        value < lower || value > upper
    }
}

/// Feature extraction from plugin outputs.
pub struct FeatureExtractor;

impl FeatureExtractor {
    /// Build an activity timeline from all timestamped artifacts.
    pub fn extract_timeline(outputs: &[PluginOutput]) -> Vec<TimelineEntry> {
        let mut entries = Vec::new();
        for output in outputs {
            for record in &output.artifacts {
                let Some(ts) = record.timestamp else {
                    continue;
                };
                let Some(dt) = DateTime::from_timestamp(ts, 0) else {
                    continue;
                };
                entries.push(TimelineEntry {
                    timestamp: dt,
                    artifact_type: record.subcategory.clone(),
                    plugin: output.plugin_name.clone(),
                    title: record.title.clone(),
                    detail: record.detail.clone(),
                    source_path: record.source_path.clone(),
                    is_suspicious: record.is_suspicious,
                });
            }
        }
        entries.sort_by_key(|e| e.timestamp);
        entries
    }

    /// Compute hourly activity distribution (24 buckets).
    pub fn hourly_distribution(timeline: &[TimelineEntry]) -> [u32; 24] {
        let mut dist = [0u32; 24];
        for entry in timeline {
            let hour = entry.timestamp.hour() as usize;
            dist[hour] += 1;
        }
        dist
    }

    /// Compute the device's "normal" activity window.
    /// Returns (start_hour, end_hour) of typical activity
    /// (hours with >5% of total activity).
    pub fn normal_activity_window(dist: &[u32; 24]) -> (u8, u8) {
        let total: u32 = dist.iter().sum();
        if total == 0 {
            return (9, 17);
        }
        let threshold = (total as f64 * 0.05) as u32;
        let mut start = 0u8;
        let mut end = 23u8;
        for (h, &count) in dist.iter().enumerate() {
            if count >= threshold {
                start = h as u8;
                break;
            }
        }
        for (h, &count) in dist.iter().enumerate().rev() {
            if count >= threshold {
                end = h as u8;
                break;
            }
        }
        (start, end)
    }

    /// Extract execution events from Prefetch / AmCache / BAM / SRUM artifacts.
    pub fn extract_executions(outputs: &[PluginOutput]) -> Vec<ExecutionEvent> {
        let mut execs = Vec::new();
        let execution_types = [
            "Prefetch", "AmCache File", "BAM/DAM Entry", "SRUM Activity",
            "ShimCache", "AmCache Legacy File",
        ];

        let all_types: Vec<&str> = outputs
            .iter()
            .flat_map(|o| o.artifacts.iter())
            .map(|r| r.subcategory.as_str())
            .collect();
        let has_lnk = all_types.contains(&"LNK Shortcut");
        let has_jumplist = all_types.iter().any(|t| t.contains("Jump List"));
        let has_userassist = all_types.contains(&"UserAssist");

        for output in outputs {
            for record in &output.artifacts {
                if !execution_types.iter().any(|et| record.subcategory == *et) {
                    continue;
                }
                let ts = record
                    .timestamp
                    .and_then(|t| DateTime::from_timestamp(t, 0));
                let exe = extract_exe_name(&record.title);
                let is_system = is_system_path(&record.source_path)
                    || is_system_path(&record.detail);

                execs.push(ExecutionEvent {
                    timestamp: ts,
                    executable: exe,
                    source_path: record.source_path.clone(),
                    plugin: output.plugin_name.clone(),
                    run_count: extract_run_count(&record.detail),
                    focus_time_ms: extract_focus_time(&record.detail),
                    has_lnk,
                    has_jumplist,
                    has_userassist,
                    is_system_path: is_system,
                });
            }
        }
        execs
    }

    /// Extract network transfer events.
    pub fn extract_transfers(outputs: &[PluginOutput]) -> Vec<TransferEvent> {
        let mut transfers = Vec::new();
        for output in outputs {
            for record in &output.artifacts {
                if record.subcategory != "SRUM Activity"
                    && record.subcategory != "PCAP"
                    && !record.subcategory.contains("Network")
                {
                    continue;
                }
                let ts = record
                    .timestamp
                    .and_then(|t| DateTime::from_timestamp(t, 0));
                transfers.push(TransferEvent {
                    timestamp: ts,
                    bytes_sent: extract_bytes(&record.detail, "sent"),
                    bytes_received: extract_bytes(&record.detail, "recv"),
                    destination: String::new(),
                    source_path: record.source_path.clone(),
                });
            }
        }
        transfers
    }

    /// Extract file timestamp clusters — groups of files with timestamps
    /// within 2 seconds of each other.
    pub fn extract_timestamp_clusters(outputs: &[PluginOutput]) -> Vec<TimestampCluster> {
        let mut stamps: Vec<(DateTime<Utc>, String)> = Vec::new();
        for output in outputs {
            for record in &output.artifacts {
                let Some(ts) = record.timestamp else {
                    continue;
                };
                let Some(dt) = DateTime::from_timestamp(ts, 0) else {
                    continue;
                };
                stamps.push((dt, record.source_path.clone()));
            }
        }
        stamps.sort_by_key(|(dt, _)| *dt);

        let mut clusters = Vec::new();
        let mut i = 0;
        while i < stamps.len() {
            let mut j = i + 1;
            while j < stamps.len() {
                let span = (stamps[j].0 - stamps[i].0)
                    .num_milliseconds()
                    .unsigned_abs() as f64
                    / 1000.0;
                if span > 2.0 {
                    break;
                }
                j += 1;
            }
            let cluster_size = j - i;
            if cluster_size >= 10 {
                let paths: Vec<String> = stamps[i..j].iter().map(|(_, p)| p.clone()).collect();
                let span = (stamps[j - 1].0 - stamps[i].0)
                    .num_milliseconds()
                    .unsigned_abs() as f64
                    / 1000.0;
                clusters.push(TimestampCluster {
                    representative_time: stamps[i].0,
                    file_count: cluster_size,
                    span_seconds: span,
                    paths,
                });
            }
            i = j;
        }
        clusters
    }

    /// Compute baseline statistics for a numeric series.
    pub fn compute_baseline(values: &[f64]) -> BaselineStats {
        if values.is_empty() {
            return BaselineStats {
                mean: 0.0,
                std_dev: 0.0,
                median: 0.0,
                iqr: 0.0,
                q1: 0.0,
                q3: 0.0,
            };
        }
        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let n = sorted.len();
        let mean = sorted.iter().sum::<f64>() / n as f64;
        let variance = sorted.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n as f64;
        let std_dev = variance.sqrt();
        #[allow(clippy::manual_is_multiple_of)]
        let median = if n % 2 == 0 {
            (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
        } else {
            sorted[n / 2]
        };
        let q1 = sorted[n / 4];
        let q3 = sorted[3 * n / 4];
        let iqr = q3 - q1;

        BaselineStats {
            mean,
            std_dev,
            median,
            iqr,
            q1,
            q3,
        }
    }

    /// Build a BaselineSummary from the full set of plugin outputs.
    pub fn build_baseline_summary(
        timeline: &[TimelineEntry],
        executions: &[ExecutionEvent],
        transfers: &[TransferEvent],
    ) -> crate::types::BaselineSummary {
        let dist = Self::hourly_distribution(timeline);
        let total: u32 = dist.iter().sum();
        let threshold = (total as f64 * 0.05).max(1.0) as u32;
        let activity_hours: Vec<u8> = dist
            .iter()
            .enumerate()
            .filter(|(_, &c)| c >= threshold)
            .map(|(h, _)| h as u8)
            .collect();

        let mut day_counts = [0u32; 7];
        for e in timeline {
            day_counts[e.timestamp.weekday().num_days_from_monday() as usize] += 1;
        }
        let day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
        let day_threshold = (total as f64 * 0.05).max(1.0) as u32;
        let activity_days: Vec<String> = day_counts
            .iter()
            .enumerate()
            .filter(|(_, &c)| c >= day_threshold)
            .map(|(d, _)| day_names[d].to_string())
            .collect();

        let (earliest, latest) = if timeline.is_empty() {
            (String::new(), String::new())
        } else {
            (
                timeline.first().unwrap().timestamp.to_rfc3339(),
                timeline.last().unwrap().timestamp.to_rfc3339(),
            )
        };
        let total_days = if timeline.len() >= 2 {
            let span = timeline.last().unwrap().timestamp - timeline.first().unwrap().timestamp;
            span.num_days().max(1) as u32
        } else {
            1
        };

        let avg_daily_exec = if total_days > 0 {
            executions.len() as f32 / total_days as f32
        } else {
            0.0
        };
        let total_transfer: u64 = transfers
            .iter()
            .map(|t| t.bytes_sent + t.bytes_received)
            .sum();
        let avg_transfer = if total_days > 0 {
            total_transfer as f64 / total_days as f64
        } else {
            0.0
        };

        crate::types::BaselineSummary {
            activity_hours,
            activity_days,
            avg_daily_executions: avg_daily_exec,
            avg_network_transfer_bytes: avg_transfer,
            artifact_date_range: (earliest, latest),
            total_timeline_days: total_days,
        }
    }
}

fn extract_exe_name(title: &str) -> String {
    let cleaned = title
        .trim_start_matches("AmCache: ")
        .trim_start_matches("Prefetch: ")
        .trim_start_matches("ShimCache: ")
        .trim_start_matches("SRUM: ");
    if let Some(paren) = cleaned.find(" (") {
        cleaned[..paren].to_string()
    } else {
        cleaned.to_string()
    }
}

fn is_system_path(path: &str) -> bool {
    let l = path.to_lowercase();
    l.contains("\\windows\\system32\\")
        || l.contains("\\windows\\syswow64\\")
        || l.contains("\\program files\\")
        || l.contains("\\program files (x86)\\")
}

fn extract_run_count(detail: &str) -> Option<u32> {
    if let Some(pos) = detail.to_lowercase().find("run count:") {
        let after = &detail[pos + 10..];
        let num: String = after.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
        num.parse().ok()
    } else {
        None
    }
}

fn extract_focus_time(detail: &str) -> Option<u64> {
    if let Some(pos) = detail.to_lowercase().find("focus time:") {
        let after = &detail[pos + 11..];
        let num: String = after.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
        num.parse().ok()
    } else {
        None
    }
}

fn extract_bytes(detail: &str, direction: &str) -> u64 {
    let l = detail.to_lowercase();
    let needle = format!("{direction}:");
    if let Some(pos) = l.find(&needle) {
        let after = &detail[pos + needle.len()..];
        let num: String = after.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
        num.parse().unwrap_or(0)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDateTime;

    #[test]
    fn hourly_distribution_counts_correctly() {
        let entries = vec![
            make_entry(2024, 1, 15, 9, 0),
            make_entry(2024, 1, 15, 9, 30),
            make_entry(2024, 1, 15, 14, 0),
            make_entry(2024, 1, 15, 3, 0),
        ];
        let dist = FeatureExtractor::hourly_distribution(&entries);
        assert_eq!(dist[9], 2);
        assert_eq!(dist[14], 1);
        assert_eq!(dist[3], 1);
        assert_eq!(dist[0], 0);
    }

    #[test]
    fn normal_activity_window_identifies_9_to_5() {
        let mut dist = [0u32; 24];
        for h in 9..=17 {
            dist[h] = 50;
        }
        dist[3] = 1;
        let (start, end) = FeatureExtractor::normal_activity_window(&dist);
        assert_eq!(start, 9);
        assert_eq!(end, 17);
    }

    #[test]
    fn baseline_stats_z_score_correct() {
        let values = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let stats = FeatureExtractor::compute_baseline(&values);
        assert!((stats.mean - 30.0).abs() < 0.01);
        let z = stats.z_score(50.0);
        assert!(z > 1.0);
        let z_mean = stats.z_score(30.0);
        assert!(z_mean.abs() < 0.01);
    }

    #[test]
    fn baseline_stats_iqr_outlier_detection() {
        let values: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let stats = FeatureExtractor::compute_baseline(&values);
        assert!(stats.iqr > 0.0);
        assert!(!stats.is_outlier_iqr(50.0));
        assert!(stats.is_outlier_iqr(200.0));
        assert!(stats.is_outlier_iqr(-100.0));
    }

    #[test]
    fn extreme_outlier_threshold_correct() {
        let values: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let stats = FeatureExtractor::compute_baseline(&values);
        assert!(!stats.is_extreme_outlier_iqr(50.0));
        assert!(stats.is_extreme_outlier_iqr(500.0));
    }

    #[test]
    fn compute_baseline_handles_empty() {
        let stats = FeatureExtractor::compute_baseline(&[]);
        assert_eq!(stats.mean, 0.0);
        assert_eq!(stats.std_dev, 0.0);
        assert_eq!(stats.iqr, 0.0);
    }

    fn make_entry(year: i32, month: u32, day: u32, hour: u32, min: u32) -> TimelineEntry {
        let dt = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(year, month, day).unwrap(),
            chrono::NaiveTime::from_hms_opt(hour, min, 0).unwrap(),
        )
        .and_utc();
        TimelineEntry {
            timestamp: dt,
            artifact_type: "test".to_string(),
            plugin: "test".to_string(),
            title: "test".to_string(),
            detail: String::new(),
            source_path: String::new(),
            is_suspicious: false,
        }
    }
}

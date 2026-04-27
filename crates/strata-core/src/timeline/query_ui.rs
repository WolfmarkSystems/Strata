//! Timeline query + presentation layer (WF-6).
//!
//! Pure-Rust presentation built on top of the A-1 TimelineDatabase
//! storage engine. Emits tabular / bodyfile / HTML / density-chart
//! output.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::timeline::database::TimelineEntry;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimelineQuery {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub artifact_types: Option<Vec<String>>,
    pub mitre_technique: Option<String>,
    #[serde(default)]
    pub suspicious_only: bool,
    pub text_search: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl TimelineQuery {
    pub fn filter_in_memory<'a>(&self, entries: &'a [TimelineEntry]) -> Vec<&'a TimelineEntry> {
        let mut out: Vec<&TimelineEntry> = entries
            .iter()
            .filter(|e| {
                if let Some(s) = self.start {
                    if e.timestamp_us < s.timestamp_micros() {
                        return false;
                    }
                }
                if let Some(end) = self.end {
                    if e.timestamp_us > end.timestamp_micros() {
                        return false;
                    }
                }
                if let Some(types) = &self.artifact_types {
                    if !types.iter().any(|t| t == &e.artifact_type) {
                        return false;
                    }
                }
                if let Some(m) = &self.mitre_technique {
                    let hit = e.mitre_technique.as_deref().unwrap_or("");
                    if !(hit == m || hit.starts_with(&format!("{}.", m))) {
                        return false;
                    }
                }
                if self.suspicious_only && !e.suspicious {
                    return false;
                }
                if let Some(q) = &self.text_search {
                    let lower = q.to_ascii_lowercase();
                    let haystack =
                        format!("{} {}", e.description, e.raw_data.as_deref().unwrap_or(""))
                            .to_ascii_lowercase();
                    if !haystack.contains(&lower) {
                        return false;
                    }
                }
                true
            })
            .collect();
        if let Some(off) = self.offset {
            if off < out.len() {
                out = out.split_off(off);
            } else {
                out.clear();
            }
        }
        if let Some(limit) = self.limit {
            out.truncate(limit);
        }
        out
    }
}

pub fn render_table(entries: &[&TimelineEntry]) -> String {
    let mut out = String::new();
    out.push_str(
        "TIMESTAMP (UTC)          TYPE                    PLUGIN      MITRE    SUSPICIOUS\n",
    );
    for e in entries {
        let ts = DateTime::<Utc>::from_timestamp_micros(e.timestamp_us).unwrap_or_default();
        out.push_str(&format!(
            "{:24} {:24}{:12}{:9}{}\n",
            ts.format("%Y-%m-%d %H:%M:%S"),
            truncate(&e.artifact_type, 23),
            truncate(&e.plugin, 11),
            truncate(e.mitre_technique.as_deref().unwrap_or(""), 8),
            if e.suspicious { "YES \u{26A0}" } else { "No" },
        ));
    }
    out
}

/// Emit a mactime / log2timeline-compatible bodyfile.
pub fn render_bodyfile(entries: &[&TimelineEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        let secs = e.timestamp_us / 1_000_000;
        // bodyfile: 0|name|0|----------|0|0|size|atime|mtime|ctime|btime
        let escaped = e.description.replace('|', "_");
        out.push_str(&format!(
            "0|{} [{}]|0|----------|0|0|0|{ts}|{ts}|{ts}|{ts}\n",
            escaped,
            e.artifact_type,
            ts = secs
        ));
    }
    out
}

pub fn render_html(entries: &[&TimelineEntry]) -> String {
    let mut out = String::new();
    out.push_str(
        "<html><head><meta charset=\"utf-8\"><title>Strata Timeline</title>\n<style>\n\
         tr.suspicious{background:#ffd6d6;} tr.high{background:#ffe8cc;} tr.medium{background:#fff9cc;}\n\
         td{padding:2px 6px;font-family:monospace;}\n</style></head><body>\n<table>\n\
         <tr><th>Time (UTC)</th><th>Type</th><th>Plugin</th><th>MITRE</th><th>Description</th></tr>\n",
    );
    for e in entries {
        let ts = DateTime::<Utc>::from_timestamp_micros(e.timestamp_us).unwrap_or_default();
        let class = if e.suspicious {
            "suspicious"
        } else if e.confidence >= 0.9 {
            "high"
        } else {
            "medium"
        };
        out.push_str(&format!(
            "<tr class=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            class,
            ts.format("%Y-%m-%d %H:%M:%S"),
            escape(&e.artifact_type),
            escape(&e.plugin),
            escape(e.mitre_technique.as_deref().unwrap_or("")),
            escape(&e.description),
        ));
    }
    out.push_str("</table></body></html>\n");
    out
}

/// Per-hour ASCII density chart.
pub fn density_chart(entries: &[&TimelineEntry]) -> String {
    use std::collections::BTreeMap;
    let mut buckets: BTreeMap<i64, usize> = BTreeMap::new();
    for e in entries {
        let secs = e.timestamp_us / 1_000_000;
        let hour = secs - (secs.rem_euclid(3600));
        *buckets.entry(hour).or_insert(0) += 1;
    }
    let max = buckets.values().copied().max().unwrap_or(0);
    let mut out = String::new();
    for (hour, count) in &buckets {
        let ts = DateTime::<Utc>::from_timestamp(*hour, 0).unwrap_or_default();
        let bar_len = if max == 0 {
            0
        } else {
            (*count * 40 / max).max(1)
        };
        let bar: String = "\u{2588}".repeat(bar_len);
        out.push_str(&format!(
            "{}  {} {}\n",
            ts.format("%Y-%m-%d %H:%M"),
            bar,
            count
        ));
    }
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        format!("{:<width$}", s, width = n)
    } else {
        format!("{}\u{2026}", &s[..n - 1])
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts: i64, ty: &str, sus: bool, mitre: &str) -> TimelineEntry {
        TimelineEntry {
            id: 1,
            timestamp_us: ts * 1_000_000,
            artifact_type: ty.into(),
            plugin: "plugin".into(),
            description: format!("{} description", ty),
            raw_data: None,
            mitre_technique: Some(mitre.into()),
            confidence: 0.8,
            source_file: None,
            suspicious: sus,
        }
    }

    #[test]
    fn filter_respects_suspicious_and_date_range() {
        let entries = [
            entry(1_717_243_200, "A", false, "T1059"),
            entry(1_717_243_210, "B", true, "T1059.001"),
            entry(1_717_243_400, "C", false, "T1547"),
        ];
        let q = TimelineQuery {
            suspicious_only: true,
            start: Some(DateTime::<Utc>::from_timestamp(1_717_243_000, 0).expect("ts")),
            ..Default::default()
        };
        let hits = q.filter_in_memory(&entries);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].artifact_type, "B");
    }

    #[test]
    fn mitre_prefix_filter_matches_sub_techniques() {
        let entries = [
            entry(1, "A", false, "T1059"),
            entry(2, "B", false, "T1059.001"),
            entry(3, "C", false, "T1547"),
        ];
        let q = TimelineQuery {
            mitre_technique: Some("T1059".into()),
            ..Default::default()
        };
        let hits = q.filter_in_memory(&entries);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn render_table_produces_header_and_rows() {
        let entries = [entry(1_717_243_200, "Prefetch", false, "T1059")];
        let refs: Vec<&TimelineEntry> = entries.iter().collect();
        let out = render_table(&refs);
        assert!(out.contains("Prefetch"));
        assert!(out.contains("TIMESTAMP"));
    }

    #[test]
    fn render_bodyfile_is_pipe_delimited_with_times() {
        let entries = [entry(1_717_243_200, "Prefetch", false, "T1059")];
        let refs: Vec<&TimelineEntry> = entries.iter().collect();
        let body = render_bodyfile(&refs);
        assert!(body.starts_with("0|"));
        assert!(body.contains("|1717243200|"));
    }

    #[test]
    fn density_chart_buckets_by_hour() {
        let entries = [
            entry(1_717_243_200, "A", false, "T"),
            entry(1_717_243_260, "B", false, "T"),
            entry(1_717_250_000, "C", false, "T"),
        ];
        let refs: Vec<&TimelineEntry> = entries.iter().collect();
        let chart = density_chart(&refs);
        let line_count = chart.lines().count();
        assert!(line_count >= 2);
    }

    #[test]
    fn render_html_contains_suspicious_class() {
        let entries = [entry(1_717_243_200, "Vault", true, "T1027")];
        let refs: Vec<&TimelineEntry> = entries.iter().collect();
        let html = render_html(&refs);
        assert!(html.contains("class=\"suspicious\""));
    }
}

//! Communication timeline + contact frequency matrix (VIZ-2).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommRecord {
    pub platform: String,
    pub timestamp: DateTime<Utc>,
    pub sender: String,
    pub recipient: String,
    pub message_type: String,
    pub has_content: bool,
    pub call_duration: Option<u64>,
    pub artifact_id: String,
}

pub fn sort_by_timestamp(records: &mut [CommRecord]) {
    records.sort_by_key(|r| r.timestamp);
}

pub fn to_csv(records: &[CommRecord]) -> String {
    let mut out = String::new();
    out.push_str("timestamp,platform,sender,recipient,message_type,has_content,call_duration_secs,artifact_id\n");
    for r in records {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            r.timestamp.to_rfc3339(),
            csv_field(&r.platform),
            csv_field(&r.sender),
            csv_field(&r.recipient),
            csv_field(&r.message_type),
            r.has_content,
            r.call_duration.map(|n| n.to_string()).unwrap_or_default(),
            csv_field(&r.artifact_id),
        ));
    }
    out
}

fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[derive(Debug, Default)]
pub struct ContactSummary {
    pub first_contact: Option<DateTime<Utc>>,
    pub last_contact: Option<DateTime<Utc>>,
    pub message_count: usize,
    pub platforms: Vec<String>,
}

pub fn contact_pair_summary(records: &[CommRecord]) -> BTreeMap<(String, String), ContactSummary> {
    let mut out: BTreeMap<(String, String), ContactSummary> = BTreeMap::new();
    for r in records {
        let (a, b) = ordered_pair(&r.sender, &r.recipient);
        let key = (a, b);
        let entry = out.entry(key).or_default();
        entry.message_count += 1;
        entry.first_contact = Some(match entry.first_contact {
            Some(t) => t.min(r.timestamp),
            None => r.timestamp,
        });
        entry.last_contact = Some(match entry.last_contact {
            Some(t) => t.max(r.timestamp),
            None => r.timestamp,
        });
        if !entry.platforms.contains(&r.platform) {
            entry.platforms.push(r.platform.clone());
        }
    }
    out
}

pub fn frequency_matrix(records: &[CommRecord]) -> BTreeMap<(String, String), usize> {
    let mut out: BTreeMap<(String, String), usize> = BTreeMap::new();
    for r in records {
        let (a, b) = ordered_pair(&r.sender, &r.recipient);
        *out.entry((a, b)).or_insert(0) += 1;
    }
    out
}

fn ordered_pair(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

pub fn render_html_timeline(records: &[CommRecord]) -> String {
    let mut out = String::from(
        "<html><head><meta charset=\"utf-8\"><title>Communication Timeline</title>\n\
         <style>td{padding:2px 6px;font-family:monospace;}.slack{background:#eef;}.signal{background:#dfd;}.whatsapp{background:#cfc;}</style>\n</head><body>\n\
         <table><tr><th>Time (UTC)</th><th>Platform</th><th>Sender</th><th>Recipient</th><th>Type</th></tr>\n",
    );
    let mut sorted = records.to_vec();
    sort_by_timestamp(&mut sorted);
    for r in sorted {
        let class = r.platform.to_ascii_lowercase().replace(' ', "-");
        out.push_str(&format!(
            "<tr class=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            escape(&class),
            r.timestamp.format("%Y-%m-%d %H:%M:%S"),
            escape(&r.platform),
            escape(&r.sender),
            escape(&r.recipient),
            escape(&r.message_type),
        ));
    }
    out.push_str("</table></body></html>\n");
    out
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(platform: &str, ts: i64, from: &str, to: &str) -> CommRecord {
        CommRecord {
            platform: platform.into(),
            timestamp: DateTime::<Utc>::from_timestamp(ts, 0).expect("ts"),
            sender: from.into(),
            recipient: to.into(),
            message_type: "text".into(),
            has_content: true,
            call_duration: None,
            artifact_id: "x".into(),
        }
    }

    #[test]
    fn csv_produces_header_and_rows() {
        let recs = vec![rec("Slack", 1_717_243_200, "alice", "bob")];
        let csv = to_csv(&recs);
        assert!(csv.starts_with("timestamp,platform,"));
        assert!(csv.contains("Slack"));
    }

    #[test]
    fn pair_summary_aggregates_platforms_and_counts() {
        let recs = vec![
            rec("Slack", 1, "alice", "bob"),
            rec("WhatsApp", 10, "bob", "alice"),
            rec("Slack", 20, "alice", "bob"),
        ];
        let summary = contact_pair_summary(&recs);
        assert_eq!(summary.len(), 1);
        let (_, s) = summary.iter().next().expect("pair");
        assert_eq!(s.message_count, 3);
        assert_eq!(s.platforms.len(), 2);
        assert_eq!(s.first_contact.map(|t| t.timestamp()), Some(1));
        assert_eq!(s.last_contact.map(|t| t.timestamp()), Some(20));
    }

    #[test]
    fn frequency_matrix_is_undirected() {
        let recs = vec![
            rec("X", 1, "alice", "bob"),
            rec("X", 2, "bob", "alice"),
            rec("X", 3, "alice", "carol"),
        ];
        let m = frequency_matrix(&recs);
        assert_eq!(*m.get(&("alice".into(), "bob".into())).unwrap_or(&0), 2);
        assert_eq!(*m.get(&("alice".into(), "carol".into())).unwrap_or(&0), 1);
    }

    #[test]
    fn sort_by_timestamp_orders_chronologically() {
        let mut recs = vec![
            rec("X", 100, "a", "b"),
            rec("X", 10, "a", "b"),
            rec("X", 50, "a", "b"),
        ];
        sort_by_timestamp(&mut recs);
        assert_eq!(recs[0].timestamp.timestamp(), 10);
        assert_eq!(recs[2].timestamp.timestamp(), 100);
    }

    #[test]
    fn render_html_timeline_contains_rows() {
        let recs = vec![rec("Slack", 1_717_243_200, "alice", "bob")];
        let html = render_html_timeline(&recs);
        assert!(html.contains("alice"));
        assert!(html.contains("Slack"));
    }
}

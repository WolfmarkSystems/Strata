use super::entities::CanonicalRecord;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationInput {
    pub source_module: String,
    pub source_record_id: String,
    pub timestamp_utc: Option<String>,
    pub hints: Vec<String>,
    pub record: CanonicalRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub correlation_id: String,
    pub source_module: String,
    pub source_record_id: String,
    pub normalized_timestamp_utc: Option<String>,
    pub identity_keys: Vec<String>,
    pub confidence_score: f64,
    pub dedupe_key: String,
    pub record: CanonicalRecord,
}

pub fn correlate_records(inputs: &[CorrelationInput]) -> Vec<CorrelationResult> {
    let mut out = Vec::with_capacity(inputs.len());
    for input in inputs {
        let mut keys: BTreeSet<String> = BTreeSet::new();
        for hint in &input.hints {
            let h = hint.trim().to_ascii_lowercase();
            if !h.is_empty() {
                keys.insert(h);
            }
        }
        let normalized_timestamp_utc = input.timestamp_utc.as_ref().map(|v| v.trim().to_string());
        let dedupe_key = format!(
            "{}|{}|{}|{}",
            input.source_module,
            input.source_record_id,
            normalized_timestamp_utc.clone().unwrap_or_default(),
            serde_json::to_string(&input.record).unwrap_or_default()
        );
        let confidence_score = if keys.is_empty() { 0.5 } else { 0.85 };
        out.push(CorrelationResult {
            correlation_id: format!("corr-{}", out.len() + 1),
            source_module: input.source_module.clone(),
            source_record_id: input.source_record_id.clone(),
            normalized_timestamp_utc,
            identity_keys: keys.into_iter().collect(),
            confidence_score,
            dedupe_key,
            record: input.record.clone(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::entities::SystemEvent;

    #[test]
    fn correlation_is_deterministic_for_same_input() {
        let input = CorrelationInput {
            source_module: "test".to_string(),
            source_record_id: "1".to_string(),
            timestamp_utc: Some("2026-01-01T00:00:00Z".to_string()),
            hints: vec!["A@B.com".to_string()],
            record: CanonicalRecord::SystemEvent(SystemEvent {
                id: "evt".to_string(),
                event_type: "login".to_string(),
                summary: "ok".to_string(),
                timestamp_utc: Some("2026-01-01T00:00:00Z".to_string()),
            }),
        };
        let a = correlate_records(std::slice::from_ref(&input));
        let b = correlate_records(std::slice::from_ref(&input));
        assert_eq!(a[0].dedupe_key, b[0].dedupe_key);
        assert_eq!(a[0].identity_keys, b[0].identity_keys);
    }
}

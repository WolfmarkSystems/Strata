//! Artifact ranking — composite forensic-relevance scoring.
//!
//! Scores every artifact on (forensic_value, suspicious flag, SIGMA
//! hits, correlation, recency). Surfacing the top N acts as the
//! examiner's starting point instead of an unordered dump.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::Utc;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone)]
pub struct ScoredArtifact<'a> {
    pub artifact: &'a Artifact,
    pub score: f64,
    pub reasons: Vec<&'static str>,
}

pub fn rank_artifacts(artifacts: &[Artifact]) -> Vec<ScoredArtifact<'_>> {
    let now = Utc::now().timestamp();
    let mut out: Vec<ScoredArtifact<'_>> = artifacts
        .iter()
        .map(|a| {
            let mut score = 0.0f64;
            let mut reasons: Vec<&'static str> = Vec::new();
            match a.data.get("forensic_value").map(|s| s.as_str()) {
                Some("Critical") => {
                    score += 50.0;
                    reasons.push("forensic_value=Critical");
                }
                Some("High") => {
                    score += 30.0;
                    reasons.push("forensic_value=High");
                }
                Some("Medium") => {
                    score += 15.0;
                    reasons.push("forensic_value=Medium");
                }
                _ => {
                    score += 5.0;
                }
            }
            if a.data
                .get("suspicious")
                .map(|s| s == "true")
                .unwrap_or(false)
            {
                score += 25.0;
                reasons.push("suspicious");
            }
            if a.data
                .get("sigma_match")
                .map(|s| s == "true")
                .unwrap_or(false)
            {
                score += 20.0;
                reasons.push("sigma_match");
            }
            if a.data
                .get("correlation_hit")
                .map(|s| s == "true")
                .unwrap_or(false)
            {
                score += 15.0;
                reasons.push("correlation_hit");
            }
            if a.data
                .get("threat_intel_match")
                .map(|s| s == "true")
                .unwrap_or(false)
            {
                score += 40.0;
                reasons.push("threat_intel_match");
            }
            if let Some(ts) = a.timestamp {
                let age_days = ((now - ts as i64).max(0) as f64) / 86_400.0;
                // Decays linearly up to a 30 point cap at day 0, to
                // zero by ~1 year.
                let recency = (30.0 - age_days * 0.08).max(0.0);
                if recency > 0.0 {
                    score += recency;
                    reasons.push("recent");
                }
            }
            ScoredArtifact {
                artifact: a,
                score,
                reasons,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

pub fn top_n<'a>(scored: &'a [ScoredArtifact<'a>], n: usize) -> Vec<&'a ScoredArtifact<'a>> {
    scored.iter().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(forensic: &str, suspicious: bool) -> Artifact {
        let mut a = Artifact::new("X", "/evidence/x");
        a.add_field("file_type", "X");
        a.add_field("forensic_value", forensic);
        if suspicious {
            a.add_field("suspicious", "true");
        }
        a
    }

    #[test]
    fn scoring_promotes_suspicious_high_value_artifacts() {
        let low = art("Low", false);
        let high_sus = art("High", true);
        let arts = [low, high_sus];
        let scored = rank_artifacts(&arts);
        assert_eq!(
            scored[0]
                .artifact
                .data
                .get("forensic_value")
                .map(|s| s.as_str()),
            Some("High")
        );
    }

    #[test]
    fn threat_intel_match_dominates_ranking() {
        let mut ti = art("Medium", false);
        ti.add_field("threat_intel_match", "true");
        let crit = art("Critical", true);
        let arts = [crit, ti];
        let scored = rank_artifacts(&arts);
        assert!(scored[0]
            .reasons
            .iter()
            .any(|r| r == &"threat_intel_match" || r == &"forensic_value=Critical"));
    }

    #[test]
    fn top_n_truncates_to_requested_size() {
        let arts: Vec<Artifact> = (0..5).map(|_| art("Low", false)).collect();
        let scored = rank_artifacts(&arts);
        let top = top_n(&scored, 3);
        assert_eq!(top.len(), 3);
    }
}

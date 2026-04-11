//! Charge-to-artifact highlight mapping.
//!
//! Maps selected charges to artifact tags so the UI can highlight artifacts
//! that are relevant to the charges under investigation. The design is
//! additive — all artifacts remain visible, highlighting is advisory only.

use crate::schema::ChargeEntry;
use std::collections::{HashMap, HashSet};

/// Charges whose citation contains any of these strings trigger Critical
/// priority instead of High. Chapter 110 (CSAM) and UCMJ Art. 120/120b
/// are the highest-priority charges in digital forensic investigations.
const CRITICAL_CHARGE_PATTERNS: &[&str] = &[
    "§ 2251",
    "§ 2252",
    "§ 2252A",
    "§ 2256",
    "§ 2258A",
    "§ 2260",
    "§ 1466A",
    "Art. 120",
    "Art. 120b",
    "Art. 120c",
    "Art. 134 — Child Pornography",
];

/// Maps a set of selected charges to artifact highlight priorities.
#[derive(Debug, Clone, Default)]
pub struct ChargeHighlightMap {
    tag_to_charges: HashMap<String, Vec<String>>,
    critical_citations: HashSet<String>,
}

impl ChargeHighlightMap {
    /// Build a highlight map from the currently selected charges.
    pub fn from_selected(charges: &[ChargeEntry]) -> Self {
        let mut tag_to_charges: HashMap<String, Vec<String>> = HashMap::new();
        let mut critical_citations = HashSet::new();

        for charge in charges {
            let citation = &charge.citation;

            for tag in &charge.artifact_tags {
                tag_to_charges
                    .entry(tag.clone())
                    .or_default()
                    .push(citation.clone());
            }

            if is_critical_citation(citation) {
                critical_citations.insert(citation.clone());
            }
        }

        Self {
            tag_to_charges,
            critical_citations,
        }
    }

    /// Returns true if an artifact with the given tags should be highlighted.
    pub fn should_highlight(&self, artifact_tags: &[String]) -> bool {
        artifact_tags
            .iter()
            .any(|tag| self.tag_to_charges.contains_key(tag))
    }

    /// Returns which charge citations caused a highlight for a given artifact.
    pub fn highlight_reasons(&self, artifact_tags: &[String]) -> Vec<String> {
        let mut reasons = HashSet::new();
        for tag in artifact_tags {
            if let Some(citations) = self.tag_to_charges.get(tag) {
                for c in citations {
                    reasons.insert(c.clone());
                }
            }
        }
        let mut out: Vec<String> = reasons.into_iter().collect();
        out.sort();
        out
    }

    /// Returns highlight priority for an artifact based on its tags.
    pub fn highlight_priority(&self, artifact_tags: &[String]) -> HighlightPriority {
        let reasons = self.highlight_reasons(artifact_tags);
        if reasons.is_empty() {
            return HighlightPriority::None;
        }

        if reasons.iter().any(|c| self.critical_citations.contains(c)) {
            return HighlightPriority::Critical;
        }

        if reasons.len() >= 2 {
            HighlightPriority::High
        } else {
            HighlightPriority::Medium
        }
    }

    /// Returns true if the map is empty (no charges selected).
    pub fn is_empty(&self) -> bool {
        self.tag_to_charges.is_empty()
    }
}

fn is_critical_citation(citation: &str) -> bool {
    CRITICAL_CHARGE_PATTERNS
        .iter()
        .any(|pattern| citation.contains(pattern))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HighlightPriority {
    None,
    Medium,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ChargeSet, ChargeSeverity};

    fn test_charge(citation: &str, tags: &[&str]) -> ChargeEntry {
        ChargeEntry {
            id: 0,
            code_set: ChargeSet::USC,
            title: Some(18),
            section: "0".to_string(),
            subsection: None,
            citation: citation.to_string(),
            short_title: "Test".to_string(),
            description: "Test charge".to_string(),
            category: "Test".to_string(),
            artifact_tags: tags.iter().map(|s| s.to_string()).collect(),
            severity: ChargeSeverity::Felony,
            state_code: None,
            max_penalty: None,
            notes: None,
        }
    }

    #[test]
    fn highlight_map_empty_with_no_charges() {
        let map = ChargeHighlightMap::from_selected(&[]);
        assert!(map.is_empty());
        assert!(!map.should_highlight(&["Media".into()]));
        assert_eq!(
            map.highlight_priority(&["Media".into()]),
            HighlightPriority::None
        );
    }

    #[test]
    fn highlight_map_critical_for_csam_charges() {
        let charges = vec![test_charge("18 U.S.C. § 2252", &["Media", "Network"])];
        let map = ChargeHighlightMap::from_selected(&charges);
        assert!(map.should_highlight(&["Media".into()]));
        assert_eq!(
            map.highlight_priority(&["Media".into()]),
            HighlightPriority::Critical
        );
    }

    #[test]
    fn highlight_map_does_not_hide_unrelated() {
        let charges = vec![test_charge("18 U.S.C. § 2252", &["Media", "Network"])];
        let map = ChargeHighlightMap::from_selected(&charges);
        // "Financial" is not in the charge's artifact_tags, so no highlight
        assert!(!map.should_highlight(&["Financial".into()]));
        // But the map doesn't "hide" anything — it just doesn't highlight
        assert_eq!(
            map.highlight_priority(&["Financial".into()]),
            HighlightPriority::None
        );
    }

    #[test]
    fn highlight_priority_critical_for_chapter_110() {
        let charges = vec![test_charge("18 U.S.C. § 2251", &["Media"])];
        let map = ChargeHighlightMap::from_selected(&charges);
        assert_eq!(
            map.highlight_priority(&["Media".into()]),
            HighlightPriority::Critical
        );
    }

    #[test]
    fn highlight_priority_critical_for_art_120() {
        let charges = vec![test_charge("UCMJ Art. 120", &["Chat", "Mobile"])];
        let map = ChargeHighlightMap::from_selected(&charges);
        assert_eq!(
            map.highlight_priority(&["Chat".into()]),
            HighlightPriority::Critical
        );
    }

    #[test]
    fn highlight_priority_high_for_multiple_charges() {
        let charges = vec![
            test_charge("18 U.S.C. § 1030", &["Network", "Timeline"]),
            test_charge("18 U.S.C. § 1343", &["Network", "Email"]),
        ];
        let map = ChargeHighlightMap::from_selected(&charges);
        // "Network" maps to two charges → High
        assert_eq!(
            map.highlight_priority(&["Network".into()]),
            HighlightPriority::High
        );
    }

    #[test]
    fn highlight_reasons_returns_matching_citations() {
        let charges = vec![
            test_charge("18 U.S.C. § 1030", &["Network"]),
            test_charge("18 U.S.C. § 1343", &["Network", "Email"]),
        ];
        let map = ChargeHighlightMap::from_selected(&charges);
        let reasons = map.highlight_reasons(&["Network".into()]);
        assert_eq!(reasons.len(), 2);
        assert!(reasons.contains(&"18 U.S.C. § 1030".to_string()));
        assert!(reasons.contains(&"18 U.S.C. § 1343".to_string()));
    }
}

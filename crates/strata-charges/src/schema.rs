//! Core types for the charge database.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ChargeEntry {
    pub id: i64,
    /// USC, UCMJ, or State
    pub code_set: ChargeSet,
    /// USC title number (None for UCMJ)
    pub title: Option<u32>,
    /// USC section or UCMJ article number
    pub section: String,
    /// e.g. "(a)(1)"
    pub subsection: Option<String>,
    /// Full citation string for report, e.g. "18 U.S.C. § 2252(a)(1)"
    pub citation: String,
    /// Official short name
    pub short_title: String,
    /// Plain-English examiner description
    pub description: String,
    /// High-level grouping
    pub category: String,
    /// Strata artifact categories this charge maps to
    pub artifact_tags: Vec<String>,
    pub severity: ChargeSeverity,
    /// None for federal/UCMJ, "TX" etc. for state
    pub state_code: Option<String>,
    /// e.g. "Life imprisonment" or "20 years"
    pub max_penalty: Option<String>,
    /// Examiner notes field (user-editable)
    pub notes: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ChargeSet {
    USC,
    UCMJ,
    State,
}

impl ChargeSet {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChargeSet::USC => "USC",
            ChargeSet::UCMJ => "UCMJ",
            ChargeSet::State => "State",
        }
    }
}

impl std::fmt::Display for ChargeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ChargeSeverity {
    Felony,
    Misdemeanor,
    UCMJArticle,
    InfrastructureOffense,
}

impl ChargeSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChargeSeverity::Felony => "Felony",
            ChargeSeverity::Misdemeanor => "Misdemeanor",
            ChargeSeverity::UCMJArticle => "UCMJ Article",
            ChargeSeverity::InfrastructureOffense => "Infrastructure Offense",
        }
    }
}

/// A set of selected charges for a case.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct SelectedCharges {
    pub charges: Vec<ChargeEntry>,
    /// Free text notes about charge selection
    pub examiner_notes: String,
    /// ISO timestamp of last selection change
    pub selected_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_charges_serializes_cleanly() {
        let sc = SelectedCharges {
            charges: vec![ChargeEntry {
                id: 1,
                code_set: ChargeSet::USC,
                title: Some(18),
                section: "2252".to_string(),
                subsection: Some("(a)(1)".to_string()),
                citation: "18 U.S.C. § 2252(a)(1)".to_string(),
                short_title: "Sexual Exploitation of Minors".to_string(),
                description:
                    "Possession/distribution of material involving sexual exploitation of minors"
                        .to_string(),
                category: "Child Exploitation".to_string(),
                artifact_tags: vec!["Media".into(), "Network".into()],
                severity: ChargeSeverity::Felony,
                state_code: None,
                max_penalty: Some("20 years".to_string()),
                notes: None,
            }],
            examiner_notes: "Primary charge".to_string(),
            selected_at: "2026-04-11T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&sc).unwrap();
        let rt: SelectedCharges = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.charges.len(), 1);
        assert_eq!(rt.charges[0].citation, "18 U.S.C. § 2252(a)(1)");
        assert_eq!(rt.examiner_notes, "Primary charge");
    }

    #[test]
    fn charge_set_display() {
        assert_eq!(ChargeSet::USC.to_string(), "USC");
        assert_eq!(ChargeSet::UCMJ.to_string(), "UCMJ");
        assert_eq!(ChargeSet::State.to_string(), "State");
    }

    #[test]
    fn severity_as_str() {
        assert_eq!(ChargeSeverity::Felony.as_str(), "Felony");
        assert_eq!(ChargeSeverity::UCMJArticle.as_str(), "UCMJ Article");
    }
}

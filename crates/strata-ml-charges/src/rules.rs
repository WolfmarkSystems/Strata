use strata_charges::{ChargeSet, ChargeSeverity};
use strata_plugin_sdk::PluginOutput;

use crate::types::*;

/// A rule that maps artifact patterns to charge suggestions.
pub struct ChargeRule {
    pub rule_id: &'static str,
    pub suggested_charge_citation: &'static str,
    pub short_title: &'static str,
    pub description: &'static str,
    pub code_set: ChargeSet,
    pub title: Option<u32>,
    pub section: &'static str,
    pub category: &'static str,
    pub severity: ChargeSeverity,
    pub confidence: SuggestionConfidence,
    pub investigative_note: &'static str,
    pub check: fn(&[PluginOutput]) -> Vec<SupportingArtifact>,
}

impl ChargeRule {
    /// Evaluate this rule against the plugin outputs. Returns a
    /// `ChargeSuggestion` if the pattern matches.
    pub fn evaluate(&self, outputs: &[PluginOutput]) -> Option<ChargeSuggestion> {
        let artifacts = (self.check)(outputs);
        if artifacts.is_empty() {
            return None;
        }
        Some(ChargeSuggestion {
            charge: make_suggested_charge(
                self.suggested_charge_citation,
                self.short_title,
                self.description,
                self.code_set.clone(),
                self.title,
                self.section,
                self.category,
                self.severity.clone(),
            ),
            basis: self.description.to_string(),
            supporting_artifacts: artifacts,
            confidence: self.confidence.clone(),
            investigative_note: self.investigative_note.to_string(),
            is_advisory: true,
        })
    }
}

/// All charge suggestion rules.
pub fn all_rules() -> Vec<ChargeRule> {
    vec![
        // CS-001: VSS/log deletion → § 1519 (Destruction of Records)
        ChargeRule {
            rule_id: "CS-001",
            suggested_charge_citation: "18 U.S.C. \u{00a7} 1519",
            short_title: "Destruction of Records",
            description: "Destruction, alteration, or falsification of records in federal investigation",
            code_set: ChargeSet::USC,
            title: Some(18),
            section: "1519",
            category: "Obstruction",
            severity: ChargeSeverity::Felony,
            confidence: SuggestionConfidence::High,
            investigative_note: "VSS deletion and log clearing constitute destruction of potential evidence. Document the exact sequence and timestamps for \u{00a7} 1519 elements.",
            check: check_anti_forensic_chain,
        },
        // CS-002: Wire/email fraud artifacts → § 1343 (Wire Fraud)
        ChargeRule {
            rule_id: "CS-002",
            suggested_charge_citation: "18 U.S.C. \u{00a7} 1343",
            short_title: "Wire Fraud",
            description: "Fraud by wire, radio, or television",
            code_set: ChargeSet::USC,
            title: Some(18),
            section: "1343",
            category: "Fraud",
            severity: ChargeSeverity::Felony,
            confidence: SuggestionConfidence::Medium,
            investigative_note: "Email/wire communications containing fraudulent representations. Requires proof of scheme to defraud and use of interstate wire.",
            check: check_wire_fraud,
        },
        // CS-003: Large transfers + cloud + off-hours → § 1832 (Trade Secrets)
        ChargeRule {
            rule_id: "CS-003",
            suggested_charge_citation: "18 U.S.C. \u{00a7} 1832",
            short_title: "Theft of Trade Secrets",
            description: "Theft of trade secrets for economic benefit",
            code_set: ChargeSet::USC,
            title: Some(18),
            section: "1832",
            category: "Economic Espionage",
            severity: ChargeSeverity::Felony,
            confidence: SuggestionConfidence::Medium,
            investigative_note: "Large data transfer to personal cloud storage at unusual hours. Requires proof transferred data constitutes trade secrets.",
            check: check_trade_secret_exfil,
        },
        // CS-004: Unauthorized network access → § 1030 (CFAA)
        ChargeRule {
            rule_id: "CS-004",
            suggested_charge_citation: "18 U.S.C. \u{00a7} 1030(a)(2)",
            short_title: "Computer Fraud",
            description: "Unauthorized access to protected computer",
            code_set: ChargeSet::USC,
            title: Some(18),
            section: "1030",
            category: "Computer Crime",
            severity: ChargeSeverity::Felony,
            confidence: SuggestionConfidence::Medium,
            investigative_note: "VPN artifacts and off-hours access to network shares suggest unauthorized access. Requires proof access exceeded authorization.",
            check: check_unauthorized_access,
        },
        // CS-005: Dark web + narcotics → 21 U.S.C. § 841
        ChargeRule {
            rule_id: "CS-005",
            suggested_charge_citation: "21 U.S.C. \u{00a7} 841",
            short_title: "Drug Distribution",
            description: "Manufacture, distribution, or possession with intent to distribute controlled substances",
            code_set: ChargeSet::USC,
            title: Some(21),
            section: "841",
            category: "Narcotics",
            severity: ChargeSeverity::Felony,
            confidence: SuggestionConfidence::Low,
            investigative_note: "Tor browser usage combined with narcotics-related communications. Requires additional evidence of drug trafficking activity.",
            check: check_dark_web_narcotics,
        },
        // CS-006: Cryptocurrency wallet → § 1956 (Money Laundering)
        ChargeRule {
            rule_id: "CS-006",
            suggested_charge_citation: "18 U.S.C. \u{00a7} 1956",
            short_title: "Money Laundering",
            description: "Laundering of monetary instruments",
            code_set: ChargeSet::USC,
            title: Some(18),
            section: "1956",
            category: "Financial Crime",
            severity: ChargeSeverity::Felony,
            confidence: SuggestionConfidence::Low,
            investigative_note: "Cryptocurrency wallet artifacts detected. Requires proof funds are proceeds of specified unlawful activity.",
            check: check_cryptocurrency,
        },
        // CS-007: Stalking app artifacts → § 2261A
        ChargeRule {
            rule_id: "CS-007",
            suggested_charge_citation: "18 U.S.C. \u{00a7} 2261A",
            short_title: "Stalking",
            description: "Interstate stalking using electronic communications",
            code_set: ChargeSet::USC,
            title: Some(18),
            section: "2261A",
            category: "Violence",
            severity: ChargeSeverity::Felony,
            confidence: SuggestionConfidence::Medium,
            investigative_note: "Stalking/spyware application artifacts detected. Document installation date, target device, and communications intercept evidence.",
            check: check_stalking_apps,
        },
        // CS-008: Identity documents + access devices → § 1028A
        ChargeRule {
            rule_id: "CS-008",
            suggested_charge_citation: "18 U.S.C. \u{00a7} 1028A",
            short_title: "Aggravated Identity Theft",
            description: "Aggravated identity theft in connection with predicate offense",
            code_set: ChargeSet::USC,
            title: Some(18),
            section: "1028A",
            category: "Identity Theft",
            severity: ChargeSeverity::Felony,
            confidence: SuggestionConfidence::Medium,
            investigative_note: "Identity documents or access devices belonging to others found. Mandatory consecutive 2-year sentence if proven.",
            check: check_identity_theft,
        },
        // CS-009: Encrypted comms + terrorism keywords → § 2339A
        ChargeRule {
            rule_id: "CS-009",
            suggested_charge_citation: "18 U.S.C. \u{00a7} 2339A",
            short_title: "Material Support for Terrorism",
            description: "Providing material support for terrorism",
            code_set: ChargeSet::USC,
            title: Some(18),
            section: "2339A",
            category: "Terrorism",
            severity: ChargeSeverity::Felony,
            confidence: SuggestionConfidence::Low,
            investigative_note: "Encrypted communications with terrorism-related content. Extremely sensitive \u{2014} requires immediate coordination with JTTF.",
            check: check_terrorism_support,
        },
        // CS-010: On-post computer + unauthorized access → UCMJ Art. 123
        ChargeRule {
            rule_id: "CS-010",
            suggested_charge_citation: "UCMJ Art. 123",
            short_title: "Offenses Concerning Govt Computers",
            description: "Unauthorized access to government computer or network",
            code_set: ChargeSet::UCMJ,
            title: None,
            section: "123",
            category: "Military Computer Crime",
            severity: ChargeSeverity::UCMJArticle,
            confidence: SuggestionConfidence::Medium,
            investigative_note: "Unauthorized access on government computer. Document whether access was from .mil domain or on-post network.",
            check: check_mil_unauthorized_access,
        },
        // CS-M01: Encrypted comms on .mil + anomalous transfer → UCMJ Art. 106a (Espionage)
        ChargeRule {
            rule_id: "CS-M01",
            suggested_charge_citation: "UCMJ Art. 106a",
            short_title: "Espionage",
            description: "Espionage \u{2014} unauthorized transmission of national defense information",
            code_set: ChargeSet::UCMJ,
            title: None,
            section: "106a",
            category: "Espionage",
            severity: ChargeSeverity::UCMJArticle,
            confidence: SuggestionConfidence::Low,
            investigative_note: "Encrypted communications from .mil domain combined with anomalous data transfer. Immediately escalate to CI/counterintelligence.",
            check: check_espionage,
        },
        // CS-M02: Personal device on classified network → UCMJ Art. 92
        ChargeRule {
            rule_id: "CS-M02",
            suggested_charge_citation: "UCMJ Art. 92",
            short_title: "Failure to Obey Order",
            description: "Failure to obey lawful order or regulation",
            code_set: ChargeSet::UCMJ,
            title: None,
            section: "92",
            category: "Military Discipline",
            severity: ChargeSeverity::UCMJArticle,
            confidence: SuggestionConfidence::Medium,
            investigative_note: "Personal device artifacts detected on classified network. Document device identifiers and network access logs.",
            check: check_personal_device_classified,
        },
        // CS-M03: Dating app + subordinate contact → UCMJ Art. 93a
        ChargeRule {
            rule_id: "CS-M03",
            suggested_charge_citation: "UCMJ Art. 93a",
            short_title: "Prohibited Activities with Subordinate",
            description: "Prohibited activities with military member of lesser rank",
            code_set: ChargeSet::UCMJ,
            title: None,
            section: "93a",
            category: "Military Discipline",
            severity: ChargeSeverity::UCMJArticle,
            confidence: SuggestionConfidence::Low,
            investigative_note: "Dating/messaging app artifacts suggest contact with subordinate. Requires proof of rank relationship and prohibited nature.",
            check: check_subordinate_contact,
        },
        // CS-M04: Comms with foreign nationals + sensitive files → UCMJ Art. 104
        ChargeRule {
            rule_id: "CS-M04",
            suggested_charge_citation: "UCMJ Art. 104",
            short_title: "Aiding the Enemy",
            description: "Communication with or aiding the enemy",
            code_set: ChargeSet::UCMJ,
            title: None,
            section: "104",
            category: "Espionage",
            severity: ChargeSeverity::UCMJArticle,
            confidence: SuggestionConfidence::Low,
            investigative_note: "Communications with foreign nationals combined with access to sensitive files. Immediate CI escalation required.",
            check: check_foreign_comms,
        },
    ]
}

fn has_artifact_matching(outputs: &[PluginOutput], keywords: &[&str]) -> Vec<SupportingArtifact> {
    let mut found = Vec::new();
    for output in outputs {
        for record in &output.artifacts {
            let haystack = format!(
                "{} {} {} {}",
                record.title, record.detail, record.subcategory, record.source_path
            )
            .to_lowercase();
            for &kw in keywords {
                if haystack.contains(kw) {
                    found.push(SupportingArtifact {
                        plugin_name: output.plugin_name.clone(),
                        artifact_description: record.title.clone(),
                        artifact_id: record.subcategory.clone(),
                        timestamp: record.timestamp.and_then(|t| {
                            chrono::DateTime::from_timestamp(t, 0).map(|d| d.to_rfc3339())
                        }),
                        relevance_explanation: format!("Matched pattern: {}", kw),
                    });
                    break;
                }
            }
        }
    }
    found
}

fn check_anti_forensic_chain(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    has_artifact_matching(
        outputs,
        &[
            "vssadmin delete",
            "wevtutil cl",
            "shadow copy",
            "log clearing",
            "anti-forensic chain",
        ],
    )
}

fn check_wire_fraud(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    has_artifact_matching(
        outputs,
        &[
            "phishing",
            "fraudulent",
            "wire transfer",
            "invoice fraud",
            "business email compromise",
            "bec",
        ],
    )
}

fn check_trade_secret_exfil(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    has_artifact_matching(
        outputs,
        &[
            "exfiltration",
            "abnormal data transfer",
            "cloud upload",
            "usb mass storage",
            "large outbound",
        ],
    )
}

fn check_unauthorized_access(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    has_artifact_matching(
        outputs,
        &[
            "unauthorized",
            "vpn",
            "brute force",
            "failed logon",
            "credential stuffing",
            "network share",
        ],
    )
}

fn check_dark_web_narcotics(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    has_artifact_matching(
        outputs,
        &["tor browser", ".onion", "dark web", "narcotics", "drug"],
    )
}

fn check_cryptocurrency(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    has_artifact_matching(
        outputs,
        &[
            "bitcoin",
            "ethereum",
            "cryptocurrency",
            "wallet.dat",
            "crypto wallet",
            "blockchain",
        ],
    )
}

fn check_stalking_apps(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    has_artifact_matching(
        outputs,
        &[
            "spyware",
            "stalkerware",
            "mspy",
            "flexispy",
            "cocospy",
            "cerberus",
            "track",
            "spy",
        ],
    )
}

fn check_identity_theft(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    has_artifact_matching(
        outputs,
        &[
            "identity",
            "ssn",
            "social security",
            "credit card",
            "access device",
            "skimmer",
            "fullz",
        ],
    )
}

fn check_terrorism_support(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    has_artifact_matching(
        outputs,
        &[
            "terrorism",
            "jihad",
            "ied",
            "radicalization",
            "isis",
            "al-qaeda",
        ],
    )
}

fn check_mil_unauthorized_access(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    has_artifact_matching(
        outputs,
        &[
            ".mil",
            "government computer",
            "on-post",
            "unauthorized access",
            "cac",
            "sipr",
        ],
    )
}

fn check_espionage(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    let mil = has_artifact_matching(outputs, &[".mil", "sipr", "classified"]);
    let transfer = has_artifact_matching(
        outputs,
        &["encrypted", "anomalous transfer", "exfiltration"],
    );
    if !mil.is_empty() && !transfer.is_empty() {
        let mut combined = mil;
        combined.extend(transfer);
        combined
    } else {
        Vec::new()
    }
}

fn check_personal_device_classified(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    has_artifact_matching(
        outputs,
        &[
            "personal device",
            "unauthorized device",
            "byod",
            "classified network",
            "siprnet",
        ],
    )
}

fn check_subordinate_contact(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    has_artifact_matching(
        outputs,
        &[
            "dating app",
            "tinder",
            "bumble",
            "hinge",
            "subordinate",
            "fraternization",
        ],
    )
}

fn check_foreign_comms(outputs: &[PluginOutput]) -> Vec<SupportingArtifact> {
    let foreign = has_artifact_matching(
        outputs,
        &["foreign national", "foreign contact", "international"],
    );
    let sensitive = has_artifact_matching(
        outputs,
        &["classified", "sensitive", "secret", "top secret"],
    );
    if !foreign.is_empty() && !sensitive.is_empty() {
        let mut combined = foreign;
        combined.extend(sensitive);
        combined
    } else {
        Vec::new()
    }
}

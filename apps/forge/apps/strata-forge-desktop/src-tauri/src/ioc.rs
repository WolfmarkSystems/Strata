use serde::{Deserialize, Serialize};

/// Classification of an Indicator of Compromise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IocType {
    Sha256Hash,
    Md5Hash,
    Sha1Hash,
    Ipv4Address,
    Ipv6Address,
    Domain,
    Url,
    FilePath,
    RegistryKey,
    ProcessName,
    CommandLine,
    Unknown,
}

/// Verdict for an IOC after enrichment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IocVerdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown,
}

/// Result of enriching a single IOC against the local knowledge base.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEnrichment {
    pub ioc: String,
    pub ioc_type: IocType,
    pub verdict: IocVerdict,
    pub confidence: u8,
    pub description: String,
    pub mitre_techniques: Vec<String>,
    pub threat_actors: Vec<String>,
    pub related_iocs: Vec<String>,
    pub forensic_artifacts: Vec<String>,
    pub recommendation: String,
}

/// Classify an IOC string into its type.
pub fn classify_ioc(input: &str) -> IocType {
    let s = input.trim();
    if s.is_empty() {
        return IocType::Unknown;
    }

    // SHA-256: 64 hex chars
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return IocType::Sha256Hash;
    }

    // MD5: 32 hex chars
    if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return IocType::Md5Hash;
    }

    // SHA-1: 40 hex chars
    if s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return IocType::Sha1Hash;
    }

    // URL
    if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://") {
        return IocType::Url;
    }

    // IPv4
    if is_ipv4(s) {
        return IocType::Ipv4Address;
    }

    // IPv6
    if s.contains(':')
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
        && s.matches(':').count() >= 2
    {
        return IocType::Ipv6Address;
    }

    // Registry key
    let upper = s.to_uppercase();
    if upper.starts_with("HKLM\\")
        || upper.starts_with("HKCU\\")
        || upper.starts_with("HKU\\")
        || upper.starts_with("HKCR\\")
        || upper.starts_with("HKEY_")
    {
        return IocType::RegistryKey;
    }

    // File path (Windows or Unix)
    if (s.len() >= 3
        && s.as_bytes().get(1) == Some(&b':')
        && (s.as_bytes().get(2) == Some(&b'\\') || s.as_bytes().get(2) == Some(&b'/')))
        || s.starts_with("\\\\")
        || s.starts_with('/')
    {
        return IocType::FilePath;
    }

    // Command line (contains spaces + known shells/interpreters)
    let lower = s.to_lowercase();
    if s.contains(' ')
        && (lower.contains("cmd")
            || lower.contains("powershell")
            || lower.contains("wscript")
            || lower.contains("cscript")
            || lower.contains("mshta")
            || lower.contains("rundll32")
            || lower.contains("regsvr32")
            || lower.contains("-enc")
            || lower.contains("-executionpolicy"))
    {
        return IocType::CommandLine;
    }

    // Domain (has dots, no spaces, looks like a hostname)
    if s.contains('.')
        && !s.contains(' ')
        && !s.contains('\\')
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        return IocType::Domain;
    }

    // Process name (ends with .exe, .dll, .sys, etc.)
    if !s.contains(' ') && !s.contains('\\') && !s.contains('/') {
        let lower_ext = lower.as_str();
        if lower_ext.ends_with(".exe")
            || lower_ext.ends_with(".dll")
            || lower_ext.ends_with(".sys")
            || lower_ext.ends_with(".scr")
            || lower_ext.ends_with(".bat")
            || lower_ext.ends_with(".ps1")
            || lower_ext.ends_with(".vbs")
            || lower_ext.ends_with(".js")
        {
            return IocType::ProcessName;
        }
    }

    IocType::Unknown
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Enrich an IOC against the local knowledge base.
pub fn enrich_ioc(ioc: &str, kb: &crate::knowledge::KnowledgeBase) -> IocEnrichment {
    let ioc_type = classify_ioc(ioc);
    let trimmed = ioc.trim().to_lowercase();

    // Try to match against known tools
    if let Some(tool) = kb.match_tool(&trimmed) {
        return IocEnrichment {
            ioc: ioc.to_string(),
            ioc_type,
            verdict: IocVerdict::Malicious,
            confidence: tool.confidence,
            description: tool.description.clone(),
            mitre_techniques: tool.mitre_techniques.clone(),
            threat_actors: tool.threat_actors.clone(),
            related_iocs: tool.indicators.clone(),
            forensic_artifacts: tool.forensic_artifacts.clone(),
            recommendation: tool.recommendation.clone(),
        };
    }

    // Try suspicious path matching
    if matches!(ioc_type, IocType::FilePath) {
        if let Some(desc) = kb.match_suspicious_path(&trimmed) {
            return IocEnrichment {
                ioc: ioc.to_string(),
                ioc_type,
                verdict: IocVerdict::Suspicious,
                confidence: 60,
                description: desc,
                mitre_techniques: vec![],
                threat_actors: vec![],
                related_iocs: vec![],
                forensic_artifacts: vec![],
                recommendation:
                    "Investigate file origin, check prefetch and timeline for execution evidence."
                        .to_string(),
            };
        }
    }

    // Try MITRE technique lookup by ID
    if trimmed.starts_with('t') && trimmed.len() >= 5 {
        if let Some(tech) = kb.lookup_technique(&trimmed.to_uppercase()) {
            return IocEnrichment {
                ioc: ioc.to_string(),
                ioc_type: IocType::Unknown,
                verdict: IocVerdict::Unknown,
                confidence: 90,
                description: format!("{} — {}", tech.id, tech.name),
                mitre_techniques: vec![tech.id.clone()],
                threat_actors: vec![],
                related_iocs: vec![],
                forensic_artifacts: tech.artifacts.clone(),
                recommendation: tech.detection.clone(),
            };
        }
    }

    // No match — return unknown
    IocEnrichment {
        ioc: ioc.to_string(),
        ioc_type,
        verdict: IocVerdict::Unknown,
        confidence: 0,
        description: "No match in local knowledge base. Query the LLM for analysis.".to_string(),
        mitre_techniques: vec![],
        threat_actors: vec![],
        related_iocs: vec![],
        forensic_artifacts: vec![],
        recommendation: "Submit to LLM for deeper analysis or check external threat intel sources."
            .to_string(),
    }
}

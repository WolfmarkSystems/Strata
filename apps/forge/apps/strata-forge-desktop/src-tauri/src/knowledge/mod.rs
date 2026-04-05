pub mod actors;
pub mod artifacts;
pub mod paths;
pub mod techniques;
pub mod tools;

use serde::{Deserialize, Serialize};

/// A known attacker tool or LOLBin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownTool {
    pub names: Vec<String>,
    pub description: String,
    pub category: String,
    pub mitre_techniques: Vec<String>,
    pub threat_actors: Vec<String>,
    pub indicators: Vec<String>,
    pub forensic_artifacts: Vec<String>,
    pub recommendation: String,
    pub confidence: u8,
}

/// A MITRE ATT&CK technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub description: String,
    pub sub_techniques: Vec<String>,
    pub detection: String,
    pub artifacts: Vec<String>,
}

/// A Windows forensic artifact reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicArtifact {
    pub name: String,
    pub path: String,
    pub description: String,
    pub forensic_value: String,
    pub interpretation: String,
    pub tools: Vec<String>,
}

/// A threat actor profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub name: String,
    pub aliases: Vec<String>,
    pub origin: String,
    pub targets: Vec<String>,
    pub techniques: Vec<String>,
    pub tools: Vec<String>,
    pub description: String,
}

/// The complete local DFIR knowledge base — compiled into the binary.
pub struct KnowledgeBase {
    pub tools: Vec<KnownTool>,
    pub techniques: Vec<MitreTechnique>,
    pub artifacts: Vec<ForensicArtifact>,
    pub suspicious_paths: Vec<(String, String)>,
    pub actors: Vec<ThreatActor>,
}

impl KnowledgeBase {
    /// Load the full embedded knowledge base.
    pub fn load() -> Self {
        Self {
            tools: tools::all_tools(),
            techniques: techniques::all_techniques(),
            artifacts: artifacts::all_artifacts(),
            suspicious_paths: paths::all_suspicious_paths(),
            actors: actors::all_actors(),
        }
    }

    /// Match an IOC against known tools by name, indicator, or hash.
    pub fn match_tool(&self, input: &str) -> Option<&KnownTool> {
        let lower = input.to_lowercase();
        // Strip path to just filename
        let filename = lower.rsplit(['\\', '/']).next().unwrap_or(&lower);

        self.tools.iter().find(|t| {
            t.names.iter().any(|n| {
                let nl = n.to_lowercase();
                filename == nl || filename.starts_with(&format!("{}.", nl)) || lower.contains(&nl)
            }) || t
                .indicators
                .iter()
                .any(|ind| lower.contains(&ind.to_lowercase()))
        })
    }

    /// Match a file path against suspicious path patterns.
    pub fn match_suspicious_path(&self, path: &str) -> Option<String> {
        let lower = path.to_lowercase().replace('/', "\\");
        self.suspicious_paths
            .iter()
            .find(|(pattern, _)| lower.contains(&pattern.to_lowercase()))
            .map(|(_, desc)| desc.clone())
    }

    /// Look up a MITRE technique by ID (e.g. "T1003" or "T1003.001").
    pub fn lookup_technique(&self, id: &str) -> Option<&MitreTechnique> {
        let upper = id.to_uppercase();
        self.techniques.iter().find(|t| t.id == upper)
    }

    /// Look up a forensic artifact by name.
    pub fn lookup_artifact(&self, name: &str) -> Option<&ForensicArtifact> {
        let lower = name.to_lowercase();
        self.artifacts
            .iter()
            .find(|a| a.name.to_lowercase().contains(&lower))
    }

    /// Look up a threat actor by name or alias.
    pub fn lookup_actor(&self, name: &str) -> Option<&ThreatActor> {
        let lower = name.to_lowercase();
        self.actors.iter().find(|a| {
            a.name.to_lowercase().contains(&lower)
                || a.aliases
                    .iter()
                    .any(|al| al.to_lowercase().contains(&lower))
        })
    }

    /// Get summary stats.
    pub fn stats(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.tools.len(),
            self.techniques.len(),
            self.artifacts.len(),
            self.suspicious_paths.len(),
            self.actors.len(),
        )
    }
}

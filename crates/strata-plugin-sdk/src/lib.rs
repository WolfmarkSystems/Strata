use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Plugin API version
pub const PLUGIN_API_VERSION: &str = "0.3.0";

/// The standard structure for a forensic artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub category: String,
    pub timestamp: Option<u64>,
    pub source: String,
    pub data: HashMap<String, String>,
}

impl Artifact {
    pub fn new(category: &str, source: &str) -> Self {
        Self {
            category: category.to_string(),
            timestamp: None,
            source: source.to_string(),
            data: HashMap::new(),
        }
    }

    pub fn add_field(&mut self, key: &str, value: &str) {
        self.data.insert(key.to_string(), value.to_string());
    }
}

/// The context provided to each plugin during execution.
#[derive(Clone)]
pub struct PluginContext {
    pub root_path: String,
    pub config: HashMap<String, String>,
    /// Results from previously-run plugins (used by Sigma for correlation).
    pub prior_results: Vec<PluginOutput>,
}

/// The result returned by a plugin.
pub type PluginResult = Result<Vec<Artifact>, PluginError>;

/// Plugin type classification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PluginType {
    Carver,
    Analyzer,
    Cipher,
}

/// Minimum license tier required to run a plugin.
///
/// This is **independent** of `strata_license::LicenseTier` to keep
/// the plugin SDK from depending on the license crate (which would
/// pull license logic into every plugin). The strata-tree app maps
/// `LicenseTier` to `PluginTier` at the gating call site in
/// `AppState::run_plugin`.
///
/// `PartialOrd`/`Ord` ordering goes Free < Trial < Professional <
/// Enterprise, so a tier check is `user_tier >= plugin.required_tier()`.
///
/// **Free** is reserved for plugins that must always be available
/// regardless of license — currently only the CSAM Sentinel plugin.
/// Per the v1.4.0 spec: free on every license tier, no gating, ever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PluginTier {
    Free = 0,
    Trial = 1,
    Professional = 2,
    Enterprise = 3,
}

impl PluginTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            PluginTier::Free => "Free",
            PluginTier::Trial => "Trial",
            PluginTier::Professional => "Professional",
            PluginTier::Enterprise => "Enterprise",
        }
    }
}

/// What a plugin can do
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginCapability {
    FileCarving,
    TimelineEnrichment,
    ArtifactExtraction,
    EncryptionAnalysis,
    ExecutionTracking,
    CredentialExtraction,
    NetworkArtifacts,
    DeletedFileRecovery,
}

/// Forensic significance level
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ForensicValue {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// Artifact category for the Artifacts panel
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ArtifactCategory {
    Communications,
    SocialMedia,
    WebActivity,
    UserActivity,
    SystemActivity,
    CloudSync,
    AccountsCredentials,
    Media,
    DeletedRecovered,
    ExecutionHistory,
    NetworkArtifacts,
    EncryptionKeyMaterial,
}

impl ArtifactCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Communications => "Communications",
            Self::SocialMedia => "Social Media",
            Self::WebActivity => "Web Activity",
            Self::UserActivity => "User Activity",
            Self::SystemActivity => "System Activity",
            Self::CloudSync => "Cloud & Sync",
            Self::AccountsCredentials => "Accounts & Credentials",
            Self::Media => "Media",
            Self::DeletedRecovered => "Deleted & Recovered",
            Self::ExecutionHistory => "Execution History",
            Self::NetworkArtifacts => "Network Artifacts",
            Self::EncryptionKeyMaterial => "Encryption Key Material",
        }
    }
}

/// A single parsed artifact record for the Artifacts panel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub category: ArtifactCategory,
    pub subcategory: String,
    pub timestamp: Option<i64>,
    pub title: String,
    pub detail: String,
    pub source_path: String,
    pub forensic_value: ForensicValue,
    pub mitre_technique: Option<String>,
    pub is_suspicious: bool,
    pub raw_data: Option<serde_json::Value>,
}

/// Plugin execution summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSummary {
    pub total_artifacts: usize,
    pub suspicious_count: usize,
    pub categories_populated: Vec<String>,
    pub headline: String,
}

/// Rich plugin result with artifacts, timeline events, and summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginOutput {
    pub plugin_name: String,
    pub plugin_version: String,
    pub executed_at: String,
    pub duration_ms: u64,
    pub artifacts: Vec<ArtifactRecord>,
    pub summary: PluginSummary,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub enum PluginError {
    Internal(String),
    UnsupportedInput(String),
    ExecutionFailed(String),
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginError::Internal(e) => write!(f, "Internal Error: {}", e),
            PluginError::UnsupportedInput(e) => write!(f, "Unsupported Input: {}", e),
            PluginError::ExecutionFailed(e) => write!(f, "Execution Failed: {}", e),
        }
    }
}

impl std::error::Error for PluginError {}

/// The core trait that all Strata plugins must implement.
pub trait StrataPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn supported_inputs(&self) -> Vec<String>;
    fn plugin_type(&self) -> PluginType;
    fn capabilities(&self) -> Vec<PluginCapability>;
    fn description(&self) -> &str;

    /// Minimum license tier required to run this plugin. The default
    /// is `Professional` — most analyzer/carver plugins are gated.
    /// **Override to `PluginTier::Free`** for plugins that must
    /// always be available regardless of license (currently only the
    /// CSAM Sentinel plugin per the v1.4.0 spec).
    ///
    /// Backward-compatible: existing plugins that don't override
    /// inherit `Professional`, matching their current de facto status.
    fn required_tier(&self) -> PluginTier {
        PluginTier::Professional
    }

    /// Run the plugin with the given context.
    fn run(&self, context: PluginContext) -> PluginResult;

    /// Run the plugin and return rich output with artifact records.
    /// Default implementation wraps run() for backwards compatibility.
    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;

        let mut records = Vec::new();
        for artifact in &artifacts {
            records.push(ArtifactRecord {
                category: ArtifactCategory::UserActivity,
                subcategory: artifact.category.clone(),
                timestamp: artifact.timestamp.map(|t| t as i64),
                title: artifact
                    .data
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| artifact.source.clone()),
                detail: artifact
                    .data
                    .get("detail")
                    .cloned()
                    .unwrap_or_default(),
                source_path: artifact.source.clone(),
                forensic_value: ForensicValue::Medium,
                mitre_technique: artifact.data.get("mitre").cloned(),
                is_suspicious: artifact
                    .data
                    .get("suspicious")
                    .map(|v| v == "true")
                    .unwrap_or(false),
                raw_data: None,
            });
        }

        let suspicious_count = records.iter().filter(|r| r.is_suspicious).count();

        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: String::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: artifacts.len(),
                suspicious_count,
                categories_populated: vec![],
                headline: format!("{}: {} artifacts", self.name(), artifacts.len()),
            },
            warnings: vec![],
        })
    }
}

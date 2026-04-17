//! # Carbon — Google / Chromium browser artifacts.
//!
//! Owns Chromium-family browsers (Chrome, Edge, Brave, Opera, Vivaldi).
//! Research reference: chromium_ripper (MIT) — studied only;
//! implementation written independently.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub mod chromium;
pub mod factory_reset;

use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct CarbonPlugin {
    name: String,
    version: String,
}

impl Default for CarbonPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl CarbonPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Carbon".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

impl StrataPlugin for CarbonPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec![
            "History".to_string(),
            "Login Data".to_string(),
            "Web Data".to_string(),
            "Favicons".to_string(),
            "Network Action Predictor".to_string(),
        ]
    }
    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![PluginCapability::ArtifactExtraction]
    }
    fn description(&self) -> &str {
        "Chromium browser artifacts — history, downloads, logins, autofill, favicons, predictor"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut out = Vec::new();
        let files = match walk_dir(root) {
            Ok(f) => f,
            Err(_) => return Ok(out),
        };
        for path in files {
            if crate::chromium::ChromiumDb::from_path(&path).is_none() {
                continue;
            }
            let records = crate::chromium::parse(&path);
            let path_str = path.to_string_lossy().to_string();
            for r in &records {
                let kind = r.artifact_type();
                let mut a = Artifact::new("Chromium Artifact", &path_str);
                a.timestamp = r.primary_time().map(|d| d.timestamp() as u64);
                let (title, detail) = render(r);
                a.add_field("title", &title);
                a.add_field("detail", &detail);
                a.add_field("file_type", kind.as_str());
                a.add_field("artifact_type", kind.as_str());
                for (k, v) in render_fields(r) {
                    a.add_field(k, &v);
                }
                a.add_field("mitre", kind.mitre());
                let severity = kind.forensic_value();
                a.add_field("forensic_value", severity);
                if matches!(
                    r,
                    crate::chromium::ChromiumRecord::HistoryDownload(_)
                        | crate::chromium::ChromiumRecord::LoginData(_)
                ) {
                    a.add_field("suspicious", "true");
                }
                out.push(a);
            }
        }
        Ok(out)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;
        let mut records: Vec<ArtifactRecord> = Vec::new();
        let mut cats: HashSet<String> = HashSet::new();
        let mut suspicious = 0usize;
        for a in &artifacts {
            let file_type = a.data.get("file_type").cloned().unwrap_or_default();
            let is_sus = a.data.get("suspicious").map(|v| v == "true").unwrap_or(false);
            if is_sus {
                suspicious += 1;
            }
            let category = match file_type.as_str() {
                "Chromium/Login Data" | "Chromium/Autofill" => ArtifactCategory::AccountsCredentials,
                "Chromium/History Download" => ArtifactCategory::ExecutionHistory,
                _ => ArtifactCategory::WebActivity,
            };
            cats.insert(category.as_str().to_string());
            let fv = match a.data.get("forensic_value").map(|s| s.as_str()) {
                Some("High") => ForensicValue::High,
                Some("Critical") => ForensicValue::Critical,
                _ => ForensicValue::Medium,
            };
            records.push(ArtifactRecord {
                category,
                subcategory: file_type,
                timestamp: a.timestamp.map(|t| t as i64),
                title: a.data.get("title").cloned().unwrap_or_else(|| a.source.clone()),
                detail: a.data.get("detail").cloned().unwrap_or_default(),
                source_path: a.source.clone(),
                forensic_value: fv,
                mitre_technique: a.data.get("mitre").cloned(),
                is_suspicious: is_sus,
                raw_data: None,
                confidence: 0,
            });
        }
        let total = records.len();
        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count: suspicious,
                categories_populated: cats.into_iter().collect(),
                headline: format!(
                    "Carbon: {} Chromium artifacts ({} high-risk)",
                    total, suspicious
                ),
            },
            warnings: vec![],
        })
    }
}

fn render(r: &crate::chromium::ChromiumRecord) -> (String, String) {
    use crate::chromium::ChromiumRecord as R;
    match r {
        R::HistoryUrl(h) => (
            format!("Chromium visit: {}", h.url),
            format!(
                "URL: {} | title: {} | visits: {} | last_visit: {}",
                h.url,
                h.title,
                h.visit_count,
                h.last_visit_time
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "-".to_string())
            ),
        ),
        R::HistoryDownload(d) => (
            format!("Chromium download: {}", d.target_path),
            format!(
                "Path: {} | bytes: {} | danger: {} | tab: {} | referrer: {}",
                d.target_path,
                d.total_bytes,
                d.danger_type,
                d.tab_url.as_deref().unwrap_or("-"),
                d.tab_referrer_url.as_deref().unwrap_or("-"),
            ),
        ),
        R::HistorySearchTerm(t) => (
            format!("Chromium search: {}", t.term),
            format!("Search term: {} | url_id: {}", t.term, t.url_id),
        ),
        R::LoginData(l) => (
            format!("Chromium login: {} @ {}", l.username_value, l.origin_url),
            format!(
                "Origin: {} | username: {} | times_used: {} | created: {} | last_used: {}",
                l.origin_url,
                l.username_value,
                l.times_used,
                l.date_created
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "-".to_string()),
                l.date_last_used
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ),
        R::Autofill(a) => (
            format!("Chromium autofill: {}={}", a.name, a.value),
            format!("Name: {} | Value: {} | Count: {}", a.name, a.value, a.count),
        ),
        R::Favicon(f) => (
            format!("Chromium favicon page: {}", f.page_url),
            format!("page_url: {}", f.page_url),
        ),
        R::NetworkActionPredictor(n) => (
            format!("Chromium typed URL: {} → {}", n.user_text, n.url),
            format!("user_text: {} | url: {}", n.user_text, n.url),
        ),
    }
}

fn render_fields(r: &crate::chromium::ChromiumRecord) -> Vec<(&'static str, String)> {
    use crate::chromium::ChromiumRecord as R;
    match r {
        R::HistoryUrl(h) => vec![
            ("url", h.url.clone()),
            ("page_title", h.title.clone()),
            ("visit_count", h.visit_count.to_string()),
        ],
        R::HistoryDownload(d) => vec![
            ("target_path", d.target_path.clone()),
            ("total_bytes", d.total_bytes.to_string()),
            ("danger_type", d.danger_type.to_string()),
        ],
        R::HistorySearchTerm(t) => vec![("search_term", t.term.clone())],
        R::LoginData(l) => vec![
            ("origin_url", l.origin_url.clone()),
            ("username_value", l.username_value.clone()),
            ("times_used", l.times_used.to_string()),
        ],
        R::Autofill(a) => vec![
            ("autofill_name", a.name.clone()),
            ("autofill_value", a.value.clone()),
            ("autofill_count", a.count.to_string()),
        ],
        R::Favicon(f) => vec![("page_url", f.page_url.clone())],
        R::NetworkActionPredictor(n) => vec![
            ("user_text", n.user_text.clone()),
            ("predicted_url", n.url.clone()),
        ],
    }
}

fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut paths = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                if let Ok(sub) = walk_dir(&p) {
                    paths.extend(sub);
                }
            } else {
                paths.push(p);
            }
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_metadata_shape() {
        let p = CarbonPlugin::new();
        assert_eq!(p.name(), "Strata Carbon");
        assert_eq!(p.version(), "1.0.0");
        assert!(!p.supported_inputs().is_empty());
    }

    #[test]
    fn run_on_empty_root_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ctx = PluginContext {
            root_path: dir.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
            prior_results: Vec::new(),
        };
        let recs = CarbonPlugin::new().run(ctx).expect("run");
        assert!(recs.is_empty());
    }
}

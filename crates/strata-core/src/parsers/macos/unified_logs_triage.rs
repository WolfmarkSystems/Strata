use crate::parser::ParsedArtifact;

pub struct UnifiedLogTriage {
    pub watch_keywords: Vec<String>,
}

impl Default for UnifiedLogTriage {
    fn default() -> Self {
        Self::new()
    }
}

impl UnifiedLogTriage {
    pub fn new() -> Self {
        Self {
            watch_keywords: vec![
                "failed".to_string(),
                "denied".to_string(),
                "error".to_string(),
                "unauthorized".to_string(),
                "root".to_string(),
                "sudo".to_string(),
            ],
        }
    }

    pub fn triage(&self, artifact: &ParsedArtifact) -> Option<ParsedArtifact> {
        let desc_lower = artifact.description.to_lowercase();
        for kw in &self.watch_keywords {
            if desc_lower.contains(kw) {
                let mut alert = artifact.clone();
                alert.artifact_type = "log_alert".to_string();
                alert.description = format!("[ALERT] {}", alert.description);
                return Some(alert);
            }
        }
        None
    }
}

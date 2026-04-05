use crate::parser::ParsedArtifact;

pub struct UnifiedLogLiveAnalyzer;

impl Default for UnifiedLogLiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl UnifiedLogLiveAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_stream(&self, artifact: &ParsedArtifact) -> Option<ParsedArtifact> {
        let desc_lower = artifact.description.to_lowercase();
        // Look for immediate security-relevant events in the tracev3 stream
        if (desc_lower.contains("login")
            || desc_lower.contains("authentication")
            || desc_lower.contains("root"))
            && (desc_lower.contains("fail")
                || desc_lower.contains("deny")
                || desc_lower.contains("error"))
        {
            let mut alert = artifact.clone();
            alert.artifact_type = "live_alert".to_string();
            alert.description = format!("[LIVE] Critical Security Event: {}", alert.description);
            return Some(alert);
        }
        None
    }
}

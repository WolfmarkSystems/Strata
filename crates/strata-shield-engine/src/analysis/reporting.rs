use crate::analysis::correlation::CorrelatedEvent;
use crate::parser::ParsedArtifact;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub struct CaseReportGenerator {
    pub case_name: String,
    pub investigator: String,
}

impl CaseReportGenerator {
    pub fn new(case_name: &str, investigator: &str) -> Self {
        Self {
            case_name: case_name.to_string(),
            investigator: investigator.to_string(),
        }
    }

    pub fn generate_markdown(&self, correlations: &[CorrelatedEvent], artifacts: &[ParsedArtifact]) -> String {
        let mut report = String::new();
        report.push_str(&format!("# Case Report: {}\n\n", self.case_name));
        report.push_str(&format!("- Investigator: {}\n", self.investigator));
        report.push_str(&format!("- Total Artifacts Found: {}\n", artifacts.len()));
        report.push_str(&format!("- Related Event Groups: {}\n\n", correlations.len()));

        report.push_str("## Timeline Narrative (Correlated Events)\n\n");
        for (i, group) in correlations.iter().enumerate() {
            let ts = group.primary_event.timestamp.unwrap_or(0);
            report.push_str(&format!("### Event Group {}: {}\n", i + 1, group.primary_event.description));
            report.push_str(&format!("- **Primary Event**: {} at {}\n", group.primary_event.description, ts));
            report.push_str("- **Related Activities**:\n");
            for related in &group.related_events {
                 report.push_str(&format!("  - {} (Type: {})\n", related.description, related.artifact_type));
            }
            report.push_str("\n");
        }

        report
    }

    pub fn save_to_file(&self, content: &str, output_path: &Path) -> std::io::Result<()> {
        let mut file = File::create(output_path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}

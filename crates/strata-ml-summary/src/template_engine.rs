//! Handlebars template engine for narrative section rendering.

use crate::extractor::{DestructionEvent, ExtractedFinding, FocusRecommendation};
use handlebars::Handlebars;
use serde_json::json;

const OVERVIEW_TPL: &str = include_str!("templates/overview.hbs");
const CHARGED_CONDUCT_TPL: &str = include_str!("templates/charged_conduct.hbs");
const DESTRUCTION_TPL: &str = include_str!("templates/destruction_event.hbs");
const FOCUS_TPL: &str = include_str!("templates/focus_recommendation.hbs");
const ADVISORY_TPL: &str = include_str!("templates/advisory.hbs");

pub struct OverviewData {
    pub device_identifier: String,
    pub significance_statement: String,
    pub charge_summary: String,
    pub artifact_count: usize,
    pub plugin_count: usize,
    pub primary_finding: String,
}

pub struct TemplateEngine {
    hbs: Handlebars<'static>,
}

impl TemplateEngine {
    pub fn new() -> Result<Self, anyhow::Error> {
        let mut hbs = Handlebars::new();
        hbs.set_strict_mode(false);
        hbs.register_template_string("overview", OVERVIEW_TPL)?;
        hbs.register_template_string("charged_conduct", CHARGED_CONDUCT_TPL)?;
        hbs.register_template_string("destruction_event", DESTRUCTION_TPL)?;
        hbs.register_template_string("focus_recommendation", FOCUS_TPL)?;
        hbs.register_template_string("advisory", ADVISORY_TPL)?;
        Ok(Self { hbs })
    }

    pub fn render_overview(&self, data: &OverviewData) -> Result<String, anyhow::Error> {
        let rendered = self.hbs.render(
            "overview",
            &json!({
                "device_identifier": data.device_identifier,
                "significance_statement": data.significance_statement,
                "charge_summary": data.charge_summary,
                "artifact_count": data.artifact_count,
                "plugin_count": data.plugin_count,
                "primary_finding": data.primary_finding,
            }),
        )?;
        Ok(rendered)
    }

    pub fn render_charged_conduct(
        &self,
        findings: &[ExtractedFinding],
    ) -> Result<String, anyhow::Error> {
        let data: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                json!({
                    "description": f.description,
                    "timestamp": f.timestamp,
                    "source_plugin": f.source_plugin,
                })
            })
            .collect();
        let rendered = self.hbs.render("charged_conduct", &json!({ "findings": data }))?;
        Ok(rendered)
    }

    pub fn render_destruction_events(
        &self,
        events: &[DestructionEvent],
    ) -> Result<String, anyhow::Error> {
        if events.is_empty() {
            return Ok(String::new());
        }

        let mut sections = Vec::new();
        for event in events {
            let steps = vec![format!(
                "{} ({})",
                event.scope,
                event.tool_used.as_deref().unwrap_or("unknown tool")
            )];
            let context = if event.confidence > 0.8 {
                "This action is consistent with deliberate evidence destruction."
            } else {
                "This action may indicate evidence destruction — manual verification recommended."
            };

            let rendered = self.hbs.render(
                "destruction_event",
                &json!({
                    "timestamp": event.timestamp,
                    "destruction_type": event.event_type,
                    "steps": steps,
                    "context_note": context,
                }),
            )?;
            sections.push(rendered);
        }
        Ok(sections.join("\n"))
    }

    pub fn render_focus_recommendations(
        &self,
        recs: &[FocusRecommendation],
    ) -> Result<String, anyhow::Error> {
        let data: Vec<serde_json::Value> = recs
            .iter()
            .map(|r| {
                json!({
                    "area": r.area,
                    "reason": r.reason,
                    "specific_path": r.specific_path,
                })
            })
            .collect();
        let rendered = self
            .hbs
            .render("focus_recommendation", &json!({ "recommendations": data }))?;
        Ok(rendered)
    }

    pub fn render_advisory_notice(&self, artifact_count: usize) -> Result<String, anyhow::Error> {
        let rendered = self
            .hbs
            .render("advisory", &json!({ "artifact_count": artifact_count }))?;
        Ok(rendered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_renders_overview_correctly() {
        let engine = TemplateEngine::new().unwrap();
        let data = OverviewData {
            device_identifier: "DELL-WS-4821".into(),
            significance_statement: "significant digital evidence".into(),
            charge_summary: "18 U.S.C. § 2252".into(),
            artifact_count: 847,
            plugin_count: 12,
            primary_finding: "evidence of charged conduct".into(),
        };
        let result = engine.render_overview(&data).unwrap();
        assert!(result.contains("DELL-WS-4821"));
        assert!(result.contains("847"));
        assert!(result.contains("18 U.S.C. § 2252"));
    }

    #[test]
    fn template_renders_destruction_event() {
        let engine = TemplateEngine::new().unwrap();
        let events = vec![DestructionEvent {
            event_type: "VSS Deletion".into(),
            timestamp: "2025-12-04 23:41:00 UTC".into(),
            tool_used: Some("vssadmin".into()),
            scope: "All shadow copies deleted".into(),
            confidence: 0.95,
            source_plugin: "Trace".into(),
            artifact_id: "trace:prefetch".into(),
        }];
        let result = engine.render_destruction_events(&events).unwrap();
        assert!(result.contains("2025-12-04"));
        assert!(result.contains("VSS Deletion"));
        assert!(result.contains("deliberate evidence destruction"));
    }

    #[test]
    fn template_renders_focus_recommendations() {
        let engine = TemplateEngine::new().unwrap();
        let recs = vec![FocusRecommendation {
            priority: 1,
            area: "Media file hash analysis".into(),
            reason: "CSAM charges selected".into(),
            specific_path: Some("/evidence/media/".into()),
        }];
        let result = engine.render_focus_recommendations(&recs).unwrap();
        assert!(result.contains("Media file hash analysis"));
        assert!(result.contains("CSAM charges"));
        assert!(result.contains("Path: /evidence/media/"));
    }

    #[test]
    fn template_renders_advisory_notice() {
        let engine = TemplateEngine::new().unwrap();
        let result = engine.render_advisory_notice(847).unwrap();
        assert!(result.contains("EXAMINER MUST REVIEW AND APPROVE"));
        assert!(result.contains("847 artifacts"));
        assert!(result.contains("court documents"));
    }
}

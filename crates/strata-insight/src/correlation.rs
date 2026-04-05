use serde::{Deserialize, Serialize};
use strata_core::errors::ForensicError;
use strata_core::parser::ParsedArtifact;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    pub primary_event: ParsedArtifact,
    pub related_events: Vec<ParsedArtifact>,
    pub correlation_score: f32,
    pub link_type: LinkType,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum LinkType {
    #[default]
    Timeline,
    FilePath,
    Process,
    Network,
    Registry,
    Chat,
    Web,
}

pub struct CorrelationEngine {
    pub time_threshold_secs: i64,
}

impl CorrelationEngine {
    pub fn new(threshold: i64) -> Self {
        Self {
            time_threshold_secs: threshold,
        }
    }

    pub fn correlate(&self, artifacts: &[ParsedArtifact]) -> Vec<CorrelatedEvent> {
        let mut correlated = Vec::new();
        let mut artifacts_with_time: Vec<&ParsedArtifact> =
            artifacts.iter().filter(|a| a.timestamp.is_some()).collect();

        // Sort by timestamp
        artifacts_with_time.sort_by_key(|a| a.timestamp.unwrap());

        for (i, art) in artifacts_with_time.iter().enumerate() {
            let ts = art.timestamp.unwrap();
            let mut related = Vec::new();

            // Look forward for related events within threshold
            for next_art in artifacts_with_time.iter().skip(i + 1) {
                let next_ts = next_art.timestamp.unwrap();

                if next_ts - ts > self.time_threshold_secs {
                    break;
                }

                let (score, _link) = self.calculate_score(art, next_art);
                if score > 0.4 {
                    related.push((*next_art).clone());
                }
            }

            if !related.is_empty() {
                let (top_score, top_link) = self.calculate_score(art, &related[0]);
                correlated.push(CorrelatedEvent {
                    primary_event: (*art).clone(),
                    related_events: related,
                    correlation_score: top_score,
                    link_type: top_link,
                });
            }
        }

        correlated
    }

    pub fn calculate_score(&self, a: &ParsedArtifact, b: &ParsedArtifact) -> (f32, LinkType) {
        let mut score = 0.0;
        let mut link_type = LinkType::Timeline;

        // Path link is very strong
        if !a.source_path.is_empty() && a.source_path == b.source_path {
            score += 1.0;
            link_type = LinkType::FilePath;
        }

        // Shared type
        if a.artifact_type == b.artifact_type {
            score += 0.3;
        }

        // Shared keywords in description
        let a_desc = a.description.to_lowercase();
        let b_desc = b.description.to_lowercase();
        if a_desc.contains(&b_desc[..5.min(b_desc.len())]) {
            score += 0.2;
        }

        (score, link_type)
    }

    #[allow(dead_code)]
    fn is_related(&self, a: &ParsedArtifact, b: &ParsedArtifact) -> bool {
        let (score, _) = self.calculate_score(a, b);
        score > 0.4
    }
}

pub fn build_link_graph(
    _artifacts: &[ParsedArtifact],
) -> Result<Vec<CorrelatedEvent>, ForensicError> {
    let engine = CorrelationEngine::new(60); // 1 minute threshold
    Ok(engine.correlate(_artifacts))
}

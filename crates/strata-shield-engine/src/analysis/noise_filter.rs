use crate::parser::ParsedArtifact;
use std::collections::HashSet;

pub struct ArtifactNoiseFilter {
    pub known_hashes: HashSet<String>,
}

impl ArtifactNoiseFilter {
    pub fn new() -> Self {
        Self {
            known_hashes: HashSet::new(),
        }
    }

    pub fn compute_artifact_key(art: &ParsedArtifact) -> String {
        format!("{}:{}:{}", art.artifact_type, art.description, art.source_path)
    }

    pub fn filter(&self, artifacts: Vec<ParsedArtifact>) -> Vec<ParsedArtifact> {
        artifacts.into_iter().filter(|a| {
            !self.known_hashes.contains(&Self::compute_artifact_key(a))
        }).collect()
    }
}

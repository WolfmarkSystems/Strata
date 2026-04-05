use crate::parser::ParsedArtifact;

pub struct GlobalSearchEngine {
    pub artifacts: Vec<ParsedArtifact>,
}

impl GlobalSearchEngine {
    pub fn new(artifacts: Vec<ParsedArtifact>) -> Self {
        Self { artifacts }
    }

    pub fn search(&self, query: &str) -> Vec<&ParsedArtifact> {
        let query_lower = query.to_lowercase();
        self.artifacts.iter().filter(|a| {
            a.description.to_lowercase().contains(&query_lower) ||
            a.artifact_type.to_lowercase().contains(&query_lower) ||
            a.source_path.to_lowercase().contains(&query_lower) ||
            a.json_data.to_string().to_lowercase().contains(&query_lower)
        }).collect()
    }
}

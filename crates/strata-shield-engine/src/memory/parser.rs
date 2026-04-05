use crate::parser::ParsedArtifact;
use std::path::Path;

pub struct MemoryParser;

impl MemoryParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_memory_dump(&self, _root: &Path) -> Result<MemoryDumpSummary, String> {
        Ok(MemoryDumpSummary { size: 0 })
    }

    pub fn extract_strings(&self, _root: &Path) -> Result<Vec<String>, String> {
        Ok(vec![])
    }

    pub fn to_artifacts(
        &self,
        _mem: &MemoryDumpSummary,
        _strings: &[String],
    ) -> Vec<ParsedArtifact> {
        vec![]
    }
}

pub struct MemoryDumpSummary {
    pub size: u64,
}

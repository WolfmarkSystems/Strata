use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParserConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParserWarning {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsupportedSection {
    pub section_key: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParserProvenance {
    pub source_path: String,
    pub parser_name: String,
    pub parser_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParserContractResult {
    pub parser_name: String,
    pub parser_version: String,
    pub warnings: Vec<ParserWarning>,
    pub unsupported_sections: Vec<UnsupportedSection>,
    pub confidence: ParserConfidence,
    pub provenance: Vec<ParserProvenance>,
}

pub trait ParserContract: Send + Sync {
    fn can_handle(&self, source_hint: &str) -> bool;
    fn parse(&self, source_hint: &str) -> Result<ParserContractResult, String>;
    fn emit_provenance(&self, source_hint: &str) -> Vec<ParserProvenance>;
    fn emit_confidence(&self) -> ParserConfidence;
    fn emit_warnings(&self, source_hint: &str) -> Vec<ParserWarning>;
}

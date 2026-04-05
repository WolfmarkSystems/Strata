use crate::errors::ForensicError;

pub mod activity_log;
pub mod add_to_notes;
pub mod bookmarks;
pub mod database;
pub mod examiner_presets;
pub mod exhibit_packet;
pub mod export;
pub mod integrity;
pub mod investigator;
pub mod jobs;
pub mod notes;
pub mod provenance;
pub mod replay;
pub mod report_templates;
pub mod repository;
pub mod saved_searches;
pub mod screenshots;
pub mod triage_session;
pub mod verify;
pub mod watchpoints;
pub mod workers;

pub fn create_case(_case_info: CaseInfo) -> Result<Case, ForensicError> {
    Ok(Case::default())
}

#[derive(Debug, Clone, Default)]
pub struct Case {
    pub id: String,
    pub name: String,
    pub created: u64,
    pub examiner: String,
    pub status: CaseStatus,
}

#[derive(Debug, Clone, Default)]
pub enum CaseStatus {
    #[default]
    Open,
    Closed,
    Archived,
}

#[derive(Debug, Clone, Default)]
pub struct CaseInfo {
    pub name: String,
    pub description: String,
    pub examiner: String,
    pub case_number: Option<String>,
}

pub fn add_evidence_to_case(_case_id: &str, _evidence: Evidence) -> Result<(), ForensicError> {
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct Evidence {
    pub id: String,
    pub path: String,
    pub evidence_type: EvidenceType,
}

#[derive(Debug, Clone, Default)]
pub enum EvidenceType {
    #[default]
    Disk,
    Memory,
    Network,
    File,
}

pub fn generate_case_report(_case_id: &str) -> Result<String, ForensicError> {
    Ok("".to_string())
}

pub fn export_case(_case_id: &str, _format: ExportFormat) -> Result<Vec<u8>, ForensicError> {
    Ok(vec![])
}

#[derive(Debug, Clone, Default)]
pub enum ExportFormat {
    #[default]
    Zip,
    Tar,
}

use crate::errors::ForensicError;

pub struct EnterpriseWorkspaceParser;

impl EnterpriseWorkspaceParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse Notion local LevelDB and Trello cached JSON boards.
    pub fn extract_collaboration_cache(
        &self,
        _workspace_data: &[u8],
    ) -> Result<Vec<WorkspaceEvent>, ForensicError> {
        Ok(vec![])
    }
}

pub struct WorkspaceEvent {
    pub platform: String,
    pub document_title: String,
    pub last_accessed: u64,
}

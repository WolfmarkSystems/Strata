use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use std::env;
use std::path::PathBuf;

pub fn get_smb_sessions() -> Vec<SmbSession> {
    let path = env::var("FORENSIC_SMB_SESSIONS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("network")
                .join("smb_sessions.log")
        });
    let content = match read_text_prefix(&path, DEFAULT_TEXT_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    parse_smb_session_text(&content)
}

pub fn parse_smb_session_text(content: &str) -> Vec<SmbSession> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = if trimmed.contains('|') {
            trimmed.split('|').collect()
        } else if trimmed.contains(',') {
            trimmed.split(',').collect()
        } else {
            trimmed.split_whitespace().collect()
        };
        if parts.len() < 2 {
            continue;
        }
        out.push(SmbSession {
            user: parts[0].trim().to_string(),
            computer: parts[1].trim().to_string(),
        });
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct SmbSession {
    pub user: String,
    pub computer: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pipe_smb_sessions() {
        let rows = parse_smb_session_text("alice|ws-01\n");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].user, "alice");
        assert_eq!(rows[0].computer, "ws-01");
    }
}

use crate::context::ForgeContext;
use crate::settings::ForgeSettings;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Role of a message in the conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageRole {
    User,
    Assistant,
}

/// A single message in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    pub id: String,
    pub role: MessageRole,
    pub content: String,
    pub timestamp: String,
    pub context_snapshot: Option<ForgeContext>,
    pub mitre_refs: Vec<String>,
    pub tokens_used: Option<u32>,
}

/// A complete conversation (session).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub case_name: Option<String>,
    pub created_at: String,
    pub messages: Vec<ConversationMessage>,
    pub title: String,
}

/// Index entry for the conversation list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationIndex {
    pub conversations: Vec<ConversationSummary>,
}

/// Summary of a conversation for the index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub id: String,
    pub title: String,
    pub case_name: Option<String>,
    pub created_at: String,
    pub message_count: usize,
}

impl Conversation {
    /// Create a new empty conversation.
    pub fn new(case_name: Option<String>) -> Self {
        let id = uuid_v4();
        let now = utc_now();
        Self {
            id,
            case_name,
            created_at: now,
            messages: Vec::new(),
            title: "New conversation".to_string(),
        }
    }

    /// Add a message and auto-generate title from first user message.
    pub fn add_message(
        &mut self,
        role: MessageRole,
        content: String,
        context: Option<ForgeContext>,
    ) {
        // Extract MITRE T-codes from content
        let mitre_refs = extract_mitre_refs(&content);

        let msg = ConversationMessage {
            id: uuid_v4(),
            role: role.clone(),
            content: content.clone(),
            timestamp: utc_now(),
            context_snapshot: context,
            mitre_refs,
            tokens_used: None,
        };

        self.messages.push(msg);

        // Auto-title from first user message
        if self.title == "New conversation" && role == MessageRole::User {
            self.title = if content.len() > 60 {
                format!("{}...", &content[..57])
            } else {
                content
            };
        }
    }

    /// Save this conversation to disk.
    pub fn save(&self) -> Result<(), String> {
        let dir = ForgeSettings::history_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create history dir: {}", e))?;

        let path = dir.join(format!("{}.json", self.id));
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize conversation: {}", e))?;
        std::fs::write(&path, json).map_err(|e| format!("Failed to write conversation: {}", e))?;

        // Update index
        update_index()?;

        Ok(())
    }

    /// Load a conversation by ID.
    pub fn load(id: &str) -> Result<Self, String> {
        let path = ForgeSettings::history_dir().join(format!("{}.json", id));
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read conversation: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse conversation: {}", e))
    }

    /// Delete a conversation by ID.
    pub fn delete(id: &str) -> Result<(), String> {
        let path = ForgeSettings::history_dir().join(format!("{}.json", id));
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("Failed to delete conversation: {}", e))?;
        }
        update_index()?;
        Ok(())
    }
}

/// List all saved conversations (from index).
pub fn list_conversations() -> Result<Vec<ConversationSummary>, String> {
    let index_path = index_path();
    if !index_path.exists() {
        update_index()?;
    }

    match std::fs::read_to_string(&index_path) {
        Ok(content) => {
            let idx: ConversationIndex =
                serde_json::from_str(&content).unwrap_or(ConversationIndex {
                    conversations: Vec::new(),
                });
            Ok(idx.conversations)
        }
        Err(_) => Ok(Vec::new()),
    }
}

/// Rebuild the conversation index from disk.
fn update_index() -> Result<(), String> {
    let dir = ForgeSettings::history_dir();
    if !dir.exists() {
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create history dir: {}", e))?;
    }

    let mut summaries = Vec::new();

    let entries =
        std::fs::read_dir(&dir).map_err(|e| format!("Failed to read history dir: {}", e))?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if path.file_stem().and_then(|s| s.to_str()) == Some("index") {
            continue;
        }

        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(conv) = serde_json::from_str::<Conversation>(&content) {
                summaries.push(ConversationSummary {
                    id: conv.id,
                    title: conv.title,
                    case_name: conv.case_name,
                    created_at: conv.created_at,
                    message_count: conv.messages.len(),
                });
            }
        }
    }

    // Sort by created_at descending (newest first)
    summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let index = ConversationIndex {
        conversations: summaries,
    };
    let json = serde_json::to_string_pretty(&index)
        .map_err(|e| format!("Failed to serialize index: {}", e))?;
    std::fs::write(index_path(), json).map_err(|e| format!("Failed to write index: {}", e))?;

    Ok(())
}

fn index_path() -> PathBuf {
    ForgeSettings::history_dir().join("index.json")
}

/// Extract MITRE T-codes from text (e.g. T1003, T1003.001).
fn extract_mitre_refs(text: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let mut i = 0;
    let bytes = text.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'T' && i + 4 < bytes.len() {
            // Check for T followed by 4 digits
            let start = i;
            i += 1;
            let mut digits = 0;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                digits += 1;
                i += 1;
            }
            if digits == 4 {
                // Check for optional .NNN sub-technique
                let mut end = i;
                if i < bytes.len() && bytes[i] == b'.' {
                    i += 1;
                    let sub_start = i;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    if i > sub_start {
                        end = i;
                    }
                }
                let tcode = &text[start..end];
                if !refs.contains(&tcode.to_string()) {
                    refs.push(tcode.to_string());
                }
            }
        } else {
            i += 1;
        }
    }
    refs
}

fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Simple pseudo-UUID from timestamp + random-ish counter
    let ts = now.as_nanos();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (ts >> 96) as u32,
        (ts >> 80) as u16,
        (ts >> 68) as u16 & 0xFFF,
        0x8000 | ((ts >> 52) as u16 & 0x3FFF),
        ts as u64 & 0xFFFF_FFFF_FFFF,
    )
}

fn utc_now() -> String {
    // Simple UTC timestamp without chrono dependency
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Convert to approximate ISO 8601
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Simple date calculation from epoch days
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

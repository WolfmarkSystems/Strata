use crate::errors::ForensicError;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct UnifiedTimelineEvent {
    pub timestamp: i64,
    pub source: TimelineSource,
    pub event_type: TimelineEventType,
    pub description: String,
    pub file_path: Option<String>,
    pub user: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TimelineSource {
    MFT,
    Registry,
    Prefetch,
    Browser,
    EventLog,
    FileSystem,
    USB,
    Network,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TimelineEventType {
    FileCreated,
    FileModified,
    FileAccessed,
    FileDeleted,
    FileRenamed,
    UserLogon,
    UserLogoff,
    ProgramExecuted,
    ProgramInstalled,
    ProgramUninstalled,
    DeviceConnected,
    DeviceDisconnected,
    NetworkConnect,
    NetworkDisconnect,
    Other(String),
}

pub struct UnifiedTimeline {
    pub events: Vec<UnifiedTimelineEvent>,
}

impl UnifiedTimeline {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn add_event(&mut self, event: UnifiedTimelineEvent) {
        self.events.push(event);
    }

    pub fn sort(&mut self) {
        self.events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    }

    pub fn filter_by_timerange(&self, start: i64, end: i64) -> Vec<&UnifiedTimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }
}

impl Default for UnifiedTimeline {
    fn default() -> Self {
        Self::new()
    }
}

pub fn export_timeline_csv(
    timeline: &UnifiedTimeline,
    output_path: &Path,
) -> Result<(), ForensicError> {
    let mut csv_content = String::from("Timestamp,Source,EventType,Description,FilePath\n");

    for event in &timeline.events {
        csv_content.push_str(&format!(
            "{},{:?},{:?},{},{}\n",
            event.timestamp,
            event.source,
            event.event_type,
            event.description.replace(',', ";"),
            event.file_path.as_deref().unwrap_or("")
        ));
    }

    std::fs::write(output_path, csv_content)?;

    Ok(())
}

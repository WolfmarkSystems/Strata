use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSeverity {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EngineEventKind {
    ActivityAppended {
        event_id: String,
        event_type: String,
    },
    JobProgress {
        job_id: String,
        job_type: String,
        progress: f32,
        message: String,
    },
    JobStatus {
        job_id: String,
        job_type: String,
        status: String,
    },
    VerifyProgress {
        check_name: String,
        status: String,
        message: String,
    },
    ReplayProgress {
        step_name: String,
        status: String,
        message: String,
    },
    ExportProgress {
        phase: String,
        progress: f32,
        message: String,
    },
    NotesCreated {
        note_id: String,
        exhibit_count: usize,
        packet_id: Option<String>,
    },
    IntegrityViolation {
        violation_id: i64,
        table_name: String,
        operation: String,
    },
    ParserProgress {
        parser_name: String,
        progress: f32,
        message: String,
    },
    ParserComplete {
        parser_name: String,
        artifacts_found: usize,
    },
    TimelineEntryAdded {
        entry_id: String,
        artifact_type: String,
    },
    PluginLoaded {
        name: String,
        version: String,
    },
    PluginExecuted {
        name: String,
        artifacts_added: usize,
    },
    PluginError {
        name: String,
        error: String,
    },
    System {
        subsystem: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineEvent {
    pub id: String,
    pub case_id: Option<String>,
    pub kind: EngineEventKind,
    pub severity: EventSeverity,
    pub occurred_utc: String,
    pub message: String,
    pub data_json: serde_json::Value,
}

impl EngineEvent {
    pub fn new(
        case_id: Option<String>,
        kind: EngineEventKind,
        severity: EventSeverity,
        message: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            case_id,
            kind,
            severity,
            occurred_utc: chrono::Utc::now().to_rfc3339(),
            message,
            data_json: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data_json = data;
        self
    }
}

pub struct EventBus {
    sender: broadcast::Sender<EngineEvent>,
    _receiver: broadcast::Receiver<EngineEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = broadcast::channel(capacity);
        Self {
            sender,
            _receiver: receiver,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.sender.subscribe()
    }

    pub fn emit(&self, event: EngineEvent) {
        if let Err(e) = self.sender.send(event) {
            eprintln!("EventBus warning: no receivers for event: {}", e);
        }
    }

    pub fn emit_simple(
        &self,
        case_id: Option<String>,
        kind: EngineEventKind,
        severity: EventSeverity,
        message: &str,
    ) {
        let event = EngineEvent::new(case_id, kind, severity, message.to_string());
        self.emit(event);
    }

    pub fn is_closed(&self) -> bool {
        self.sender.receiver_count() == 0
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eventbus_emit_and_receive() {
        let bus = EventBus::new(100);
        let mut rx = bus.subscribe();

        let event = EngineEvent::new(
            Some("case1".to_string()),
            EngineEventKind::System {
                subsystem: "test".to_string(),
            },
            EventSeverity::Info,
            "Test message".to_string(),
        );

        bus.emit(event.clone());

        let received = rx.blocking_recv().unwrap();
        assert_eq!(received.id, event.id);
        assert_eq!(received.case_id, Some("case1".to_string()));
    }

    #[test]
    fn test_multiple_subscribers() {
        let bus = EventBus::new(100);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.emit(EngineEvent::new(
            None,
            EngineEventKind::System {
                subsystem: "test".to_string(),
            },
            EventSeverity::Info,
            "test".to_string(),
        ));

        let _ = rx1.blocking_recv().unwrap();
        let _ = rx2.blocking_recv().unwrap();
    }

    #[test]
    fn test_event_serialization() {
        let event = EngineEvent::new(
            Some("case1".to_string()),
            EngineEventKind::VerifyProgress {
                check_name: "hash_chain".to_string(),
                status: "pass".to_string(),
                message: "Check passed".to_string(),
            },
            EventSeverity::Info,
            "Verify check completed".to_string(),
        );

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: EngineEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, event.id);
        assert_eq!(deserialized.case_id, event.case_id);
    }
}

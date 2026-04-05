use crate::events::{EngineEvent, EngineEventKind, EventBus, EventSeverity};
use crate::evidence::EvidenceAnalyzer;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub struct EngineContext {
    pub event_bus: Arc<EventBus>,
    pub case_id: Option<String>,
    pub analyzer: std::sync::Mutex<Option<EvidenceAnalyzer>>,
    pub active_evidence_path: std::sync::Mutex<Option<PathBuf>>,
}

impl EngineContext {
    pub fn new() -> Self {
        let db_path =
            std::env::temp_dir().join(format!("forensic_suite_{}.db", uuid::Uuid::new_v4()));

        let analyzer = EvidenceAnalyzer::new(&db_path).ok();

        Self {
            event_bus: Arc::new(EventBus::new(1000)),
            case_id: None,
            analyzer: std::sync::Mutex::new(analyzer),
            active_evidence_path: std::sync::Mutex::new(None),
        }
    }

    pub fn with_case(case_id: &str) -> Self {
        let db_path = std::env::temp_dir().join(format!("forensic_suite_{}.db", case_id));

        let analyzer = EvidenceAnalyzer::new(&db_path).ok();

        Self {
            event_bus: Arc::new(EventBus::new(1000)),
            case_id: Some(case_id.to_string()),
            analyzer: std::sync::Mutex::new(analyzer),
            active_evidence_path: std::sync::Mutex::new(None),
        }
    }

    pub fn watch_events(&self, running: Arc<AtomicBool>) {
        let mut rx = self.event_bus.subscribe();
        let _case_id = self.case_id.clone();

        while running.load(Ordering::SeqCst) {
            match rx.try_recv() {
                Ok(event) => {
                    let timestamp = &event.occurred_utc[..19];
                    let kind_str = match &event.kind {
                        EngineEventKind::ActivityAppended { .. } => "Activity",
                        EngineEventKind::JobProgress { .. } => "JobProgress",
                        EngineEventKind::JobStatus { .. } => "JobStatus",
                        EngineEventKind::VerifyProgress { .. } => "Verify",
                        EngineEventKind::ReplayProgress { .. } => "Replay",
                        EngineEventKind::ExportProgress { .. } => "Export",
                        EngineEventKind::NotesCreated { .. } => "Notes",
                        EngineEventKind::IntegrityViolation { .. } => "Violation",
                        EngineEventKind::ParserProgress { .. } => "ParserProgress",
                        EngineEventKind::ParserComplete { .. } => "ParserComplete",
                        EngineEventKind::TimelineEntryAdded { .. } => "Timeline",
                        EngineEventKind::PluginLoaded { .. } => "PluginLoaded",
                        EngineEventKind::PluginExecuted { .. } => "PluginExecuted",
                        EngineEventKind::PluginError { .. } => "PluginError",
                        EngineEventKind::System { .. } => "System",
                    };

                    let severity_str = match event.severity {
                        EventSeverity::Info => "INFO",
                        EventSeverity::Warn => "WARN",
                        EventSeverity::Error => "ERROR",
                    };

                    let case_str = event.case_id.as_deref().unwrap_or("-");

                    let data_str = if let Some(obj) = event.data_json.as_object() {
                        let keys: Vec<_> = obj.keys().take(3).collect();
                        if keys.is_empty() {
                            "{}".to_string()
                        } else {
                            format!(
                                "{{{}}}",
                                keys.iter()
                                    .map(|k| k.as_str())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            )
                        }
                    } else {
                        "{}".to_string()
                    };

                    println!(
                        "[{}] [{}] [{}] case={} msg=\"{}\" data={}",
                        timestamp,
                        kind_str,
                        severity_str,
                        case_str,
                        event.message.replace('\"', "'"),
                        data_str
                    );
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                    eprintln!("Warning: Dropped {} events", n);
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                    break;
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    pub fn watch_events_blocking(&self) {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        let _watcher = thread::spawn(move || {
            while r.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(50));
            }
        });

        self.watch_events(running);
    }
}

impl Default for EngineContext {
    fn default() -> Self {
        Self::new()
    }
}

pub fn format_event_line(event: &EngineEvent) -> String {
    let timestamp = &event.occurred_utc[..19];
    let kind_str = match &event.kind {
        EngineEventKind::ActivityAppended { .. } => "Activity",
        EngineEventKind::JobProgress { .. } => "JobProgress",
        EngineEventKind::JobStatus { .. } => "JobStatus",
        EngineEventKind::VerifyProgress { .. } => "Verify",
        EngineEventKind::ReplayProgress { .. } => "Replay",
        EngineEventKind::ExportProgress { .. } => "Export",
        EngineEventKind::NotesCreated { .. } => "Notes",
        EngineEventKind::IntegrityViolation { .. } => "Violation",
        EngineEventKind::ParserProgress { .. } => "ParserProgress",
        EngineEventKind::ParserComplete { .. } => "ParserComplete",
        EngineEventKind::TimelineEntryAdded { .. } => "Timeline",
        EngineEventKind::PluginLoaded { .. } => "PluginLoaded",
        EngineEventKind::PluginExecuted { .. } => "PluginExecuted",
        EngineEventKind::PluginError { .. } => "PluginError",
        EngineEventKind::System { .. } => "System",
    };

    let severity_str = match event.severity {
        EventSeverity::Info => "INFO",
        EventSeverity::Warn => "WARN",
        EventSeverity::Error => "ERROR",
    };

    let case_str = event.case_id.as_deref().unwrap_or("-");

    format!(
        "[{}] [{}] [{}] case={} msg=\"{}\"",
        timestamp,
        kind_str,
        severity_str,
        case_str,
        event.message.replace('\"', "'")
    )
}

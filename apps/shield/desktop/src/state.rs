use forensic_engine::case::database::CaseDatabaseManager;
use forensic_engine::events::{EngineEvent, EventBus};
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_EVENTS: usize = 1000;

pub struct AppState {
    pub db_manager: CaseDatabaseManager,
    pub opened_cases: HashSet<String>,
    pub event_bus: Arc<EventBus>,
    pub event_buffer: Arc<Mutex<VecDeque<EngineEvent>>>,
    pub worker_loop_running: Arc<AtomicBool>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            db_manager: CaseDatabaseManager::new(std::path::Path::new(".")),
            opened_cases: HashSet::new(),
            event_bus: Arc::new(EventBus::new(1000)),
            event_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_EVENTS))),
            worker_loop_running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn add_event(&self, event: EngineEvent) {
        if let Ok(mut buffer) = self.event_buffer.lock() {
            if buffer.len() >= MAX_EVENTS {
                buffer.pop_front();
            }
            buffer.push_back(event);
        }
    }

    pub fn get_events(&self, case_id: Option<String>, limit: usize) -> Vec<EngineEvent> {
        if let Ok(buffer) = self.event_buffer.lock() {
            buffer
                .iter()
                .filter(|e| {
                    if let Some(ref cid) = case_id {
                        e.case_id.as_ref() == Some(cid)
                    } else {
                        true
                    }
                })
                .rev()
                .take(limit)
                .cloned()
                .collect()
        } else {
            vec![]
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

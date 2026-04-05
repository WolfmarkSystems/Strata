// case/examiner.rs — Examiner session tracking.
// Examiner identity is required before case work begins.
// Default "Unidentified Examiner" is permitted for testing but flagged in all logs.

pub const DEFAULT_EXAMINER: &str = "Unidentified Examiner";
pub const DEFAULT_EXAMINER_WARNING: &str =
    "WARNING: No named examiner set. All actions will be logged as 'Unidentified Examiner'. \
     Set an examiner name before beginning a formal examination.";

#[derive(Debug, Clone)]
pub struct ExaminerSession {
    pub name: String,
    pub session_start_utc: String,
    pub is_default: bool,
}

impl Default for ExaminerSession {
    fn default() -> Self {
        Self {
            name: DEFAULT_EXAMINER.to_string(),
            session_start_utc: chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            is_default: true,
        }
    }
}

impl ExaminerSession {
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let is_default = name.trim().is_empty() || name == DEFAULT_EXAMINER;
        Self {
            name: if is_default { DEFAULT_EXAMINER.to_string() } else { name },
            session_start_utc: chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            is_default,
        }
    }

    pub fn show_warning(&self) -> bool {
        self.is_default
    }
}

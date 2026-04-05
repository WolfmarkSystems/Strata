use std::path::PathBuf;

pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_UNSUPPORTED: i32 = 2;
pub const EXIT_VALIDATION: i32 = 3;

pub fn now_utc_rfc3339_nanos() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[derive(serde::Serialize, Clone)]
pub struct CliResultEnvelope {
    pub tool_version: String,
    pub timestamp_utc: String,
    pub platform: String,
    pub command: String,
    pub args: Vec<String>,
    pub status: String,
    pub exit_code: i32,
    pub error: Option<String>,
    pub warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    pub outputs: std::collections::HashMap<String, Option<String>>,
    pub sizes: std::collections::HashMap<String, u64>,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl CliResultEnvelope {
    pub fn new(command: &str, args: Vec<String>, exit_code: i32, elapsed_ms: u64) -> Self {
        Self {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp_utc: now_utc_rfc3339_nanos(),
            platform: std::env::consts::OS.to_string(),
            command: command.to_string(),
            args,
            status: if exit_code == 0 {
                "ok".to_string()
            } else {
                "error".to_string()
            },
            exit_code,
            error: None,
            warning: None,
            error_type: None,
            hint: None,
            outputs: std::collections::HashMap::new(),
            sizes: std::collections::HashMap::new(),
            elapsed_ms,
            data: None,
        }
    }

    #[allow(dead_code)]
    pub fn ok(mut self) -> Self {
        self.status = "ok".to_string();
        self.exit_code = EXIT_OK;
        self
    }

    pub fn warn(mut self, warning: String) -> Self {
        self.status = "warn".to_string();
        self.warning = Some(warning);
        if self.exit_code == 0 {
            self.exit_code = EXIT_OK;
        }
        self
    }

    pub fn error(mut self, error: String) -> Self {
        self.status = "error".to_string();
        self.error = Some(error);
        if self.exit_code == 0 {
            self.exit_code = EXIT_ERROR;
        }
        self
    }

    pub fn with_error_type(mut self, error_type: &str) -> Self {
        self.error_type = Some(error_type.to_string());
        self
    }

    pub fn with_hint(mut self, hint: &str) -> Self {
        self.hint = Some(hint.to_string());
        self
    }

    pub fn with_output(mut self, key: &str, path: Option<String>) -> Self {
        self.outputs.insert(key.to_string(), path);
        self
    }

    pub fn with_outputs(
        mut self,
        outputs: std::collections::HashMap<String, Option<String>>,
    ) -> Self {
        self.outputs = outputs;
        self
    }

    pub fn with_size(mut self, key: &str, size: u64) -> Self {
        self.sizes.insert(key.to_string(), size);
        self
    }

    pub fn with_sizes(mut self, sizes: std::collections::HashMap<String, u64>) -> Self {
        self.sizes = sizes;
        self
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn write_to_file(&self, path: &PathBuf) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            strata_fs::create_dir_all(parent)?;
        }
        strata_fs::write(path, serde_json::to_string_pretty(self).unwrap_or_default())
    }
}

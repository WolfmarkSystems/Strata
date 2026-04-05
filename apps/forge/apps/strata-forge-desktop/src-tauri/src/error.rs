use serde::Serialize;
use std::fmt;

/// Central error type for Forge backend operations.
#[derive(Debug, Clone, Serialize)]
pub struct ForgeError {
    pub message: String,
    pub kind: ForgeErrorKind,
}

#[derive(Debug, Clone, Serialize)]
pub enum ForgeErrorKind {
    LlmConnection,
    LlmTimeout,
    LlmResponse,
    ContextServer,
    Io,
    Config,
    Internal,
}

impl fmt::Display for ForgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}] {}", self.kind, self.message)
    }
}

impl std::error::Error for ForgeError {}

impl ForgeError {
    pub fn llm_connection(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            kind: ForgeErrorKind::LlmConnection,
        }
    }

    pub fn llm_timeout(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            kind: ForgeErrorKind::LlmTimeout,
        }
    }

    pub fn llm_response(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            kind: ForgeErrorKind::LlmResponse,
        }
    }

    pub fn io(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            kind: ForgeErrorKind::Io,
        }
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            kind: ForgeErrorKind::Internal,
        }
    }
}

impl From<ForgeError> for String {
    fn from(e: ForgeError) -> String {
        e.to_string()
    }
}

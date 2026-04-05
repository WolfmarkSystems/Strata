use thiserror::Error;

#[derive(Debug, Error)]
pub enum ForensicError {
    #[error("Unsupported parser: {0}")]
    UnsupportedParser(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum TempraError {
    #[error("detection failed: {0}")]
    Detection(String),

    #[error("module loading failed for {path}: {reason}")]
    ModuleLoad { path: PathBuf, reason: String },

    #[error("module validation failed: {0}")]
    ModuleValidation(String),

    #[error("command execution failed: {command}: {reason}")]
    CommandExec { command: String, reason: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

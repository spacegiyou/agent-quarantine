//! Typed error handling for the core crate.

use thiserror::Error;

/// Errors produced by the core library. The CLI layer converts these into
/// friendly, actionable messages (see `docs/architecture.md`); the core never
/// prints and never panics for expected failure modes.
#[derive(Debug, Error)]
pub enum CoreError {
    /// An underlying I/O failure (reading a policy file, writing the audit log).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A policy configuration file could not be parsed.
    #[error("could not parse policy config: {0}")]
    PolicyParse(String),

    /// An audit event line could not be parsed while reading a session log.
    #[error("could not parse audit event: {0}")]
    EventParse(String),

    /// A value could not be serialized (audit event, policy config).
    #[error("serialization error: {0}")]
    Serialize(String),

    /// A catch-all for other recoverable errors.
    #[error("{0}")]
    Other(String),
}

/// Convenience result type used throughout the core crate.
pub type Result<T> = std::result::Result<T, CoreError>;

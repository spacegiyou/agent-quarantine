//! Audit trail: structured events, secret redaction, and a JSONL logger.

pub mod event;
pub mod logger;
pub mod redact;

pub use event::Event;
pub use logger::AuditLogger;
pub use redact::{redact_arg, redact_argv};

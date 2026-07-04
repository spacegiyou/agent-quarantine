//! Core logic for Agent Quarantine: a local command firewall and safety layer
//! for AI coding agents.
//!
//! This crate is deliberately free of process-spawning and terminal I/O so that
//! the policy engine, command classifier, secret redaction, audit log, preflight
//! scanner, and report generator can all be unit-tested as pure logic. The CLI
//! crate wires these pieces to real processes and PATH shims.
//!
//! ## Honest security boundary
//!
//! The MVP is a *command firewall* built on `PATH` shims, not a sandbox. See
//! [`docs/limitations.md`](https://github.com/agent-quarantine/agent-quarantine). In
//! particular, absolute-path binaries can bypass the shims and allowed binaries
//! can still perform arbitrary file and network I/O.

pub mod audit;
pub mod command;
pub mod error;
pub mod policy;
pub mod preflight;
pub mod report;

pub use error::{CoreError, Result};

pub use audit::{AuditLogger, Event};
pub use command::{classify, CommandAttempt};
pub use policy::{Action, Decision, Engine, Policy, RiskLevel};
pub use preflight::{scan_path, Finding, ScanOptions, Severity};

/// The product version, sourced from the crate version at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

//! Policy: the typed decision model, configuration schema, deterministic rule
//! set, and the engine that turns a command attempt into an explainable
//! decision.

pub mod config;
pub mod decision;
pub mod engine;
pub mod rules;

pub use config::{Mode, NonInteractive, Policy};
pub use decision::{Action, Decision, RiskLevel};
pub use engine::Engine;

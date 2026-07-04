//! The typed, explainable decision model.
//!
//! Every command attempt resolves to exactly one [`Decision`]. Decisions are
//! never a black-box score: they always carry the rule IDs that fired, plain
//! language reasons, and (where useful) safer alternatives.

use serde::{Deserialize, Serialize};

/// What Agent Quarantine will do with a command attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Run the command without interruption (still logged).
    Allow,
    /// Pause and require human approval before running.
    Ask,
    /// Refuse to run the command.
    Block,
}

impl Action {
    /// Stable lowercase name used in logs, reports, and JSON output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Ask => "ask",
            Action::Block => "block",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How dangerous an action is if it goes wrong. Ordered from least to most
/// severe, so `RiskLevel::Critical > RiskLevel::Low`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Read-only or otherwise reversible.
    Low,
    /// Worth a glance; mutation, network, or package activity.
    Medium,
    /// Could damage the workspace or leak data.
    High,
    /// Almost certainly destructive or an exfiltration vector.
    Critical,
}

impl RiskLevel {
    /// Stable lowercase name used in logs, reports, and JSON output.
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The full, explainable outcome of classifying a command attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Allow, ask, or block.
    pub action: Action,
    /// The severity that drove the action.
    pub risk: RiskLevel,
    /// Kebab-case rule IDs that contributed to this decision.
    pub rule_ids: Vec<String>,
    /// Plain-language reasons a human can read.
    pub reasons: Vec<String>,
    /// Optional suggestions for a safer way to accomplish the goal.
    pub safer_alternatives: Vec<String>,
}

impl Decision {
    /// A plain "allow, nothing notable" decision.
    pub fn allow(rule_id: &str, reason: &str) -> Self {
        Decision {
            action: Action::Allow,
            risk: RiskLevel::Low,
            rule_ids: vec![rule_id.to_string()],
            reasons: vec![reason.to_string()],
            safer_alternatives: Vec::new(),
        }
    }

    /// The default decision for anything not otherwise matched.
    pub fn default_ask(reason: &str) -> Self {
        Decision {
            action: Action::Ask,
            risk: RiskLevel::Medium,
            rule_ids: vec!["unknown-command".to_string()],
            reasons: vec![reason.to_string()],
            safer_alternatives: Vec::new(),
        }
    }
}

//! Structured audit events, serialized one-per-line as JSONL.
//!
//! A single flat [`Event`] struct is used for every event type (its `type`
//! field discriminates). Optional fields are omitted when empty so each line
//! stays readable. Command output is never captured.

use serde::{Deserialize, Serialize};

use crate::policy::decision::Decision;

/// One line in a session's audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Stable event name: `session_start`, `preflight_finding`,
    /// `command_decision`, `approval_decision`, `command_exit`, `session_end`.
    #[serde(rename = "type")]
    pub event_type: String,
    /// The session this event belongs to.
    pub session_id: String,
    /// RFC 3339 UTC timestamp.
    pub timestamp: String,
    /// Display string of the command (already redacted).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub command: Option<String>,
    /// Redacted argument vector.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub argv: Vec<String>,
    /// Working directory the command ran in.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cwd: Option<String>,
    /// Decision action, if applicable (`allow` / `ask` / `block`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub action: Option<String>,
    /// Risk level, if applicable.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub risk: Option<String>,
    /// Rule IDs that fired.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub rule_ids: Vec<String>,
    /// Plain-language reasons.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub reasons: Vec<String>,
    /// Exit status for `command_exit`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exit_status: Option<i32>,
    /// Approval outcome for `approval_decision` (`allow-once` / `deny` / ...).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub approval: Option<String>,
    /// Free-form detail (used by `preflight_finding` and `session_start`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
}

impl Event {
    fn base(event_type: &str, session_id: &str) -> Self {
        Event {
            event_type: event_type.to_string(),
            session_id: session_id.to_string(),
            timestamp: now_rfc3339(),
            command: None,
            argv: Vec::new(),
            cwd: None,
            action: None,
            risk: None,
            rule_ids: Vec::new(),
            reasons: Vec::new(),
            exit_status: None,
            approval: None,
            detail: None,
        }
    }

    /// A `session_start` event.
    pub fn session_start(session_id: &str, cwd: &str, detail: &str) -> Self {
        let mut e = Event::base("session_start", session_id);
        e.cwd = Some(cwd.to_string());
        e.detail = Some(detail.to_string());
        e
    }

    /// A `command_decision` event. `argv` must already be redacted.
    pub fn command_decision(
        session_id: &str,
        command: &str,
        argv: Vec<String>,
        cwd: &str,
        decision: &Decision,
    ) -> Self {
        let mut e = Event::base("command_decision", session_id);
        e.command = Some(command.to_string());
        e.argv = argv;
        e.cwd = Some(cwd.to_string());
        e.action = Some(decision.action.as_str().to_string());
        e.risk = Some(decision.risk.as_str().to_string());
        e.rule_ids = decision.rule_ids.clone();
        e.reasons = decision.reasons.clone();
        e
    }

    /// An `approval_decision` event recording what the human chose.
    pub fn approval_decision(session_id: &str, command: &str, approval: &str) -> Self {
        let mut e = Event::base("approval_decision", session_id);
        e.command = Some(command.to_string());
        e.approval = Some(approval.to_string());
        e
    }

    /// A `command_exit` event.
    pub fn command_exit(session_id: &str, command: &str, exit_status: i32) -> Self {
        let mut e = Event::base("command_exit", session_id);
        e.command = Some(command.to_string());
        e.exit_status = Some(exit_status);
        e
    }

    /// A `preflight_finding` event.
    pub fn preflight_finding(session_id: &str, rule_id: &str, detail: &str) -> Self {
        let mut e = Event::base("preflight_finding", session_id);
        e.rule_ids = vec![rule_id.to_string()];
        e.detail = Some(detail.to_string());
        e
    }

    /// A `session_end` event.
    pub fn session_end(session_id: &str) -> Self {
        Event::base("session_end", session_id)
    }
}

/// Current time as an RFC 3339 UTC string like `2026-07-01T12:00:01Z`.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::decision::{Action, Decision, RiskLevel};

    #[test]
    fn command_decision_serializes_expected_fields() {
        let decision = Decision {
            action: Action::Ask,
            risk: RiskLevel::Medium,
            rule_ids: vec!["network-tool".into()],
            reasons: vec!["contacts the network".into()],
            safer_alternatives: vec![],
        };
        let event = Event::command_decision(
            "aq_test",
            "curl https://example.invalid",
            vec!["curl".into(), "https://example.invalid".into()],
            "/repo",
            &decision,
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"command_decision\""));
        assert!(json.contains("\"action\":\"ask\""));
        assert!(json.contains("\"risk\":\"medium\""));
        // Empty optional fields are omitted.
        assert!(!json.contains("exit_status"));

        let parsed: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn session_end_is_minimal() {
        let json = serde_json::to_string(&Event::session_end("aq_test")).unwrap();
        assert!(json.contains("\"type\":\"session_end\""));
        assert!(!json.contains("command"));
    }
}

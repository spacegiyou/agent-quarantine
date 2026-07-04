//! The registry of built-in rules.
//!
//! Detection lives in [`crate::command::classify`], which returns the IDs of the
//! rules that fired. This module owns the *metadata* for each ID — its action,
//! risk, human-readable reason, and a safer alternative. Keeping detection and
//! metadata separate is what lets the engine produce explainable decisions
//! without a black-box score.

use crate::policy::decision::{Action, RiskLevel};

/// Static description of one rule.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// Kebab-case identifier, stable across versions and shown in logs/reports.
    pub id: &'static str,
    /// What this rule wants to do to a matching command.
    pub action: Action,
    /// How severe a match is.
    pub risk: RiskLevel,
    /// A plain-language reason shown to the user.
    pub reason: &'static str,
    /// An optional safer way to accomplish the same goal.
    pub safer_alternative: Option<&'static str>,
}

/// All built-in rules. The order here is only for readability; the engine
/// resolves conflicts by action severity, not by list position.
pub const RULES: &[Rule] = &[
    // ---- Block by default -------------------------------------------------
    Rule {
        id: "remote-script-piped-to-shell",
        action: Action::Block,
        risk: RiskLevel::Critical,
        reason: "downloads code from the network and immediately executes it in a shell",
        safer_alternative: Some(
            "download the script to a file, read it, then run only the reviewed local copy",
        ),
    },
    Rule {
        id: "destructive-root-removal",
        action: Action::Block,
        risk: RiskLevel::Critical,
        reason: "recursively force-deletes a root, home, or parent directory",
        safer_alternative: Some(
            "delete a specific named path inside the workspace instead of a broad recursive target",
        ),
    },
    Rule {
        id: "credential-file-read",
        action: Action::Block,
        risk: RiskLevel::High,
        reason: "reads, copies, or exfiltrates a credential or secret file",
        safer_alternative: Some(
            "reference secrets through environment variables or a secrets manager, never by reading the file",
        ),
    },
    Rule {
        id: "git-force-push",
        action: Action::Block,
        risk: RiskLevel::High,
        reason: "force-pushes or deletes a remote branch, which can rewrite shared history",
        safer_alternative: Some("push normally, or use --force-with-lease after review"),
    },
    Rule {
        id: "reverse-shell-pattern",
        action: Action::Block,
        risk: RiskLevel::Critical,
        reason: "matches a pattern that opens an interactive shell over the network",
        safer_alternative: None,
    },
    Rule {
        id: "docker-privileged-host-mount",
        action: Action::Block,
        risk: RiskLevel::High,
        reason: "runs a container with privileged access or mounts sensitive host paths",
        safer_alternative: Some(
            "drop --privileged and mount only the specific workspace subdirectory you need",
        ),
    },
    Rule {
        id: "persistence-mechanism",
        action: Action::Block,
        risk: RiskLevel::High,
        reason: "installs a persistence mechanism (cron, launch agent, service, or shell startup file)",
        safer_alternative: Some("run the task explicitly when needed instead of installing autostart"),
    },
    // ---- Ask by default ---------------------------------------------------
    Rule {
        id: "shell-interpreter",
        action: Action::Ask,
        risk: RiskLevel::Medium,
        reason: "runs an arbitrary shell script, which can do anything",
        safer_alternative: Some("run the specific command directly instead of through 'sh -c'"),
    },
    Rule {
        id: "network-tool",
        action: Action::Ask,
        risk: RiskLevel::Medium,
        reason: "contacts the network, which can download code or send out data",
        safer_alternative: None,
    },
    Rule {
        id: "package-manager-install",
        action: Action::Ask,
        risk: RiskLevel::Medium,
        reason: "installs dependencies, which may run lifecycle scripts from untrusted packages",
        safer_alternative: Some("review the lockfile and install with scripts disabled where supported"),
    },
    Rule {
        id: "dns-txt-lookup",
        action: Action::Ask,
        risk: RiskLevel::Medium,
        reason: "performs a DNS TXT lookup, a known data-exfiltration channel",
        safer_alternative: None,
    },
    Rule {
        id: "docker-run",
        action: Action::Ask,
        risk: RiskLevel::Medium,
        reason: "launches a container",
        safer_alternative: None,
    },
    Rule {
        id: "privilege-change",
        action: Action::Ask,
        risk: RiskLevel::Medium,
        reason: "changes permissions or escalates privileges",
        safer_alternative: None,
    },
    Rule {
        id: "base64-decode-exec",
        action: Action::Ask,
        risk: RiskLevel::Medium,
        reason: "decodes base64 content and pipes it toward execution, a common obfuscation",
        safer_alternative: Some("decode to a file, inspect it, then decide whether to run it"),
    },
    // ---- Allow by default -------------------------------------------------
    Rule {
        id: "read-only-command",
        action: Action::Allow,
        risk: RiskLevel::Low,
        reason: "a read-only inspection command",
        safer_alternative: None,
    },
];

/// Look up a rule's metadata by ID.
pub fn lookup(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_id_is_unique_and_kebab_case() {
        let mut seen = std::collections::HashSet::new();
        for rule in RULES {
            assert!(seen.insert(rule.id), "duplicate rule id: {}", rule.id);
            assert!(
                rule.id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "rule id not kebab-case: {}",
                rule.id
            );
        }
    }

    #[test]
    fn lookup_finds_known_rule() {
        let rule = lookup("remote-script-piped-to-shell").unwrap();
        assert_eq!(rule.action, Action::Block);
        assert_eq!(rule.risk, RiskLevel::Critical);
        assert!(lookup("no-such-rule").is_none());
    }
}

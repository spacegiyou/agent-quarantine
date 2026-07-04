//! The policy configuration schema (`agent-quarantine.yaml`).
//!
//! The schema is intentionally broader than the MVP enforces so that on-disk
//! configs stay forward-compatible. Fields that are parsed but not yet enforced
//! are documented as such here and in `docs/policy.md`; we never silently
//! pretend to honor a setting we ignore.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

/// The default interaction mode for `ask` decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Allow low-risk automatically, but never downgrade a block. Use with care.
    Allow,
    /// Prompt for approval on `ask` decisions (the default, fail-closed).
    #[default]
    Ask,
    /// Treat every `ask` decision as a block. Maximum caution.
    Block,
}

/// What to do with `ask` decisions when there is no interactive terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NonInteractive {
    /// Deny (fail closed). The safe default.
    #[default]
    Deny,
    /// Allow only `low` risk `ask` decisions; deny everything higher.
    AllowLowRisk,
}

/// Logging-related knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Redact secret-looking values before writing them to the log.
    pub redact_secrets: bool,
    /// Whether to capture wrapped command output (never enabled in the MVP).
    pub include_command_output: bool,
    /// Truncate any single argument to this many characters in the log.
    pub max_arg_length: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            redact_secrets: true,
            include_command_output: false,
            max_arg_length: 500,
        }
    }
}

/// Command-classification defaults for categories that do not match a specific
/// rule. Values are the *names* of actions; the engine reads them as fallbacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CommandDefaults {
    /// Action for commands the classifier does not recognize.
    pub unknown: Action,
    /// Action for shell interpreters invoked with `-c`.
    pub shell: Action,
    /// Action for package-manager installs.
    pub package_manager_install: Action,
    /// Action for network tools.
    pub network_tool: Action,
    /// Action for destructive commands.
    pub destructive: Action,
}

impl Default for CommandDefaults {
    fn default() -> Self {
        CommandDefaults {
            unknown: Action::Ask,
            shell: Action::Ask,
            package_manager_install: Action::Ask,
            network_tool: Action::Ask,
            destructive: Action::Block,
        }
    }
}

use crate::policy::decision::Action;

/// The full policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Schema version (currently `1`).
    pub version: u32,
    /// Default interaction mode.
    pub mode: Mode,
    /// Non-interactive behavior for `ask` decisions.
    pub non_interactive: NonInteractive,
    /// Logging knobs.
    pub logging: LoggingConfig,
    /// Command-category fallbacks.
    pub commands: CommandDefaults,
    /// Extra glob patterns treated as sensitive credential paths. These are
    /// merged with the built-in list in [`crate::command`].
    pub sensitive_paths: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            version: 1,
            mode: Mode::default(),
            non_interactive: NonInteractive::default(),
            logging: LoggingConfig::default(),
            commands: CommandDefaults::default(),
            sensitive_paths: Vec::new(),
        }
    }
}

impl Policy {
    /// Parse a policy from YAML text.
    pub fn from_yaml(text: &str) -> Result<Self> {
        serde_yaml::from_str(text).map_err(|e| CoreError::PolicyParse(e.to_string()))
    }

    /// Load a policy from a file path.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::from_yaml(&text)
    }

    /// Serialize the policy to YAML.
    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).map_err(|e| CoreError::Serialize(e.to_string()))
    }

    /// The commented starter config written by `agent-quarantine policy init`.
    pub fn starter_yaml() -> &'static str {
        STARTER_POLICY
    }
}

/// A human-friendly, commented default config. Kept as a string (rather than
/// serialized) so the file the user gets is documented and stable.
const STARTER_POLICY: &str = r#"# Agent Quarantine policy
# Docs: docs/policy.md. Unset fields fall back to safe defaults.
version: 1

# Default handling for "ask" decisions when a terminal is present:
#   ask   - prompt for approval (default, fail-closed)
#   block - treat every ask as a block (maximum caution)
#   allow - auto-allow low risk, never downgrade a block (use with care)
mode: ask

# What to do with "ask" decisions when there is no interactive terminal:
#   deny            - fail closed (default)
#   allow-low-risk  - permit only low-risk ask decisions
non_interactive: deny

logging:
  redact_secrets: true
  include_command_output: false
  max_arg_length: 500

commands:
  unknown: ask
  shell: ask
  package_manager_install: ask
  network_tool: ask
  destructive: block

# Extra credential-like paths to treat as sensitive, in addition to the
# built-in list (.env, id_rsa, ~/.ssh, ~/.aws, cloud + registry tokens, ...).
sensitive_paths: []
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_round_trips_through_yaml() {
        let policy = Policy::default();
        let yaml = policy.to_yaml().unwrap();
        let parsed = Policy::from_yaml(&yaml).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.mode, Mode::Ask);
        assert_eq!(parsed.non_interactive, NonInteractive::Deny);
        assert!(parsed.logging.redact_secrets);
    }

    #[test]
    fn starter_yaml_parses() {
        let parsed = Policy::from_yaml(Policy::starter_yaml()).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.commands.destructive, Action::Block);
    }

    #[test]
    fn partial_yaml_uses_defaults() {
        let parsed = Policy::from_yaml("version: 1\nmode: block\n").unwrap();
        assert_eq!(parsed.mode, Mode::Block);
        // Unspecified fields fall back to defaults.
        assert_eq!(parsed.non_interactive, NonInteractive::Deny);
        assert_eq!(parsed.logging.max_arg_length, 500);
    }

    #[test]
    fn rejects_malformed_yaml() {
        let err = Policy::from_yaml("mode: : :\n").unwrap_err();
        assert!(matches!(err, CoreError::PolicyParse(_)));
    }
}

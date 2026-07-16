//! Command-line surface for `agent-quarantine`, defined with clap derive.

use std::path::PathBuf;

use agent_quarantine_core::policy::config::{Mode, NonInteractive};
use clap::{Args, Parser, Subcommand, ValueEnum};

/// A local command firewall and safety layer for AI coding agents.
#[derive(Debug, Parser)]
#[command(
    name = "agent-quarantine",
    version,
    about = "A local command firewall and safety layer for AI coding agents.",
    long_about = "Agent Quarantine wraps an AI coding agent so that the commands it launches are \
observed, dangerous ones are blocked, risky ones require approval, and everything is written to a \
readable audit log. It is a command firewall built on PATH shims, not a sandbox."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a command behind Agent Quarantine shims.
    Run(RunArgs),
    /// Scan a repository before letting an agent work on it.
    Preflight(PreflightArgs),
    /// Generate a readable report from a session log.
    Report(ReportArgs),
    /// Create or inspect policy configuration.
    Policy(PolicyArgs),
    /// Generate shell completion scripts for `aq`.
    Completions(CompletionsArgs),
    /// Print version information.
    Version,
    /// Internal shim entrypoint (normally reached via PATH shims).
    #[command(hide = true)]
    Shim(ShimArgs),
}

/// `agent-quarantine completions <SHELL>`
#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    pub shell: CompletionShell,
}

/// Shells supported by the completion generator.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

/// `agent-quarantine run [OPTIONS] -- <COMMAND>...`
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Path to a policy file (defaults to the workspace `agent-quarantine.yaml`).
    #[arg(long, value_name = "PATH")]
    pub policy: Option<PathBuf>,
    /// Directory to write the session log into.
    #[arg(long, value_name = "PATH")]
    pub log_dir: Option<PathBuf>,
    /// Override the interaction mode.
    #[arg(long, value_enum)]
    pub mode: Option<ModeArg>,
    /// Behavior for `ask` decisions when there is no terminal.
    #[arg(long = "non-interactive", value_enum)]
    pub non_interactive: Option<NonInteractiveArg>,
    /// Skip the preflight scan before running.
    #[arg(long)]
    pub no_preflight: bool,
    /// Remove secret-looking environment variables from the wrapped command.
    #[arg(long)]
    pub sanitize_env: bool,
    /// Workspace root (defaults to the git root or current directory).
    #[arg(long, value_name = "PATH")]
    pub workspace: Option<PathBuf>,
    /// Emit machine-readable JSON where supported.
    #[arg(long)]
    pub json: bool,
    /// The command to run, given after `--`.
    #[arg(last = true, required = true, num_args = 1.., value_name = "COMMAND")]
    pub command: Vec<String>,
}

/// `agent-quarantine preflight [PATH]`
#[derive(Debug, Args)]
pub struct PreflightArgs {
    /// Path to scan.
    #[arg(default_value = ".", value_name = "PATH")]
    pub path: PathBuf,
    /// Emit findings as JSON.
    #[arg(long)]
    pub json: bool,
    /// Exit non-zero if any finding meets or exceeds this severity.
    #[arg(long, value_name = "LEVEL")]
    pub fail_on: Option<String>,
}

/// `agent-quarantine report <SESSION_JSONL>`
#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Path to a session JSONL log.
    #[arg(value_name = "SESSION_JSONL")]
    pub session: PathBuf,
    /// Output format (only `markdown` is supported in the MVP).
    #[arg(long, default_value = "markdown")]
    pub format: String,
    /// Write the report to a file instead of stdout.
    #[arg(long, short = 'o', value_name = "PATH")]
    pub output: Option<PathBuf>,
}

/// `agent-quarantine policy <SUBCOMMAND>`
#[derive(Debug, Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

/// Policy subcommands.
#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Write a starter `agent-quarantine.yaml`.
    Init(PolicyInitArgs),
    /// Print the effective policy as YAML.
    Show(PolicyShowArgs),
}

/// `agent-quarantine policy init`
#[derive(Debug, Args)]
pub struct PolicyInitArgs {
    /// Where to write the policy file.
    #[arg(
        long,
        short = 'o',
        default_value = "agent-quarantine.yaml",
        value_name = "PATH"
    )]
    pub output: PathBuf,
    /// Overwrite the file if it already exists.
    #[arg(long)]
    pub force: bool,
}

/// `agent-quarantine policy show`
#[derive(Debug, Args)]
pub struct PolicyShowArgs {
    /// Policy file to load (defaults to the workspace config or built-in defaults).
    #[arg(long, value_name = "PATH")]
    pub policy: Option<PathBuf>,
}

/// `agent-quarantine shim <PROGRAM> [ARGS]...` (internal).
#[derive(Debug, Args)]
pub struct ShimArgs {
    /// The program name being shimmed.
    #[arg(value_name = "PROGRAM")]
    pub program: String,
    /// The arguments to that program.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "ARGS"
    )]
    pub args: Vec<String>,
}

/// clap-facing mirror of [`Mode`].
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ModeArg {
    /// Auto-allow low risk; never downgrade a block.
    Allow,
    /// Prompt on `ask` decisions.
    Ask,
    /// Treat every `ask` as a block.
    Block,
}

impl From<ModeArg> for Mode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Allow => Mode::Allow,
            ModeArg::Ask => Mode::Ask,
            ModeArg::Block => Mode::Block,
        }
    }
}

/// clap-facing mirror of [`NonInteractive`].
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum NonInteractiveArg {
    /// Deny `ask` decisions.
    Deny,
    /// Allow only low-risk `ask` decisions.
    AllowLowRisk,
}

impl From<NonInteractiveArg> for NonInteractive {
    fn from(value: NonInteractiveArg) -> Self {
        match value {
            NonInteractiveArg::Deny => NonInteractive::Deny,
            NonInteractiveArg::AllowLowRisk => NonInteractive::AllowLowRisk,
        }
    }
}

//! Shell completion generation for the documented `aq` alias.

use std::io;
use std::process::ExitCode;

use clap::CommandFactory;
use clap_complete::aot::{generate, Shell};

use crate::cli::{Cli, CompletionShell, CompletionsArgs};

/// Generate a completion script on stdout for the selected shell.
pub fn execute(args: CompletionsArgs) -> anyhow::Result<ExitCode> {
    let shell = match args.shell {
        CompletionShell::Bash => Shell::Bash,
        CompletionShell::Zsh => Shell::Zsh,
        CompletionShell::Fish => Shell::Fish,
    };
    let mut command = public_command();
    let mut stdout = io::stdout();
    generate(shell, &mut command, "aq", &mut stdout);
    Ok(ExitCode::SUCCESS)
}

/// Build the command tree without internal-only subcommands.
///
/// The AOT generators include hidden subcommands, so passing `Cli::command()`
/// directly would expose the internal `shim` entrypoint as a completion.
fn public_command() -> clap::Command {
    let command = Cli::command();
    let public_subcommands = command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .cloned()
        .collect::<Vec<_>>();

    clap::Command::new("agent-quarantine")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A local command firewall and safety layer for AI coding agents.")
        .subcommand_required(true)
        .subcommands(public_subcommands)
}

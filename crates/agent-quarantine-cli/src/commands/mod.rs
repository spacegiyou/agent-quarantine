//! Subcommand implementations and the top-level dispatcher.

pub mod completions;
pub mod policy;
pub mod preflight;
pub mod report;
pub mod run;
pub mod shim;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

/// Parse arguments and run the selected subcommand.
pub fn dispatch() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run(args) => run::execute(args),
        Command::Preflight(args) => preflight::execute(args),
        Command::Report(args) => report::execute(args),
        Command::Policy(args) => policy::execute(args),
        Command::Completions(args) => completions::execute(args),
        Command::Version => {
            println!("agent-quarantine {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        Command::Shim(args) => shim::execute_subcommand(args),
    };
    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("agent-quarantine: {err}");
            // 64 == EX_USAGE-ish; used for CLI/config errors.
            ExitCode::from(64)
        }
    }
}

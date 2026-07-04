//! `agent-quarantine policy` — create or inspect policy configuration.

use std::fs;
use std::process::ExitCode;

use agent_quarantine_core::policy::config::Policy;
use anyhow::{anyhow, Context, Result};

use crate::cli::{PolicyArgs, PolicyCommand, PolicyInitArgs, PolicyShowArgs};

pub fn execute(args: PolicyArgs) -> Result<ExitCode> {
    match args.command {
        PolicyCommand::Init(a) => init(a),
        PolicyCommand::Show(a) => show(a),
    }
}

fn init(args: PolicyInitArgs) -> Result<ExitCode> {
    if args.output.exists() && !args.force {
        return Err(anyhow!(
            "{} already exists; pass --force to overwrite",
            args.output.display()
        ));
    }
    fs::write(&args.output, Policy::starter_yaml())
        .with_context(|| format!("could not write {}", args.output.display()))?;
    eprintln!("Wrote starter policy to {}", args.output.display());
    Ok(ExitCode::SUCCESS)
}

fn show(args: PolicyShowArgs) -> Result<ExitCode> {
    let policy = match &args.policy {
        Some(path) => Policy::from_file(path)
            .with_context(|| format!("could not load policy from {}", path.display()))?,
        None => {
            let default_path = std::env::current_dir()?.join("agent-quarantine.yaml");
            if default_path.exists() {
                Policy::from_file(&default_path)?
            } else {
                Policy::default()
            }
        }
    };
    print!("{}", policy.to_yaml()?);
    Ok(ExitCode::SUCCESS)
}

//! `agent-quarantine report` — render a session log as Markdown.

use std::fs;
use std::process::ExitCode;

use agent_quarantine_core::audit::AuditLogger;
use agent_quarantine_core::report::render_markdown;
use anyhow::{anyhow, Context, Result};

use crate::cli::ReportArgs;

pub fn execute(args: ReportArgs) -> Result<ExitCode> {
    if args.format != "markdown" {
        return Err(anyhow!(
            "unsupported format '{}': only 'markdown' is supported in this version",
            args.format
        ));
    }

    let events = AuditLogger::read_events(&args.session)
        .with_context(|| format!("could not read session log {}", args.session.display()))?;
    let markdown = render_markdown(&events);

    match &args.output {
        Some(path) => {
            fs::write(path, markdown)
                .with_context(|| format!("could not write report to {}", path.display()))?;
            eprintln!("Wrote report to {}", path.display());
        }
        None => print!("{markdown}"),
    }
    Ok(ExitCode::SUCCESS)
}

//! `agent-quarantine preflight` — scan a repository and report findings.

use std::process::ExitCode;

use agent_quarantine_core::preflight::{scan_path, ScanOptions, Severity};
use anyhow::{anyhow, Result};

use crate::cli::PreflightArgs;

/// Exit code when a finding meets or exceeds the `--fail-on` threshold.
const EXIT_THRESHOLD_HIT: u8 = 2;

pub fn execute(args: PreflightArgs) -> Result<ExitCode> {
    let threshold = match &args.fail_on {
        Some(level) => Some(Severity::parse(level).ok_or_else(|| {
            anyhow!("invalid --fail-on level '{level}' (low|medium|high|critical)")
        })?),
        None => None,
    };

    let findings = scan_path(&args.path, &ScanOptions::default())?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else if findings.is_empty() {
        println!("No risky files found under {}.", args.path.display());
    } else {
        println!(
            "{} finding(s) under {}:\n",
            findings.len(),
            args.path.display()
        );
        for f in &findings {
            let loc = match f.line {
                Some(line) => format!("{}:{}", f.file.display(), line),
                None => f.file.display().to_string(),
            };
            println!("[{}] {} ({})", f.severity, f.title, f.id);
            println!("  where: {loc}");
            println!("  {}", f.detail);
            println!("  fix: {}\n", f.recommendation);
        }
    }

    if let Some(threshold) = threshold {
        if findings.iter().any(|f| f.severity >= threshold) {
            return Ok(ExitCode::from(EXIT_THRESHOLD_HIT));
        }
    }
    Ok(ExitCode::SUCCESS)
}

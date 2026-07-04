//! `agent-quarantine run` — set up a session, inject shims, optionally preflight,
//! then launch the wrapped command.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use agent_quarantine_core::audit::{AuditLogger, Event};
use agent_quarantine_core::policy::config::Policy;
use agent_quarantine_core::preflight::{scan_path, ScanOptions};
use anyhow::{anyhow, Context, Result};

use crate::cli::RunArgs;
use crate::commands::shim;

/// Environment variable names that look secret, for `--sanitize-env`.
const SECRET_ENV_MARKERS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "CREDENTIAL",
    "APIKEY",
    "API_KEY",
];

pub fn execute(args: RunArgs) -> Result<ExitCode> {
    let workspace = resolve_workspace(args.workspace.as_deref())?;
    let mut policy = load_policy(args.policy.as_deref(), &workspace)?;
    if let Some(mode) = args.mode {
        policy.mode = mode.into();
    }
    if let Some(ni) = args.non_interactive {
        policy.non_interactive = ni.into();
    }

    let session_id = new_session_id();
    let log_file = match &args.log_dir {
        Some(dir) => dir.join(format!("{session_id}.jsonl")),
        None => workspace
            .join(".agent-quarantine")
            .join("sessions")
            .join(format!("{session_id}.jsonl")),
    };
    let logger = AuditLogger::new(&log_file);
    logger
        .ensure_parent()
        .with_context(|| format!("could not create log directory for {}", log_file.display()))?;

    // A temp directory holds the shim bin dir and the resolved policy. It must
    // outlive the wrapped process, so we keep the handle until the end.
    let shim_root = tempfile::Builder::new()
        .prefix(&format!("agent-quarantine-{session_id}-"))
        .tempdir()
        .context("could not create shim directory")?;
    let shim_bin = shim_root.path().join("bin");
    let policy_path = shim_root.path().join("policy.yaml");
    fs::write(&policy_path, policy.to_yaml()?)?;

    let exe = std::env::current_exe().context("could not locate the agent-quarantine binary")?;
    shim::create_shims(&shim_bin, &exe).context("could not create command shims")?;

    let original_path = std::env::var("PATH").unwrap_or_default();
    let new_path = prepend_path(&shim_bin, &original_path);

    logger.log(&Event::session_start(
        &session_id,
        &workspace.display().to_string(),
        "Agent Quarantine session started",
    ))?;

    if !args.no_preflight {
        run_preflight(&workspace, &logger, &session_id, args.json);
    }

    let (program, rest) = args
        .command
        .split_first()
        .ok_or_else(|| anyhow!("no command given after --"))?;

    print_startup_warning(&log_file);

    let mut child = Command::new(program);
    child
        .args(rest)
        .env("PATH", &new_path)
        .env("AQ_SESSION_ID", &session_id)
        .env("AQ_WORKSPACE", &workspace)
        .env("AQ_LOG_FILE", &log_file)
        .env("AQ_POLICY_FILE", &policy_path)
        .env("AQ_ORIGINAL_PATH", &original_path)
        .env("AQ_SHIM_DIR", &shim_bin)
        .env("AQ_NON_INTERACTIVE", non_interactive_env(&policy))
        .env("AQ_MODE", mode_env(&policy));

    if args.sanitize_env {
        for key in sensitive_env_keys() {
            child.env_remove(key);
        }
    }

    let status = child
        .status()
        .with_context(|| format!("failed to launch wrapped command '{program}'"))?;

    logger.log(&Event::session_end(&session_id))?;

    let code = status.code().unwrap_or(1);
    Ok(ExitCode::from(code as u8))
}

fn resolve_workspace(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return path
            .canonicalize()
            .with_context(|| format!("workspace path not found: {}", path.display()));
    }
    let cwd = std::env::current_dir().context("could not determine current directory")?;
    Ok(find_git_root(&cwd).unwrap_or(cwd))
}

fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        if d.join(".git").exists() {
            return Some(d.to_path_buf());
        }
        dir = d.parent();
    }
    None
}

fn load_policy(explicit: Option<&Path>, workspace: &Path) -> Result<Policy> {
    if let Some(path) = explicit {
        return Policy::from_file(path)
            .with_context(|| format!("could not load policy from {}", path.display()));
    }
    let default_path = workspace.join("agent-quarantine.yaml");
    if default_path.exists() {
        return Policy::from_file(&default_path)
            .with_context(|| format!("could not load policy from {}", default_path.display()));
    }
    Ok(Policy::default())
}

fn prepend_path(shim_bin: &Path, original: &str) -> std::ffi::OsString {
    let mut dirs = vec![shim_bin.to_path_buf()];
    dirs.extend(std::env::split_paths(original));
    std::env::join_paths(dirs).unwrap_or_else(|_| shim_bin.as_os_str().to_os_string())
}

fn new_session_id() -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    format!("aq_{}", &id[..12])
}

fn non_interactive_env(policy: &Policy) -> &'static str {
    use agent_quarantine_core::policy::config::NonInteractive;
    match policy.non_interactive {
        NonInteractive::Deny => "deny",
        NonInteractive::AllowLowRisk => "allow-low-risk",
    }
}

fn mode_env(policy: &Policy) -> &'static str {
    use agent_quarantine_core::policy::config::Mode;
    match policy.mode {
        Mode::Allow => "allow",
        Mode::Ask => "ask",
        Mode::Block => "block",
    }
}

fn sensitive_env_keys() -> Vec<String> {
    std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| {
            let upper = k.to_ascii_uppercase();
            SECRET_ENV_MARKERS.iter().any(|m| upper.contains(m))
        })
        .collect()
}

fn run_preflight(workspace: &Path, logger: &AuditLogger, session_id: &str, json: bool) {
    let findings = match scan_path(workspace, &ScanOptions::default()) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("agent-quarantine: preflight skipped ({err})");
            return;
        }
    };
    for finding in &findings {
        let detail = format!("{} ({})", finding.title, finding.file.display());
        let _ = logger.log(&Event::preflight_finding(session_id, &finding.id, &detail));
    }
    if json {
        return; // findings are in the log; keep stdout clean for the wrapped program
    }
    if findings.is_empty() {
        eprintln!("Preflight: no risky repository files detected.");
    } else {
        eprintln!("Preflight: {} finding(s) before launch:", findings.len());
        for finding in &findings {
            eprintln!(
                "  [{}] {} — {}",
                finding.severity,
                finding.title,
                finding.file.display()
            );
        }
        eprintln!();
    }
}

fn print_startup_warning(log_file: &Path) {
    eprintln!("Agent Quarantine is active for this session.\n");
    eprintln!("MVP boundary:");
    eprintln!("  - command shims are active for common tools");
    eprintln!("  - high-risk commands will be blocked or require approval");
    eprintln!("  - this is not a full kernel sandbox");
    eprintln!("  - absolute-path binaries may bypass shims\n");
    eprintln!("Session log:\n  {}\n", log_file.display());
}

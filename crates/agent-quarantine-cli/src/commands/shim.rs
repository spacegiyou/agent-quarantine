//! Shim behavior: the logic that runs when `agent-quarantine` is invoked under
//! a shimmed name like `curl` or `git`, plus helpers `run` uses to create the
//! shim directory.

use std::fs;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use agent_quarantine_core::audit::{redact_argv, AuditLogger, Event};
use agent_quarantine_core::command::{resolve_real_executable, CommandAttempt};
use agent_quarantine_core::policy::config::{Mode, NonInteractive, Policy};
use agent_quarantine_core::policy::decision::{Action, Decision, RiskLevel};
use agent_quarantine_core::policy::Engine;
use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use crate::cli::ShimArgs;

/// The set of commands Agent Quarantine intercepts via PATH shims.
pub const SHIM_COMMANDS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "python",
    "python3",
    "node",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "bun",
    "curl",
    "wget",
    "git",
    "ssh",
    "scp",
    "rsync",
    "nc",
    "ncat",
    "socat",
    "docker",
    "make",
    "pip",
    "pip3",
    "uv",
    "cargo",
    "go",
    "dig",
    "nslookup",
    "env",
    "sudo",
    "doas",
    "xargs",
    "timeout",
    "nohup",
    "setsid",
    "script",
    "perl",
    "ruby",
    "php",
    "awk",
    "sed",
    "tar",
    "zip",
    "openssl",
    "base64",
    "chmod",
    "chown",
    "crontab",
    "launchctl",
    "systemctl",
    "rm",
    "cat",
    "cp",
    "mv",
    "ls",
    "pwd",
    "grep",
    "rg",
    "find",
    "head",
    "tail",
    "less",
    "more",
    "tee",
    "touch",
    "mkdir",
    "ln",
    "dd",
];

/// True if `name` is one of the commands we shim.
pub fn is_shim_name(name: &str) -> bool {
    SHIM_COMMANDS.contains(&name)
}

/// Exit code used when a command is blocked (matches a denied `exec`).
const EXIT_BLOCKED: i32 = 126;
/// Exit code used when the real executable cannot be found.
const EXIT_NO_EXECUTABLE: i32 = 127;

/// Entry point when the binary is invoked under a shimmed `argv[0]`.
pub fn run_shim(program: &str) -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run_shim_inner(program, &args) {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("agent-quarantine (shim '{program}'): {err}");
            ExitCode::from(EXIT_NO_EXECUTABLE as u8)
        }
    }
}

/// Entry point for the hidden `agent-quarantine shim <program> [args]` command.
pub fn execute_subcommand(args: ShimArgs) -> Result<ExitCode> {
    let code = run_shim_inner(&args.program, &args.args)?;
    Ok(ExitCode::from(code as u8))
}

/// Create the shim directory contents: one entry per shimmed command, each
/// pointing at the real `agent-quarantine` binary.
pub fn create_shims(bin_dir: &Path, exe: &Path) -> std::io::Result<()> {
    fs::create_dir_all(bin_dir)?;
    for name in SHIM_COMMANDS {
        let link = bin_dir.join(name);
        let _ = fs::remove_file(&link);
        if symlink(exe, &link).is_err() && fs::hard_link(exe, &link).is_err() {
            fs::copy(exe, &link)?;
            set_executable(&link)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::fs::hard_link(target, link)
}

#[cfg(unix)]
fn set_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Everything a shim needs to make a decision, loaded from the session env.
struct ShimContext {
    session_id: String,
    log_file: PathBuf,
    policy: Policy,
    original_path: String,
    shim_dir: PathBuf,
}

impl ShimContext {
    fn load() -> Result<Self> {
        let session_id = env_req("AQ_SESSION_ID")?;
        let log_file = PathBuf::from(env_req("AQ_LOG_FILE")?);
        let original_path = std::env::var("AQ_ORIGINAL_PATH").unwrap_or_default();
        let shim_dir = PathBuf::from(std::env::var("AQ_SHIM_DIR").unwrap_or_default());
        let policy = match std::env::var("AQ_POLICY_FILE") {
            Ok(p) if !p.is_empty() => Policy::from_file(Path::new(&p)).unwrap_or_default(),
            _ => Policy::default(),
        };
        Ok(ShimContext {
            session_id,
            log_file,
            policy,
            original_path,
            shim_dir,
        })
    }
}

fn env_req(key: &str) -> Result<String> {
    std::env::var(key)
        .map_err(|_| anyhow!("{key} is not set; shims must be launched by 'agent-quarantine run'"))
}

/// The resolved runtime action plus a note about how it was decided.
struct Outcome {
    action: Action,
    approval: Option<String>,
}

fn run_shim_inner(program: &str, args: &[String]) -> Result<i32> {
    let ctx = ShimContext::load()?;
    let attempt = CommandAttempt::new(program, args.to_vec());
    let engine = Engine::new(ctx.policy.clone());
    let base = engine.classify(&attempt);

    // Build a redacted view for logging and prompts.
    let mut full_argv = Vec::with_capacity(args.len() + 1);
    full_argv.push(program.to_string());
    full_argv.extend_from_slice(args);
    let max = ctx.policy.logging.max_arg_length;
    let redacted_argv = if ctx.policy.logging.redact_secrets {
        redact_argv(&full_argv, max)
    } else {
        full_argv.clone()
    };
    let display = redacted_argv.join(" ");

    let logger = AuditLogger::new(&ctx.log_file);
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let fingerprint = session_fingerprint(program, args, &cwd, &base);

    let is_tty = std::io::stdin().is_terminal();
    let outcome = resolve_outcome(&base, &ctx, &display, &fingerprint, is_tty);

    // Log the decision with the action that actually took effect.
    let logged = Decision {
        action: outcome.action,
        ..base.clone()
    };
    let _ = logger.log(&Event::command_decision(
        &ctx.session_id,
        &display,
        redacted_argv,
        &cwd,
        &logged,
    ));
    if let Some(approval) = &outcome.approval {
        let _ = logger.log(&Event::approval_decision(
            &ctx.session_id,
            &display,
            approval,
        ));
    }

    match outcome.action {
        Action::Block => {
            print_block(&display, &base);
            Ok(EXIT_BLOCKED)
        }
        Action::Allow => {
            let status = exec_real(program, args, &ctx)?;
            let _ = logger.log(&Event::command_exit(&ctx.session_id, &display, status));
            Ok(status)
        }
        Action::Ask => {
            // resolve_outcome never returns Ask.
            print_block(&display, &base);
            Ok(EXIT_BLOCKED)
        }
    }
}

fn resolve_outcome(
    base: &Decision,
    ctx: &ShimContext,
    display: &str,
    fingerprint: &str,
    is_tty: bool,
) -> Outcome {
    match base.action {
        Action::Block => Outcome {
            action: Action::Block,
            approval: None,
        },
        Action::Allow => Outcome {
            action: Action::Allow,
            approval: None,
        },
        Action::Ask => {
            if ctx.policy.mode == Mode::Block {
                return Outcome {
                    action: Action::Block,
                    approval: Some("mode-block".to_string()),
                };
            }

            if session_allows(ctx, fingerprint) {
                return Outcome {
                    action: Action::Allow,
                    approval: Some("allow-session-remembered".to_string()),
                };
            }

            if !is_tty {
                return if ctx.policy.non_interactive == NonInteractive::AllowLowRisk
                    && base.risk == RiskLevel::Low
                {
                    Outcome {
                        action: Action::Allow,
                        approval: Some("non-interactive-allow-low-risk".to_string()),
                    }
                } else {
                    Outcome {
                        action: Action::Block,
                        approval: Some("non-interactive-deny".to_string()),
                    }
                };
            }

            if ctx.policy.mode == Mode::Allow && base.risk == RiskLevel::Low {
                return Outcome {
                    action: Action::Allow,
                    approval: Some("mode-allow-low-risk".to_string()),
                };
            }

            match prompt(display, base) {
                PromptChoice::AllowOnce => Outcome {
                    action: Action::Allow,
                    approval: Some("allow-once".to_string()),
                },
                PromptChoice::AllowSession => {
                    remember_session(ctx, fingerprint);
                    Outcome {
                        action: Action::Allow,
                        approval: Some("allow-session".to_string()),
                    }
                }
                PromptChoice::Deny => Outcome {
                    action: Action::Block,
                    approval: Some("deny".to_string()),
                },
            }
        }
    }
}

enum PromptChoice {
    AllowOnce,
    AllowSession,
    Deny,
}

fn prompt(display: &str, decision: &Decision) -> PromptChoice {
    let mut err = std::io::stderr();
    write_prompt(&mut err, display, decision);
    let _ = write!(
        err,
        "\n[a] allow once  [s] allow exact command for session  [d] deny (default): "
    );
    let _ = err.flush();

    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return PromptChoice::Deny;
    }
    match line.trim().to_ascii_lowercase().as_str() {
        "a" | "allow" => PromptChoice::AllowOnce,
        "s" | "session" => PromptChoice::AllowSession,
        _ => PromptChoice::Deny,
    }
}

fn write_prompt(err: &mut impl Write, display: &str, decision: &Decision) {
    let _ = writeln!(err, "\nAgent Quarantine needs approval.\n");
    let _ = writeln!(err, "Command:");
    let _ = writeln!(err, "  {display}\n");
    let _ = writeln!(err, "Risk: {}", decision.risk);
    if !decision.rule_ids.is_empty() {
        let _ = writeln!(err, "Rules:");
        for rule in &decision.rule_ids {
            let _ = writeln!(err, "  - {rule}");
        }
    }
    if !decision.reasons.is_empty() {
        let _ = writeln!(err, "Why:");
        for reason in &decision.reasons {
            let _ = writeln!(err, "  - {reason}");
        }
    }
    if !decision.safer_alternatives.is_empty() {
        let _ = writeln!(err, "Safer:");
        for alt in &decision.safer_alternatives {
            let _ = writeln!(err, "  - {alt}");
        }
    }
}

fn session_allowlist_path(ctx: &ShimContext) -> PathBuf {
    ctx.log_file.with_extension("allow")
}

fn session_allows(ctx: &ShimContext, fingerprint: &str) -> bool {
    match fs::read_to_string(session_allowlist_path(ctx)) {
        Ok(text) => text.lines().any(|l| l == fingerprint),
        Err(_) => false,
    }
}

fn remember_session(ctx: &ShimContext, fingerprint: &str) {
    let path = session_allowlist_path(ctx);
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{fingerprint}");
    }
}

fn session_fingerprint(program: &str, args: &[String], cwd: &str, decision: &Decision) -> String {
    let mut hasher = Sha256::new();
    fingerprint_field(&mut hasher, "program", program);
    fingerprint_field(&mut hasher, "cwd", cwd);
    for arg in args {
        fingerprint_field(&mut hasher, "arg", arg);
    }
    for rule_id in &decision.rule_ids {
        fingerprint_field(&mut hasher, "rule", rule_id);
    }
    format!("sha256:{}", hex(&hasher.finalize()))
}

fn fingerprint_field(hasher: &mut Sha256, label: &str, value: &str) {
    hasher.update(label.as_bytes());
    hasher.update(b"\0");
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(value.as_bytes());
    hasher.update(b"\0");
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn print_block(display: &str, decision: &Decision) {
    let mut err = std::io::stderr();
    let _ = writeln!(err, "\nAgent Quarantine blocked a command.\n");
    let _ = writeln!(err, "  {display}\n");
    if !decision.reasons.is_empty() {
        let _ = writeln!(err, "Why:");
        for reason in &decision.reasons {
            let _ = writeln!(err, "  - {reason}");
        }
    }
    if !decision.safer_alternatives.is_empty() {
        let _ = writeln!(err, "\nSafer:");
        for alt in &decision.safer_alternatives {
            let _ = writeln!(err, "  - {alt}");
        }
    }
    if !decision.rule_ids.is_empty() {
        let _ = writeln!(err, "\nRule: {}", decision.rule_ids.join(", "));
    }
}

fn exec_real(program: &str, args: &[String], ctx: &ShimContext) -> Result<i32> {
    let self_exe = std::env::current_exe().ok();
    let real = resolve_real_executable(
        program,
        &ctx.original_path,
        &ctx.shim_dir,
        self_exe.as_deref(),
    )
    .ok_or_else(|| {
        anyhow!(
            "could not find real executable for shim '{program}'.\n\
                 Searched AQ_ORIGINAL_PATH and excluded AQ_SHIM_DIR."
        )
    })?;
    let status = Command::new(&real)
        .args(args)
        .status()
        .with_context(|| format!("failed to run real '{program}' at {}", real.display()))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask_decision() -> Decision {
        Decision {
            action: Action::Ask,
            risk: RiskLevel::Medium,
            rule_ids: vec!["network-tool".to_string()],
            reasons: vec!["contacts the network".to_string()],
            safer_alternatives: vec!["review the destination first".to_string()],
        }
    }

    #[test]
    fn prompt_includes_command_rules_reasons_and_safer_alternatives() {
        let mut out = Vec::new();
        write_prompt(
            &mut out,
            "curl --token [REDACTED] https://example.invalid",
            &ask_decision(),
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Command:"));
        assert!(text.contains("curl --token [REDACTED] https://example.invalid"));
        assert!(text.contains("Risk: medium"));
        assert!(text.contains("network-tool"));
        assert!(text.contains("contacts the network"));
        assert!(text.contains("review the destination first"));
    }

    #[test]
    fn session_fingerprint_uses_raw_command_without_revealing_it() {
        let one = session_fingerprint(
            "curl",
            &[
                "--token".to_string(),
                "sk-FAKE1111111111".to_string(),
                "https://example.invalid".to_string(),
            ],
            "/repo",
            &ask_decision(),
        );
        let two = session_fingerprint(
            "curl",
            &[
                "--token".to_string(),
                "sk-FAKE2222222222".to_string(),
                "https://example.invalid".to_string(),
            ],
            "/repo",
            &ask_decision(),
        );

        assert!(one.starts_with("sha256:"));
        assert_eq!(one.len(), "sha256:".len() + 64);
        assert_ne!(one, two);
        assert!(!one.contains("FAKE1111111111"));
        assert!(!two.contains("FAKE2222222222"));
    }
}

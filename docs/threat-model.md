# Threat model

Agent Quarantine defends a developer who runs an AI coding agent inside a
repository they do **not** fully trust. The agent can read files, run commands,
and follow instructions found in the repo — any of which may be adversarial.

## Assets we try to protect

- Source code in the workspace.
- Secrets: `.env`, SSH keys, cloud credentials (`~/.aws`, `~/.config/gcloud`,
  `~/.kube`), package-registry tokens (`~/.npmrc`, `~/.pypirc`).
- Git remotes and history.
- The local filesystem and the developer's machine more broadly.

## Adversaries

- **A malicious repository** whose files trigger dangerous commands.
- **A prompt-injected instruction file** (`AGENTS.md`, `CLAUDE.md`,
  `.cursorrules`, MCP configs) that tells the agent to ignore safety, reveal
  secrets, or run a remote installer.
- **A compromised dependency** whose install lifecycle scripts run on
  `npm install` / `pip install`.
- **A malicious MCP server** configured to launch a shell or reach broad paths.
- **A compromised install script** fetched and piped into a shell.

## Trust boundaries

- **Trusted:** the developer, the `agent-quarantine` binary, and the policy file
  the developer controls.
- **Untrusted:** the wrapped agent's decisions, the repository contents, network
  responses, and any instruction or config file discovered in the workspace.

Agent Quarantine sits on the boundary between the (untrusted) agent and the
(real) tools it wants to run. It classifies each command attempt and enforces an
allow / ask / block decision before the real tool executes.

## Where the boundary holds — and where it does not

The enforcement point is the `PATH` shim. It reliably intercepts commands the
agent runs *by name* through common tools. It does **not** intercept
absolute-path binaries, pre-existing processes, or I/O performed by an allowed
binary. See [limitations](limitations.md) for the full list. Treat Agent
Quarantine as a strong first layer and a source of visibility, not as
containment.

# Architecture

Two crates:

- **`agent-quarantine-core`** — pure logic, no process spawning or terminal I/O,
  so every piece is unit-testable:
  - `policy/` — the decision model, config schema, rule registry, and engine.
  - `command/` — normalize an intercepted command, classify it against the rule
    set, and resolve the real executable behind a shim.
  - `audit/` — structured events, secret redaction, and the JSONL logger.
  - `preflight/` — repository scanner (file classification + detectors).
  - `report/` — render a session log as Markdown.
- **`agent-quarantine-cli`** — the `agent-quarantine` binary that wires the core
  to real processes, `PATH` shims, and the terminal.

## The shim mechanism

One binary plays two roles, dispatched by `argv[0]`:

1. **CLI mode** (`agent-quarantine` / `aq`): parses subcommands.
2. **Shim mode** (`curl`, `git`, `sh`, …): evaluates the intercepted command.

`aq run`:

1. Resolves the workspace (explicit → git root → cwd).
2. Loads and resolves the policy, writing it to a temp file for the shims.
3. Creates a session id and a temp shim directory.
4. Creates one symlink per shimmed command, each pointing at the real binary.
5. Exports `AQ_*` environment variables and prepends the shim dir to `PATH`.
6. Optionally runs preflight.
7. Spawns the wrapped command and returns its exit code.

When the agent (or any descendant) runs `curl`, the OS finds the shim first. The
shim loads the session context from `AQ_*`, classifies its own `argv`, applies the
policy, logs a `command_decision`, then:

- **allow** → resolve the real executable from `AQ_ORIGINAL_PATH` (excluding the
  shim dir) and exec it, returning its exit code;
- **ask** → prompt on a TTY (`allow once` / `allow exact command for session` / `deny`), or
  apply the non-interactive policy;
- **block** → print a plain-language explanation and exit `126`.

## Audit log

Events are JSONL at `.agent-quarantine/sessions/<session-id>.jsonl`:
`session_start`, `preflight_finding`, `command_decision`, `approval_decision`,
`command_exit`, `session_end`. Arguments are redacted before they are written.
Command output is never captured.

## Exit codes

- `run` returns the wrapped command's exit code; a blocked shim exits `126`; a
  shim that cannot find its real executable exits `127`.
- `preflight` exits `0` (clean or below threshold), `2` (finding at/above
  `--fail-on`), or `64` for a usage error.

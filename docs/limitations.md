# Limitations

Agent Quarantine is a **command firewall built on `PATH` shims**, not a sandbox.
Read this before you rely on it for anything that matters.

## What the shim boundary cannot do

- **Absolute-path binaries bypass the shims.** `PATH` shims only intercept
  commands looked up by name. `/usr/bin/curl https://…` runs the real binary
  directly and is never seen by Agent Quarantine.
- **Already-running processes are outside the boundary.** Anything started
  before `aq run`, or re-parented away, is not intercepted.
- **Allowed binaries can still do anything.** When a command is allowed, the real
  tool runs with full access. `git`, `python`, `node`, and friends can read
  files and open network connections on their own.
- **Environment variables may be visible** to the wrapped agent unless you pass
  `--sanitize-env`, and even then sanitization is best-effort by name.
- **It is not a VM, kernel sandbox, seccomp/eBPF filter, EDR, or malware
  detector.** It does not contain a process at the kernel level.

## What it deliberately does not promise

- It **cannot guarantee** prevention of all data exfiltration.
- It does not detect novel or obfuscated attacks beyond its rule set.
- It does not inspect the *contents* transferred by an allowed network tool.

## Why it is still useful

- It **blocks the common, dangerous commands** an AI coding agent is most likely
  to be tricked into running (`curl | sh`, `rm -rf /`, credential reads, force
  pushes, reverse-shell patterns, privileged Docker, persistence).
- It **creates visibility**: every decision is logged as JSONL you can review
  with `aq report`.
- It **makes risky actions explicit** by pausing for approval instead of running
  silently.

## Stronger containment is future work

Kernel-level sandboxing, seccomp/eBPF, and a transparent network proxy are listed
as out of scope for `v0.1.0`. They are the right long-term direction; the shim
firewall is the pragmatic, inspectable first layer.

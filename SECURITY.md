# Security policy

## Reporting a vulnerability

If you find a security issue in Agent Quarantine, please report it privately
first. Open a GitHub security advisory (preferred) or email the maintainers
listed in `Cargo.toml`. Do not open a public issue with exploit details until a
fix is available.

Please include:

- affected version / commit,
- a description of the impact,
- the smallest **benign** reproduction that demonstrates the gap.

We aim to acknowledge reports within a few days.

## Scope and honest expectations

Agent Quarantine is a `PATH`-shim command firewall, not a sandbox. Bypasses that
are inherent to the shim model — absolute-path binaries, pre-existing processes,
I/O by an allowed binary — are documented in [docs/limitations.md](docs/limitations.md)
and are **known limitations, not vulnerabilities**. Reports that improve
detection, close a gap the docs claim to cover, or fix incorrect redaction are
very welcome.

## Please do not submit real attacks

Do **not** include real malware, working reverse shells, destructive commands,
live exfiltration code, or real secrets in issues, pull requests, tests, or
fixtures. Demonstrate detectors with harmless triggers, following the
[`examples/safe-risky-repo`](examples/safe-risky-repo) pattern. PRs that add real
payloads will be closed.

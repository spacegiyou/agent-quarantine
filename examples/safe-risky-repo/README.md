# safe-risky-repo

A deliberately "risky-looking" but completely harmless repository used to
demonstrate `agent-quarantine preflight`.

Run:

```bash
agent-quarantine preflight examples/safe-risky-repo
```

Expected findings (all benign triggers):

- `npm-lifecycle-script` — `package.json` defines `postinstall`/`setup` scripts.
- `agent-instruction-ignore-safety` — `AGENTS.md` contains an "ignore previous
  instructions" line.

Nothing in this folder touches the network, deletes files, reads secrets, or
runs a real payload.

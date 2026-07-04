# Policy reference

Agent Quarantine loads a policy from, in order: `--policy <path>`, a
`agent-quarantine.yaml` in the workspace root, or built-in defaults. Generate a
starter file with `aq policy init` and inspect the effective policy with
`aq policy show`.

The schema is intentionally broader than the MVP enforces so on-disk configs stay
forward-compatible. Fields that are parsed but **not yet enforced** are marked
below; the tool never pretends to honor a setting it ignores.

## Fields

```yaml
version: 1                 # schema version

mode: ask                  # default handling of "ask" decisions when a TTY exists
                           #   ask   - prompt (default, fail-closed)
                           #   block - treat every ask as a block
                           #   allow - auto-allow low risk; never downgrade a block

non_interactive: deny      # handling of "ask" decisions with no TTY
                           #   deny            - fail closed (default)
                           #   allow-low-risk  - permit only low-risk ask decisions

logging:
  redact_secrets: true     # redact secret-looking values before logging
  include_command_output: false   # (reserved) output is never captured in the MVP
  max_arg_length: 500      # truncate any single logged argument to this length

commands:                  # (reserved) category fallbacks; the built-in rule
  unknown: ask             # engine drives decisions today, defaults shown here
  shell: ask
  package_manager_install: ask
  network_tool: ask
  destructive: block

sensitive_paths: []        # extra credential-like path fragments to treat as
                           # sensitive, merged with the built-in list
```

## Safe example policies

These examples are intentionally boring and copy-pasteable. They show common
agent workflows without using real secrets or destructive commands.

### Read-only repo inspection with package installs gated

```yaml
version: 1
mode: ask
non_interactive: deny
commands:
  unknown: ask
  package_manager_install: ask
```

With this baseline, read-only commands such as `git status`, `git diff`,
`git log`, `ls`, `cat`, `grep`, and `rg` stay allowed by the built-in rules,
while package installs still pause for approval.

### Keep credential-file reads blocked

Credential-like paths stay blocked by the built-in detector even if the agent is
otherwise allowed to inspect the repo. For example:

- blocked: `cat .env`
- blocked: `rg API_KEY .env`
- blocked: `cp ~/.ssh/id_rsa /tmp/id_rsa`

### CI or automation fail-closed mode

Use a non-interactive deny policy in CI so approval prompts never turn into
implicit allows:

```yaml
version: 1
mode: ask
non_interactive: deny
logging:
  redact_secrets: true
```

## Precedence and overrides

- CLI flags override the file: `--mode`, `--non-interactive`.
- The rule engine decides the action for each command; `mode` only affects how
  `ask` decisions resolve, and it **never downgrades a block**.

## Decision model

Every command resolves to one explainable `Decision`:

- `action`: `allow` | `ask` | `block`
- `risk`: `low` | `medium` | `high` | `critical`
- `rule_ids`, `reasons`, `safer_alternatives`

Conflicts resolve by severity: any block wins over any ask, which wins over
allow. The reasons attached to the decision are the ones that drove the final
action. See the built-in rules in `crates/agent-quarantine-core/src/policy/rules.rs`.

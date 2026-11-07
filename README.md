# hermes-secret-gate

> **Stop agent-drafted secrets from leaving the machine.**

Hermes agents draft code, configs, and messages all day — and some of
them contain credentials the agent was never meant to paste. This plugin
gives Hermes a deterministic, offline secret guard: scan text before it
is shared, gate outbound shares fail-closed, and keep a receipt for
every decision. A BLOCKED receipt can never be approved — the only fix
is to remove the secret and re-scan.

## What it does

| Tool | What it returns |
| --- | --- |
| `secret_scan` | `CLEAR` / `REVIEW` / `LEAKED` + masked findings (rule, line, public prefix + length). The secret itself is never returned. |
| `secret_gate_check` | `ALLOW` / `WARN` / `BLOCK` + receipt id. The last check before any outbound share. |
| `secret_gate_receipts` | Recent receipts for audit. No secret material, ever. |

Plus a `post_tool_call` hook that audits **every** tool result for
leaked secrets and logs a warning with a receipt — it never blocks or
alters another tool's result — and a `/secret-gate <text>` slash command
for a quick inline scan.

## Rules (deterministic, stdlib only)

- **LEAKED** — AWS access keys, GitHub tokens (`ghp_`/`gho_`/`github_pat_`),
  Slack tokens, private-key blocks, JWTs, OpenAI-style keys, key/secret
  assignments, password assignments.
- **REVIEW** — high-entropy token-shaped strings, paths to credential
  files (`.ssh/id_*`, `.aws/credentials`, `.env`, kubeconfig).
- **CLEAR** — nothing matched.

The scanner never raises: an internal error is reported as REVIEW so a
broken scan can never silently pass.

## Install

```bash
hermes plugins install hermes-secret-gate
hermes plugins enable hermes-secret-gate
```

Local development (from this repo):

```bash
hermes plugins validate ./ --install-deps
hermes plugins doctor ./
```

## Use

Ask Hermes to check anything before it goes out:

> "Scan this draft before I post it" → `secret_scan`
> "Gate this message before sending it to GitHub" → `secret_gate_check`

Or in any chat: `/secret-gate <text>`.

## Honest limits

- Pattern + entropy detection, not a guarantee: a novel credential
  format the rules do not know will not be caught. REVIEW exists for
  exactly that uncertainty.
- The scanner reads only the text you hand it. It does not watch the
  filesystem, the network, or other apps.
- Receipts live in the plugin's bounded ring (100) and `ctx.state`;
  they are an audit trail, not a vault — they hold masked previews only.
- The bundled skill (`skills/secret-gate/SKILL.md`) ships as a file for
  reference; the plugin does not auto-register it, because the
  `register_skill` call signature was not verified against the installed
  Hermes version at build time.

## Disclosure (catalog rule 13)

- No network calls. No credentials read or stored. No shell commands.
  No background processes. No telemetry. Stdlib only, no dependencies.
- The hook reads tool results in memory to audit them; it never writes
  them anywhere except the masked receipt.

## Development

```bash
python3 -m unittest discover -s tests -v   # stdlib only, no venv needed
```

## License

MIT — see `LICENSE`.

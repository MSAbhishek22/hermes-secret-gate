---
name: secret-gate
description: Scan text for leaked secrets before sharing it, and gate outbound shares with a fail-closed verdict.
---

# Secret Gate — when to scan before you share

You draft code, configs, and messages all day. Some of them contain
credentials you were never meant to paste. This skill tells you when to
call the secret-gate tools so a secret never leaves the machine.

## When to scan

Call `secret_scan` before the agent hands text to any of these:

- a person (chat reply, issue, PR description, email draft)
- a file that leaves the repo (a paste, a gist, a public snippet)
- an external tool (a ticket, a form, a webhook payload)
- a public place (a forum post, a social post, a demo)

If the text came from the agent itself — generated code, a suggested
config, a draft message — scan it. Agents hallucinate plausible-looking
keys, and they also faithfully copy real ones from context.

## How to read the verdict

- **CLEAR** — nothing matched. Safe to send.
- **REVIEW** — suspicious but not conclusive (a high-entropy string, a
  path to a credential file). Show the masked finding to the user and
  let them decide. Never silently send REVIEW content to a public place.
- **LEAKED** — a known credential format matched. **Do not send.**
  Tell the user which rule fired and what to do: remove the secret,
  rotate it if it was ever shared, then re-scan.

## The gate

`secret_gate_check` is the last check before an outbound share. It
returns ALLOW, WARN, or BLOCK plus a receipt id:

- **BLOCK** — the content is LEAKED. Do not send it. A BLOCKED receipt
  can never be approved; the only fix is to remove the secret and
  re-scan.
- **WARN** — the content is REVIEW. A human must look before sending.
- **ALLOW** — the content is CLEAR.

`secret_gate_receipts` lists recent receipts for audit. Receipts never
contain secret material — only the rule, the line, and a masked preview.

## What the plugin never does

- It never sends text anywhere. The scan is local and deterministic.
- It never returns a secret. Findings carry a masked preview (public
  prefix + length) only.
- It never approves a blocked share, never disables a guard, and never
  touches Hermes core. The `post_tool_call` hook only audits tool
  results and logs a warning; it never blocks or alters them.

"""hermes-secret-gate — registration.

Wires the scanner's schemas to its handlers and subscribes the audit
hook. Uses only public Hermes surfaces (``register_tool``,
``register_hook``, ``register_command``); it never patches Hermes core,
never reads credential files, never makes network calls, and never
auto-approves anything.

``register()`` is called exactly once at startup. If it crashes, Hermes
disables the plugin and continues — so every step here is defensive.
"""

from __future__ import annotations

import logging

from . import schemas, scanner, tools
from .receipts import ReceiptStore

logger = logging.getLogger(__name__)

# One store per plugin load; receipts are mirrored into ctx.state when
# the host provides it.
_store = ReceiptStore()

# Findings from tool-result audits are capped so one noisy tool cannot
# flood the receipt ring.
_MAX_HOOK_FINDINGS_PER_CALL = 5


def _on_post_tool_call(tool_name, args, result, task_id, **kwargs):
    """Hook: audit every tool result for leaked secrets.

    Runs after every tool call (not just ours). It only records a
    receipt and logs a warning — it never blocks, alters, or re-routes
    another tool's result, and it never approves anything.
    """
    try:
        if not isinstance(result, str) or not result:
            return
        scanned = scanner.scan_text(result)
        if scanned["verdict"] == scanner.VERDICT_CLEAR:
            return
        findings = scanned["findings"][:_MAX_HOOK_FINDINGS_PER_CALL]
        receipt = _store.record(
            kind="tool_result",
            verdict=scanned["verdict"],
            gate="WARN" if scanned["verdict"] == scanner.VERDICT_REVIEW else "BLOCK",
            findings=findings,
        )
        logger.warning(
            "secret-gate: tool '%s' returned %s content (receipt %s, rules %s)",
            tool_name,
            scanned["verdict"],
            receipt["receipt_id"],
            ", ".join(sorted({f["rule"] for f in findings})),
        )
    except Exception:
        # A hook must never break the agent's turn.
        logger.exception("secret-gate: audit hook failed")


def register(ctx):
    """Wire schemas to handlers, register the hook and the slash command."""
    global _store
    try:
        _store = ReceiptStore(ctx)
    except Exception:
        _store = ReceiptStore()

    ctx.register_tool(
        name="secret_scan",
        toolset="secret-gate",
        schema=schemas.SECRET_SCAN,
        handler=tools.secret_scan,
    )
    ctx.register_tool(
        name="secret_gate_check",
        toolset="secret-gate",
        schema=schemas.SECRET_GATE_CHECK,
        handler=tools.make_secret_gate_check(_store),
    )
    ctx.register_tool(
        name="secret_gate_receipts",
        toolset="secret-gate",
        schema=schemas.SECRET_GATE_RECEIPTS,
        handler=tools.make_secret_gate_receipts(_store),
    )

    # Audit hook: every tool result gets scanned, nothing gets blocked.
    ctx.register_hook("post_tool_call", _on_post_tool_call)

    # Slash command: /secret-gate <text> — quick inline scan.
    ctx.register_command(
        "secret-gate",
        tools.make_slash_scan(_store),
        description="Scan text for leaked secrets before sharing it",
    )

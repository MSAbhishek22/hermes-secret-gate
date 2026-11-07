"""Tool handlers — the code that runs when Hermes calls each tool.

Rules for handlers (per the Hermes developer guide):
  1. Signature: ``def handler(args: dict, **kwargs) -> str``
  2. Return a JSON string — always, success and errors alike.
  3. Never raise: catch all exceptions, return error JSON instead.
  4. Accept ``**kwargs`` for forward compatibility.
"""

from __future__ import annotations

import json

try:
    # Package import (real Hermes load): plugin.tools
    from . import scanner
    from .receipts import ReceiptStore
except ImportError:  # pragma: no cover - top-level import (unit tests)
    import scanner
    from receipts import ReceiptStore

_GATE_MAP = {
    scanner.VERDICT_CLEAR: "ALLOW",
    scanner.VERDICT_REVIEW: "WARN",
    scanner.VERDICT_LEAKED: "BLOCK",
}


def _error(message: str) -> str:
    return json.dumps({"error": message})


def secret_scan(args: dict, **kwargs) -> str:
    """Scan text and return the verdict plus masked findings."""
    try:
        text = args.get("text", "")
        if not isinstance(text, str):
            return _error("text must be a string")
        result = scanner.scan_text(text)
        return json.dumps(result)
    except Exception as exc:  # never raise out of a handler
        return _error(f"secret_scan failed: {type(exc).__name__}")


def make_secret_gate_check(store: ReceiptStore):
    """Build the gate handler bound to a receipt store."""

    def secret_gate_check(args: dict, **kwargs) -> str:
        try:
            text = args.get("text", "")
            if not isinstance(text, str):
                return _error("text must be a string")
            destination = args.get("destination", "")
            if not isinstance(destination, str):
                destination = str(destination)
            result = scanner.scan_text(text)
            gate = _GATE_MAP[result["verdict"]]
            receipt = store.record(
                kind="gate_check",
                verdict=result["verdict"],
                gate=gate,
                findings=result["findings"],
            )
            return json.dumps(
                {
                    "verdict": result["verdict"],
                    "gate": gate,
                    "receipt_id": receipt["receipt_id"],
                    "destination": destination,
                    "findings": result["findings"],
                    "lines_scanned": result["lines_scanned"],
                    "note": (
                        "BLOCK means do not send. A BLOCKED receipt can "
                        "never be approved — remove the secret and re-scan."
                        if gate == "BLOCK"
                        else "WARN means a human must look before sending."
                        if gate == "WARN"
                        else "CLEAR — safe to send."
                    ),
                }
            )
        except Exception as exc:  # never raise out of a handler
            return _error(f"secret_gate_check failed: {type(exc).__name__}")

    return secret_gate_check


def make_secret_gate_receipts(store: ReceiptStore):
    """Build the receipts-listing handler bound to a receipt store."""

    def secret_gate_receipts(args: dict, **kwargs) -> str:
        try:
            limit = args.get("limit", 10)
            try:
                limit = int(limit)
            except (TypeError, ValueError):
                limit = 10
            return json.dumps(
                {
                    "receipts": store.list_recent(limit),
                    "count": len(store.list_recent(limit)),
                }
            )
        except Exception as exc:  # never raise out of a handler
            return _error(f"secret_gate_receipts failed: {type(exc).__name__}")

    return secret_gate_receipts


def make_slash_scan(store: ReceiptStore):
    """Build the /secret-gate slash-command handler.

    Slash handlers receive a single raw-args string and return the text
    shown in chat. The reply is a short human-readable verdict, never
    the scanned secret.
    """

    def handle_secret_gate(raw_args: str) -> str:
        text = (raw_args or "").strip()
        if not text:
            return (
                "Usage: /secret-gate <text> — scans the text for leaked "
                "secrets. Nothing is sent anywhere; the scan is local."
            )
        try:
            result = scanner.scan_text(text)
            gate = _GATE_MAP[result["verdict"]]
            receipt = store.record(
                kind="slash_scan",
                verdict=result["verdict"],
                gate=gate,
                findings=result["findings"],
            )
            lines = [
                f"Secret gate: {result['verdict']} ({gate})",
                f"Receipt: {receipt['receipt_id']}",
            ]
            for f in result["findings"]:
                lines.append(
                    f"- {f['rule']} (line {f['line']}): {f['masked']} — {f['hint']}"
                )
            if gate == "BLOCK":
                lines.append("Do not send this. Remove the secret and re-scan.")
            elif gate == "WARN":
                lines.append("A human should look before this is sent.")
            return "\n".join(lines)
        except Exception as exc:  # never raise out of a handler
            return f"Secret gate scan failed ({type(exc).__name__}); treat as REVIEW."

    return handle_secret_gate

"""Gate receipts — an append-only, in-memory record of gate decisions.

A receipt names the verdict, the rules that fired, and how to replay the
check. It never contains secret material: findings are stored masked
(public prefix + length only), exactly as the scanner reports them.

Receipts are kept in a bounded in-memory ring (default 100) and, when a
Hermes ``ctx.state`` is available, mirrored there so they survive a
restart. A BLOCKED receipt can never be "approved" clean — there is no
approve path at all; the only fix is to remove the secret and re-scan.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

MAX_RECEIPTS = 100


def new_receipt_id(counter: int) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"HSG-{stamp}-{counter:04d}"


class ReceiptStore:
    """Bounded receipt ring with optional ctx.state mirroring."""

    def __init__(self, ctx=None, max_receipts: int = MAX_RECEIPTS):
        self._ctx = ctx
        self._max = max_receipts
        self._memory: list[dict] = []
        self._counter = 0

    def record(self, kind: str, verdict: str, gate: str, findings: list) -> dict:
        """Append a receipt and return it (masked findings only)."""
        self._counter += 1
        receipt = {
            "receipt_id": new_receipt_id(self._counter),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            "verdict": verdict,
            "gate": gate,
            "rules": sorted({f["rule"] for f in findings}),
            "findings": [
                {
                    "rule": f["rule"],
                    "line": f["line"],
                    "masked": f["masked"],
                    "severity": f["severity"],
                }
                for f in findings
            ],
            "replay": "Re-run secret_scan on the same text; the same "
            "rules must fire with the same verdict.",
        }
        self._memory.append(receipt)
        if len(self._memory) > self._max:
            self._memory = self._memory[-self._max :]
        self._mirror()
        return receipt

    def list_recent(self, limit: int = 10) -> list[dict]:
        limit = max(1, min(int(limit), 50))
        return list(self._memory[-limit:])

    def _mirror(self) -> None:
        """Best-effort mirror into ctx.state; never raises."""
        if self._ctx is None:
            return
        try:
            state = getattr(self._ctx, "state", None)
            if state is None:
                return
            state.set("receipts", json.dumps(self._memory))
        except Exception:
            pass

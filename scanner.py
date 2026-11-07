"""Deterministic secret scanner — stdlib only, no network, no I/O.

Scans text line by line for credential-shaped material and returns a
verdict plus findings. Findings never contain secret material: the only
evidence shown is the rule id, the line number, and a masked preview
consisting of the token's public prefix (e.g. ``ghp_``) and its length.

Verdicts:
  CLEAR  — no rule matched.
  REVIEW — a suspicious-but-not-conclusive pattern matched (high-entropy
           token, a path to a credential file, a secret-shaped assignment
           that did not match a known provider format). A human decides.
  LEAKED — a known provider credential format matched. Fail closed:
           treat as leaked until proven otherwise.

The scanner never raises. Any internal error is reported as REVIEW with
rule ``scanner_error`` so a broken scan can never silently pass.
"""

from __future__ import annotations

import math
import re

VERDICT_CLEAR = "CLEAR"
VERDICT_REVIEW = "REVIEW"
VERDICT_LEAKED = "LEAKED"

# A finding is a dict: {"rule": str, "line": int, "masked": str,
# "severity": "LEAKED" | "REVIEW", "hint": str}

# --- Named credential formats (LEAKED on match) ---------------------------

_PATTERNS = [
    (
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AWS access key ID",
    ),
    (
        "github_token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
        "GitHub personal / OAuth / refresh token",
    ),
    (
        "github_pat",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        "GitHub fine-grained personal access token",
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "Slack token",
    ),
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"
        ),
        "Private key block",
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "JSON Web Token",
    ),
    (
        "openai_key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        "OpenAI-style API key",
    ),
    (
        "generic_api_key",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-/.+=]{20,})['\"]?"
        ),
        "Key/secret assigned in code or config",
    ),
    (
        "password_assignment",
        re.compile(
            r"(?i)\bpassword\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
        ),
        "Password assigned in code or config",
    ),
]

# --- Suspicious-but-not-conclusive patterns (REVIEW) -----------------------

_SECRET_PATHS = re.compile(
    r"(?:~|/home/[A-Za-z0-9_.-]+|/Users/[A-Za-z0-9_.-]+|%USERPROFILE%|C:\\Users\\[A-Za-z0-9_.-]+)"
    r"/(?:\.ssh/(?:id_[a-z0-9]+|known_hosts|config)|\.aws/credentials|\.gnupg/|\.kube/config|\.docker/config\.json)"
    r"|(?:^|[\s\"'])(?:\.env(?:\.[A-Za-z0-9_-]+)?|credentials\.json|id_rsa|id_ed25519)(?:[\s\"']|$)",
    re.IGNORECASE,
)

_TOKEN_CANDIDATE = re.compile(r"[A-Za-z0-9_\-/.+=]{32,}")

_MIN_ENTROPY = 4.0
_MIN_ENTROPY_LEN = 32


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    n = len(text)
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def _classes(text: str) -> int:
    n = 0
    if re.search(r"[a-z]", text):
        n += 1
    if re.search(r"[A-Z]", text):
        n += 1
    if re.search(r"[0-9]", text):
        n += 1
    if re.search(r"[^A-Za-z0-9]", text):
        n += 1
    return n


def _masked(match_text: str, public_prefix_len: int = 4) -> str:
    """Public prefix + length only. Never returns secret material."""
    prefix = match_text[:public_prefix_len]
    return f"{prefix}… ({len(match_text)} chars)"


def _public_prefix(match_text: str) -> str:
    """The recognisable, non-secret head of a token (e.g. 'ghp_', 'AKIA')."""
    m = re.match(r"[A-Za-z]{2,4}_", match_text)
    if m:
        return m.group(0)
    if match_text.startswith("AKIA"):
        return "AKIA"
    if match_text.startswith("eyJ"):
        return "eyJ"
    if match_text.startswith("sk-"):
        return "sk-"
    if match_text.startswith("xox"):
        return match_text[:4]
    if match_text.startswith("-----BEGIN"):
        return "-----BEGIN"
    return match_text[:4]


def _masked_for(match_text: str) -> str:
    prefix = _public_prefix(match_text)
    return f"{prefix}… ({len(match_text)} chars)"


def scan_text(text: str) -> dict:
    """Scan *text* and return {"verdict", "findings", "lines_scanned"}.

    Never raises and never includes secret material in the result.
    """
    findings: list[dict] = []
    try:
        lines = text.splitlines() or [""]
        for lineno, line in enumerate(lines, start=1):
            findings.extend(_scan_line(line, lineno))
    except Exception as exc:  # fail closed: a broken scan is a REVIEW
        findings.append(
            {
                "rule": "scanner_error",
                "line": 0,
                "masked": f"scanner failed ({type(exc).__name__})",
                "severity": VERDICT_REVIEW,
                "hint": "The scan itself errored; treat the text as unreviewed.",
            }
        )
    verdict = VERDICT_CLEAR
    if any(f["severity"] == VERDICT_LEAKED for f in findings):
        verdict = VERDICT_LEAKED
    elif findings:
        verdict = VERDICT_REVIEW
    return {
        "verdict": verdict,
        "findings": findings,
        "lines_scanned": len(text.splitlines()) if text else 0,
    }


def _scan_line(line: str, lineno: int) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, int]] = set()

    for rule, pattern, hint in _PATTERNS:
        for m in pattern.finditer(line):
            # For assignment patterns the secret is capture group 1.
            secret = m.group(1) if m.lastindex else m.group(0)
            key = (rule, m.start())
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "rule": rule,
                    "line": lineno,
                    "masked": _masked_for(secret),
                    "severity": VERDICT_LEAKED,
                    "hint": hint,
                }
            )

    if _SECRET_PATHS.search(line):
        key = ("secret_path", 0)
        if key not in seen:
            seen.add(key)
            out.append(
                {
                    "rule": "secret_path",
                    "line": lineno,
                    "masked": "path to a credential file",
                    "severity": VERDICT_REVIEW,
                    "hint": "References a credential file (SSH key, AWS "
                    "credentials, kubeconfig, .env). Review before sharing.",
                }
            )

    # High-entropy token heuristic (REVIEW only — never a LEAKED verdict
    # on entropy alone).
    for m in _TOKEN_CANDIDATE.finditer(line):
        token = m.group(0)
        if len(token) < _MIN_ENTROPY_LEN:
            continue
        if "://" in token or token.startswith(("http", "www.")):
            continue
        if _classes(token) >= 3 and _shannon_entropy(token) >= _MIN_ENTROPY:
            key = ("high_entropy_token", m.start())
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "rule": "high_entropy_token",
                    "line": lineno,
                    "masked": _masked_for(token),
                    "severity": VERDICT_REVIEW,
                    "hint": "Long high-entropy string that looks like a "
                    "token. Confirm it is not a credential before sharing.",
                }
            )
    return out

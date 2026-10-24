"""Secret detection helpers.

Known-format patterns are high confidence. Name-based detection (``API_KEY=...``)
is gated by a placeholder filter and a Shannon-entropy threshold to keep false
positives low. Evidence is always redacted - mcp-guard never prints a secret.
"""

from __future__ import annotations

import math
import re
from collections import Counter

KNOWN_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?:proj-|svcacct-|admin-)?(?!ant-)[A-Za-z0-9_\-]{32,}")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}")),
    ("Azure storage account key", re.compile(r"AccountKey=[A-Za-z0-9+/]{60,}={0,2}")),
    ("Private key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Database URL with password", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:/\s]+:[^@/\s]{3,}@")),
]

SECRET_NAME = re.compile(
    r"(?i)(api[_\-]?key|apikey|token|secret|passw(?:or)?d|\bpwd\b|private[_\-]?key|"
    r"access[_\-]?key|client[_\-]?secret|credential|connection[_\-]?string|\bpat\b|authorization|auth)"
)

_PLACEHOLDER = re.compile(
    r"(?i)^(?:"
    r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|\{\{.*\}\}|<[^>]*>|"
    r"(?:your|my|insert|replace|change|enter|example|sample|dummy|placeholder|todo|xxx|redacted)[\w\-\s]*|"
    r"op://.*|env:.*|keychain:.*|vault:.*|true|false|null|none|bearer|basic"
    r")$"
)


def is_placeholder(value: str) -> bool:
    v = value.strip()
    if not v:
        return True
    if _PLACEHOLDER.match(v):
        return True
    # value merely references an env var / input somewhere inside
    if "${" in v or "{{" in v or "$(" in v:
        return True
    # "Bearer ${TOKEN}" style handled above; "Bearer <token>" too
    if len(set(v.replace("-", "").replace("_", ""))) <= 2:  # xxxxxxxx, ********
        return True
    return False


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    v = value.strip()
    scheme = ""
    m = re.match(r"(?i)^(bearer|basic|token)\s+", v)
    if m:
        scheme, v = m.group(0), v[m.end():]
    if len(v) <= 8:
        return scheme + "*" * len(v)
    return f"{scheme}{v[:4]}…{'*' * 4} ({len(v)} chars)"


def find_known_secret(value: str) -> str | None:
    """Return the secret type if ``value`` contains a known-format secret."""
    for label, pattern in KNOWN_SECRET_PATTERNS:
        if pattern.search(value):
            return label
    return None


def looks_like_generic_secret(name: str, value: str) -> bool:
    """Heuristic for ``SOMETHING_TOKEN=<literal>`` with no known format."""
    if not SECRET_NAME.search(name):
        return False
    v = value.strip()
    # strip auth schemes so "Bearer abc123..." is judged on the token itself
    v = re.sub(r"(?i)^(bearer|basic|token)\s+", "", v)
    if len(v) < 12 or is_placeholder(v) or re.fullmatch(r"\d+", v):
        return False
    if re.match(r"(?i)^https?://", v) and "@" not in v:
        return False  # e.g. TOKEN_URL=https://...
    return shannon_entropy(v) >= 3.0

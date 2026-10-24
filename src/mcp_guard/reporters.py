"""Output formats: human text, JSON, and SARIF 2.1.0 (GitHub code scanning)."""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from . import __version__
from .models import Finding, Severity
from .poisoning import TOOL_RULES
from .rules import RULES

ALL_RULES = {**RULES, **TOOL_RULES}

_COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}
_RESET, _DIM, _BOLD = "\033[0m", "\033[2m", "\033[1m"


@lru_cache(maxsize=256)
def _lines(path: str) -> tuple[str, ...]:
    try:
        return tuple(Path(path).read_text(encoding="utf-8-sig").splitlines())
    except (OSError, UnicodeDecodeError):
        return ()


def locate(finding: Finding) -> int:
    """Best-effort 1-based line number of the finding's server entry."""
    lines = _lines(finding.source)
    if not lines:
        return 1
    if finding.rule_id.startswith("TP") and finding.message.startswith("["):
        tool = finding.message[1:finding.message.find("]")]
        needle = f'"name": {json.dumps(tool)}'
        for i, line in enumerate(lines, 1):
            if needle in line or needle.replace(": ", ":") in line:
                return i
    if finding.server:
        needle = json.dumps(finding.server)
        for i, line in enumerate(lines, 1):
            if needle + ":" in line.replace(" ", "") or f"{needle} :" in line:
                return i
        for i, line in enumerate(lines, 1):
            if needle in line:
                return i
    return 1


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.source, f.server or "", f.rule_id))


def render_text(findings: list[Finding], scanned: list[str], color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    c = (lambda code, s: f"{code}{s}{_RESET}") if color else (lambda code, s: s)
    out: list[str] = []
    out.append(c(_BOLD, f"mcp-guard {__version__}") + f" - scanned {len(scanned)} file(s)")
    for s in scanned:
        out.append(c(_DIM, f"  · {s}"))
    out.append("")
    if not findings:
        out.append(c(_COLORS[Severity.LOW], "No issues found."))
        return "\n".join(out)
    for f in sort_findings(findings):
        sev = f"{f.severity.name:<8}"
        where = f"{f.source}:{locate(f)}" + (f"  [{f.server}]" if f.server else "")
        out.append(f"{c(_COLORS[f.severity], sev)} {c(_BOLD, f.rule_id)} {f.title}")
        out.append(f"         {where}")
        out.append(f"         {f.message}")
        if f.evidence:
            out.append(c(_DIM, f"         evidence: {f.evidence}"))
        if f.remediation:
            out.append(c(_DIM, f"         fix: {f.remediation}"))
        out.append("")
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[s]} {s.name.lower()}" for s in sorted(counts, reverse=True))
    out.append(c(_BOLD, f"{len(findings)} finding(s): {summary}"))
    return "\n".join(out)


def render_json(findings: list[Finding], scanned: list[str]) -> str:
    counts = Counter(f.severity.name.lower() for f in findings)
    doc = {
        "tool": "mcp-guard",
        "version": __version__,
        "scanned": scanned,
        "summary": {"total": len(findings), **counts},
        "findings": [{**f.to_dict(), "line": locate(f)} for f in sort_findings(findings)],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _uri(path: str) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return p.resolve().as_uri()


_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0", Severity.INFO: "0.0",
}


def render_sarif(findings: list[Finding], scanned: list[str]) -> str:
    used = sorted({f.rule_id for f in findings})
    rule_index = {rid: i for i, rid in enumerate(used)}
    rules = []
    for rid in used:
        r = ALL_RULES[rid]
        rules.append({
            "id": rid,
            "name": r.title.title().replace(" ", "").replace("-", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.description},
            "help": {"text": r.remediation, "markdown": f"**Fix:** {r.remediation}"},
            "defaultConfiguration": {"level": r.severity.sarif_level},
            "properties": {
                "tags": ["security", "mcp", "ai-agents"],
                "security-severity": _SECURITY_SEVERITY[r.severity],
            },
        })
    results = []
    for f in sort_findings(findings):
        msg = f.message + (f" (server: {f.server})" if f.server else "")
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": f.severity.sarif_level,
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(f.source)},
                    "region": {"startLine": locate(f)},
                }
            }],
            "properties": {"security-severity": _SECURITY_SEVERITY[f.severity],
                           "severity": f.severity.name.lower()},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcp-guard",
                "version": __version__,
                "informationUri": "https://github.com/A-m-anuel/mcp-guard",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)

"""Detect tool poisoning / prompt injection in MCP tool definitions.

Input is the JSON result of an MCP ``tools/list`` call, in any of these shapes::

    {"tools": [...]}                      # raw tools/list result
    [...]                                 # bare list of tools
    {"server-name": {"tools": [...]}}     # several servers
    {"server-name": [...]}

Also supports rug-pull detection: save a baseline of tool-definition hashes, then
compare later snapshots against it.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .models import Finding, Severity


@dataclass(frozen=True)
class ToolRule:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str


TOOL_RULES: dict[str, ToolRule] = {
    r.id: r
    for r in [
        ToolRule("TP001", "Hidden instructions in tool description", Severity.HIGH,
                 "The description contains instructions aimed at the model rather than the user "
                 "(e.g. <IMPORTANT> blocks, 'ignore previous instructions', 'do not tell the user').",
                 "Do not install this server. Report it to the registry/publisher."),
        ToolRule("TP002", "Reference to sensitive files", Severity.HIGH,
                 "The tool definition mentions credential or config files (SSH keys, cloud "
                 "credentials, .env, MCP configs) - a common exfiltration setup.",
                 "Review why the tool needs this; treat as malicious unless clearly justified."),
        ToolRule("TP003", "Invisible or bidirectional Unicode", Severity.HIGH,
                 "The definition contains zero-width, bidi-override or Unicode tag characters that "
                 "hide text from human reviewers while the model still reads it.",
                 "Treat as malicious; inspect the raw bytes of the description."),
        ToolRule("TP004", "Data exfiltration instruction", Severity.HIGH,
                 "The description instructs the model to send, embed or forward data to a URL "
                 "or into a tool argument.",
                 "Do not install; report the server."),
        ToolRule("TP005", "Cross-tool shadowing", Severity.MEDIUM,
                 "The description tries to change how the model uses other tools or servers "
                 "(e.g. 'when the send_email tool is used, always ...').",
                 "Tool descriptions should only describe their own tool. Review the server."),
        ToolRule("TP006", "Unusually long description", Severity.LOW,
                 "Very long descriptions are a common place to hide injected instructions.",
                 "Read the full description manually."),
        ToolRule("TP007", "Tool definition changed since baseline", Severity.HIGH,
                 "A previously approved tool's description or schema changed (possible rug pull).",
                 "Re-review the tool before allowing further use; pin the server version."),
        ToolRule("TP008", "New tool since baseline", Severity.LOW,
                 "The server exposes a tool that was not present when the baseline was taken.",
                 "Review the new tool and refresh the baseline if acceptable."),
    ]
}

HIDDEN_INSTRUCTION = re.compile(
    r"(?i)("
    r"<\s*(important|system|instructions?|secret|hidden)\s*>|"
    r"\[\s*(INST|SYSTEM)\s*\]|"
    r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules)|"
    r"disregard\s+(all\s+|any\s+)?(previous|prior|above)\b|"
    r"(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show|notify|alert)\s+(this\s+to\s+)?(the\s+)?user|"
    r"without\s+(telling|informing|notifying|asking)\s+the\s+user|"
    r"the\s+user\s+(must|should)\s+not\s+(know|see|be\s+told)|"
    r"before\s+(using|calling)\s+this\s+tool,?\s+(you\s+must|first|always)|"
    r"you\s+are\s+now\s+|new\s+system\s+prompt"
    r")"
)

SENSITIVE_PATHS = re.compile(
    r"(?i)(~/\.ssh|\.ssh/|id_rsa|id_ed25519|authorized_keys|\.aws/credentials|\.azure/|"
    r"\.config/gcloud|\.kube/config|\.docker/config\.json|\.npmrc|\.pypirc|\.netrc|\.git-credentials|"
    r"(^|[\s/'\"`])\.env\b|/etc/(passwd|shadow)|mcp\.json|claude_desktop_config|\.claude\.json|"
    r"keychain|wallet\.dat|private\s+key)"
)

EXFIL = re.compile(
    r"(?i)("
    r"(send|post|upload|forward|transmit|exfiltrate)\s+.{0,60}?\s+to\s+(https?://|the\s+(url|endpoint|server|webhook))|"
    r"(include|embed|pass|put|insert|append)\s+.{0,80}?\s+(in|into|as)\s+(the\s+)?['\"`]?\w+['\"`]?\s+(parameter|argument|field|param)|"
    r"(read|cat|open)\s+.{0,40}?\s+and\s+(pass|send|include)\s+(its|the)\s+content"
    r")"
)

SHADOWING = re.compile(
    r"(?i)("
    r"when\s+(the\s+)?[`'\"]?[\w.\-]+[`'\"]?\s+tool\s+is\s+(used|called|invoked)|"
    r"(whenever|every\s+time)\s+(you|the\s+(model|assistant))\s+(use|call|invoke)s?\s+(any\s+)?(other\s+)?tool|"
    r"instead\s+of\s+(using\s+)?the\s+[`'\"]?[\w.\-]+[`'\"]?\s+tool|"
    r"(all|any)\s+(emails?|messages?|requests?)\s+must\s+(be\s+sent\s+to|include|cc|bcc)"
    r")"
)

INVISIBLE_RANGES = [
    (0x200B, 0x200F),   # zero-width + LRM/RLM
    (0x202A, 0x202E),   # bidi embedding / override
    (0x2060, 0x2064),   # word joiner, invisible operators
    (0x2066, 0x2069),   # bidi isolates
    (0xFEFF, 0xFEFF),   # BOM / ZWNBSP
    (0xE0000, 0xE007F), # Unicode tag characters (ASCII smuggling)
]

LONG_DESCRIPTION = 1500


def _invisible_chars(text: str) -> list[str]:
    hits = []
    for ch in text:
        cp = ord(ch)
        if any(lo <= cp <= hi for lo, hi in INVISIBLE_RANGES):
            hits.append(f"U+{cp:04X}")
    return hits


def _decode_tag_chars(text: str) -> str:
    """Unicode tag chars map 1:1 to ASCII; reveal any smuggled message."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def _text_fields(tool: dict[str, Any]) -> Iterable[tuple[str, str]]:
    """Yield (location, text) for every human/model-visible string in a tool."""
    for key in ("name", "title", "description"):
        if isinstance(tool.get(key), str):
            yield key, tool[key]
    annotations = tool.get("annotations")
    if isinstance(annotations, dict) and isinstance(annotations.get("title"), str):
        yield "annotations.title", annotations["title"]

    def walk(node: Any, path: str) -> Iterable[tuple[str, str]]:
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("description", "title", "default", "examples", "enum", "const") or k == "$comment":
                    if isinstance(v, str):
                        yield f"{path}.{k}", v
                    elif isinstance(v, list):
                        for i, item in enumerate(v):
                            if isinstance(item, str):
                                yield f"{path}.{k}[{i}]", item
                if isinstance(v, (dict, list)):
                    yield from walk(v, f"{path}.{k}")
                if k == "properties" and isinstance(v, dict):
                    for prop in v:
                        yield f"{path}.properties.<name>", prop
        elif isinstance(node, list):
            for i, item in enumerate(node):
                yield from walk(item, f"{path}[{i}]")

    for key in ("inputSchema", "input_schema", "outputSchema"):
        if isinstance(tool.get(key), dict):
            yield from walk(tool[key], key)


def normalise_tools(data: Any, source_name: str = "") -> dict[str, list[dict[str, Any]]]:
    """Return {server_name: [tool, ...]} from any supported input shape."""
    if isinstance(data, list):
        return {source_name or "server": [t for t in data if isinstance(t, dict)]}
    if isinstance(data, dict):
        if isinstance(data.get("tools"), list):
            return {source_name or "server": [t for t in data["tools"] if isinstance(t, dict)]}
        result = data.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):  # JSON-RPC envelope
            return {source_name or "server": [t for t in result["tools"] if isinstance(t, dict)]}
        out: dict[str, list[dict[str, Any]]] = {}
        for name, value in data.items():
            if isinstance(value, dict) and isinstance(value.get("tools"), list):
                out[str(name)] = [t for t in value["tools"] if isinstance(t, dict)]
            elif isinstance(value, list) and all(isinstance(t, dict) for t in value):
                out[str(name)] = list(value)
        return out
    return {}


def _f(rule_id: str, source: str, server: str, tool: str, message: str, evidence: str = "") -> Finding:
    r = TOOL_RULES[rule_id]
    return Finding(rule_id=rule_id, title=r.title, severity=r.severity, message=f"[{tool}] {message}",
                   source=source, server=server, remediation=r.remediation, evidence=evidence[:200])


def _snippet(text: str, match: re.Match[str]) -> str:
    start, end = max(0, match.start() - 30), min(len(text), match.end() + 30)
    return " ".join(text[start:end].split())


def scan_tool(tool: dict[str, Any], server: str, source: str) -> list[Finding]:
    name = str(tool.get("name", "<unnamed>"))
    findings: list[Finding] = []
    seen: set[str] = set()

    def add(f: Finding) -> None:
        key = f.rule_id
        if key not in seen:  # one finding per rule per tool keeps output readable
            seen.add(key)
            findings.append(f)

    for location, text in _text_fields(tool):
        invisible = _invisible_chars(text)
        if invisible:
            hidden = _decode_tag_chars(text)
            extra = f" Decoded hidden text: '{hidden[:120]}'" if hidden else ""
            add(_f("TP003", source, server, name,
                   f"{len(invisible)} invisible/bidi character(s) in {location}.{extra}",
                   ", ".join(sorted(set(invisible))[:8])))
        # analyse with invisible chars removed and compatibility-normalised
        clean = unicodedata.normalize("NFKC", "".join(c for c in text if not _invisible_chars(c)))
        clean = clean + " " + _decode_tag_chars(text)
        for rule_id, pattern in (("TP001", HIDDEN_INSTRUCTION), ("TP002", SENSITIVE_PATHS),
                                 ("TP004", EXFIL), ("TP005", SHADOWING)):
            m = pattern.search(clean)
            if m:
                add(_f(rule_id, source, server, name, f"Suspicious text in {location}.", _snippet(clean, m)))
        if location == "description" and len(text) > LONG_DESCRIPTION:
            add(_f("TP006", source, server, name, f"Description is {len(text)} characters long."))
    return findings


def tool_fingerprint(tool: dict[str, Any]) -> str:
    relevant = {k: tool.get(k) for k in ("name", "title", "description", "inputSchema", "annotations")}
    blob = json.dumps(relevant, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def make_baseline(servers: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return {
        "version": 1,
        "servers": {
            server: {str(t.get("name")): tool_fingerprint(t) for t in tools}
            for server, tools in servers.items()
        },
    }


def compare_baseline(servers: dict[str, list[dict[str, Any]]], baseline: dict[str, Any],
                     source: str) -> list[Finding]:
    findings: list[Finding] = []
    base = baseline.get("servers", {}) if isinstance(baseline, dict) else {}
    for server, tools in servers.items():
        known = base.get(server)
        if known is None:
            continue  # server not in baseline - nothing to compare
        for tool in tools:
            name = str(tool.get("name"))
            fp = tool_fingerprint(tool)
            if name not in known:
                findings.append(_f("TP008", source, server, name, "Tool not present in baseline."))
            elif known[name] != fp:
                findings.append(_f("TP007", source, server, name,
                                   "Definition hash differs from baseline.",
                                   f"{known[name][:12]} -> {fp[:12]}"))
    return findings


def scan_tools_file(path: Path, baseline: dict[str, Any] | None = None) -> tuple[list[Finding], dict[str, list[dict[str, Any]]]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    servers = normalise_tools(data, source_name=path.stem)
    findings: list[Finding] = []
    for server, tools in servers.items():
        for tool in tools:
            findings.extend(scan_tool(tool, server, str(path)))
    if baseline is not None:
        findings.extend(compare_baseline(servers, baseline, str(path)))
    return findings, servers

"""Core data models for mcp-guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity '{value}' (valid: {valid})") from exc

    @property
    def sarif_level(self) -> str:
        if self >= Severity.HIGH:
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"


@dataclass
class Server:
    """A single MCP server entry, normalised across client config formats."""

    name: str
    source: str  # path of the config file
    raw: dict[str, Any]
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    transport: str | None = None

    @property
    def is_remote(self) -> bool:
        return self.url is not None


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    message: str
    source: str
    server: str | None = None
    remediation: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name.lower(),
            "message": self.message,
            "source": self.source,
            "server": self.server,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }

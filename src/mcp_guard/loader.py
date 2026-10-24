"""Load MCP client configuration files and normalise server entries.

Supported layouts (all JSON / JSONC):

* ``{"mcpServers": {...}}``  - Claude Desktop, Claude Code (.mcp.json), Cursor,
  Windsurf, Cline, Gemini CLI
* ``{"servers": {...}}``     - VS Code (.vscode/mcp.json)
* ``{"mcp": {"servers": {...}}}`` - VS Code user settings.json
* ``{"context_servers": {...}}`` - Zed
"""

from __future__ import annotations

import json
import os
import platform
from pathlib import Path
from typing import Any, Iterable

from .models import Server

SERVER_KEYS = ("mcpServers", "servers", "context_servers")
URL_KEYS = ("url", "serverUrl", "httpUrl")


class ConfigError(Exception):
    pass


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, respecting strings."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(c)
            i += 1
    cleaned = "".join(out)
    # remove trailing commas before } or ] (outside strings - safe after comment strip
    # because we only touch commas followed by whitespace and a closing bracket)
    result: list[str] = []
    in_str = False
    i, n = 0, len(cleaned)
    while i < n:
        c = cleaned[i]
        if in_str:
            result.append(c)
            if c == "\\" and i + 1 < n:
                result.append(cleaned[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            result.append(c)
        elif c == ",":
            j = i + 1
            while j < n and cleaned[j] in " \t\r\n":
                j += 1
            if j < n and cleaned[j] in "}]":
                i += 1
                continue
            result.append(c)
        else:
            result.append(c)
        i += 1
    return "".join(result)


def load_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            return json.loads(strip_jsonc(text))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"invalid JSON in {path}: {exc}") from exc


def _find_server_maps(data: Any) -> list[dict[str, Any]]:
    maps: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return maps
    for key in SERVER_KEYS:
        value = data.get(key)
        if isinstance(value, dict):
            maps.append(value)
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        maps.append(mcp["servers"])
    # Claude Code ~/.claude.json keeps per-project servers under "projects"
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project in projects.values():
            if isinstance(project, dict) and isinstance(project.get("mcpServers"), dict):
                maps.append(project["mcpServers"])
    return maps


def _as_str_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): "" if v is None else str(v) for k, v in value.items()}


def normalise_server(name: str, raw: dict[str, Any], source: str) -> Server:
    command = raw.get("command")
    args = raw.get("args") or []
    env = raw.get("env") or {}
    # Zed: "command": {"path": ..., "args": [...], "env": {...}}
    if isinstance(command, dict):
        args = command.get("args") or args
        env = command.get("env") or env
        command = command.get("path")
    url = next((raw[k] for k in URL_KEYS if isinstance(raw.get(k), str)), None)
    transport = raw.get("type") or raw.get("transport")
    return Server(
        name=name,
        source=source,
        raw=raw,
        command=str(command) if command is not None else None,
        args=[str(a) for a in args] if isinstance(args, list) else [],
        env=_as_str_dict(env),
        url=url,
        headers=_as_str_dict(raw.get("headers")),
        transport=str(transport) if transport else None,
    )


def load_config(path: Path) -> tuple[Any, list[Server]]:
    """Return (raw parsed document, normalised servers)."""
    data = load_json(path)
    servers: list[Server] = []
    for server_map in _find_server_maps(data):
        for name, raw in server_map.items():
            if isinstance(raw, dict):
                servers.append(normalise_server(str(name), raw, str(path)))
    return data, servers


def load_servers(path: Path) -> list[Server]:
    return load_config(path)[1]


def default_config_paths(home: Path | None = None, cwd: Path | None = None) -> list[Path]:
    """Well-known MCP config locations for common clients."""
    home = home or Path.home()
    cwd = cwd or Path.cwd()
    system = platform.system()
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))

    if system == "Darwin":
        claude_desktop = home / "Library/Application Support/Claude/claude_desktop_config.json"
        vscode_user = home / "Library/Application Support/Code/User"
    elif system == "Windows":
        claude_desktop = appdata / "Claude/claude_desktop_config.json"
        vscode_user = appdata / "Code/User"
    else:
        claude_desktop = home / ".config/Claude/claude_desktop_config.json"
        vscode_user = home / ".config/Code/User"

    return [
        claude_desktop,
        home / ".claude.json",                       # Claude Code (user scope)
        cwd / ".mcp.json",                           # Claude Code (project scope)
        home / ".cursor/mcp.json",                   # Cursor (global)
        cwd / ".cursor/mcp.json",                    # Cursor (project)
        cwd / ".vscode/mcp.json",                    # VS Code (workspace)
        vscode_user / "mcp.json",                    # VS Code (user)
        vscode_user / "settings.json",               # VS Code (legacy "mcp" key)
        home / ".codeium/windsurf/mcp_config.json",  # Windsurf
        home / ".gemini/settings.json",              # Gemini CLI (user)
        cwd / ".gemini/settings.json",               # Gemini CLI (project)
        home / ".config/zed/settings.json",          # Zed
    ]


def discover(paths: Iterable[Path] | None = None) -> list[Path]:
    candidates = list(paths) if paths is not None else default_config_paths()
    seen: set[Path] = set()
    found: list[Path] = []
    for p in candidates:
        try:
            resolved = p.resolve()
        except OSError:
            continue
        if resolved in seen or not p.is_file():
            continue
        seen.add(resolved)
        found.append(p)
    return found

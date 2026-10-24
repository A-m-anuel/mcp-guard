"""Command-line interface.

Exit codes: 0 = no findings at/above --fail-on, 1 = findings at/above --fail-on, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .loader import ConfigError, discover, load_config
from .models import Finding, Severity
from .poisoning import TOOL_RULES, make_baseline, scan_tools_file
from .reporters import render_json, render_sarif, render_text
from .rules import RULES, check_file, scan_servers

CONFIG_FILENAMES = {
    "mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json",
    "cline_mcp_settings.json", "mcp_settings.json", ".claude.json",
}
SETTINGS_DIRS = {".gemini", ".vscode", ".claude", ".cursor", "zed"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", "site-packages"}


def find_configs_in_dir(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        parent = Path(dirpath).name
        for name in filenames:
            if name in CONFIG_FILENAMES or (
                parent in SETTINGS_DIRS and name in ("settings.json", "settings.local.json")
            ):
                found.append(Path(dirpath) / name)
    return sorted(found)


def collect_paths(inputs: list[str], use_discovery: bool) -> list[Path]:
    paths: list[Path] = []
    for raw in inputs:
        p = Path(raw).expanduser()
        if p.is_dir():
            paths.extend(find_configs_in_dir(p))
        elif p.is_file():
            paths.append(p)
        else:
            raise FileNotFoundError(f"no such file or directory: {raw}")
    if use_discovery or not inputs:
        paths.extend(discover())
    unique: dict[Path, Path] = {}
    for p in paths:
        unique.setdefault(p.resolve(), p)
    return list(unique.values())


def _filter(findings: list[Finding], min_sev: Severity, ignore: set[str]) -> list[Finding]:
    return [f for f in findings if f.severity >= min_sev and f.rule_id not in ignore]


def _emit(findings: list[Finding], scanned: list[str], fmt: str, output: str | None) -> None:
    if fmt == "json":
        text = render_json(findings, scanned)
    elif fmt == "sarif":
        text = render_sarif(findings, scanned)
    else:
        text = render_text(findings, scanned, color=None if output is None else False)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {fmt} report to {output} ({len(findings)} finding(s))", file=sys.stderr)
    else:
        print(text)


def _exit_code(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "never":
        return 0
    threshold = Severity.parse(fail_on)
    return 1 if any(f.severity >= threshold for f in findings) else 0


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        paths = collect_paths(args.paths, args.discover)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings: list[Finding] = []
    scanned: list[str] = []
    errors = 0
    for path in paths:
        try:
            data, servers = load_config(path)
        except ConfigError as exc:
            print(f"warning: {exc}", file=sys.stderr)
            errors += 1
            continue
        scanned.append(str(path))
        file_findings = scan_servers(servers)
        file_findings.extend(check_file(path, data, servers, file_findings))
        findings.extend(file_findings)
    if not scanned and errors:
        return 2
    findings = _filter(findings, Severity.parse(args.min_severity), set(args.ignore))
    _emit(findings, scanned, args.format, args.output)
    return _exit_code(findings, args.fail_on)


def cmd_tools(args: argparse.Namespace) -> int:
    baseline = None
    if args.baseline:
        try:
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read baseline: {exc}", file=sys.stderr)
            return 2
    findings: list[Finding] = []
    all_servers: dict = {}
    scanned: list[str] = []
    for raw in args.files:
        path = Path(raw)
        try:
            file_findings, servers = scan_tools_file(path, baseline)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            return 2
        findings.extend(file_findings)
        all_servers.update(servers)
        scanned.append(str(path))
    if args.save_baseline:
        Path(args.save_baseline).write_text(json.dumps(make_baseline(all_servers), indent=2) + "\n",
                                            encoding="utf-8")
        print(f"saved baseline for {sum(len(t) for t in all_servers.values())} tool(s) "
              f"to {args.save_baseline}", file=sys.stderr)
    findings = _filter(findings, Severity.parse(args.min_severity), set(args.ignore))
    _emit(findings, scanned, args.format, args.output)
    return _exit_code(findings, args.fail_on)


def cmd_rules(_: argparse.Namespace) -> int:
    for rule in list(RULES.values()) + list(TOOL_RULES.values()):
        print(f"{rule.id}  {rule.severity.name:<8} {rule.title}")
        print(f"        {rule.description}")
    return 0


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    p.add_argument("--min-severity", default="info",
                   help="hide findings below this level (info|low|medium|high|critical)")
    p.add_argument("--fail-on", default="high",
                   help="exit 1 if any finding is at/above this level, or 'never' (default: high)")
    p.add_argument("--ignore", default=[], type=lambda s: [x.strip().upper() for x in s.split(",") if x.strip()],
                   help="comma-separated rule IDs to skip, e.g. MCP003,MCP013")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description="Security scanner for MCP server configs and MCP tool definitions.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan MCP client config files (default)")
    scan.add_argument("paths", nargs="*",
                      help="config files or directories; with none, well-known client locations are scanned")
    scan.add_argument("--discover", action="store_true",
                      help="also scan well-known client config locations")
    _common(scan)
    scan.set_defaults(func=cmd_scan)

    tools = sub.add_parser("tools", help="scan MCP tools/list output for tool poisoning")
    tools.add_argument("files", nargs="+", help="JSON file(s) with tools/list results")
    tools.add_argument("--baseline", help="compare against a saved baseline (rug-pull detection)")
    tools.add_argument("--save-baseline", metavar="FILE", help="write a baseline of tool fingerprints")
    _common(tools)
    tools.set_defaults(func=cmd_tools)

    rules = sub.add_parser("rules", help="list all rules")
    rules.set_defaults(func=cmd_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:  # avoid UnicodeEncodeError on legacy Windows consoles
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("scan", "tools", "rules", "-h", "--help", "--version"):
        argv.insert(0, "scan")
    parser = build_parser()
    args = parser.parse_args(argv)
    for attr in ("min_severity", "fail_on"):
        value = getattr(args, attr, None)
        if value and value != "never":
            try:
                Severity.parse(value)
            except ValueError as exc:
                parser.error(str(exc))
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

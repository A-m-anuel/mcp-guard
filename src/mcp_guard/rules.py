"""Security rules for MCP server configurations."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urlparse

from .models import Finding, Server, Severity
from .secrets import (
    find_known_secret,
    is_placeholder,
    looks_like_generic_secret,
    redact,
)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str


RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        Rule("MCP001", "Hardcoded secret", Severity.HIGH,
             "A credential is stored in plain text in the MCP config (env, headers or URL). "
             "Config files are often synced, backed up or committed to git.",
             "Reference the secret from the environment or the client's input prompt "
             "(e.g. ${env:API_KEY} / ${input:api_key}) and rotate the exposed key."),
        Rule("MCP002", "Secret passed on command line", Severity.HIGH,
             "A credential is passed as a process argument, where any local user can read it "
             "via the process list (ps, /proc/<pid>/cmdline).",
             "Pass the secret through the server's env block instead of args."),
        Rule("MCP003", "Unpinned package", Severity.MEDIUM,
             "The server is fetched and executed by a package runner (npx/uvx/pipx/...) without "
             "an exact version. A compromised or hijacked release runs automatically on next launch.",
             "Pin an exact version, e.g. npx -y @scope/pkg@1.4.2 or uvx pkg==1.4.2."),
        Rule("MCP004", "Package from unvetted source", Severity.MEDIUM,
             "The package is installed straight from a git repo, URL or tarball, bypassing "
             "registry provenance and making the code mutable.",
             "Install a published, version-pinned release, or pin the git ref to a commit SHA."),
        Rule("MCP005", "Remote server over plain HTTP", Severity.HIGH,
             "A remote MCP server is reached over unencrypted HTTP/WS. Tool calls, results and "
             "any auth headers can be read or altered on the network.",
             "Use an https:// (or wss://) endpoint."),
        Rule("MCP006", "Credentials in server URL", Severity.HIGH,
             "The server URL embeds credentials (userinfo or token query parameter), which leak "
             "into logs, proxies and history.",
             "Send credentials in an Authorization header sourced from the environment."),
        Rule("MCP007", "Over-broad filesystem access", Severity.HIGH,
             "The server is granted the filesystem root, a whole drive or the user's home "
             "directory. A prompt-injected agent can then read SSH keys, cloud credentials "
             "and other MCP configs.",
             "Grant only the specific project directories the server needs."),
        Rule("MCP008", "Remote script piped to shell", Severity.CRITICAL,
             "The launch command downloads code and pipes it straight into a shell or "
             "interpreter on every start.",
             "Install a pinned, verified release instead of curl | sh."),
        Rule("MCP009", "Dangerous container options", Severity.HIGH,
             "The server runs in a container with options that break isolation (privileged, "
             "host network/PID, Docker socket or host root mount, extra capabilities).",
             "Drop the flag; mount only the directories needed, read-only where possible."),
        Rule("MCP010", "Unpinned container image", Severity.MEDIUM,
             "The container image has no tag or uses :latest, so its content can change "
             "between launches.",
             "Pin the image by digest (image@sha256:...) or at least an immutable version tag."),
        Rule("MCP011", "Tool calls auto-approved", Severity.MEDIUM,
             "Tool calls from this server run without human confirmation. Combined with "
             "prompt injection this lets untrusted content trigger actions silently.",
             "Remove auto-approval, or limit it to read-only tools."),
        Rule("MCP012", "Possible typosquatted package", Severity.HIGH,
             "The package name is one or two characters away from a well-known MCP server "
             "package - a classic typosquatting pattern.",
             "Verify the exact package name and publisher before running it."),
        Rule("MCP013", "Archived reference server", Severity.LOW,
             "This official reference server was archived upstream and no longer receives "
             "maintenance or security fixes.",
             "Move to the vendor-maintained replacement (e.g. github/github-mcp-server)."),
        Rule("MCP014", "Config file readable by other users", Severity.MEDIUM,
             "The config contains secrets and is readable by group/other users on this system.",
             "chmod 600 the file."),
        Rule("MCP015", "All project MCP servers auto-enabled", Severity.MEDIUM,
             "Every MCP server defined in any opened project is enabled without a prompt, so "
             "cloning a malicious repository can run attacker-defined servers.",
             "Set enableAllProjectMcpServers to false and approve project servers individually."),
        Rule("MCP016", "Shell wrapper hides real command", Severity.LOW,
             "The server is launched through a shell -c string, which hides the actual "
             "command from review and from this scanner's other checks.",
             "Call the executable directly with an args array."),
    ]
}

# --------------------------------------------------------------------------- helpers

PACKAGE_RUNNERS = {"npx", "bunx", "uvx", "pipx", "pnpx"}
SHELLS = {"sh", "bash", "zsh", "dash", "fish", "cmd", "powershell", "pwsh"}
CONTAINER_RUNTIMES = {"docker", "podman", "nerdctl"}

WELL_KNOWN_PACKAGES = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-brave-search",
    "@playwright/mcp",
    "@upstash/context7-mcp",
    "@azure/mcp",
    "@notionhq/notion-mcp-server",
    "@supabase/mcp-server-supabase",
    "@sentry/mcp-server",
    "@stripe/mcp",
    "mcp-server-fetch",
    "mcp-server-git",
    "mcp-server-time",
    "mcp-server-sqlite",
]

ARCHIVED_PACKAGES = {
    "@modelcontextprotocol/server-aws-kb-retrieval": "AWS KB Retrieval",
    "@modelcontextprotocol/server-brave-search": "Brave Search",
    "@modelcontextprotocol/server-everart": "EverArt",
    "@modelcontextprotocol/server-github": "GitHub",
    "@modelcontextprotocol/server-gitlab": "GitLab",
    "@modelcontextprotocol/server-gdrive": "Google Drive",
    "@modelcontextprotocol/server-google-maps": "Google Maps",
    "@modelcontextprotocol/server-postgres": "PostgreSQL",
    "@modelcontextprotocol/server-puppeteer": "Puppeteer",
    "@modelcontextprotocol/server-redis": "Redis",
    "@modelcontextprotocol/server-slack": "Slack",
    "mcp-server-sentry": "Sentry",
    "mcp-server-sqlite": "SQLite",
}

EXACT_NPM_VERSION = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0", "host.docker.internal"}
CRED_QUERY = re.compile(r"(?i)(api[_\-]?key|apikey|token|secret|password|passwd|access[_\-]?key|auth|sig|signature|key)$")
HOME_DIR = re.compile(r"^(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|/home/[^/]+|/Users/[^/]+|/root|[A-Za-z]:[\\/]Users[\\/][^\\/]+)[\\/]?$")
ROOT_DIR = re.compile(r"^(?:/|[A-Za-z]:[\\/]?|\\\\)$")


def basename(cmd: str | None) -> str:
    if not cmd:
        return ""
    name = PurePath(cmd.replace("\\", "/")).name.lower()
    for ext in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(ext):
            name = name[: -len(ext)]
    return name


def effective_command(server: Server) -> tuple[str, list[str]]:
    """Unwrap `cmd /c npx ...` (Windows idiom) to (npx, [...])."""
    cmd, args = basename(server.command), list(server.args)
    if cmd == "cmd" and args and args[0].lower() in ("/c", "/k") and len(args) > 1:
        return basename(args[1]), args[2:]
    return cmd, args


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def split_npm_spec(spec: str) -> tuple[str, str | None]:
    """'@scope/name@1.2.3' -> ('@scope/name', '1.2.3'); 'name' -> ('name', None)."""
    if spec.startswith("npm:"):
        spec = spec[4:]
    at = spec.rfind("@")
    if at > 0:
        return spec[:at], spec[at + 1:]
    return spec, None


def split_py_spec(spec: str) -> tuple[str, str | None, bool]:
    """Return (name, version, exact)."""
    m = re.match(r"^([A-Za-z0-9_.\-\[\],]+?)\s*(===|==|@|>=|<=|~=|!=|>|<)\s*(.+)$", spec)
    if not m:
        return spec, None, False
    name = re.sub(r"\[.*\]$", "", m.group(1))
    op, version = m.group(2), m.group(3)
    return name, version, op in ("==", "===", "@") and "*" not in version


def is_url_or_git(spec: str) -> bool:
    s = spec.lower()
    if s.startswith(("git+", "git:", "github:", "gitlab:", "bitbucket:", "http://", "https://", "file:")):
        return True
    if s.endswith((".tgz", ".tar.gz", ".whl", ".zip")):
        return True
    # npx owner/repo shorthand resolves to GitHub (scoped packages start with @)
    return bool(re.fullmatch(r"[a-z0-9_.\-]+/[a-z0-9_.\-]+(?:#.*)?", s))


def runner_package(cmd: str, args: list[str]) -> tuple[str, str] | None:
    """Return (ecosystem, package-spec) launched by a package runner, if any."""
    a = list(args)
    if cmd in ("pnpm", "yarn") and a and a[0] == "dlx":
        cmd, a = "npx", a[1:]
    if cmd == "pipx" and a and a[0] == "run":
        a = a[1:]
    if cmd == "uv" and len(a) >= 2 and a[0] == "tool" and a[1] == "run":
        cmd, a = "uvx", a[2:]
    if cmd not in PACKAGE_RUNNERS:
        return None
    eco = "npm" if cmd in ("npx", "bunx", "pnpx") else "pypi"
    value_flags = {"-p", "--package", "--from", "--with", "--python", "--spec", "--index-url", "--registry", "-c", "--call"}
    i = 0
    while i < len(a):
        tok = a[i]
        if tok in ("--from", "--spec", "-p", "--package") and i + 1 < len(a):
            return eco, a[i + 1]
        if "=" in tok and tok.split("=", 1)[0] in ("--from", "--spec", "--package"):
            return eco, tok.split("=", 1)[1]
        if tok in value_flags:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        return eco, tok
    return None


def _finding(rule_id: str, server: Server | None, source: str, message: str, evidence: str = "",
             severity: Severity | None = None) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        title=rule.title,
        severity=severity if severity is not None else rule.severity,
        message=message,
        source=source,
        server=server.name if server else None,
        remediation=rule.remediation,
        evidence=evidence,
    )


def is_project_scoped(source: str) -> bool:
    """Project-level configs are commonly committed to git, so leaks are worse."""
    p = Path(source)
    try:
        home = Path.home().resolve()
        parent = p.resolve().parent
    except OSError:
        return False
    if p.name == ".mcp.json":
        return True
    if p.parent.name in (".vscode", ".cursor", ".gemini") and parent.parent != home:
        return True
    return False


# --------------------------------------------------------------------------- server rules

def check_secrets(server: Server) -> Iterable[Finding]:
    escalate = Severity.CRITICAL if is_project_scoped(server.source) else None
    scope_note = " (project-scoped file - likely committed to git)" if escalate else ""
    for where, mapping in (("env", server.env), ("header", server.headers)):
        for key, value in mapping.items():
            label = find_known_secret(value)
            if label:
                yield _finding("MCP001", server, server.source,
                               f"{label} hardcoded in {where} '{key}'{scope_note}.", redact(value), escalate)
            elif looks_like_generic_secret(key, value):
                yield _finding("MCP001", server, server.source,
                               f"Literal credential in {where} '{key}'{scope_note}.", redact(value), escalate)
    for i, arg in enumerate(server.args):
        label = find_known_secret(arg)
        prev = server.args[i - 1] if i else ""
        flag_name, _, flag_val = arg.partition("=")
        generic = (
            (prev.startswith("-") and looks_like_generic_secret(prev, arg))
            or (arg.startswith("-") and flag_val and looks_like_generic_secret(flag_name, flag_val))
            or (re.fullmatch(r"[A-Z][A-Z0-9_]*=.+", arg) is not None
                and looks_like_generic_secret(flag_name, flag_val))  # docker -e KEY=value
        )
        if label or generic:
            what = label or "Credential"
            yield _finding("MCP002", server, server.source,
                           f"{what} passed as command-line argument #{i}.", redact(arg))
    if server.url:
        label = find_known_secret(server.url)
        if label:
            yield _finding("MCP001", server, server.source,
                           f"{label} embedded in server URL{scope_note}.", redact(server.url), escalate)


def check_url(server: Server) -> Iterable[Finding]:
    if not server.url:
        return
    parsed = urlparse(server.url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme in ("http", "ws") and host not in LOOPBACK_HOSTS and not host.startswith("127."):
        extra = " Authorization header is sent in clear text." if any(
            k.lower() in ("authorization", "x-api-key") for k in server.headers) else ""
        yield _finding("MCP005", server, server.source,
                       f"Remote server uses {parsed.scheme}:// to {host}.{extra}", server.url)
    if parsed.password or (parsed.username and not is_placeholder(parsed.username)):
        yield _finding("MCP006", server, server.source, "Server URL contains user credentials.",
                       redact(server.url))
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if CRED_QUERY.search(key) and value and not is_placeholder(value):
            yield _finding("MCP006", server, server.source,
                           f"Credential in URL query parameter '{key}'.", f"{key}={redact(value)}")


def check_packages(server: Server) -> Iterable[Finding]:
    cmd, args = effective_command(server)
    found = runner_package(cmd, args)
    if not found:
        return
    eco, spec = found
    if is_url_or_git(spec):
        pinned_commit = re.search(r"[#@][0-9a-f]{40}$", spec) is not None
        if not pinned_commit:
            yield _finding("MCP004", server, server.source,
                           f"{cmd} runs code directly from '{spec}'.", spec)
        return
    if eco == "npm":
        name, version = split_npm_spec(spec)
        exact = bool(version and EXACT_NPM_VERSION.match(version))
    else:
        name, version, exact = split_py_spec(spec)
    if not exact:
        detail = f"non-exact version '{version}'" if version else "no version specified"
        yield _finding("MCP003", server, server.source,
                       f"{cmd} launches '{name}' with {detail}.", spec)
    yield from _check_package_name(server, name)


def _check_package_name(server: Server, name: str) -> Iterable[Finding]:
    lname = name.lower()
    if lname in ARCHIVED_PACKAGES:
        sev = Severity.MEDIUM if lname.endswith("server-postgres") else None
        note = (" A read-only bypass via SQL injection has been publicly reported for this server "
                "(Datadog Security Labs)." if sev else "")
        yield _finding("MCP013", server, server.source,
                       f"'{name}' ({ARCHIVED_PACKAGES[lname]}) is archived.{note}", name, sev)
        return
    if lname in WELL_KNOWN_PACKAGES or len(lname) < 8:
        return
    for known in WELL_KNOWN_PACKAGES:
        d = levenshtein(lname, known)
        if 0 < d <= 2:
            yield _finding("MCP012", server, server.source,
                           f"'{name}' is {d} edit(s) away from well-known '{known}'.", name)
            return


def _path_candidates(args: list[str]) -> Iterable[str]:
    for arg in args:
        if arg.startswith("-") and "=" in arg:
            arg = arg.split("=", 1)[1]
        for part in arg.split(","):
            yield part.strip()


def check_filesystem(server: Server) -> Iterable[Finding]:
    cmd, args = effective_command(server)
    if cmd in CONTAINER_RUNTIMES:
        return  # handled by the container rule (host side of mounts)
    for p in _path_candidates(args):
        if ROOT_DIR.match(p):
            yield _finding("MCP007", server, server.source,
                           f"Server is given the filesystem root '{p}'.", p, Severity.CRITICAL)
        elif HOME_DIR.match(p):
            yield _finding("MCP007", server, server.source,
                           f"Server is given the whole home directory '{p}'.", p)


def check_shell(server: Server) -> Iterable[Finding]:
    cmd = basename(server.command)
    if cmd not in SHELLS:
        return
    args = server.args
    if cmd == "cmd" and args and args[0].lower() in ("/c", "/k") and len(args) > 1 \
            and basename(args[1]) not in SHELLS and len(args) > 2:
        return  # plain Windows `cmd /c npx ...` - analysed via effective_command
    script = " ".join(args)
    if re.search(r"(?i)(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b.*\|\s*(sudo\s+)?"
                 r"(sh|bash|zsh|python3?|node|iex|invoke-expression)\b", script):
        yield _finding("MCP008", server, server.source,
                       "Launch command pipes a downloaded script into an interpreter.", script[:200])
    elif any(a in ("-c", "/c", "-command", "-Command", "/k") for a in args):
        yield _finding("MCP016", server, server.source,
                       f"Server launched via '{cmd} -c'.", script[:200])


_DOCKER_VALUE_FLAGS = {
    "-e", "--env", "-v", "--volume", "--mount", "--name", "--network", "--net", "-p", "--publish",
    "-w", "--workdir", "-u", "--user", "--entrypoint", "--env-file", "--pid", "--ipc", "--cap-add",
    "--cap-drop", "--security-opt", "--platform", "-l", "--label", "--add-host", "--memory", "-m",
    "--cpus", "--device", "--userns", "--uts", "--pull", "--restart", "-h", "--hostname",
}


def check_container(server: Server) -> Iterable[Finding]:
    cmd, args = effective_command(server)
    if cmd not in CONTAINER_RUNTIMES or "run" not in args:
        return
    a = args[args.index("run") + 1:]
    image = None
    i = 0
    while i < len(a):
        tok = a[i]
        flag, has_eq, val = tok.partition("=")
        if tok.startswith("-"):
            value = val if has_eq else (a[i + 1] if flag in _DOCKER_VALUE_FLAGS and i + 1 < len(a) else "")
            yield from _docker_flag(server, flag, value)
            i += 1 if (has_eq or flag not in _DOCKER_VALUE_FLAGS) else 2
            continue
        image = tok
        break
    if image:
        if "@sha256:" in image:
            return
        last = image.rsplit("/", 1)[-1]
        tag = last.split(":", 1)[1] if ":" in last else None
        if tag in (None, "latest"):
            yield _finding("MCP010", server, server.source,
                           f"Image '{image}' is {'untagged' if tag is None else ':latest'}.", image)


def _docker_flag(server: Server, flag: str, value: str) -> Iterable[Finding]:
    msg = None
    if flag == "--privileged":
        msg = "Container runs with --privileged."
    elif flag in ("--network", "--net") and value == "host":
        msg = "Container shares the host network namespace."
    elif flag in ("--pid", "--ipc", "--uts", "--userns") and value == "host":
        msg = f"Container shares the host {flag.lstrip('-')} namespace."
    elif flag == "--cap-add" and value.upper().replace("CAP_", "") in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE"):
        msg = f"Container gains capability {value}."
    elif flag == "--security-opt" and "unconfined" in value:
        msg = f"Container disables a security profile ({value})."
    elif flag in ("-v", "--volume", "--mount"):
        if flag == "--mount":
            m = re.search(r"(?:source|src)=([^,]+)", value)
            host = m.group(1) if m else ""
        else:
            host = value.split(":", 1)[0] if not re.match(r"^[A-Za-z]:\\", value) else value[:3]
        if "docker.sock" in value:
            msg = "Docker socket mounted into container (host root equivalent)."
        elif ROOT_DIR.match(host):
            msg = f"Host filesystem root mounted ('{value}')."
        elif HOME_DIR.match(host):
            yield _finding("MCP007", server, server.source,
                           f"Whole home directory mounted into container ('{value}').", value)
    if msg:
        yield _finding("MCP009", server, server.source, msg, f"{flag} {value}".strip())


def check_auto_approve(server: Server) -> Iterable[Finding]:
    raw = server.raw
    for key in ("autoApprove", "alwaysAllow", "auto_approve"):
        tools = raw.get(key)
        if isinstance(tools, list) and tools:
            wildcard = any(t in ("*", "all") for t in tools)
            yield _finding("MCP011", server, server.source,
                           f"'{key}' auto-approves {'ALL tools' if wildcard else ', '.join(map(str, tools[:6]))}.",
                           str(tools[:10]), Severity.HIGH if wildcard else None)
        elif tools is True:
            yield _finding("MCP011", server, server.source, f"'{key}' is enabled for all tools.",
                           "true", Severity.HIGH)
    if raw.get("trust") is True:
        yield _finding("MCP011", server, server.source,
                       "'trust: true' bypasses all tool-call confirmations for this server.", "trust: true",
                       Severity.HIGH)


SERVER_CHECKS: list[Callable[[Server], Iterable[Finding]]] = [
    check_secrets,
    check_url,
    check_packages,
    check_filesystem,
    check_shell,
    check_container,
    check_auto_approve,
]

# --------------------------------------------------------------------------- file rules


def check_file(path: Path, data: Any, servers: list[Server], file_findings_so_far: list[Finding]) -> Iterable[Finding]:
    if isinstance(data, dict) and data.get("enableAllProjectMcpServers") is True:
        yield _finding("MCP015", None, str(path), "enableAllProjectMcpServers is true.",
                       "enableAllProjectMcpServers: true")
    has_secret = any(f.rule_id in ("MCP001", "MCP002") for f in file_findings_so_far)
    if has_secret and os.name == "posix":
        try:
            mode = path.stat().st_mode
        except OSError:
            return
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            yield _finding("MCP014", None, str(path),
                           f"File mode is {stat.filemode(mode)} and it contains secrets.",
                           oct(mode & 0o777))


def scan_servers(servers: list[Server]) -> list[Finding]:
    findings: list[Finding] = []
    for server in servers:
        for check in SERVER_CHECKS:
            findings.extend(check(server))
    return findings

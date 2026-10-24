# mcp-guard

**Security scanner for MCP (Model Context Protocol) server configurations and AI-agent tool definitions.**

AI coding assistants and desktop agents (Claude, Cursor, VS Code Copilot, Windsurf, Gemini CLI, Zed, Cline) now load third-party MCP servers that run with the user's privileges, see their files, and act on their behalf. The config files that wire these servers up have become a new, mostly unscanned attack surface:

- API keys pasted in plain text into `mcp.json` and committed to git
- `npx -y some-package` with no version pin: a hijacked release executes on the next launch
- Filesystem servers granted `/` or the whole home directory, including `~/.ssh` and cloud credentials
- Remote servers over plain `http://` with bearer tokens in clear text
- Tool calls auto-approved, so a prompt-injected agent acts without asking
- Malicious tool descriptions that smuggle instructions to the model (**tool poisoning**), sometimes hidden with invisible Unicode, and servers that silently change their tools after approval (**rug pulls**)

`mcp-guard` finds these issues statically, before an agent ever starts the server.

- Zero dependencies (Python 3.9+ standard library only)
- Understands every major client's config format, including JSONC with comments
- Text, JSON and **SARIF 2.1.0** output for GitHub code scanning
- CI-friendly exit codes, plus a ready-to-use GitHub Action
- Never prints secrets: all evidence is redacted

## Quick start

```bash
pip install git+https://github.com/A-m-anuel/mcp-guard

mcp-guard                      # scan the well-known config locations on this machine
mcp-guard scan path/to/repo    # scan every MCP config in a directory tree
mcp-guard scan .mcp.json -f sarif -o results.sarif
```

Example output (from [`examples/vulnerable`](examples/vulnerable/claude_desktop_config.json)):

```
CRITICAL MCP007 Over-broad filesystem access
         examples/vulnerable/claude_desktop_config.json:3  [filesystem]
         Server is given the filesystem root '/'.
         fix: Grant only the specific project directories the server needs.

HIGH     MCP012 Possible typosquatted package
         examples/vulnerable/claude_desktop_config.json:18  [notes]
         '@modelcontextprotocol/server-fileystem' is 1 edit(s) away from well-known '@modelcontextprotocol/server-filesystem'.

HIGH     MCP001 Hardcoded secret
         examples/vulnerable/claude_desktop_config.json:7  [github]
         Literal credential in env 'GITHUB_PERSONAL_ACCESS_TOKEN'.
         evidence: q8Zr…**** (32 chars)
...
22 finding(s): 2 critical, 11 high, 8 medium, 1 low
```

## What it checks

### Config rules (`mcp-guard scan`)

| ID | Severity | Rule |
|----|----------|------|
| MCP001 | High (Critical in project files) | Hardcoded secret in `env`, `headers` or URL: known formats (GitHub, OpenAI, Anthropic, AWS, Slack, Stripe, Azure, JWT, DB URLs, private keys) plus entropy-checked `*_KEY/*_TOKEN/*_SECRET` values |
| MCP002 | High | Secret passed as a command-line argument (readable via the process list) |
| MCP003 | Medium | Unpinned package launched by `npx`, `bunx`, `pnpm dlx`, `uvx`, `uv tool run`, `pipx run` |
| MCP004 | Medium | Package run directly from git, URL, tarball or `owner/repo` shorthand |
| MCP005 | High | Remote server over plain `http://` / `ws://` (loopback excluded) |
| MCP006 | High | Credentials embedded in the server URL (userinfo or `?token=` style query) |
| MCP007 | High / Critical | Server granted the filesystem root, a whole drive or the home directory (args or container mounts) |
| MCP008 | Critical | `curl … \| sh` style remote script piped into an interpreter |
| MCP009 | High | Container isolation broken: `--privileged`, host network/PID, Docker socket or host-root mount, dangerous capabilities, unconfined profiles |
| MCP010 | Medium | Container image untagged or `:latest` (pin by digest) |
| MCP011 | Medium / High | Tool calls auto-approved (`autoApprove`, `alwaysAllow`, Gemini `trust: true`) |
| MCP012 | High | Package name within 2 edits of a well-known MCP package (typosquatting) |
| MCP013 | Low / Medium | Archived official reference server that no longer receives fixes |
| MCP014 | Medium | Config file containing secrets is readable by other users (POSIX) |
| MCP015 | Medium | Claude Code `enableAllProjectMcpServers: true`: any cloned repo can start servers |
| MCP016 | Low | Server launched through `sh -c`, hiding the real command from review |

Secrets in **project-scoped** files (`.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json` inside a repo) are escalated to **Critical** because those files are routinely committed.

### Tool-definition rules (`mcp-guard tools`)

| ID | Severity | Rule |
|----|----------|------|
| TP001 | High | Hidden instructions aimed at the model (`<IMPORTANT>`, "ignore previous instructions", "do not tell the user", …) |
| TP002 | High | References to credential/config files (`~/.ssh`, `.aws/credentials`, `.env`, `mcp.json`, …) |
| TP003 | High | Invisible, bidi-override or Unicode **tag** characters; tag-smuggled text is decoded and shown |
| TP004 | High | Exfiltration instructions (send data to a URL, stuff file contents into a parameter) |
| TP005 | Medium | Cross-tool shadowing ("when the `send_email` tool is used, always bcc …") |
| TP006 | Low | Unusually long description |
| TP007 | High | Tool definition changed since the approved baseline (**rug pull**) |
| TP008 | Low | New tool appeared since the baseline |

Every string a model can see is scanned, including JSON-Schema parameter descriptions, defaults, enums and property names.

Run `mcp-guard rules` for the full descriptions.

## Supported clients

| Client | Locations scanned by default |
|--------|------------------------------|
| Claude Desktop | `claude_desktop_config.json` (macOS / Windows / Linux paths) |
| Claude Code | `~/.claude.json` (incl. per-project servers), `./.mcp.json` |
| Cursor | `~/.cursor/mcp.json`, `./.cursor/mcp.json` |
| VS Code | `./.vscode/mcp.json`, user `mcp.json`, legacy `"mcp"` key in `settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Gemini CLI | `~/.gemini/settings.json`, `./.gemini/settings.json` |
| Zed | `~/.config/zed/settings.json` (`context_servers`) |
| Cline / Roo | any file passed explicitly (`autoApprove` / `alwaysAllow` understood) |

When scanning a directory, mcp-guard picks up all of the file names above (skipping `.git`, `node_modules` and virtualenvs).

## Detecting tool poisoning and rug pulls

Dump a server's tool list, for example with the MCP Inspector CLI:

```bash
npx @modelcontextprotocol/inspector --cli npx -y @acme/some-server@1.2.3 --method tools/list > tools.json
mcp-guard tools tools.json
```

Accepted input: a raw `tools/list` result, a JSON-RPC response, a bare list of tools, or `{"server-name": {...}}` for several servers.

Pin what you reviewed, then detect changes later:

```bash
mcp-guard tools tools.json --save-baseline mcp-baseline.json   # after manual review
mcp-guard tools tools-today.json --baseline mcp-baseline.json  # TP007 / TP008 on changes
```

Try it on the bundled sample: `mcp-guard tools examples/poisoned_tools.json`. It includes an `<IMPORTANT>` exfiltration payload, a shadowing description and an instruction hidden in invisible Unicode tag characters.

## CI integration

### GitHub Action

```yaml
name: MCP security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  mcp-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: A-m-anuel/mcp-guard@main
        id: scan
        with:
          path: .
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

Findings then show up in the repository's **Security → Code scanning** tab.

### Any CI / pre-commit

```bash
mcp-guard scan . --fail-on high      # exit 1 if any high/critical finding
```

| Option | Meaning |
|--------|---------|
| `-f text\|json\|sarif` | Output format |
| `-o FILE` | Write report to a file |
| `--fail-on LEVEL` | Exit 1 at/above this severity (`never` to always exit 0). Default `high` |
| `--min-severity LEVEL` | Hide findings below this level |
| `--ignore MCP003,MCP013` | Skip rules |
| `--discover` | Also scan well-known locations when paths are given |

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` usage or parse error.

## Fixing findings: a safe config

[`examples/secure/.vscode/mcp.json`](examples/secure/.vscode/mcp.json) scans clean:

```jsonc
{
  "inputs": [{ "type": "promptString", "id": "github_token", "password": true }],
  "servers": {
    "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "${workspaceFolder}"] },
    "github":     { "type": "http", "url": "https://api.githubcopilot.com/mcp/",
                    "headers": { "Authorization": "Bearer ${input:github_token}" } },
    "fetch":      { "command": "uvx", "args": ["mcp-server-fetch==2025.4.7"] }
  }
}
```

(Version numbers in the examples are illustrative; pin the release you actually reviewed.)

## Limitations

- Static analysis of configuration only: mcp-guard does not execute servers or audit their source code.
- Tool-poisoning detection is pattern-based. It catches the published attack styles and obfuscation tricks, but a determined attacker can phrase instructions to evade any fixed pattern list. Treat a clean result as "no known indicators", not as proof of safety.
- Typosquat detection compares against a curated list of popular MCP packages.

## Development

```bash
git clone https://github.com/A-m-anuel/mcp-guard && cd mcp-guard
python -m unittest discover -s tests -v    # or: pytest
```

Test fixtures assemble fake credentials at runtime so the repository never contains strings that look like real provider keys.

## License

MIT © 2026 Amanuel Abate Seid
